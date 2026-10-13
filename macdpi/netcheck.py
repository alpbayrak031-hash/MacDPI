"""Internet reachability checks used to gate startup and to recover from sleep.

Deliberately does not resolve a hostname: on a captive or half-up network DNS
is exactly the thing that hangs, so reachability is tested by opening a TCP
connection straight to a known address.
"""

import asyncio
import socket

# Well-known anycast resolvers, reachable on 443 from almost anywhere.
FALLBACK_TARGETS = [("1.1.1.1", 443), ("9.9.9.9", 443), ("208.67.222.222", 443)]


async def _can_connect(ip: str, port: int, timeout: float) -> bool:
    # asyncio owns the socket here on purpose: a hand-rolled socket that is
    # closed after a cancelled connect can leave its descriptor registered
    # with the event loop, which then waits forever on a callback that can
    # never fire.
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def is_online(ctx, timeout: float = 3.0) -> bool:
    targets = []
    if ctx.doh and ctx.doh_ip:
        targets.append((ctx.doh_ip, 443))
    targets.extend(t for t in FALLBACK_TARGETS if t not in targets)

    for ip, port in targets:
        if await _can_connect(ip, port, timeout):
            return True
    return False


async def wait_until_online(ctx, log, max_wait: float) -> bool:
    """Poll until the network answers, or `max_wait` seconds elapse.

    At login the Wi-Fi interface usually exists well before it has associated
    and routed, so starting up the moment launchd fires would just mean a burst
    of failed lookups.
    """
    waited = 0.0
    delay = 1.0
    announced = False
    while waited < max_wait:
        if await is_online(ctx):
            if announced:
                log.info(f"network reachable after {waited:.0f}s")
            return True
        if not announced:
            log.info("waiting for an internet connection...")
            announced = True
        await asyncio.sleep(delay)
        waited += delay
        delay = min(delay * 1.5, 15.0)
    log.warn(f"no internet connection after {max_wait:.0f}s; "
             "serving anyway and will recover when it returns")
    return False


def _local_address():
    """The address this Mac would send from right now, or None if offline.

    "Connecting" a UDP socket transmits nothing; it only makes the kernel pick
    a route, which reveals the local address on the active interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


async def _default_route():
    """(gateway, interface) of the default route, or None if it has none."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "/sbin/route", "-n", "get", "default",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 3)
    except (OSError, asyncio.TimeoutError):
        return None
    fields = {}
    for line in out.decode("latin-1").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    if "gateway" not in fields:
        return None
    return fields["gateway"], fields.get("interface")


async def network_identity():
    """A cheap fingerprint of the network the Mac is attached to."""
    address = _local_address()
    if address is None:
        return None
    return address, await _default_route()


async def monitor(ctx, resolver, log, stop, interval: float = 30.0,
                  on_change=None):
    """Watch for the connection dropping, coming back, or moving networks.

    Any of those can put the Mac behind a different filter, so the DNS cache
    and the DoH circuit breaker are cleared, and `on_change` is called so the
    proxy stops trusting strategies it verified on the previous network.
    """
    def changed(why):
        log.info(f"{why}; flushing DNS cache and re-verifying strategies")
        resolver.reset()
        if on_change is not None:
            on_change()

    online = True
    network = await network_identity()
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), interval)
                return
            except asyncio.TimeoutError:
                pass

            now_online = await is_online(ctx)
            current = await network_identity()
            if now_online and not online:
                changed("internet connection restored")
            elif not now_online and online:
                log.warn("internet connection lost")
            elif now_online and current is not None and current != network:
                changed("network changed")
            online = now_online
            if current is not None:
                network = current
    except asyncio.CancelledError:
        pass

"""Internet reachability checks used to gate startup and to recover from sleep.

Deliberately does not resolve a hostname: on a captive or half-up network DNS
is exactly the thing that hangs, so reachability is tested by opening a TCP
connection straight to a known address.
"""

import asyncio

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


async def monitor(ctx, resolver, log, stop, interval: float = 30.0):
    """Watch for the connection dropping and coming back.

    On the way back, the DNS cache and the DoH circuit breaker are cleared so a
    laptop waking on a different network does not keep serving stale addresses.
    """
    online = True
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), interval)
                return
            except asyncio.TimeoutError:
                pass

            now_online = await is_online(ctx)
            if now_online and not online:
                log.info("internet connection restored; flushing DNS cache")
                resolver.reset()
            elif not now_online and online:
                log.warn("internet connection lost")
            online = now_online
    except asyncio.CancelledError:
        pass

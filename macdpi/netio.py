"""Non-blocking socket wrapper with the low-level knobs the strategies need.

asyncio's own stream transports hide `send()` flags, so the upstream side of
every connection is driven through raw sockets instead.
"""

import asyncio
import errno
import itertools
import random
import socket

# When transparent interception is on, the engine's own upstream connections
# must not themselves be redirected back into the engine - that would loop
# forever. pf excludes a reserved band of source ports, chosen below the macOS
# ephemeral range (49152+) so nothing else ever picks them, and every upstream
# socket binds into that band. See pfgen.py for the matching firewall rule.
SRC_PORT_LOW = 40000
SRC_PORT_HIGH = 44999
# Start at a random point in the band so that two processes sharing it (the
# engine and a `--test` run, say) do not walk the same ports in step.
_SRC_PORTS = list(range(SRC_PORT_LOW, SRC_PORT_HIGH + 1))
_src_port_start = random.randrange(len(_SRC_PORTS))
_src_port_cycle = itertools.cycle(
    _SRC_PORTS[_src_port_start:] + _SRC_PORTS[:_src_port_start])

# connect() errors that mean "this source port is taken for that destination".
_PORT_CLASH = (errno.EADDRINUSE, errno.EADDRNOTAVAIL)


def _bind_reserved_source_port(sock: socket.socket):
    """Bind to a port in the reserved band, retrying past 4-tuple clashes.

    SO_REUSEADDR/SO_REUSEPORT let one source port serve many distinct
    destinations, so the band is nowhere near exhausted in practice; a clash
    only happens when the same source port is reused for the same destination,
    and then the next candidate resolves it.
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (OSError, AttributeError):
        pass
    bind_addr = "::" if sock.family == socket.AF_INET6 else "0.0.0.0"
    for _ in range(64):
        port = next(_src_port_cycle)
        try:
            sock.bind((bind_addr, port))
            return
        except OSError:
            continue
    # Fall back to a kernel-chosen port; it will be in the ephemeral range and
    # thus redirected, but failing to bind at all would be worse.


class Upstream:
    """One outbound TCP connection, driven directly on the file descriptor."""

    def __init__(self, sock: socket.socket, loop=None):
        self.sock = sock
        self.loop = loop or asyncio.get_running_loop()
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @classmethod
    async def connect(cls, ip: str, port: int, timeout: float, loop=None,
                      reserve_source_port: bool = False):
        loop = loop or asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        # One source port serves many destinations, but not the same one
        # twice: once the band has wrapped round, a port may still be carrying
        # an older connection to this very address, and connect() then fails
        # with EADDRINUSE. That says nothing about the server, so move on to
        # the next port rather than report the destination unreachable.
        attempts = 8 if reserve_source_port else 1
        for attempt in range(attempts):
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
            if reserve_source_port:
                _bind_reserved_source_port(sock)
            fd = sock.fileno()
            try:
                await asyncio.wait_for(loop.sock_connect(sock, (ip, port)),
                                       timeout)
            except BaseException as exc:
                # Unregister before closing. A cancelled sock_connect can leave
                # the descriptor registered with the loop, and closing it out
                # from under the selector strands a callback that never fires -
                # which hangs the whole proxy, not just this connection.
                loop.remove_writer(fd)
                sock.close()
                if (isinstance(exc, OSError) and exc.errno in _PORT_CLASH
                        and attempt + 1 < attempts):
                    continue
                raise
            return cls(sock, loop)

    async def _writable(self):
        fut = self.loop.create_future()
        fd = self.sock.fileno()
        self.loop.add_writer(fd, lambda: fut.done() or fut.set_result(None))
        try:
            await fut
        finally:
            self.loop.remove_writer(fd)

    async def send(self, data: bytes, flags: int = 0):
        """sendall(), but with access to send flags such as MSG_OOB."""
        view = memoryview(data)
        while view:
            try:
                sent = self.sock.send(view, flags)
            except (BlockingIOError, InterruptedError):
                await self._writable()
                continue
            view = view[sent:]

    async def send_oob(self, byte: bytes = b"\x00"):
        """Send one urgent byte.

        With SO_OOBINLINE off (the default) the peer's TCP stack pulls this
        byte back out of the stream, but most DPI boxes ignore the urgent
        pointer and read it inline — which corrupts whatever they think the
        hostname is.
        """
        await self.send(byte, socket.MSG_OOB)

    async def recv(self, n: int = 65536) -> bytes:
        return await self.loop.sock_recv(self.sock, n)

    def _ttl_opt(self):
        if self.sock.family == socket.AF_INET6:
            return socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS
        return socket.IPPROTO_IP, socket.IP_TTL

    def get_ttl(self) -> int:
        try:
            ttl = self.sock.getsockopt(*self._ttl_opt())
        except OSError:
            ttl = 0
        # IPv6 reports -1 for "use the system default".
        return ttl if ttl > 0 else 64

    def set_ttl(self, ttl: int):
        self.sock.setsockopt(*self._ttl_opt(), ttl)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

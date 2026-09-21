"""Non-blocking socket wrapper with the low-level knobs the strategies need.

asyncio's own stream transports hide `send()` flags, so the upstream side of
every connection is driven through raw sockets instead.
"""

import asyncio
import itertools
import socket

# When transparent interception is on, the engine's own upstream connections
# must not themselves be redirected back into the engine - that would loop
# forever. pf excludes a reserved band of source ports, chosen below the macOS
# ephemeral range (49152+) so nothing else ever picks them, and every upstream
# socket binds into that band. See pfgen.py for the matching firewall rule.
SRC_PORT_LOW = 40000
SRC_PORT_HIGH = 44999
_src_port_cycle = itertools.cycle(range(SRC_PORT_LOW, SRC_PORT_HIGH + 1))


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
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        if reserve_source_port:
            _bind_reserved_source_port(sock)
        fd = sock.fileno()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        except BaseException:
            # Unregister before closing. A cancelled sock_connect can leave the
            # descriptor registered with the loop, and closing it out from
            # under the selector strands a callback that never fires - which
            # hangs the whole proxy, not just this connection.
            loop.remove_writer(fd)
            sock.close()
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

    def set_ttl(self, ttl: int):
        if self.sock.family == socket.AF_INET6:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

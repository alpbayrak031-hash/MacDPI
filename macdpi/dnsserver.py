"""A local DNS server that answers over DNS-over-HTTPS.

MacDPI already resolves names over DoH for everything that reaches its proxy.
What it cannot cover is software that resolves names itself through the system
resolver *before* connecting - Roblox's client is one - on a network that drops
plain DNS for blocked names. Those apps never reach the proxy; they fail at
"DnsResolve". Pointing the system resolver at this server fixes that: every
lookup is carried over DoH (with the same evasion as the rest of MacDPI), so
the network never sees a plain query for the name.

Safety: if DoH cannot answer within a short budget, the query is forwarded to
the network's own resolvers instead, so a DoH outage degrades to "same as
before" rather than taking every name on the Mac down with it.

Port 53 is privileged, but macOS lets an unprivileged process bind it on the
wildcard address (not on 127.0.0.1 alone). Binding the wildcard would expose a
resolver to the LAN, so only queries from this machine are answered.
"""

import asyncio
import ipaddress
import socket
import struct
import subprocess

DOH_BUDGET = 3.0          # seconds to wait for DoH before falling back
PLAIN_TIMEOUT = 2.0       # per upstream, for the plain fallback
MAX_UDP = 1232            # larger answers are truncated so the client retries on TCP
LAST_RESORT = ("1.1.1.1", "8.8.8.8")


def _is_local(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    # A reply from a wildcard socket to this Mac's own address.
    try:
        own = {i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        own = set()
    return str(ip) in own


def parse_question(query: bytes):
    """(qname, qtype) of a query's first question, or (None, None)."""
    if len(query) < 12:
        return None, None
    pos, labels = 12, []
    while pos < len(query):
        n = query[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 or pos + 1 + n > len(query):
            return None, None
        labels.append(query[pos + 1:pos + 1 + n].decode("latin-1"))
        pos += 1 + n
    if pos + 4 > len(query):
        return None, None
    return ".".join(labels), struct.unpack(">H", query[pos:pos + 2])[0]


def _servfail(query: bytes) -> bytes:
    """A SERVFAIL reply echoing the question."""
    if len(query) < 12:
        return b""
    flags = 0x8000 | (query[2] & 0x01) << 8 | 0x0080 | 2        # QR, RD, RA, SERVFAIL
    return query[:2] + struct.pack(">H", flags) + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]


def _truncate(reply: bytes) -> bytes:
    """Header + question only, TC set: tells the client to retry over TCP."""
    if len(reply) < 12:
        return reply
    qd = struct.unpack(">H", reply[4:6])[0]
    pos = 12
    for _ in range(qd):
        while pos < len(reply) and reply[pos] != 0:
            pos += 1 + reply[pos] if not reply[pos] & 0xC0 else 2
        pos += 5
    flags = struct.unpack(">H", reply[2:4])[0] | 0x0200
    return reply[:2] + struct.pack(">H", flags) + reply[4:6] + b"\x00" * 6 + reply[12:pos]


def system_upstreams():
    """The network's own resolvers (never loopback), for the fallback."""
    out = []
    try:
        text = subprocess.run(["/usr/sbin/scutil", "--dns"], capture_output=True,
                              text=True, timeout=3).stdout
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("nameserver[") and ":" in line:
                addr = line.split(":", 1)[1].strip()
                if addr and not addr.startswith("127.") and addr != "::1" \
                        and ":" not in addr and addr not in out:
                    out.append(addr)
    except (OSError, subprocess.SubprocessError):
        pass
    # Once the system resolver points at us, scutil only shows 127.0.0.1, so ask
    # DHCP directly for what the network handed out on the primary interface.
    try:
        route = subprocess.run(["/sbin/route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=3).stdout
        iface = next((l.split(":", 1)[1].strip() for l in route.splitlines()
                      if l.strip().startswith("interface:")), "en0")
        dhcp = subprocess.run(["/usr/sbin/ipconfig", "getoption", iface, "domain_name_server"],
                              capture_output=True, text=True, timeout=3).stdout
        for addr in dhcp.replace(",", " ").split():
            if addr and not addr.startswith("127.") and ":" not in addr and addr not in out:
                out.insert(0, addr)
    except (OSError, subprocess.SubprocessError):
        pass
    for addr in LAST_RESORT:
        if addr not in out:
            out.append(addr)
    return out


def _plain_forward(query: bytes, servers):
    """Blocking: ask each upstream over UDP until one answers."""
    for server in servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(PLAIN_TIMEOUT)
        try:
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(65535)
            if data[:2] == query[:2]:
                return data
        except OSError:
            continue
        finally:
            sock.close()
    return b""


class DnsServer:
    def __init__(self, ctx, resolver, log):
        self.ctx, self.resolver, self.log = ctx, resolver, log
        self.stats = {"queries": 0, "doh": 0, "fallback": 0, "failed": 0, "refused": 0}
        self._udp = None
        self._tcp = None
        self._upstreams = []

    async def start(self):
        loop = asyncio.get_running_loop()
        self._upstreams = system_upstreams()
        port = self.ctx.dns_port
        self._udp, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self), local_addr=("0.0.0.0", port))
        self._tcp = await asyncio.start_server(
            self._handle_tcp, "0.0.0.0", port, reuse_address=True, backlog=128)
        self.log.info(f"DNS server on port {port} (answers this Mac only; "
                      f"DoH first, falls back to {', '.join(self._upstreams[:3])})")

    async def close(self):
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()

    async def answer(self, query: bytes) -> bytes:
        """Resolve one wire-format query."""
        self.stats["queries"] += 1
        name, _ = parse_question(query)
        if name is None:
            return _servfail(query)
        if self.ctx.doh:
            try:
                reply = await asyncio.wait_for(self.resolver.doh_wire(query), DOH_BUDGET)
                if reply[:2] != query[:2]:
                    reply = query[:2] + reply[2:]
                self.stats["doh"] += 1
                return reply
            except Exception as exc:                          # noqa: BLE001
                self.log.debug(f"dns {name}: DoH failed ({exc!r}); falling back")
        loop = asyncio.get_running_loop()
        if not self._upstreams or self.stats["fallback"] % 50 == 49:
            self._upstreams = await loop.run_in_executor(None, system_upstreams)
        reply = await loop.run_in_executor(None, _plain_forward, query, self._upstreams)
        if reply:
            self.stats["fallback"] += 1
            return reply
        self.stats["failed"] += 1
        return _servfail(query)

    async def _handle_tcp(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            if not peer or not _is_local(peer[0]):
                self.stats["refused"] += 1
                return
            while True:
                head = await asyncio.wait_for(reader.readexactly(2), 10)
                query = await asyncio.wait_for(
                    reader.readexactly(struct.unpack(">H", head)[0]), 10)
                reply = await self.answer(query)
                writer.write(struct.pack(">H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server, self.transport = server, None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not _is_local(addr[0]):
            self.server.stats["refused"] += 1
            return
        asyncio.ensure_future(self._reply(data, addr))

    async def _reply(self, data, addr):
        try:
            reply = await self.server.answer(data)
            if len(reply) > MAX_UDP:
                reply = _truncate(reply)
            if reply:
                self.transport.sendto(reply, addr)
        except Exception as exc:                              # noqa: BLE001
            self.server.log.debug(f"dns reply error: {exc!r}")

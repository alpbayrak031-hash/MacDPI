"""DNS-over-HTTPS resolver.

ISPs that censor by returning forged A records are defeated here rather than
in the desync layer. The resolver is addressed by IP so no plaintext lookup is
ever needed to bootstrap it.
"""

import asyncio
import random
import ssl
import struct
import time

from .desync import DEFAULT_LADDER, TLS_STRATEGIES
from .netio import Upstream
from .tlsclient import TLSStream

TYPE_A = 1
TYPE_AAAA = 28
TYPE_CNAME = 5
TYPE_SRV = 33

# Lookups run over a few keep-alive connections at once, so a page that needs
# thirty names does not queue them all behind a single one.
DOH_CONNECTIONS = 4
# How long a provider that failed is set aside before it is tried again.
PROVIDER_COOLDOWN = 120
MAX_RESPONSE = 65536


def _encode_label(label: str) -> bytes:
    # SRV names carry underscore labels (_minecraft._tcp), which IDNA rejects;
    # those are plain ASCII, so only non-ASCII labels need IDNA at all.
    try:
        return label.encode("ascii")
    except UnicodeEncodeError:
        return label.encode("idna")


def encode_query(name: str, qtype: int) -> bytes:
    qid = random.getrandbits(16)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(l)]) + l for l in (_encode_label(p) for p in name.split(".") if p)
    ) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def _skip_name(buf: bytes, pos: int) -> int:
    while True:
        ln = buf[pos]
        if ln == 0:
            return pos + 1
        if ln & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + ln


def _read_name(buf: bytes, pos: int, _depth: int = 0):
    """Read a DNS name at `pos`, following compression pointers.

    Returns (dotted_name, position_after_the_name_field). Only the bytes up to
    the first pointer belong to this field; a pointer's target is read but does
    not advance the field position.
    """
    labels = []
    end = None
    while _depth < 32:
        if pos >= len(buf):
            break
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:                  # compression pointer
            if pos + 1 >= len(buf):
                break
            target = ((length & 0x3F) << 8) | buf[pos + 1]
            if end is None:
                end = pos + 2
            sub, _ = _read_name(buf, target, _depth + 1)
            if sub:
                labels.append(sub)
            pos = end
            break
        labels.append(buf[pos + 1:pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    return ".".join(l for l in labels if l), (end if end is not None else pos)


def decode_srv(buf: bytes):
    """Return a list of (priority, weight, port, target) from SRV answers."""
    if len(buf) < 12:
        return []
    qd, an = struct.unpack(">HH", buf[4:8])
    pos = 12
    for _ in range(qd):
        pos = _skip_name(buf, pos) + 4
    out = []
    for _ in range(an):
        pos = _skip_name(buf, pos)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        rec_end = pos + rdlen
        if rtype == TYPE_SRV and rdlen >= 7:
            priority, weight, port = struct.unpack(">HHH", buf[pos:pos + 6])
            target, _ = _read_name(buf, pos + 6)
            if target:
                out.append((priority, weight, port, target.rstrip(".")))
        pos = rec_end
    return out


def decode_answers(buf: bytes):
    """Yield (rtype, rdata, ttl) for every answer record."""
    if len(buf) < 12:
        return
    qd, an = struct.unpack(">HH", buf[4:8])
    pos = 12
    for _ in range(qd):
        pos = _skip_name(buf, pos) + 4
    for _ in range(an):
        pos = _skip_name(buf, pos)
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        yield rtype, buf[pos:pos + rdlen], ttl
        pos += rdlen


def _fmt_ip(rtype: int, rdata: bytes):
    if rtype == TYPE_A and len(rdata) == 4:
        return ".".join(str(b) for b in rdata)
    if rtype == TYPE_AAAA and len(rdata) == 16:
        parts = [f"{rdata[i] << 8 | rdata[i + 1]:x}" for i in range(0, 16, 2)]
        return ":".join(parts)
    return None


class _ProviderError(Exception):
    """The resolver answered, but not with a usable DNS response."""


class _Conn:
    """One keep-alive HTTPS connection to a DoH provider."""

    __slots__ = ("stream", "provider", "strategy", "buf", "keep", "fresh")

    def __init__(self, stream, provider, strategy):
        self.stream = stream
        self.provider = provider
        self.strategy = strategy
        self.buf = bytearray()
        self.keep = True
        # True until a query has succeeded on it. A failure on a fresh
        # connection is the provider's fault; on a reused one it is usually
        # just a keep-alive that the server timed out.
        self.fresh = True

    def close(self):
        self.stream.close()


# Anything that means "this connection is no good, try another".
_RETRYABLE = (_ProviderError, ConnectionError, OSError, ValueError,
              ssl.SSLError, asyncio.TimeoutError)


class Resolver:
    """Caching DoH resolver with a system-DNS fallback."""

    def __init__(self, ctx, log):
        self.ctx = ctx
        self.log = log
        self._cache = {}
        # One lookup per name at a time: a browser opening six connections to
        # a host must not turn into six identical queries.
        self._pending = {}
        self._idle = []
        # Created on first use, so they bind to the loop that is running.
        self._slots = None
        self._discovery = None
        self._doh_broken_until = 0.0
        # The (provider, strategy) that last worked, tried first next time so
        # every combination is not re-probed once one is known good.
        self._doh_pin = None
        # Providers that failed recently, with the time they may be retried.
        self._cooldown = {}

    def reset(self):
        """Forget cached answers and re-arm DoH after a network change."""
        self._cache.clear()
        self._doh_broken_until = 0.0
        self._doh_pin = None
        self._cooldown.clear()
        for conn in self._idle:
            conn.close()
        self._idle.clear()

    @property
    def active_host(self):
        """The DoH provider actually answering right now, if one is known."""
        if not self.ctx.doh:
            return None
        if self._doh_pin is not None:
            return self._doh_pin[0][1]
        return self.ctx.doh_host

    async def resolve(self, host: str, want_v6: bool = False):
        """Return a list of IP strings for `host`, best candidate first."""
        if _looks_like_ip(host):
            return [host]

        hit = self._cache.get(host)
        if hit and hit[1] > time.time():
            return hit[0]

        task = self._pending.get(host)
        if task is None:
            task = asyncio.ensure_future(self._lookup(host, want_v6))
            self._pending[host] = task

            def _done(t, host=host):
                self._pending.pop(host, None)
                if not t.cancelled():
                    t.exception()
            task.add_done_callback(_done)
        # Shielded: one caller giving up must not cancel the lookup the others
        # are waiting on.
        return await asyncio.shield(task)

    async def _lookup(self, host: str, want_v6: bool):
        ips = []
        if self.ctx.doh and time.time() >= self._doh_broken_until:
            try:
                ips = await self._resolve_doh(host, want_v6)
            except Exception as exc:                       # noqa: BLE001
                self.log.warn(f"DoH lookup failed for {host}: {exc}")
                self._doh_broken_until = time.time() + 30

        if not ips:
            ips = await self._resolve_system(host)

        if ips:
            ttl = max(60, min(self.ctx.dns_max_ttl, 300))
            self._cache[host] = (ips, time.time() + ttl)
        return ips

    async def _resolve_system(self, host: str):
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, proto=6)
        except OSError:
            return []
        v4 = [i[4][0] for i in infos if i[0].name == "AF_INET"]
        v6 = [i[4][0] for i in infos if i[0].name == "AF_INET6"]
        return v4 + v6

    # --- DoH ---------------------------------------------------------------

    async def _resolve_doh(self, host: str, want_v6: bool):
        if self._slots is None:
            self._slots = asyncio.Semaphore(DOH_CONNECTIONS)
        async with self._slots:
            last = None
            for _attempt in range(3):
                conn = await self._checkout()
                try:
                    ips = await self._query(conn, host, TYPE_A)
                    if want_v6:
                        ips += await self._query(conn, host, TYPE_AAAA)
                except _RETRYABLE as exc:
                    last = exc
                    conn.close()
                    if conn.fresh:
                        # A brand-new connection that cannot answer: the
                        # provider itself is the problem. Move on to another.
                        self._demote(conn.provider, exc)
                    continue
                self._checkin(conn)
                return ips
            raise last or ConnectionError("DoH query failed")

    async def _checkout(self):
        if self._idle:
            return self._idle.pop()
        return await self._connect()

    def _checkin(self, conn):
        if conn.keep and len(self._idle) < DOH_CONNECTIONS:
            self._idle.append(conn)
        else:
            conn.close()

    def _demote(self, provider, reason):
        if self._doh_pin is not None and self._doh_pin[0] == provider:
            self._doh_pin = None
        self._cooldown[provider] = time.time() + PROVIDER_COOLDOWN
        self.log.debug(f"DoH provider {provider[1]} ({provider[0]}) set aside: "
                       f"{reason}")

    def _providers(self):
        providers = self.ctx.doh_providers or [
            (self.ctx.doh_ip, self.ctx.doh_host, self.ctx.doh_path)]
        now = time.time()
        ready = [p for p in providers if self._cooldown.get(p, 0) <= now]
        # If everything is cooling down, try them all again rather than
        # leaving the user on the network's own DNS.
        return ready or list(providers)

    def _strategies(self):
        first = self.ctx.doh_strategy
        return [first] + [n for n in DEFAULT_LADDER if n != first]

    async def _connect(self):
        """Open a connection to a working provider, finding one if need be."""
        conn = await self._dial_pinned()
        if conn is not None:
            return conn
        if self._discovery is None:
            self._discovery = asyncio.Lock()
        async with self._discovery:
            # Whoever held the lock before us may already have found one.
            conn = await self._dial_pinned()
            if conn is not None:
                return conn
            return await self._discover()

    async def _dial_pinned(self):
        pin = self._doh_pin
        if pin is None:
            return None
        try:
            return await self._dial(*pin)
        except _RETRYABLE:
            if self._doh_pin == pin:
                self._doh_pin = None
            return None

    async def _discover(self):
        """Find a (provider, strategy) pair that reaches a genuine resolver.

        Several providers cover a network that blocks one DoH endpoint;
        several strategies cover one that DPI-filters the DoH handshake itself.
        The handshake verifies the resolver's certificate and name, so a
        combination that only reaches an interceptor fails and is passed over.
        """
        deadline = time.monotonic() + self.ctx.doh_budget
        for provider in self._providers():
            if time.monotonic() > deadline:
                break
            conn = await self._race(provider)
            if conn is not None:
                self._doh_pin = (provider, conn.strategy)
                self.log.info(f"DoH via {provider[1]} ({provider[0]}) "
                              f"using {conn.strategy}")
                return conn
            self._cooldown[provider] = time.time() + PROVIDER_COOLDOWN
        raise ConnectionError("no DoH provider reachable")

    async def _race(self, provider):
        """Try every strategy against one provider; the first through wins."""
        async def attempt(index, name):
            if index:
                await asyncio.sleep(index * self.ctx.probe_stagger)
            return await self._dial(provider, name)

        pending = {asyncio.ensure_future(attempt(i, n))
                   for i, n in enumerate(self._strategies())}
        winner = None
        try:
            while pending and winner is None:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task.cancelled() or task.exception() is not None:
                        continue
                    if winner is None:
                        winner = task.result()
                    else:
                        task.result().close()
        finally:
            for task in pending:
                task.cancel()
            for late in await asyncio.gather(*pending, return_exceptions=True):
                if isinstance(late, _Conn):
                    late.close()
        return winner

    async def _dial(self, provider, strategy):
        ip, dhost, _path = provider
        if not _looks_like_ip(ip):
            candidates = await self._resolve_system(ip)
            if not candidates:
                raise ConnectionError(f"cannot resolve {ip}")
            ip = candidates[0]
        up = await Upstream.connect(
            ip, 443, self.ctx.probe_timeout,
            reserve_source_port=self.ctx.transparent)
        try:
            stream = TLSStream(up, dhost, TLS_STRATEGIES.get(strategy), self.ctx)
            await asyncio.wait_for(stream.handshake(), self.ctx.probe_timeout)
        except BaseException:
            up.close()
            raise
        return _Conn(stream, provider, strategy)

    async def _query_raw(self, conn, name: str, qtype: int) -> bytes:
        body = encode_query(name, qtype)
        _ip, dhost, dpath = conn.provider
        req = (
            f"POST {dpath} HTTP/1.1\r\n"
            f"Host: {dhost}\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode() + body

        await conn.stream.write(req)
        status, payload, conn.keep = await asyncio.wait_for(
            _read_response(conn), self.ctx.dns_timeout)
        if status != 200:
            raise _ProviderError(f"HTTP {status} from {dhost}")
        conn.fresh = False
        return payload

    async def _query(self, conn, host: str, qtype: int):
        payload = await self._query_raw(conn, host, qtype)
        ips = []
        try:
            for rtype, rdata, _ttl in decode_answers(payload):
                if rtype == TYPE_CNAME:
                    continue
                ip = _fmt_ip(rtype, rdata)
                if ip:
                    ips.append(ip)
        except (IndexError, struct.error) as exc:
            raise _ProviderError("malformed DNS answer") from exc
        return ips

    async def resolve_srv(self, name: str):
        """Resolve an SRV record. Returns (host, port) sorted best-first, or []."""
        if not self.ctx.doh or time.time() < self._doh_broken_until:
            return []
        if self._slots is None:
            self._slots = asyncio.Semaphore(DOH_CONNECTIONS)
        async with self._slots:
            for _attempt in range(3):
                conn = await self._checkout()
                try:
                    payload = await self._query_raw(conn, name, TYPE_SRV)
                except _RETRYABLE as exc:
                    conn.close()
                    if conn.fresh:
                        self._demote(conn.provider, exc)
                    continue
                self._checkin(conn)
                try:
                    records = decode_srv(payload)
                except (IndexError, struct.error):
                    return []
                # Lowest priority first, then higher weight; "." means no service.
                records.sort(key=lambda r: (r[0], -r[1]))
                return [(t, p) for _pri, _w, p, t in records if t != "."]
        return []

    async def resolve_service(self, host: str, default_port: int):
        """Resolve a host the Minecraft way: SRV first, then a plain A/AAAA.

        Returns (ip_list, port). SRV lets a server publish its real address
        under a name the player never types, so it must be honoured or those
        servers are unreachable.
        """
        try:
            srv = await self.resolve_srv("_minecraft._tcp." + host)
        except Exception:                                      # noqa: BLE001
            srv = []
        for target, port in srv:
            ips = await self.resolve(target)
            if ips:
                return ips, port
        return await self.resolve(host), default_port


# --- minimal HTTP/1.1 response reading -------------------------------------


async def _fill(conn):
    chunk = await conn.stream.read()
    if not chunk:
        raise ConnectionError("DoH connection closed")
    conn.buf += chunk
    if len(conn.buf) > MAX_RESPONSE:
        raise ValueError("DoH response too large")


async def _line(conn) -> bytes:
    while b"\r\n" not in conn.buf:
        await _fill(conn)
    end = conn.buf.index(b"\r\n")
    line = bytes(conn.buf[:end])
    del conn.buf[:end + 2]
    return line


async def _exactly(conn, n: int) -> bytes:
    if n > MAX_RESPONSE:
        raise ValueError("DoH response too large")
    while len(conn.buf) < n:
        await _fill(conn)
    data = bytes(conn.buf[:n])
    del conn.buf[:n]
    return data


async def _read_response(conn):
    """Read one HTTP response. Returns (status, body, connection_reusable)."""
    try:
        status = int((await _line(conn)).split()[1])
    except (IndexError, ValueError) as exc:
        raise ValueError("malformed DoH response") from exc

    headers = {}
    while True:
        line = await _line(conn)
        if not line:
            break
        key, _, value = line.partition(b":")
        headers[key.strip().lower()] = value.strip()

    keep = headers.get(b"connection", b"").lower() != b"close"
    if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
        body = bytearray()
        while True:
            size = int((await _line(conn)).split(b";")[0] or b"0", 16)
            if size == 0:
                while await _line(conn):        # trailers, up to a blank line
                    pass
                break
            body += await _exactly(conn, size)
            await _exactly(conn, 2)             # the CRLF after each chunk
            if len(body) > MAX_RESPONSE:
                raise ValueError("DoH response too large")
        return status, bytes(body), keep
    if b"content-length" in headers:
        return status, await _exactly(conn, int(headers[b"content-length"])), keep
    # No framing at all: the body, if any, runs to the end of the connection,
    # which therefore cannot be used again. Error replies commonly look like
    # this, and for those the status is all that matters.
    if status == 200:
        try:
            while True:
                await _fill(conn)
        except ConnectionError:
            pass
    body = bytes(conn.buf)
    conn.buf.clear()
    return status, body, False


def _looks_like_ip(host: str) -> bool:
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

"""DNS-over-HTTPS resolver.

ISPs that censor by returning forged A records are defeated here rather than
in the desync layer. The resolver is addressed by IP so no plaintext lookup is
ever needed to bootstrap it.
"""

import asyncio
import os
import random
import ssl
import struct
import time

from .netio import Upstream
from .tlsclient import TLSStream

TYPE_A = 1
TYPE_AAAA = 28
TYPE_CNAME = 5


def encode_query(name: str, qtype: int) -> bytes:
    qid = random.getrandbits(16)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(l)]) + l for l in (p.encode("idna") for p in name.split(".") if p)
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


class Resolver:
    """Caching DoH resolver with a system-DNS fallback."""

    def __init__(self, ctx, log):
        self.ctx = ctx
        self.log = log
        self._cache = {}
        self._lock = asyncio.Lock()
        self._stream = None
        self._doh_broken_until = 0.0
        # The (provider, strategy) that last worked, tried first next time so we
        # do not re-probe every combination once one is known good.
        self._doh_pin = None
        # The provider (ip, host, path) the current stream is talking to, so the
        # request carries the right Host header and path after a fallback.
        self._active_provider = None

    def reset(self):
        """Forget cached answers and re-arm DoH after a network change."""
        self._cache.clear()
        self._doh_broken_until = 0.0
        self._doh_pin = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    async def resolve(self, host: str, want_v6: bool = False):
        """Return a list of IP strings for `host`, best candidate first."""
        if _looks_like_ip(host):
            return [host]

        hit = self._cache.get(host)
        if hit and hit[1] > time.time():
            return hit[0]

        ips = []
        if self.ctx.doh and time.time() >= self._doh_broken_until:
            try:
                ips = await self._resolve_doh(host, want_v6)
            except Exception as exc:                       # noqa: BLE001
                self.log.warn(f"DoH lookup failed for {host}: {exc}")
                self._doh_broken_until = time.time() + 30
                await self._drop_stream()

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

    async def _drop_stream(self):
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _doh_attempts(self):
        """(provider, strategy) pairs to try, the last known-good one first.

        Trying several providers covers a network that blocks one DoH endpoint;
        trying several strategies covers one that DPI-filters the DoH handshake
        itself. The TLS handshake verifies the resolver's certificate, so a
        combination that only reaches an interceptor fails and is skipped.
        """
        providers = self.ctx.doh_providers or [
            (self.ctx.doh_ip, self.ctx.doh_host, self.ctx.doh_path)]
        strategies = [self.ctx.doh_strategy, "tlsfrag", "tlsfrag+oob",
                      "multisplit", "direct"]
        seen = set()
        pairs = []
        for combo in ([self._doh_pin] if self._doh_pin else []):
            pairs.append(combo); seen.add(combo)
        for prov in providers:
            for strat in strategies:
                combo = (prov, strat)
                if combo not in seen:
                    seen.add(combo); pairs.append(combo)
        return pairs

    async def _get_stream(self):
        if self._stream is not None:
            return self._stream
        from .desync import TLS_STRATEGIES
        last = None
        for provider, strat in self._doh_attempts():
            ip, dhost, _path = provider
            if not _looks_like_ip(ip):
                candidates = await self._resolve_system(ip)
                if not candidates:
                    continue
                ip = candidates[0]
            up = None
            try:
                up = await Upstream.connect(
                    ip, 443, self.ctx.connect_timeout,
                    reserve_source_port=self.ctx.transparent)
                stream = TLSStream(up, dhost, TLS_STRATEGIES.get(strat), self.ctx)
                await asyncio.wait_for(stream.handshake(),
                                       self.ctx.handshake_timeout)
                if self._doh_pin != (provider, strat):
                    self._doh_pin = (provider, strat)
                    self.log.info(f"DoH via {dhost} using {strat}")
                self._active_provider = provider
                self._stream = stream
                return stream
            except (ssl.SSLError, asyncio.TimeoutError, OSError) as exc:
                last = exc
                if up is not None:
                    up.close()
        raise last or ConnectionError("no DoH provider reachable")

    async def _resolve_doh(self, host: str, want_v6: bool):
        async with self._lock:
            for attempt in (1, 2):
                try:
                    v4 = await self._doh_query(host, TYPE_A)
                    v6 = await self._doh_query(host, TYPE_AAAA) if want_v6 else []
                    return v4 + v6
                except (ConnectionError, OSError, ValueError):
                    await self._drop_stream()
                    if attempt == 2:
                        raise
            return []

    async def _doh_query(self, host: str, qtype: int):
        body = encode_query(host, qtype)
        # The stream is opened before the request so the Host/path match
        # whichever provider actually answered (it may be a fallback).
        stream = await self._get_stream()
        _ip, dhost, dpath = self._active_provider or (
            self.ctx.doh_ip, self.ctx.doh_host, self.ctx.doh_path)
        req = (
            f"POST {dpath} HTTP/1.1\r\n"
            f"Host: {dhost}\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode() + body

        await stream.write(req)

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(stream.read(), self.ctx.dns_timeout)
            if not chunk:
                raise ConnectionError("DoH connection closed")
            raw += chunk

        head, _, rest = raw.partition(b"\r\n\r\n")
        length = _content_length(head)
        if length is None:
            raise ValueError("DoH response without Content-Length")
        while len(rest) < length:
            chunk = await asyncio.wait_for(stream.read(), self.ctx.dns_timeout)
            if not chunk:
                raise ConnectionError("DoH response truncated")
            rest += chunk

        ips = []
        for rtype, rdata, _ttl in decode_answers(rest[:length]):
            if rtype == TYPE_CNAME:
                continue
            ip = _fmt_ip(rtype, rdata)
            if ip:
                ips.append(ip)
        return ips


def _content_length(head: bytes):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return None
    return None


def _looks_like_ip(host: str) -> bool:
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

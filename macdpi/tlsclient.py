"""A TLS client driven through MemoryBIO.

Needed because the DoH resolver has to reach the network from inside a
censored link too — going through the BIO lets the same evasion strategies be
applied to our own ClientHello.
"""

import os
import ssl

from .netio import Upstream

# python.org builds ship no CA bundle of their own; fall back to the one macOS
# installs so DoH keeps working on a stock system.
_CA_FALLBACKS = (
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats()["x509_ca"]:
        return ctx
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
        return ctx
    except Exception:                                          # noqa: BLE001
        pass
    for path in _CA_FALLBACKS:
        if os.path.exists(path):
            try:
                ctx.load_verify_locations(path)
                return ctx
            except OSError:
                continue
    return ctx


class TLSStream:
    def __init__(self, up: Upstream, hostname: str, strategy, ctx,
                 ssl_ctx: ssl.SSLContext = None):
        self.up = up
        self.hostname = hostname
        self.strategy = strategy
        self.ctx = ctx
        self._ssl_ctx = ssl_ctx or make_ssl_context()
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = self._ssl_ctx.wrap_bio(
            self._in, self._out, server_hostname=hostname
        )

    async def _flush(self, first_write: bool):
        data = self._out.read()
        if not data:
            return first_write
        if first_write and self.strategy is not None:
            await self.strategy(self.up, data, self.ctx)
            return False
        await self.up.send(data)
        return first_write

    async def _feed(self):
        chunk = await self.up.recv()
        if not chunk:
            raise ConnectionResetError("peer closed during TLS handshake")
        self._in.write(chunk)

    async def handshake(self):
        first = True
        while True:
            try:
                self._obj.do_handshake()
            except ssl.SSLWantReadError:
                first = await self._flush(first)
                await self._feed()
                continue
            break
        await self._flush(first)

    async def write(self, data: bytes):
        self._obj.write(data)
        await self.up.send(self._out.read())

    async def read(self, n: int = 65536) -> bytes:
        while True:
            try:
                return self._obj.read(n)
            except ssl.SSLWantReadError:
                try:
                    await self._feed()
                except ConnectionResetError:
                    return b""

    def close(self):
        self.up.close()

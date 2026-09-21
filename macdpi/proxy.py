"""The local proxy: HTTP CONNECT, plaintext HTTP and SOCKS5 on one port.

Browsers point at this; it opens the real connection itself and applies the
evasion there. Because the censored TCP connection is the proxy's and not the
browser's, an injected RST kills a connection the browser never sees, and the
retry ladder can transparently try a different strategy.
"""

import asyncio
import collections
import json
import os
import socket
import ssl
import struct
import time

from . import desync, tls
from .config import STATE_DIR, STATE_FILE
from .netio import Upstream
from .tlsclient import TLSStream, make_ssl_context

CONNECT_OK = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: macdpi\r\n\r\n"
REC_HANDSHAKE = 0x16
REC_ALERT = 0x15

# A hostname no real site uses, sent as SNI by the capture self-test. If the
# transparent listener sees it, the pf redirect is genuinely intercepting this
# Mac's own outbound traffic - which is the one thing that cannot be verified
# without actually loading the firewall rules.
SELFTEST_SNI = "macdpi-selftest.invalid"
HOP_HEADERS = {b"proxy-connection", b"proxy-authorization", b"connection",
               b"keep-alive", b"upgrade", b"te", b"trailer"}


class Proxy:
    def __init__(self, ctx, resolver, log):
        self.ctx = ctx
        self.resolver = resolver
        self.log = log
        self.learned = _load_state() if ctx.learn else {}
        self._dirty = False
        self.stats = {"connections": 0, "failed": 0, "active": 0,
                      "bytes_up": 0, "bytes_down": 0}
        self.strategy_counts = collections.Counter()
        self.recent = collections.deque(maxlen=200)
        self._selftest_seen = asyncio.Event()
        # A CA-verifying context used only to tell a real server apart from an
        # intercepting middlebox during auto-selection.
        self._verify_ctx = make_ssl_context()
        self._verify_ctx.check_hostname = False   # we check the issuer, not the name
        # One in-flight strategy probe per host, so a browser opening ten
        # connections at once does not launch ten identical probes.
        self._selecting = {}
        # Hosts where no strategy produced a trusted cert, with an expiry, so an
        # oddly-certificated host is not re-probed on every hit.
        self._select_failed = {}
        # Hosts that appear blocked at the IP/packet level (connections never
        # complete). Kept briefly so we fail fast instead of grinding through
        # the whole ladder on a dead address.
        self._unreachable = {}

    # --- dispatch ----------------------------------------------------------

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            first = await asyncio.wait_for(reader.read(1), 30)
            if not first:
                return
            if first[0] == 0x05:
                await self._socks5(first, reader, writer)
            else:
                await self._http(first, reader, writer)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:                              # noqa: BLE001
            self.log.debug(f"client {peer} error: {exc!r}")
        finally:
            _close(writer)

    # --- HTTP proxy --------------------------------------------------------

    async def _http(self, seed, reader, writer):
        head = seed + await _read_until(reader, b"\r\n\r\n", 64 * 1024)
        line, _, rest = head.partition(b"\r\n")
        parts = line.split()
        if len(parts) < 3:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        method, target = parts[0], parts[1]

        if method.upper() == b"CONNECT":
            host, port = _split_hostport(target.decode("latin-1"), 443)
            writer.write(CONNECT_OK)
            await writer.drain()
            await self._tunnel(host, port, reader, writer, tls_expected=True)
            return

        await self._plain_http(method, target, rest, reader, writer)

    async def _plain_http(self, method, target, header_block, reader, writer):
        if not target.lower().startswith((b"http://", b"https://")):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        scheme, _, remainder = target.partition(b"://")
        authority, slash, path = remainder.partition(b"/")
        host, port = _split_hostport(
            authority.decode("latin-1"), 443 if scheme == b"https" else 80
        )
        origin_form = (b"/" + path) if slash else b"/"

        headers = [l for l in header_block.split(b"\r\n") if l]
        kept = [h for h in headers
                if h.split(b":", 1)[0].strip().lower() not in HOP_HEADERS]
        kept.append(b"Connection: close")

        request = (method + b" " + origin_form + b" HTTP/1.1\r\n"
                   + b"\r\n".join(kept) + b"\r\n\r\n")

        try:
            up, pending, name = await self._open(host, port, request,
                                                 tls_expected=False,
                                                 http=True)
        except Exception as exc:                              # noqa: BLE001
            self.stats["failed"] += 1
            self.log.warn(f"{host}:{port} unreachable: {exc}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        if self.ctx.verbose:
            self.log.info(f"http {host}:{port} via {name}")
        if pending:
            writer.write(pending)
            await writer.drain()
        await self._relay(reader, writer, up)

    # --- SOCKS5 ------------------------------------------------------------

    async def _socks5(self, seed, reader, writer):
        nmethods = (await reader.readexactly(1))[0]
        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00")
        await writer.drain()

        header = await reader.readexactly(4)
        if header[1] != 0x01:                                  # CONNECT only
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = header[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("latin-1")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6,
                                    await reader.readexactly(16))
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack(">H", await reader.readexactly(2))[0]

        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        await self._tunnel(host, port, reader, writer,
                           tls_expected=(port == 443))

    # --- tunnel ------------------------------------------------------------

    async def _tunnel(self, host, port, reader, writer, tls_expected):
        try:
            first = await asyncio.wait_for(reader.read(65536), 30)
        except asyncio.TimeoutError:
            return
        if not first:
            return

        looks_tls = tls.is_client_hello(first)
        try:
            up, pending, name = await self._open(
                host, port, first, tls_expected=looks_tls
            )
        except Exception as exc:                              # noqa: BLE001
            self.stats["failed"] += 1
            self.log.warn(f"{host}:{port} unreachable: {exc}")
            return

        if self.ctx.verbose:
            self.log.info(f"tunnel {host}:{port} via {name}")
        if pending:
            writer.write(pending)
            await writer.drain()
        await self._relay(reader, writer, up)

    # --- transparent interception -----------------------------------------

    async def handle_transparent(self, reader, writer, upstream_port):
        """Handle a pf-redirected connection.

        There is no proxy handshake here: the app believes it is talking
        straight to the server. The destination is recovered from the traffic
        itself - the SNI in a TLS ClientHello, or the Host header of a plain
        HTTP request - which is exactly what a DPI box keys on, and which we
        then resolve ourselves over DoH.
        """
        peer = writer.get_extra_info("peername")
        try:
            first = await asyncio.wait_for(reader.read(65536), 30)
            if not first:
                return

            if tls.is_client_hello(first):
                host = tls.sni_host(first)
                if host == SELFTEST_SNI:
                    # The capture self-test's probe reached us, which proves the
                    # redirect works. Acknowledge and stop; never dial out.
                    self._selftest_seen.set()
                    return
                if not host:
                    # No SNI means no hostname to route by. Rather than guess,
                    # drop it; these are rare for real web traffic and the pf
                    # bypass table is meant to keep such services off this path.
                    self.log.debug(f"transparent: ClientHello without SNI from {peer}")
                    return
                up, pending, name = await self._open(
                    host, upstream_port, first, tls_expected=True)
            else:
                host = _http_host(first)
                if not host:
                    self.log.debug(f"transparent: no Host header from {peer}")
                    return
                up, pending, name = await self._open(
                    host, upstream_port, first, tls_expected=False, http=True)

            if self.ctx.verbose:
                self.log.info(f"transparent {host}:{upstream_port} via {name}")
            if pending:
                writer.write(pending)
                await writer.drain()
            await self._relay(reader, writer, up)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:                              # noqa: BLE001
            self.stats["failed"] += 1
            self.log.debug(f"transparent {peer} error: {exc!r}")
        finally:
            _close(writer)

    async def _open(self, host, port, first, tls_expected, http=False):
        """Connect upstream and send `first` using the best known strategy.

        Returns (upstream, bytes_already_read_from_server, strategy_name).
        """
        self.stats["connections"] += 1
        ips = await self.resolver.resolve(host)
        if not ips:
            raise ConnectionError(f"no address for {host}")
        ips = ips[:self.ctx.max_ips]

        verified_pick = None
        if http:
            order = ["http"]
        elif tls_expected and self._is_auto():
            # A "did I get a handshake back?" success check is fooled by an
            # intercepting middlebox, which answers with its own valid handshake
            # and a forged certificate. So for auto mode we choose the strategy
            # by cert validation instead (see _select_strategy) and cache it.
            now = time.time()
            if self._unreachable.get(host, 0) > now:
                # Recently seen as IP-blocked; don't grind the ladder on a dead
                # address. Fail fast so the browser shows its error promptly.
                raise ConnectionError(f"{host} appears blocked at the IP level")
            pick = self.learned.get(host)
            if (pick is None and self._select_failed.get(host, 0) < now):
                pick = await self._select_strategy(host, port)
            if pick:
                # Use only the verified strategy - never fall back down the
                # ladder to one we know reaches the interceptor, or that
                # connection would get a forged cert. One retry absorbs a
                # transient blip; a real failure invalidates the pick below.
                verified_pick = pick
                order = [pick, pick]
            elif self._unreachable.get(host, 0) > now:
                raise ConnectionError(f"{host} appears blocked at the IP level")
            else:
                order = self._ladder_for(host)   # reachable but unverified: passive
        else:
            order = self._ladder_for(host)

        pinned = None
        last = None
        for name in order:
            try:
                up, pinned = await self._dial(ips, port, pinned)
            except Exception as exc:                          # noqa: BLE001
                last = exc
                break

            try:
                if http:
                    await desync.http_send(up, first, self.ctx)
                else:
                    await desync.TLS_STRATEGIES[name](up, first, self.ctx)

                if not tls_expected:
                    self._record(host, port, name)
                    return up, b"", name

                reply = await asyncio.wait_for(up.recv(),
                                               self.ctx.handshake_timeout)
                if not reply:
                    raise ConnectionResetError("server closed after ClientHello")
                if reply[0] != REC_HANDSHAKE:
                    # A healthy server answers a ClientHello with a handshake
                    # record. An alert - or plain junk, which is what some
                    # front-ends send when a middlebox delivered our desync
                    # bytes inline - means this strategy corrupted the hello.
                    raise ConnectionResetError(
                        f"non-handshake reply to ClientHello (0x{reply[0]:02x})"
                    )
                self._remember(host, name)
                self._record(host, port, name)
                return up, reply, name
            except (OSError, asyncio.TimeoutError) as exc:
                last = exc
                up.close()
                self.log.debug(f"{host}: {name} failed ({exc!r})")
                continue

        if verified_pick is not None:
            # The strategy we verified stopped working. Drop it so the next
            # connection re-probes rather than repeating a dead choice - the
            # network may have changed (moved AP, new firewall policy).
            self.learned.pop(host, None)
            self._select_failed.pop(host, None)
            self._dirty = True
            self.log.debug(f"{host}: verified pick {verified_pick} failed; "
                           "will re-probe next time")
        raise last or ConnectionError(f"all strategies failed for {host}")

    def _record(self, host, port, name):
        self.strategy_counts[name] += 1
        self.recent.append({"time": time.time(), "host": host,
                            "port": port, "strategy": name})

    # --- verified auto-selection -------------------------------------------

    def _is_auto(self):
        """True when more than one strategy is on the ladder (i.e. not pinned)."""
        return len(self.ctx.ladder) > 1

    async def _select_strategy(self, host, port):
        """Pick a strategy whose cert validates, deduping concurrent callers."""
        task = self._selecting.get(host)
        if task is None:
            task = asyncio.ensure_future(self._run_selection(host, port))
            self._selecting[host] = task
            task.add_done_callback(lambda _t: self._selecting.pop(host, None))
        return await task

    async def _run_selection(self, host, port):
        # Probe every strategy at once rather than in sequence. Different
        # strategies genuinely differ on a given network - some blocked, some
        # not - so we must try them all, but doing so concurrently bounds the
        # whole thing by a single timeout instead of one per strategy. Among the
        # strategies whose cert validates, the earliest in the ladder wins, so
        # the choice stays deterministic and follows the ladder's preference.
        ladder = list(self.ctx.ladder)
        results = await asyncio.gather(
            *[self._probe_strategy(host, port, name) for name in ladder])

        for name, status in zip(ladder, results):
            if status == "valid":
                self._remember(host, name)
                self.save_state()
                if self.ctx.verbose:
                    self.log.info(f"auto-selected {name} for {host} (cert verified)")
                return name

        if all(s in ("blocked", "unreachable") for s in results):
            # No strategy even got a certificate back - the handshake is being
            # killed or the address dropped on all of them. Nothing local beats
            # this; a VPN is needed. Fail fast next time rather than re-probing.
            self._unreachable[host] = time.time() + 30
            self.log.debug(f"{host} blocked on every strategy; needs a VPN")
            return None

        # Some strategy completed a handshake but with an untrusted cert - a
        # middlebox forging certs on all of them, or a genuinely self-signed
        # site. Let the client's own TLS decide, via a passive relay.
        self._select_failed[host] = time.time() + 60
        self.log.debug(f"no strategy produced a trusted cert for {host}; "
                       "falling back to passive relay")
        return None

    async def _probe_strategy(self, host, port, strategy) -> str:
        """Probe one strategy. Returns one of:

        - 'valid'        the cert validates - this strategy reaches the real server
        - 'intercepted'  handshake completed but the cert is untrusted (a
                         cert-forging middlebox, or a real self-signed site)
        - 'blocked'      connected, but the handshake was reset or timed out
                         before any cert arrived (RST injection / drop)
        - 'unreachable'  the connection itself never completed (IP/packet block)
        """
        up = None
        try:
            ips = await self.resolver.resolve(host)
            if not ips:
                return "unreachable"
            up = await Upstream.connect(
                ips[0], port, self.ctx.probe_timeout,
                reserve_source_port=self.ctx.transparent)
        except (asyncio.TimeoutError, OSError):
            return "unreachable"
        try:
            stream = TLSStream(up, host, desync.TLS_STRATEGIES[strategy],
                               self.ctx, ssl_ctx=self._verify_ctx)
            await asyncio.wait_for(stream.handshake(), self.ctx.probe_timeout)
            return "valid"
        except ssl.SSLCertVerificationError:
            return "intercepted"      # a cert arrived, just not a trusted one
        except (ssl.SSLError, asyncio.TimeoutError, OSError):
            return "blocked"          # handshake killed before any cert
        finally:
            up.close()

    async def _dial(self, ips, port, pinned):
        candidates = ([pinned] + [i for i in ips if i != pinned]) if pinned else ips
        last = None
        for ip in candidates:
            try:
                up = await Upstream.connect(
                    ip, port, self.ctx.connect_timeout,
                    reserve_source_port=self.ctx.transparent)
                return up, ip
            except (OSError, asyncio.TimeoutError) as exc:
                last = exc
        raise last or ConnectionError("no reachable address")

    # --- strategy memory ---------------------------------------------------

    def _ladder_for(self, host):
        base = list(self.ctx.ladder)
        if len(base) == 1:
            return base
        known = self.learned.get(host)
        if known in base:
            base.remove(known)
            base.insert(0, known)
        return base

    def _remember(self, host, name):
        if not self.ctx.learn:
            return
        if self.learned.get(host) != name:
            self.learned[host] = name
            self._dirty = True

    def save_state(self):
        if self.ctx.learn and self._dirty:
            _save_state(self.learned)
            self._dirty = False

    # --- relaying ----------------------------------------------------------

    async def _relay(self, reader, writer, up):
        self.stats["active"] += 1
        try:
            await asyncio.gather(
                self._client_to_server(reader, up),
                self._server_to_client(up, writer),
                return_exceptions=True,
            )
        finally:
            self.stats["active"] -= 1
            up.close()

    async def _client_to_server(self, reader, up):
        try:
            while True:
                data = await self._with_idle(reader.read(65536))
                if not data:
                    break
                self.stats["bytes_up"] += len(data)
                await up.send(data)
        finally:
            try:
                up.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    async def _server_to_client(self, up, writer):
        try:
            while True:
                data = await self._with_idle(up.recv())
                if not data:
                    break
                self.stats["bytes_down"] += len(data)
                writer.write(data)
                await writer.drain()
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except (OSError, RuntimeError):
                pass

    def _with_idle(self, awaitable):
        if self.ctx.idle_timeout and self.ctx.idle_timeout > 0:
            return asyncio.wait_for(awaitable, self.ctx.idle_timeout)
        return awaitable


# --- small helpers ---------------------------------------------------------


async def _read_until(reader, delim, limit):
    buf = b""
    while delim not in buf:
        if len(buf) > limit:
            raise ValueError("request header too large")
        chunk = await reader.read(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _http_host(data: bytes):
    """Pull the Host header out of a plaintext HTTP request's first bytes."""
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("latin-1")
            # Strip any :port the client tacked on.
            if host.startswith("["):                           # [v6]:port
                return host[1:].split("]", 1)[0]
            return host.split(":", 1)[0]
    return None


def _split_hostport(value: str, default_port: int):
    if value.startswith("["):                                  # [v6]:port
        addr, _, tail = value[1:].partition("]")
        port = int(tail[1:]) if tail.startswith(":") else default_port
        return addr, port
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, int(port or default_port)
    return value, default_port


def _close(writer):
    try:
        writer.close()
    except Exception:                                          # noqa: BLE001
        pass


def _load_state():
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass

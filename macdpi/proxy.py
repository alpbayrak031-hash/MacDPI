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

from . import desync, mcproto, tls
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
# A client that has sent no more than this after its ClientHello, then hangs
# up, never finished the handshake: a TLS 1.3 alert is ~30 bytes on the wire
# and a TLS 1.2 one 7, while the smallest genuine second flight is ~60.
ABORT_BYTES = 48
# How many of the client's chunks after the first are checked for a second
# ClientHello. It can only come before any application data, so it is always
# among the very first.
HELLO_WATCH_CHUNKS = 3
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
        # When each host's cached strategy was last seen to reach the real
        # server (monotonic clock). Deliberately not persisted: a pick learned
        # on an earlier run, or on another network, is re-checked with a single
        # probe before it is trusted again, because a strategy that has gone
        # stale does not fail - it quietly delivers the interceptor's forged
        # certificate instead.
        self._verified_at = {}
        # Strong references to fire-and-forget tasks, which the event loop
        # itself holds only weakly.
        self._background = set()

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

        first = await _complete_record(reader, first)
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
        await self._relay(reader, writer, up, host=host,
                          strategy=name if looks_tls else None,
                          received=len(pending))

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

            strategy = None
            first = await _complete_record(reader, first)
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
                strategy = name
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
            await self._relay(reader, writer, up, host=host, strategy=strategy,
                              received=len(pending))
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:                              # noqa: BLE001
            self.stats["failed"] += 1
            self.log.debug(f"transparent {peer} error: {exc!r}")
        finally:
            _close(writer)

    async def handle_transparent_raw(self, reader, writer, upstream_port):
        """Handle a pf-redirected Minecraft (Java) multiplayer connection.

        As in handle_transparent there is no proxy handshake and no original
        destination IP to recover, so the server address is read from
        Minecraft's own Handshake packet and resolved over DoH - which also
        sidesteps a poisoned DNS answer the client would otherwise have used.
        There is no certificate to verify here, so rather than probe strategies
        the first packet is simply split through the hostname, the plaintext
        field a DPI box matches on; the server reassembles the stream as normal.
        """
        peer = writer.get_extra_info("peername")
        up = None
        try:
            first = await asyncio.wait_for(reader.read(65536), 30)
            if not first:
                return
            first = await _complete_packet(reader, first)
            hs = mcproto.parse_handshake(first)
            if hs is None:
                # A legacy ping, a partial read, or not Minecraft at all. With
                # no hostname there is nothing to route by, so drop it.
                self.log.debug(f"minecraft: unroutable first packet from {peer}")
                return

            self.stats["connections"] += 1
            ips, port = await self.resolver.resolve_service(hs.host, hs.port)
            if not ips:
                self.stats["failed"] += 1
                self.log.warn(f"{hs.host}:{hs.port} unreachable: no address")
                return
            up, _ip = await self._dial(ips[:self.ctx.max_ips], port, None)

            pos = mcproto.split_position(hs)
            await up.send(first[:pos])
            if self.ctx.delay:
                await asyncio.sleep(self.ctx.delay)
            await up.send(first[pos:])

            self._record(hs.host, port, "mc-split")
            if self.ctx.verbose:
                self.log.info(f"minecraft {hs.host}:{port} "
                              f"(state {hs.next_state}) via mc-split")
            await self._relay(reader, writer, up)
            up = None                               # _relay owns it now
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:                              # noqa: BLE001
            self.stats["failed"] += 1
            self.log.debug(f"minecraft {peer} error: {exc!r}")
        finally:
            if up is not None:
                up.close()
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

        if http:
            return await self._attempt(host, port, ips, first, ["http"],
                                       tls_expected=False, http=True)
        if not (tls_expected and self._is_auto()):
            return await self._attempt(host, port, ips, first,
                                       self._ladder_for(host), tls_expected)

        # A "did I get a handshake back?" success check is fooled by an
        # intercepting middlebox, which answers with its own valid handshake
        # and a forged certificate. So in auto mode the strategy is chosen by
        # cert validation instead (see _run_selection) and cached.
        pick = await self._verified_pick(host, port)
        if pick is None:
            # Reachable, but no strategy produced a trusted certificate: relay
            # passively and let the client's own TLS decide. Nothing is cached
            # from this, since "got a handshake back" proves nothing here.
            return await self._attempt(host, port, ips, first,
                                       self._ladder_for(host), True,
                                       remember=False)
        try:
            # Use only the verified strategy - never fall back down the ladder
            # to one known to reach the interceptor, or this connection would
            # be handed a forged cert. It gets a shorter wait than usual: if a
            # strategy that worked a moment ago has gone silent, it is far more
            # likely to be newly dropped than slow, and re-selecting is cheap.
            return await self._attempt(
                host, port, ips, first, [pick], True,
                reply_timeout=min(self.ctx.handshake_timeout, 3.0))
        except (OSError, asyncio.TimeoutError) as exc:
            # The verified strategy stopped working: the network changed, or
            # the middlebox changed its mind. Re-select right now, while the
            # client is still waiting, instead of failing this connection and
            # making the app retry.
            self._forget(host)
            self.log.debug(f"{host}: verified pick {pick} failed ({exc!r}); "
                           "re-selecting")
            pick = await self._verified_pick(host, port)
            if pick is None:
                raise
            return await self._attempt(host, port, ips, first, [pick], True)

    async def _attempt(self, host, port, ips, first, order, tls_expected,
                       http=False, remember=True, reply_timeout=None):
        """Try each strategy in `order` until the server answers properly."""
        if reply_timeout is None:
            reply_timeout = self.ctx.handshake_timeout
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

                reply = await asyncio.wait_for(up.recv(), reply_timeout)
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
                if remember:
                    self._remember(host, name)
                self._record(host, port, name)
                return up, reply, name
            except (OSError, asyncio.TimeoutError) as exc:
                last = exc
                up.close()
                self.log.debug(f"{host}: {name} failed ({exc!r})")
                continue

        raise last or ConnectionError(f"all strategies failed for {host}")

    def _record(self, host, port, name):
        self.strategy_counts[name] += 1
        self.recent.append({"time": time.time(), "host": host,
                            "port": port, "strategy": name})

    # --- verified auto-selection -------------------------------------------

    def _is_auto(self):
        """True when more than one strategy is on the ladder (i.e. not pinned)."""
        return len(self.ctx.ladder) > 1

    async def _verified_pick(self, host, port):
        """The strategy known to reach the real `host`, or None for none.

        Raises ConnectionError when the host is blocked on every strategy, so
        the client is told promptly rather than after grinding the ladder.
        """
        now = time.time()
        if self._unreachable.get(host, 0) > now:
            raise ConnectionError(f"{host} is blocked on every strategy")

        pick = self.learned.get(host)
        if pick not in self.ctx.ladder:
            pick = None
        if pick is not None:
            seen = self._verified_at.get(host)
            if seen is None:
                # Learned on an earlier run or another network. Check it with
                # one probe before trusting it; re-select if it has gone stale.
                pick = await self._select_strategy(host, port, cached=pick)
            elif time.monotonic() - seen > self.ctx.reverify_after:
                # Verified a while ago on this network: keep using it, and
                # re-check in the background so drift is caught without making
                # this connection wait.
                self._selection_task(host, port, cached=pick)
        elif self._select_failed.get(host, 0) < now:
            pick = await self._select_strategy(host, port)

        if pick is None and self._unreachable.get(host, 0) > time.time():
            raise ConnectionError(f"{host} is blocked on every strategy")
        return pick

    def _selection_task(self, host, port, cached=None):
        """The in-flight selection for `host`, started if there is none."""
        task = self._selecting.get(host)
        if task is None:
            task = asyncio.ensure_future(
                self._run_selection(host, port, cached))
            self._selecting[host] = task

            def _done(t, host=host):
                self._selecting.pop(host, None)
                if not t.cancelled() and t.exception() is not None:
                    self.log.debug(f"selection for {host} failed: "
                                   f"{t.exception()!r}")
            task.add_done_callback(_done)
        return task

    async def _select_strategy(self, host, port, cached=None):
        """Pick a strategy whose cert validates, deduping concurrent callers."""
        # Shielded: one client giving up must not cancel the probe that every
        # other connection to this host is waiting on.
        return await asyncio.shield(self._selection_task(host, port, cached))

    async def _run_selection(self, host, port, cached=None):
        if cached is not None:
            if await self._probe_strategy(host, port, cached) == "valid":
                self._verified_at[host] = time.monotonic()
                return cached
            self._forget(host)
            self.log.info(f"{host}: {cached} no longer reaches the real "
                          "server; re-selecting")

        # Probe every strategy rather than stopping at the first failures:
        # strategies genuinely differ on a given network - some blocked, some
        # not - so a later one can work where the earlier ones do not. They run
        # concurrently, each starting a beat after the one before it, so a
        # network that needs no evasion settles on the first rung having barely
        # started the rest, while a hostile one still gets through the whole
        # ladder in well under a second.
        ladder = list(self.ctx.ladder)
        loop = asyncio.get_running_loop()

        async def staggered(index, name):
            if index:
                await asyncio.sleep(index * self.ctx.probe_stagger)
            return await self._probe_strategy(host, port, name)

        tasks = {asyncio.ensure_future(staggered(i, n)): n
                 for i, n in enumerate(ladder)}
        pending = set(tasks)
        results = {}
        winner = None
        deadline = None
        try:
            while pending:
                timeout = (None if deadline is None
                           else max(0.0, deadline - loop.time()))
                done, pending = await asyncio.wait(
                    pending, timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    try:
                        results[tasks[task]] = task.result()
                    except Exception:                         # noqa: BLE001
                        results[tasks[task]] = "blocked"
                valid = [n for n in ladder if results.get(n) == "valid"]
                if not valid:
                    continue
                winner = valid[0]
                # Among strategies that validate, the earliest on the ladder
                # wins. Rungs above the current winner that have not answered
                # yet get a short grace period - they started first, so if they
                # are still silent they are almost certainly being dropped, and
                # waiting out their timeout would stall the client for nothing.
                ahead = set(ladder[:ladder.index(winner)])
                if not any(tasks[t] in ahead for t in pending):
                    break
                if deadline is None:
                    deadline = loop.time() + self.ctx.probe_grace
                elif loop.time() >= deadline:
                    break
        finally:
            # Rungs above the winner that ran out of grace keep going in the
            # background (see _upgrade); everything else is abandoned.
            ahead = (set(ladder[:ladder.index(winner)])
                     if winner is not None else set())
            late = {t: tasks[t] for t in pending if tasks[t] in ahead}
            stop = [t for t in pending if t not in late]
            for task in stop:
                task.cancel()
            if stop:
                await asyncio.gather(*stop, return_exceptions=True)

        if winner is not None:
            self._remember(host, winner)
            self._verified_at[host] = time.monotonic()
            self._select_failed.pop(host, None)
            self._unreachable.pop(host, None)
            self.save_state()
            if self.ctx.verbose:
                self.log.info(f"auto-selected {winner} for {host} (cert verified)")
            if late:
                job = asyncio.ensure_future(
                    self._upgrade(host, winner, late, ladder))
                self._background.add(job)
                job.add_done_callback(self._background.discard)
            return winner

        if all(s in ("blocked", "unreachable") for s in results.values()):
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

    async def _upgrade(self, host, winner, late, ladder):
        """Let slower, higher-ranked probes finish, and prefer one if it works.

        The client was not kept waiting for these, so it is already using
        `winner`. But a preferred strategy that merely answered a moment late
        (a lost SYN, a busy link) is still the better long-term choice, and
        this is how the cached pick converges on it.
        """
        statuses = await asyncio.gather(*late, return_exceptions=True)
        valid = {name for name, status in zip(late.values(), statuses)
                 if status == "valid"}
        for name in ladder:
            if name in valid:
                # Only if nothing has replaced or dropped the pick meanwhile.
                if self.learned.get(host) == winner:
                    self._remember(host, name)
                    self._verified_at[host] = time.monotonic()
                    self.save_state()
                    if self.ctx.verbose:
                        self.log.info(f"upgraded {host} from {winner} to "
                                      f"{name} (cert verified)")
                return

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
                reserve_source_port=self.ctx.transparent or self.ctx.minecraft_route)
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
                    reserve_source_port=self.ctx.transparent or self.ctx.minecraft_route)
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

    def _forget(self, host):
        """Drop everything cached about how to reach `host`."""
        if self.learned.pop(host, None) is not None:
            self._dirty = True
        self._verified_at.pop(host, None)
        self._select_failed.pop(host, None)

    def forget_verification(self):
        """Treat every cached strategy as unverified again.

        Called when the network changes: what reached the real server on the
        last network may reach an interceptor on this one, so each host gets
        re-checked (one probe) the next time it is used.
        """
        self._verified_at.clear()
        self._select_failed.clear()
        self._unreachable.clear()

    def save_state(self):
        if self.ctx.learn and self._dirty:
            _save_state(self.learned)
            self._dirty = False

    # --- relaying ----------------------------------------------------------

    async def _relay(self, reader, writer, up, host=None, strategy=None,
                     received=0):
        """Pump bytes both ways until either side is done.

        `strategy` is the TLS strategy this connection was opened with (None
        for plaintext), and `received` how much of the server's reply has
        already been read - both only feed the handshake bookkeeping below.
        """
        self.stats["active"] += 1
        flow = {"up": 0, "down": received}
        started = time.monotonic()
        try:
            await asyncio.gather(
                self._client_to_server(reader, up, flow, host, strategy),
                self._server_to_client(up, writer, flow),
                return_exceptions=True,
            )
        finally:
            self.stats["active"] -= 1
            up.close()
        if strategy is not None:
            self._note_handshake_outcome(host, flow,
                                         time.monotonic() - started)

    def _note_handshake_outcome(self, host, flow, elapsed):
        """Spot a client that rejected the certificate it was handed.

        The engine relays TLS without decrypting it, so it cannot see a forged
        certificate go past. It can see the consequence, though: the client
        receives the server's handshake flight and hangs up having sent at most
        an alert. When that happens on a strategy we believed verified, the
        strategy has probably gone stale, so it is re-checked before the next
        connection uses it - which is what makes an app's retry succeed.
        """
        seen = self._verified_at.get(host)
        if seen is None:
            return
        if (flow["down"] and flow["up"] <= ABORT_BYTES and elapsed < 8.0
                and time.monotonic() - seen > 20.0):
            del self._verified_at[host]
            self.log.debug(f"{host}: client abandoned the handshake; "
                           "will re-verify the strategy")

    async def _client_to_server(self, reader, up, flow, host=None,
                                strategy=None):
        # A server may answer the first ClientHello with a HelloRetryRequest,
        # and the client then sends a second ClientHello - hostname and all.
        # Left alone it would cross the wire in one clean record, handing a DPI
        # box that follows the handshake exactly what the first one hid. So
        # the client's opening few chunks are watched for it, and it gets the
        # same treatment.
        resend = desync.TLS_STRATEGIES.get(strategy) if host else None
        watched = 0
        try:
            while True:
                data = await self._with_idle(reader.read(65536))
                if not data:
                    break
                self.stats["bytes_up"] += len(data)
                flow["up"] += len(data)
                if resend is not None:
                    watched += 1
                    offset = tls.find_client_hello(data, host)
                    if offset is not None:
                        if offset:
                            await up.send(data[:offset])
                        await resend(up, data[offset:], self.ctx)
                        resend = None
                        continue
                    if watched >= HELLO_WATCH_CHUNKS:
                        resend = None
                await up.send(data)
        finally:
            try:
                up.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    async def _server_to_client(self, up, writer, flow):
        try:
            while True:
                data = await self._with_idle(up.recv())
                if not data:
                    break
                self.stats["bytes_down"] += len(data)
                flow["down"] += len(data)
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


async def _complete_record(reader, first, timeout=2.0, limit=65536):
    """Read on until the whole first TLS record - the ClientHello - is in hand.

    A ClientHello with post-quantum key shares runs to a couple of kilobytes
    and can arrive in more than one read, and nothing stops the first read
    from delivering only a byte or two of it. The strategies need all of it:
    too little and it is not even recognisable as TLS, and the hostname may
    sit in the part that has not arrived yet. Anything that does not start
    like a TLS handshake record is returned untouched.
    """
    deadline = time.monotonic() + timeout

    def wanted():
        if first[:1] != bytes([tls.REC_HANDSHAKE]) or len(first) >= limit:
            return False
        return len(first) < 6 or (tls.is_client_hello(first)
                                  and tls.record_missing(first) > 0)

    while wanted():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            more = await asyncio.wait_for(reader.read(65536), remaining)
        except asyncio.TimeoutError:
            break
        if not more:
            break
        first += more
    return first


async def _complete_packet(reader, first, timeout=2.0, limit=4096):
    """Read on until Minecraft's first packet is whole (it is tiny).

    The length-prefixed Handshake almost always arrives in one segment, but a
    client is free to dribble it; the hostname may be in a part not yet read.
    """
    deadline = time.monotonic() + timeout
    while len(first) < limit:
        need = mcproto.packet_length(first)
        if need is not None and len(first) >= need:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            more = await asyncio.wait_for(reader.read(65536), remaining)
        except asyncio.TimeoutError:
            break
        if not more:
            break
        first += more
    return first


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

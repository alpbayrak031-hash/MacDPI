"""Control channel for the menu bar app.

A Unix domain socket rather than a TCP port on purpose: a web page can reach
127.0.0.1 through the proxy it is already talking to, but it cannot open a Unix
socket, so the control surface stays out of reach of anything running in a tab.

Protocol is one JSON object per line, request and response.
"""

import asyncio
import json
import os
import socket
import ssl
import time

from . import __version__, pfgen
from .config import STATE_DIR
from .desync import DEFAULT_LADDER, TLS_STRATEGIES
from .proxy import SELFTEST_SNI

SOCKET_PATH = os.path.join(STATE_DIR, "control.sock")
BYPASS_FILE = os.path.join(STATE_DIR, "bypass.txt")


def _load_bypass():
    try:
        with open(BYPASS_FILE) as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def _save_bypass(entries):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = BYPASS_FILE + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("# Destinations MacDPI leaves alone - one host, IP or CIDR per line.\n")
        for entry in entries:
            fh.write(entry + "\n")
    os.replace(tmp, BYPASS_FILE)


def _make_client_hello(hostname: str) -> bytes:
    """A real ClientHello carrying `hostname` as its SNI, for the self-test."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=hostname)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


class ControlServer:
    def __init__(self, ctx, proxy, resolver, log, stop):
        self.ctx = ctx
        self.proxy = proxy
        self.resolver = resolver
        self.log = log
        self.stop = stop
        self.started = time.time()
        self.requests = 0
        self._server = None

    async def start(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        # A leftover socket from a killed process would block the bind.
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(self._handle, SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o600)
        self.log.debug(f"control socket at {SOCKET_PATH}")
        return self._server

    async def close(self):
        if self._server is not None:
            self._server.close()
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass

    async def _handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                try:
                    request = json.loads(line)
                    self.requests += 1
                    reply = self._dispatch(request)
                    if asyncio.iscoroutine(reply):
                        reply = await reply
                except Exception as exc:                       # noqa: BLE001
                    reply = {"ok": False, "error": str(exc)}
                writer.write((json.dumps(reply) + "\n").encode())
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:                                  # noqa: BLE001
                pass

    def _dispatch(self, request):
        command = request.get("cmd")
        handler = getattr(self, f"_cmd_{command}", None)
        if handler is None:
            return {"ok": False, "error": f"unknown command {command!r}"}
        return handler(request)

    # --- commands ----------------------------------------------------------

    def _cmd_status(self, _request):
        stats = self.proxy.stats
        return {
            "ok": True,
            "version": __version__,
            "pid": os.getpid(),
            "port": self.ctx.port,
            "uptime": time.time() - self.started,
            "mode": self.ctx.mode,
            "ladder": self.ctx.ladder,
            "doh": self.ctx.doh_host if self.ctx.doh else None,
            "connections": stats["connections"],
            "failed": stats["failed"],
            "active": stats["active"],
            "bytes_up": stats["bytes_up"],
            "bytes_down": stats["bytes_down"],
            "strategies": dict(self.proxy.strategy_counts),
            "learned_count": len(self.proxy.learned),
            "control_requests": self.requests,
            "transparent": self.ctx.transparent,
            "tproxy_tls_port": self.ctx.tproxy_tls_port,
            "tproxy_http_port": self.ctx.tproxy_http_port,
            "bypass_count": len(_load_bypass()),
        }

    def _cmd_get_bypass(self, _request):
        return {"ok": True, "bypass": _load_bypass()}

    def _cmd_set_bypass(self, request):
        entries = request.get("bypass")
        if not isinstance(entries, list):
            return {"ok": False, "error": "bypass must be a list"}
        cleaned = [str(e).strip() for e in entries if str(e).strip()]
        try:
            _save_bypass(cleaned)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "bypass": cleaned}

    def _cmd_pf_ruleset(self, _request):
        """Return the pf.conf text for the current bypass list.

        The engine generates it (it can resolve bypass hostnames); the menu app
        writes and loads it as root. Generating here keeps the privileged step
        to just 'write this exact text and run pfctl', with no logic as root.
        """
        text = pfgen.build_ruleset(
            _load_bypass(),
            tls_port=self.ctx.tproxy_tls_port,
            http_port=self.ctx.tproxy_http_port,
        )
        return {"ok": True, "ruleset": text}

    async def _cmd_selftest(self, request):
        """Verify the pf redirect is actually capturing this Mac's traffic.

        Sends a ClientHello with a sentinel SNI to a public :443 address from an
        ordinary source port. If the redirect is live, it lands on our own
        transparent listener, which recognises the sentinel and signals us. If
        nothing signals within the timeout, capture is not working and the
        caller should roll the firewall change back.
        """
        if not self.ctx.transparent:
            return {"ok": False, "error": "transparent mode is not enabled"}
        timeout = float(request.get("timeout", 4.0))
        target = request.get("target", "1.1.1.1")
        self.proxy._selftest_seen.clear()

        async def probe():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, 443), timeout)
            except (OSError, asyncio.TimeoutError):
                return
            try:
                writer.write(_make_client_hello(SELFTEST_SNI))
                await writer.drain()
                await asyncio.sleep(timeout)
            except OSError:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        task = asyncio.ensure_future(probe())
        try:
            await asyncio.wait_for(self.proxy._selftest_seen.wait(), timeout)
            captured = True
        except asyncio.TimeoutError:
            captured = False
        finally:
            task.cancel()
        return {"ok": True, "captured": captured}

    def _cmd_learned(self, _request):
        return {"ok": True, "learned": dict(self.proxy.learned)}

    def _cmd_recent(self, request):
        limit = int(request.get("limit", 50))
        items = list(self.proxy.recent)[-limit:]
        return {"ok": True, "recent": items}

    def _cmd_strategies(self, _request):
        return {"ok": True,
                "strategies": list(TLS_STRATEGIES),
                "default_ladder": DEFAULT_LADDER,
                "current": self.ctx.mode}

    def _cmd_set_mode(self, request):
        mode = request.get("mode")
        if mode != "auto" and mode not in TLS_STRATEGIES:
            return {"ok": False, "error": f"unknown strategy {mode!r}"}
        self.ctx.mode = mode
        self.ctx.ladder = list(DEFAULT_LADDER) if mode == "auto" else [mode]
        self.log.info(f"strategy changed to {mode}")
        return {"ok": True, "mode": mode, "ladder": self.ctx.ladder}

    def _cmd_flush_dns(self, _request):
        self.resolver.reset()
        self.log.info("DNS cache flushed")
        return {"ok": True}

    def _cmd_forget(self, request):
        host = request.get("host")
        if host:
            self.proxy.learned.pop(host, None)
        else:
            self.proxy.learned.clear()
        self.proxy._dirty = True
        self.proxy.save_state()
        self.log.info(f"forgot learned strategy for {host or 'all hosts'}")
        return {"ok": True, "learned_count": len(self.proxy.learned)}

    def _cmd_shutdown(self, _request):
        self.log.info("shutdown requested over control socket")
        self.stop.set()
        return {"ok": True}

    def _cmd_ping(self, _request):
        return {"ok": True, "pong": True}

"""The engine's self-check: notice it is unwell, and put itself right.

Everything here exists because the same few things went wrong in practice:

* the event loop got swamped or blocked, so a listener stopped accepting and
  clients timed out against a process that still looked alive;
* a listener silently went away while the process lived on;
* file descriptors or memory crept up until connections began to fail;
* after any of that, "restart it" was the right answer but nothing did it.

Three layers, cheapest first:

1. A heartbeat thread, independent of the event loop. If the loop stops
   beating - something blocked it - the process is beyond saving from the
   inside, so the thread ends it and launchd starts a clean one.
2. Async self-probes: connect to our own listeners, query our own DNS server,
   watch loop lag, descriptors and memory. A few bad readings in a row mean a
   graceful restart.
3. A restart budget. Restarting forever on a fault a restart cannot cure only
   makes things worse (and masks the fault), so after a few restarts in a short
   window the doctor stops restarting, says so, and reports itself degraded.

Restarting is only done under launchd (`--watchdog`), which relaunches the
engine on exit; run in a terminal, the doctor still checks and reports but
never kills the process out from under you.
"""

import asyncio
import json
import os
import resource
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .config import STATE_DIR

EVENT_LOG = os.path.join(STATE_DIR, "doctor.log")
STATE_FILE = os.path.join(STATE_DIR, "doctor.json")
EVENT_LOG_MAX = 512 * 1024

INTERVAL = 10.0              # seconds between self-checks
PROBE_TIMEOUT = 2.5
FAILS_BEFORE_RESTART = 3     # consecutive failed checks of the same kind
HEARTBEAT_STALE = 30.0       # loop silent this long -> the thread ends the process
LAG_BAD = 4.0                # event-loop lag (seconds) that counts as a bad reading
FD_FRACTION = 0.85
RSS_LIMIT = 1.5 * 1024 ** 3
RESTART_BUDGET = 3           # self-restarts allowed ...
RESTART_WINDOW = 15 * 60     # ... within this many seconds
EXIT_WEDGED = 75
EXIT_RESTART = 0


def _now():
    return time.time()


def _mono():
    # Heartbeat clock. On macOS this is mach_absolute_time, which stops while
    # the Mac sleeps, so a lid closed for an hour is not "an hour of silence".
    return time.monotonic()


class EventLog:
    """A small, size-capped, human-readable record of what the doctor did."""

    def __init__(self, path=EVENT_LOG):
        self.path = path
        self.recent = []

    def add(self, kind, message):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{kind}] {message}"
        self.recent.append(line)
        del self.recent[:-40]
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            if os.path.exists(self.path) and os.path.getsize(self.path) > EVENT_LOG_MAX:
                os.replace(self.path, self.path + ".1")
            with open(self.path, "a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


class RestartBudget:
    """How many times the doctor has restarted the engine lately (persisted)."""

    def __init__(self, path=STATE_FILE):
        self.path = path

    def _load(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            return [t for t in data.get("restarts", []) if _now() - t < RESTART_WINDOW]
        except (OSError, ValueError):
            return []

    def recent(self):
        return self._load()

    def allowed(self):
        return len(self._load()) < RESTART_BUDGET

    def record(self):
        stamps = self._load() + [_now()]
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w") as fh:
                json.dump({"restarts": stamps}, fh)
        except OSError:
            pass


def count_fds():
    try:
        return len(os.listdir("/dev/fd"))
    except OSError:
        return 0


def rss_bytes():
    # macOS reports ru_maxrss in bytes (Linux in kilobytes). It is a peak, which
    # is exactly what a leak guard wants.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


# Names a censoring network commonly blackholes. A normal network resolves all
# of them, so seeing the system resolver fail on one that DoH resolves is a
# reliable sign of DNS-level blocking rather than a general outage.
DNS_CANARIES = ("discord.com", "roblox.com", "www.wikipedia.org", "x.com")
DNS_PROBE_BUDGET = 5.0


def dns_selftest(port, timeout=4.0):
    """Ask our own DNS server for a name and require a real answer."""
    query = (struct.pack(">HHHHHH", 0x4D44, 0x0100, 1, 0, 0, 0)
             + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        return len(data) >= 12 and data[:2] == query[:2] and (data[3] & 0x0F) == 0
    except OSError:
        return False
    finally:
        sock.close()


class Doctor:
    def __init__(self, ctx, log, stop, resolver, listeners, dns_server=None,
                 can_restart=False):
        """`listeners` is [(name, port)] of the TCP ports we serve on loopback."""
        self.ctx, self.log, self.stop, self.resolver = ctx, log, stop, resolver
        self.listeners = list(listeners)
        self.dns_server = dns_server
        self.can_restart = can_restart
        self.events = EventLog()
        self.budget = RestartBudget()
        self.fails = {}
        self.checks = {}
        self.degraded = False
        self.restart_reason = None
        self.started = _now()
        self._beat = _mono()
        self._lag = 0.0
        self._doh_fails = 0
        self._last_dns_check = 0.0
        self._dns_probe_running = False
        self._last_blocked = []
        # getaddrinfo on a blackholed name can hang for ~30s; keep those
        # threads off the shared executor the DNS fallback uses.
        self._probe_pool = ThreadPoolExecutor(max_workers=len(DNS_CANARIES),
                                              thread_name_prefix='macdpi-dnsprobe')

    # --- public ------------------------------------------------------------

    def start(self, loop):
        """Begin checking. Returns the asyncio task; also starts the heartbeat thread."""
        self._beat = _mono()
        if self.can_restart:
            threading.Thread(target=self._heartbeat_thread, daemon=True,
                             name="macdpi-doctor-heartbeat").start()
        self.events.add("start", f"doctor armed (restarts {'on' if self.can_restart else 'off'}; "
                                 f"watching {', '.join(n for n, _ in self.listeners) or 'nothing'})")
        # The beat comes from its own tiny task, not the check cycle: a slow
        # cycle on a bad network (probes, the DoH canary) is not a wedged loop.
        self._pulse_task = loop.create_task(self._pulse())
        return loop.create_task(self._run())

    async def _pulse(self):
        try:
            while not self.stop.is_set():
                self._beat = _mono()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    async def dns_probe(self):
        """Compare what the system resolver and DoH each say about the canaries.

        Returns {"blocked": [names], "checked": n}. A name is "blocked" when DoH
        resolves it but the system resolver does not: exactly the case that
        breaks apps which look names up themselves (Roblox) while browsers, who
        let the proxy do it, keep working. If the system resolver already points
        at our DNS server there is nothing to detect - it goes over DoH too.
        """
        if self._dns_probe_running or not self.ctx.doh:
            return {"blocked": [], "checked": 0, "skipped": True}
        self._dns_probe_running = True
        loop = asyncio.get_running_loop()
        try:
            async def one(name):
                async def system():
                    try:
                        infos = await asyncio.wait_for(
                            loop.run_in_executor(self._probe_pool, socket.getaddrinfo,
                                                 name, 443, socket.AF_INET), DNS_PROBE_BUDGET)
                        return bool(infos)
                    except Exception:                                 # noqa: BLE001
                        return False
                async def doh():
                    try:
                        return bool(await asyncio.wait_for(self.resolver.resolve(name), DNS_PROBE_BUDGET))
                    except Exception:                                 # noqa: BLE001
                        return False
                sys_ok, doh_ok = await asyncio.gather(system(), doh())
                return name, sys_ok, doh_ok
            results = await asyncio.gather(*[one(n) for n in DNS_CANARIES])
            blocked = [n for n, sys_ok, doh_ok in results if doh_ok and not sys_ok]
            if blocked and blocked != self._last_blocked:
                self.events.add("problem", "system DNS fails for " + ", ".join(blocked)
                                + " while DoH resolves them (plain DNS is being blocked)")
            if not blocked and self._last_blocked:
                self.events.add("ok", "system DNS resolves the canary names again")
            self._last_blocked = blocked
            return {"blocked": blocked, "checked": len(results),
                    "detail": {n: {"system": a, "doh": b} for n, a, b in results}}
        finally:
            self._dns_probe_running = False

    def report(self):
        recent = self.budget.recent()
        return {
            "ok": all(c["ok"] for c in self.checks.values()) and not self.degraded,
            "degraded": self.degraded,
            "can_restart": self.can_restart,
            "checks": [{"name": n, **c} for n, c in sorted(self.checks.items())],
            "restarts_recent": len(recent),
            "uptime": _now() - self.started,
            "lag": round(self._lag, 2),
            "fds": count_fds(),
            "rss_mb": round(rss_bytes() / 1048576, 1),
            "events": self.events.recent[-15:],
        }

    # --- layer 1: a heartbeat that does not depend on the event loop -------

    def _heartbeat_thread(self):
        while True:
            before = time.time()
            time.sleep(5)
            if time.time() - before > 15:
                # This thread's own 5s nap overran: the whole Mac was asleep (or
                # the process was suspended), not just the event loop. Give the
                # loop a fresh start rather than count the gap against it.
                self._beat = _mono()
                continue
            silent = _mono() - self._beat
            if silent > HEARTBEAT_STALE and not self.stop.is_set():
                self.events.add("wedged", f"event loop silent for {silent:.0f}s; ending the process "
                                          "so launchd can start a clean one")
                if self.budget.allowed():
                    self.budget.record()
                os._exit(EXIT_WEDGED)

    # --- layer 2: probes ---------------------------------------------------

    async def _run(self):
        loop = asyncio.get_running_loop()
        try:
            while not self.stop.is_set():
                try:
                    await asyncio.wait_for(self.stop.wait(), INTERVAL)
                    return
                except asyncio.TimeoutError:
                    pass
                self._beat = _mono()
                await self._cycle(loop)
        except asyncio.CancelledError:
            pass

    async def _cycle(self, loop):
        # event-loop lag: how late does a short sleep wake us?
        t0 = loop.time()
        await asyncio.sleep(0.25)
        self._lag = max(0.0, loop.time() - t0 - 0.25)
        self._beat = _mono()
        self._set("loop", self._lag < LAG_BAD, f"lag {self._lag:.2f}s")

        for name, target in self.listeners:
            if isinstance(target, int):
                ok = await self._probe_port(target)
                self._set(f"listener:{name}", ok,
                          f"127.0.0.1:{target} " + ("accepts" if ok else "not accepting"))
            else:
                ok, detail = self._server_alive(target)
                self._set(f"listener:{name}", ok, detail)

        if self.dns_server is not None and _now() - self._last_dns_check > 60:
            self._last_dns_check = _now()
            ok = await loop.run_in_executor(None, dns_selftest, self.ctx.dns_port)
            self._set("dns-server", ok, "answers" if ok else "not answering")

        fds = count_fds()
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        limit = soft if soft not in (-1, resource.RLIM_INFINITY) else 1 << 20
        self._set("descriptors", fds < limit * FD_FRACTION, f"{fds} of {limit}")

        rss = rss_bytes()
        self._set("memory", rss < RSS_LIMIT, f"{rss / 1048576:.0f} MB peak")

        await self._doh_canary()
        self._decide()

    @staticmethod
    def _server_alive(server):
        """A listener checked without connecting to it (see serve())."""
        if server is None:
            return False, "could not bind"
        if not server.is_serving():
            return False, "stopped serving"
        socks = server.sockets or []
        if not socks or any(sk.fileno() < 0 for sk in socks):
            return False, "socket closed"
        port = socks[0].getsockname()[1]
        return True, f"127.0.0.1:{port} serving"

    async def _probe_port(self, port):
        try:
            _r, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), PROBE_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return False
        w.close()
        return True

    async def _doh_canary(self):
        """If DoH keeps failing while the network is up, clear its state once."""
        if not self.ctx.doh:
            return
        try:
            ips = await asyncio.wait_for(self.resolver.resolve("example.com"), 8)
            ok = bool(ips)
        except Exception:                                         # noqa: BLE001
            ok = False
        self._doh_fails = 0 if ok else self._doh_fails + 1
        self._set("doh", ok or self._doh_fails < 3, "resolving" if ok else f"failing x{self._doh_fails}")
        if self._doh_fails == 3:
            self.resolver.reset()
            self.events.add("healed", "DoH failed 3 checks in a row; cleared the resolver's state")

    def _set(self, name, ok, detail):
        prev = self.checks.get(name)
        self.checks[name] = {"ok": ok, "detail": detail}
        self.fails[name] = 0 if ok else self.fails.get(name, 0) + 1
        if prev is not None and prev["ok"] != ok:
            self.events.add("ok" if ok else "problem", f"{name}: {detail}")

    # --- layer 3: decide, within a budget ----------------------------------

    def _decide(self):
        urgent = [n for n in self.fails
                  if self.fails[n] >= FAILS_BEFORE_RESTART
                  and (n.startswith("listener:") or n in ("loop", "descriptors", "memory", "dns-server"))]
        if not urgent:
            if self.degraded and self.budget.allowed():
                self.degraded = False
            return
        reason = ", ".join(f"{n} ({self.checks[n]['detail']})" for n in urgent)
        if not self.can_restart:
            return                      # report only; never kill a foreground run
        if not self.budget.allowed():
            if not self.degraded:
                self.degraded = True
                self.events.add("degraded", f"{reason}, but already restarted {RESTART_BUDGET}x in "
                                            f"{RESTART_WINDOW // 60} min; not restarting again - "
                                            "a restart is not curing this")
            return
        self.budget.record()
        self.restart_reason = reason
        self.events.add("restart", f"restarting the engine: {reason}")
        self.log.warn(f"doctor: restarting the engine ({reason})")
        self.stop.set()

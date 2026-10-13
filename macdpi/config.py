"""Runtime configuration and logging."""

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .desync import DEFAULT_LADDER, TLS_STRATEGIES

STATE_DIR = os.path.expanduser("~/.macdpi")
STATE_FILE = os.path.join(STATE_DIR, "learned.json")

# Resolvers selectable by name with --doh. Each is (ip, hostname, path), and
# is addressed by IP so no plaintext lookup is needed to reach it. All of them
# answer DoH over HTTP/1.1, which is what the resolver here speaks (Quad9, for
# one, is HTTP/2-only and so is not listed).
DOH_PRESETS = {
    "cloudflare": ("1.1.1.1", "cloudflare-dns.com", "/dns-query"),
    "google": ("8.8.8.8", "dns.google", "/dns-query"),
    "opendns": ("208.67.222.222", "doh.opendns.com", "/dns-query"),
    "adguard": ("94.140.14.14", "dns.adguard-dns.com", "/dns-query"),
    "dnssb": ("185.222.222.222", "doh.dns.sb", "/dns-query"),
    "nextdns": ("45.90.28.0", "dns.nextdns.io", "/dns-query"),
    "controld": ("76.76.2.0", "freedns.controld.com", "/p0"),
}

# Further addresses for the same services, tried after the presets. A network
# that blocks DoH by IP usually blocks the famous anycast address and nothing
# else, so a provider's second address - or, for Cloudflare, an address inside
# its ordinary CDN range that cannot be blocked without taking half the web
# down with it - is often still open.
DOH_FALLBACKS = [
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query"),
    ("8.8.4.4", "dns.google", "/dns-query"),
    ("104.16.248.249", "cloudflare-dns.com", "/dns-query"),
    ("146.112.41.2", "doh.opendns.com", "/dns-query"),
    ("104.16.249.249", "mozilla.cloudflare-dns.com", "/dns-query"),
    ("94.140.14.140", "unfiltered.adguard-dns.com", "/dns-query"),
]


@dataclass
class Context:
    host: str = "127.0.0.1"
    port: int = 8881
    mode: str = "auto"
    ladder: list = field(default_factory=lambda: list(DEFAULT_LADDER))
    delay: float = 0.0
    oob_byte: bytes = b"\x00"

    doh: bool = True
    doh_ip: str = "1.1.1.1"
    doh_host: str = "cloudflare-dns.com"
    doh_path: str = "/dns-query"
    # Tried first when reaching the resolver; the rest of the ladder follows.
    doh_strategy: str = "recver"
    # Give up on DoH (and fall back to system DNS for a while) if no provider
    # can be reached within this many seconds.
    doh_budget: float = 12.0
    # The resolver tries these providers in order (each is (ip, host, path)), so
    # a network that blocks one DoH endpoint still resolves through another.
    doh_providers: list = field(default_factory=list)

    connect_timeout: float = 8.0
    handshake_timeout: float = 5.0
    # Shorter budget for the auto-selection probes, so an IP-blocked host is
    # given up on quickly rather than hanging the first page load.
    probe_timeout: float = 4.0
    # Auto-selection starts one probe per strategy, each this long after the
    # previous, so a network needing no evasion barely starts the later ones.
    probe_stagger: float = 0.05
    # Once some strategy has validated, how long to wait for a higher-ranked
    # one that has not answered yet before settling.
    probe_grace: float = 0.25
    # A cached strategy older than this is re-checked in the background.
    reverify_after: float = 300.0
    dns_timeout: float = 6.0
    idle_timeout: float = 600.0
    dns_max_ttl: int = 300
    max_ips: int = 4

    http_tricks: bool = True
    host_padding: int = 2

    learn: bool = True
    verbose: bool = False

    wait_for_network: float = 0.0
    watch_network: bool = True

    # Transparent ("all apps") interception. When on, the engine also listens on
    # these loopback ports, where a pf rdr rule delivers redirected :443/:80
    # traffic, and it binds every upstream socket into the reserved source-port
    # band so its own traffic is not redirected back into it.
    transparent: bool = False
    tproxy_tls_port: int = 8443
    tproxy_http_port: int = 8480


class Log:
    LEVELS = {"error": 0, "warn": 1, "info": 2, "debug": 3}

    def __init__(self, level: str = "info"):
        self.level = self.LEVELS.get(level, 2)

    def _emit(self, tag: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        print(f"{ts} [{tag}] {msg}", file=sys.stderr, flush=True)

    def error(self, msg): self.level >= 0 and self._emit("!", msg)
    def warn(self, msg):  self.level >= 1 and self._emit("~", msg)
    def info(self, msg):  self.level >= 2 and self._emit("+", msg)
    def debug(self, msg): self.level >= 3 and self._emit(".", msg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macdpi",
        description="Local DPI-circumvention proxy for macOS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "strategies: " + ", ".join(TLS_STRATEGIES) + "\n"
            "In 'auto' mode every strategy is probed and the first one whose "
            "certificate validates is remembered per host."
        ),
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="listen address (default: %(default)s)")
    p.add_argument("--port", type=int, default=8881,
                   help="listen port (default: %(default)s)")
    p.add_argument("-m", "--mode", default="auto",
                   choices=["auto", *TLS_STRATEGIES],
                   help="evasion strategy, or auto to probe (default: %(default)s)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="seconds between split segments; raise to 0.05 if "
                        "splitting alone is not enough (default: %(default)s)")
    p.add_argument("--doh", default="cloudflare",
                   help="DoH resolver: a preset (%s) or a full URL, or 'off' "
                        "to use system DNS (default: %%(default)s)"
                        % ", ".join(DOH_PRESETS))
    p.add_argument("--no-http-tricks", action="store_true",
                   help="do not rewrite Host headers on plaintext HTTP")
    p.add_argument("--no-learn", action="store_true",
                   help="do not remember which strategy worked per host")
    p.add_argument("--idle-timeout", type=float, default=600.0,
                   help="drop idle tunnels after N seconds (default: %(default)s)")
    p.add_argument("--wait-for-network", type=float, default=0.0,
                   metavar="SECONDS",
                   help="on startup, wait up to N seconds for an internet "
                        "connection before serving (default: %(default)s)")
    p.add_argument("--no-watch-network", action="store_true",
                   help="do not flush the DNS cache when the connection "
                        "drops and returns")
    p.add_argument("--transparent", action="store_true",
                   help="also run transparent listeners for pf-redirected "
                        "traffic, so every app is covered (not just proxy-aware "
                        "ones); requires the pf rules to be loaded separately")
    p.add_argument("--tproxy-tls-port", type=int, default=8443,
                   help="transparent listener port for redirected :443 "
                        "(default: %(default)s)")
    p.add_argument("--tproxy-http-port", type=int, default=8480,
                   help="transparent listener port for redirected :80 "
                        "(default: %(default)s)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="log every connection and the strategy used")
    p.add_argument("--test", nargs="*", metavar="HOST",
                   help="probe hosts through each strategy and exit")
    return p


def context_from_args(args) -> Context:
    ctx = Context(
        host=args.host,
        port=args.port,
        mode=args.mode,
        delay=args.delay,
        http_tricks=not args.no_http_tricks,
        learn=not args.no_learn,
        idle_timeout=args.idle_timeout,
        verbose=args.verbose,
        wait_for_network=args.wait_for_network,
        watch_network=not args.no_watch_network,
        transparent=args.transparent,
        tproxy_tls_port=args.tproxy_tls_port,
        tproxy_http_port=args.tproxy_http_port,
    )
    if args.mode != "auto":
        ctx.ladder = [args.mode]

    doh = args.doh.strip().lower()
    if doh == "quad9":
        raise SystemExit(
            "macdpi: Quad9 only serves DoH over HTTP/2, which this resolver "
            "does not speak. Choose one of: " + ", ".join(DOH_PRESETS))
    if doh in ("off", "no", "none", "system"):
        ctx.doh = False
    elif doh in DOH_PRESETS:
        ctx.doh_ip, ctx.doh_host, ctx.doh_path = DOH_PRESETS[doh]
    else:
        parsed = urlparse(args.doh)
        if not parsed.hostname:
            raise SystemExit(f"macdpi: cannot parse --doh value {args.doh!r}")
        ctx.doh_host = parsed.hostname
        ctx.doh_path = parsed.path or "/dns-query"
        ctx.doh_ip = parsed.hostname

    # The chosen resolver leads; every other preset follows as a fallback, so a
    # network that blocks one endpoint still resolves through another.
    if ctx.doh:
        primary = (ctx.doh_ip, ctx.doh_host, ctx.doh_path)
        ctx.doh_providers = [primary] + [
            p for p in [*DOH_PRESETS.values(), *DOH_FALLBACKS] if p != primary
        ]
    return ctx

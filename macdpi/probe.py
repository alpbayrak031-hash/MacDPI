"""`--test`: try every strategy against a host and report what got through."""

import asyncio

from .desync import TLS_STRATEGIES
from .netio import Upstream
from .tlsclient import TLSStream

DEFAULT_HOSTS = [
    "www.wikipedia.org",
    "www.reddit.com",
    "discord.com",
    "x.com",
    "medium.com",
]


async def probe_one(host, strategy_name, resolver, ctx):
    """Complete a real TLS handshake using one strategy. Returns None on success."""
    ips = await resolver.resolve(host)
    if not ips:
        return "no DNS answer"
    up = None
    try:
        up = await Upstream.connect(ips[0], 443, ctx.connect_timeout)
        stream = TLSStream(up, host, TLS_STRATEGIES[strategy_name], ctx)
        await asyncio.wait_for(stream.handshake(), ctx.handshake_timeout)
        return None
    except asyncio.TimeoutError:
        return "timeout"
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    finally:
        if up is not None:
            up.close()


async def run(hosts, resolver, ctx, log):
    hosts = hosts or DEFAULT_HOSTS
    names = list(TLS_STRATEGIES)
    width = max(len(h) for h in hosts) + 2

    print()
    print("Probing each strategy with a real TLS handshake.")
    print(f"DNS: {'DoH ' + ctx.doh_host if ctx.doh else 'system resolver'}")
    print()
    print(" " * width + "  ".join(f"{n:^13}" for n in names))

    summary = {n: 0 for n in names}
    for host in hosts:
        cells = []
        for name in names:
            err = await probe_one(host, name, resolver, ctx)
            if err is None:
                summary[name] += 1
                cells.append(f"{'ok':^13}")
            else:
                cells.append(f"{err[:13]:^13}")
        print(f"{host:<{width}}" + "  ".join(cells))

    print()
    best = max(summary, key=lambda n: summary[n])
    total = len(hosts)
    for name in names:
        print(f"  {name:<14} {summary[name]}/{total}")
    print()
    if summary[best] == 0:
        print("Nothing got through. The block is probably at the IP layer, "
              "which this tool cannot bypass - you would need a VPN or Tor.")
    elif summary["direct"] == total:
        print("Everything worked without evasion; nothing here is being "
              "filtered by DPI on this network right now.")
    else:
        print(f"Best strategy on this network: {best}  "
              f"(run with: --mode {best})")
    print()

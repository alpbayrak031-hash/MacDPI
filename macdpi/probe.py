"""`--test`: try every strategy against a host and report what got through."""

import asyncio
import ssl

from .desync import DEFAULT_LADDER, TLS_STRATEGIES
from .netio import Upstream
from .tlsclient import TLSStream

DEFAULT_HOSTS = [
    "www.wikipedia.org",
    "www.youtube.com",
    "www.reddit.com",
    "www.instagram.com",
    "discord.com",
    "x.com",
    "www.twitch.tv",
    "www.roblox.com",
    "medium.com",
]


async def probe_one(host, strategy_name, resolver, ctx):
    """Complete a real TLS handshake using one strategy. Returns None on success."""
    ips = await resolver.resolve(host)
    if not ips:
        return "no DNS answer"
    up = None
    try:
        # Bound to the reserved source-port band, so that with "cover all
        # apps" on, the probe goes straight out instead of being redirected
        # into the running engine - which would test the engine's choice of
        # strategy rather than this one.
        up = await Upstream.connect(ips[0], 443, ctx.probe_timeout,
                                    reserve_source_port=True)
        stream = TLSStream(up, host, TLS_STRATEGIES[strategy_name], ctx)
        await asyncio.wait_for(stream.handshake(), ctx.probe_timeout)
        return None
    except asyncio.TimeoutError:
        return "dropped"
    except ssl.SSLCertVerificationError:
        return "forged cert"
    except ssl.SSLError:
        return "tls error"
    except ConnectionError:
        return "reset"
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    finally:
        if up is not None:
            up.close()


async def probe_host(host, resolver, ctx):
    """Probe every strategy against `host` at once. Returns {strategy: error}."""
    names = list(DEFAULT_LADDER)
    errors = await asyncio.gather(
        *[probe_one(host, name, resolver, ctx) for name in names])
    return dict(zip(names, errors))


def _describe(results):
    """One line saying how a host fared."""
    working = [name for name, err in results.items() if err is None]
    if results["direct"] is None:
        return "open       no evasion needed"
    how = results["direct"]
    if working:
        return f"FILTERED   ({how}) - gets through with: {', '.join(working)}"
    if how == "no DNS answer":
        return "no DNS answer"
    return f"BLOCKED    ({how}) - no strategy gets through"


async def run(hosts, resolver, ctx, log):
    hosts = hosts or DEFAULT_HOSTS
    width = max(len(h) for h in hosts) + 2

    print()
    print("Probing each strategy with a real, certificate-verified TLS handshake.")
    print(f"DNS: {'DoH ' + ctx.doh_host if ctx.doh else 'system resolver'}")
    print()

    all_results = await asyncio.gather(
        *[probe_host(host, resolver, ctx) for host in hosts])
    for host, results in zip(hosts, all_results):
        print(f"{host:<{width}}{_describe(results)}")

    total = len(hosts)
    score = {name: sum(1 for r in all_results if r[name] is None)
             for name in DEFAULT_LADDER}
    print()
    print("Sites reached, by strategy:")
    for name in DEFAULT_LADDER:
        print(f"  {name:<15} {score[name]}/{total}")
    print()

    reachable = sum(1 for r in all_results if any(e is None for e in r.values()))
    filtered = sum(1 for r in all_results
                   if r["direct"] is not None
                   and any(e is None for e in r.values()))
    dead = total - reachable
    best = max(DEFAULT_LADDER, key=lambda n: score[n])

    if score["direct"] == total:
        print("Everything worked without evasion; nothing here is being "
              "filtered by DPI on this network right now.")
    elif reachable == 0:
        print("Nothing got through. The block is probably at the IP layer, "
              "which this tool cannot bypass - you would need a VPN or Tor.")
    else:
        if filtered:
            print(f"{filtered} of {total} sites are filtered on this network "
                  "and reachable with evasion. In auto mode MacDPI picks a "
                  "working strategy for each site by itself.")
            print(f"Most effective single strategy here: {best}  "
                  f"({score[best]}/{total}; run with: --mode {best})")
        if dead:
            print(f"{dead} of {total} could not be reached with any strategy. "
                  "That is a block nothing local beats (the address itself is "
                  "dropped) - it needs a VPN or Tor.")
    print()

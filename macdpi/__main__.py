"""Entry point: python3 -m macdpi"""

import asyncio
import resource
import signal
import sys

from . import __version__, netcheck, probe
from .config import Log, build_parser, context_from_args
from .control import ControlServer
from .dns import Resolver
from .proxy import Proxy


def _raise_fd_limit(log):
    """Lift the open-file limit well above launchd's stingy default.

    launchd starts agents with a soft RLIMIT_NOFILE of 256. That is fine for
    browsers-only, but 'cover all apps' funnels every connection from every app
    through here, and 256 is exhausted almost immediately - which surfaces as
    'Too many open files' and connections being refused. Each tunnel needs two
    descriptors, so we ask for a headroom of ~16k.
    """
    want = 16384
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        ceiling = hard if hard != resource.RLIM_INFINITY else want
        new_soft = min(max(soft, want), ceiling)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        log.info(f"open-file limit: {new_soft} (was {soft})")
        return new_soft
    except (ValueError, OSError) as exc:
        log.warn(f"could not raise open-file limit: {exc}")
        return None


async def serve(ctx, log):
    _raise_fd_limit(log)
    resolver = Resolver(ctx, log)
    prox = Proxy(ctx, resolver, log)

    if ctx.wait_for_network > 0:
        await netcheck.wait_until_online(ctx, log, ctx.wait_for_network)

    server = await asyncio.start_server(
        prox.handle, ctx.host, ctx.port, reuse_address=True, backlog=512
    )
    log.info(f"macdpi {__version__} listening on {ctx.host}:{ctx.port} "
             f"(HTTP proxy + SOCKS5)")
    log.info(f"mode={ctx.mode}  dns="
             f"{'DoH:' + ctx.doh_host if ctx.doh else 'system'}")
    log.info("point macOS system proxy here, or run: ./dpictl on")

    tproxy_servers = []
    if ctx.transparent:
        for tport, uport in ((ctx.tproxy_tls_port, 443),
                             (ctx.tproxy_http_port, 80)):
            handler = _make_transparent_handler(prox, uport)
            try:
                srv = await asyncio.start_server(
                    handler, "127.0.0.1", tport, reuse_address=True, backlog=512
                )
            except OSError as exc:
                log.error(f"cannot open transparent listener on {tport}: {exc}")
                continue
            tproxy_servers.append(srv)
            log.info(f"transparent listener on 127.0.0.1:{tport} "
                     f"(redirected :{uport})")
        log.info("transparent mode on: load the pf rules to cover all apps")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    control = ControlServer(ctx, prox, resolver, log, stop)
    try:
        await control.start()
    except OSError as exc:
        log.warn(f"control socket unavailable: {exc}")

    tasks = [asyncio.create_task(_periodic_save(prox, stop))]
    if ctx.watch_network:
        tasks.append(asyncio.create_task(
            netcheck.monitor(ctx, resolver, log, stop)
        ))

    async with server:
        await stop.wait()

    log.info(f"shutting down "
             f"({prox.stats['connections']} connections, "
             f"{prox.stats['failed']} failed)")
    for srv in tproxy_servers:
        srv.close()
    for task in tasks:
        task.cancel()
    await control.close()
    prox.save_state()


def _make_transparent_handler(prox, upstream_port):
    async def handler(reader, writer):
        await prox.handle_transparent(reader, writer, upstream_port)
    return handler


async def _periodic_save(prox, stop):
    try:
        while not stop.is_set():
            await asyncio.sleep(20)
            prox.save_state()
    except asyncio.CancelledError:
        pass


def main(argv=None):
    args = build_parser().parse_args(argv)
    ctx = context_from_args(args)
    log = Log("debug" if args.verbose else "info")

    if args.test is not None:
        resolver = Resolver(ctx, log)
        asyncio.run(probe.run(args.test, resolver, ctx, log))
        return 0

    try:
        asyncio.run(serve(ctx, log))
    except OSError as exc:
        log.error(f"cannot listen on {ctx.host}:{ctx.port}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

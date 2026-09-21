"""DPI evasion strategies applied to the first packet of a connection.

Every strategy leaves a byte-for-byte identical stream at the server; only the
way the bytes are cut up on the wire changes, which is what a DPI box keys on.
"""

import asyncio
import re

from . import tls

# --- helpers ---------------------------------------------------------------


def _sni_split_pos(data: bytes) -> int:
    """A TCP split position that lands in the middle of the hostname."""
    found = tls.find_sni(data)
    if found:
        off, ln = found
        return off + max(1, ln // 2)
    return min(len(data) - 1, 3) if len(data) > 1 else 0


async def _pause(ctx):
    if ctx.delay > 0:
        await asyncio.sleep(ctx.delay)


# --- TLS strategies --------------------------------------------------------


async def direct(up, data, ctx):
    await up.send(data)


async def split(up, data, ctx):
    """One TCP split through the middle of the SNI."""
    pos = _sni_split_pos(data)
    if pos <= 0:
        return await up.send(data)
    await up.send(data[:pos])
    await _pause(ctx)
    await up.send(data[pos:])


async def multisplit(up, data, ctx):
    """Several small segments so no single packet holds a readable hostname."""
    found = tls.find_sni(data)
    if not found:
        return await split(up, data, ctx)
    off, ln = found
    points = sorted({1, off + 1, off + ln // 2, off + ln - 1})
    points = [p for p in points if 0 < p < len(data)]
    prev = 0
    for p in points:
        await up.send(data[prev:p])
        await _pause(ctx)
        prev = p
    await up.send(data[prev:])


async def tlsfrag(up, data, ctx):
    """Split the ClientHello across two TLS records, and two TCP segments.

    Stronger than a plain TCP split: even a DPI that fully reassembles TCP has
    to also reassemble handshake messages across records to recover the SNI.
    """
    found = tls.find_sni(data)
    if not found:
        return await split(up, data, ctx)
    off, ln = found
    body_pos = off + max(1, ln // 2) - 5
    framed = tls.fragment_record(data, body_pos)
    if framed is data or len(framed) == len(data):
        return await split(up, data, ctx)
    boundary = 5 + body_pos
    await up.send(framed[:boundary])
    await _pause(ctx)
    await up.send(framed[boundary:])


async def oob(up, data, ctx):
    """Split the SNI and wedge an urgent byte into the gap."""
    pos = _sni_split_pos(data)
    if pos <= 0:
        return await up.send(data)
    await up.send(data[:pos])
    await up.send_oob(ctx.oob_byte)
    await _pause(ctx)
    await up.send(data[pos:])


async def tlsfrag_oob(up, data, ctx):
    """Record fragmentation plus an urgent byte — the loudest option."""
    found = tls.find_sni(data)
    if not found:
        return await oob(up, data, ctx)
    off, ln = found
    body_pos = off + max(1, ln // 2) - 5
    framed = tls.fragment_record(data, body_pos)
    boundary = 5 + body_pos
    await up.send(framed[:boundary])
    await up.send_oob(ctx.oob_byte)
    await _pause(ctx)
    await up.send(framed[boundary:])


async def multisplit_oob(up, data, ctx):
    """Several small TCP segments *and* an urgent byte in the SNI gap.

    Distinct mechanism from either alone: it defeats a DPI that recovers the
    hostname despite fine TCP segmentation, yet also mishandles urgent data.
    """
    found = tls.find_sni(data)
    if not found:
        return await oob(up, data, ctx)
    off, ln = found
    mid = off + max(1, ln // 2)
    points = sorted({1, off + 1, mid, off + ln - 1})
    points = [p for p in points if 0 < p < len(data)]
    prev = 0
    for p in points:
        await up.send(data[prev:p])
        if p == mid:
            await up.send_oob(ctx.oob_byte)
        await _pause(ctx)
        prev = p
    await up.send(data[prev:])


TLS_STRATEGIES = {
    "direct": direct,
    "split": split,
    "multisplit": multisplit,
    "tlsfrag": tlsfrag,
    "oob": oob,
    "tlsfrag+oob": tlsfrag_oob,
    "multisplit+oob": multisplit_oob,
}

# Tried in order until a strategy yields a certificate that validates (see
# proxy._run_selection). Record fragmentation leads because every server
# accepts it; the urgent-byte tricks follow because they are the only ones that
# beat a middlebox which fully reassembles TCP and TLS records, though a few
# front-ends mishandle urgent data. 'direct' stays last as the no-op fallback
# for networks doing no DPI at all.
DEFAULT_LADDER = ["tlsfrag", "oob", "tlsfrag+oob", "multisplit+oob",
                  "multisplit", "split", "direct"]


# --- plain HTTP ------------------------------------------------------------

_HOST_RE = re.compile(rb"\r\n(Host):[ \t]*", re.IGNORECASE)


def mangle_http(request: bytes, ctx) -> bytes:
    """GoodbyeDPI's classic header tricks, which most origin servers tolerate.

    Header names are case-insensitive and leading whitespace in a value is
    stripped, so `hOSt:  example.com` reaches the server unchanged in meaning
    while defeating DPI rules that match the literal bytes `Host: `.
    """
    if not ctx.http_tricks:
        return request
    m = _HOST_RE.search(request)
    if not m:
        return request
    start, end = m.span()
    replacement = b"\r\nhOSt:" + b" " * ctx.host_padding
    return request[:start] + replacement + request[end:]


def http_split_pos(request: bytes) -> int:
    """Split position inside the Host header value."""
    m = _HOST_RE.search(request)
    if m:
        return m.end() + 2
    return min(len(request) - 1, 2) if len(request) > 1 else 0


async def http_send(up, data, ctx):
    data = mangle_http(data, ctx)
    pos = http_split_pos(data)
    if pos <= 0:
        return await up.send(data)
    await up.send(data[:pos])
    await _pause(ctx)
    await up.send(data[pos:])

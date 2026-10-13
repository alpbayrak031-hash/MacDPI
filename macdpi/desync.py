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


def _sni_body_span(data: bytes):
    """(offset, length) of the hostname within the first record's *body*."""
    found = tls.find_sni(data)
    if not found:
        return None
    off, ln = found
    return off - 5, ln


async def _send_chunks(up, chunks, ctx):
    """Send each chunk as its own TCP segment."""
    for i, chunk in enumerate(chunks):
        if i:
            await _pause(ctx)
        await up.send(chunk)


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
    span = _sni_body_span(data)
    if not span:
        return await split(up, data, ctx)
    off, ln = span
    chunks = tls.fragment_records(data, [off + max(1, ln // 2)])
    if len(chunks) < 2:
        return await split(up, data, ctx)
    await _send_chunks(up, chunks, ctx)


async def tinyrec(up, data, ctx):
    """Put a single byte of the ClientHello in a TLS record of its own.

    That first record holds only the handshake type, with the message's length
    and everything else in the next record. A DPI box that can stitch a
    hostname back together across two records still has to recognise the
    stream as a ClientHello first, and many only do so when the first record
    carries the whole handshake header.
    """
    chunks = tls.fragment_records(data, [1])
    if len(chunks) < 2:
        return await split(up, data, ctx)
    await _send_chunks(up, chunks, ctx)


async def multirec(up, data, ctx):
    """Scatter the ClientHello across many TLS records.

    Cuts fall after the handshake type, after the handshake header, and three
    times through the hostname - six records in all. Aimed at a DPI box that
    reassembles a fixed, small number of record fragments.
    """
    span = _sni_body_span(data)
    if not span:
        return await tinyrec(up, data, ctx)
    off, ln = span
    cuts = [1, 4, off + 1, off + max(1, ln // 2), off + ln - 1]
    chunks = tls.fragment_records(data, cuts)
    if len(chunks) < 2:
        return await split(up, data, ctx)
    await _send_chunks(up, chunks, ctx)


async def recver(up, data, ctx):
    """Rewrite the record-layer version so a DPI box does not see TLS at all.

    Different in kind from every fragmentation trick: those hide the hostname
    inside a stream the DPI still knows is TLS, and a thorough box then falls
    back on other evidence (it fetches the server's certificate itself, say).
    Here the stream never matches the DPI's idea of a TLS record in the first
    place, so no TLS inspection is attempted - while the server, which is
    required to ignore this field, carries on normally. Nothing about the
    segmentation changes, so this is also the cheapest strategy there is.
    """
    await up.send(tls.with_record_version(data, RECVER_VERSION))


async def disorder(up, data, ctx):
    """Deliver the two halves of the hostname out of order.

    The first half is sent with a TTL too small to get past the local router,
    so it is lost; the second half goes out normally and arrives first. The
    kernel then retransmits the first half at full TTL. The server reorders as
    TCP always does, but a DPI box that inspects packets in arrival order
    without buffering sees the tail of the hello before its head. Costs one
    retransmission timeout, so it sits low on the ladder.
    """
    pos = _sni_split_pos(data)
    if pos <= 0:
        return await up.send(data)
    ttl = up.get_ttl()
    try:
        up.set_ttl(1)
        await up.send(data[:pos])
        # Let the doomed segment leave before the TTL is put back.
        await asyncio.sleep(max(ctx.delay, 0.01))
    finally:
        up.set_ttl(ttl)
    await up.send(data[pos:])


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
    span = _sni_body_span(data)
    if not span:
        return await oob(up, data, ctx)
    off, ln = span
    chunks = tls.fragment_records(data, [off + max(1, ln // 2)])
    if len(chunks) < 2:
        return await oob(up, data, ctx)
    await up.send(chunks[0])
    await up.send_oob(ctx.oob_byte)
    await _pause(ctx)
    await up.send(chunks[1])


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
    "disorder": disorder,
    "tlsfrag": tlsfrag,
    "tinyrec": tinyrec,
    "multirec": multirec,
    "recver": recver,
    "oob": oob,
    "tlsfrag+oob": tlsfrag_oob,
    "multisplit+oob": multisplit_oob,
}

# The order of preference among strategies whose certificate validates (see
# proxy._run_selection) - every one is probed, and the earliest that reaches
# the real server wins.
#
# 'recver' leads: it is free (no extra packets), every mainstream TLS stack
# accepts it, and it is the only strategy that survives a middlebox which
# reassembles TCP and TLS records *and* falls back on the server's certificate
# when it cannot read the hostname. The record-fragmentation family follows
# for DPI that ignores the record version; then the urgent-byte tricks, which
# beat full reassembly too but which some front-ends (Google, Apple, anything
# on Windows) mishandle; then plain TCP segmentation. 'direct' stays last as
# the no-op fallback for networks doing no DPI at all.
DEFAULT_LADDER = ["recver", "tlsfrag", "tinyrec", "multirec",
                  "oob", "tlsfrag+oob", "multisplit+oob",
                  "multisplit", "split", "disorder", "direct"]

# What `recver` writes over the ClientHello's record-layer version. Servers
# look at the major byte at most (and TLS 1.3 tells them to ignore the field
# entirely), so the major stays 3; the minor is one no TLS version has ever
# used, so it cannot match a DPI signature listing the known ones.
RECVER_VERSION = b"\x03\xff"


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

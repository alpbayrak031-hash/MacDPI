"""Just enough TLS parsing to locate the SNI inside a ClientHello.

The whole point of the tool is to make the SNI hard for a DPI box to read,
so everything here is about finding exactly where the hostname sits.
"""

REC_HANDSHAKE = 0x16
HS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000


def is_client_hello(data: bytes) -> bool:
    return len(data) >= 6 and data[0] == REC_HANDSHAKE and data[5] == HS_CLIENT_HELLO


def find_sni(data: bytes):
    """Return (offset, length) of the SNI host name within `data`, or None.

    `data` starts at the 5-byte TLS record header, so the offset is absolute
    and can be used directly as a split position.
    """
    if not is_client_hello(data):
        return None
    try:
        rec_len = int.from_bytes(data[3:5], "big")
        end = min(len(data), 5 + rec_len)

        p = 5
        p += 4                                              # handshake header
        p += 2 + 32                                         # version + random
        p += 1 + data[p]                                    # session id
        p += 2 + int.from_bytes(data[p:p + 2], "big")       # cipher suites
        p += 1 + data[p]                                    # compression
        p += 2                                              # extensions length

        while p + 4 <= end:
            etype = int.from_bytes(data[p:p + 2], "big")
            elen = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            if etype == EXT_SERVER_NAME:
                q = p + 2                                   # name list length
                if data[q] != 0:                            # host_name type
                    return None
                nlen = int.from_bytes(data[q + 1:q + 3], "big")
                if nlen <= 0 or q + 3 + nlen > end:
                    return None
                return q + 3, nlen
            p += elen
    except (IndexError, ValueError):
        return None
    return None


def sni_host(data: bytes):
    found = find_sni(data)
    if not found:
        return None
    off, ln = found
    try:
        return data[off:off + ln].decode("ascii")
    except UnicodeDecodeError:
        return None


def find_client_hello(data: bytes, host: str):
    """Offset of a ClientHello record for `host` within `data`, or None.

    Walks `data` record by record, so it finds a ClientHello that follows
    another record (a second ClientHello is commonly preceded by a dummy
    change_cipher_spec). The hostname must match: once a session is encrypted
    its records are arbitrary bytes, and requiring a well-formed ClientHello
    naming the very host this connection is for rules out a chance match.
    """
    want = (host or "").lower().rstrip(".")
    off = 0
    while off + 6 <= len(data):
        if data[off] not in (0x14, 0x15, REC_HANDSHAKE, 0x17):
            return None
        if data[off] == REC_HANDSHAKE and data[off + 5] == HS_CLIENT_HELLO:
            name = sni_host(data[off:])
            if name and name.lower().rstrip(".") == want:
                return off
            return None
        off += 5 + int.from_bytes(data[off + 3:off + 5], "big")
    return None


def record_missing(data: bytes) -> int:
    """How many bytes of the first TLS record have not arrived yet (0 if whole)."""
    if len(data) < 5:
        return 0
    return max(0, 5 + int.from_bytes(data[3:5], "big") - len(data))


def fragment_records(data: bytes, cuts):
    """Re-encode the first TLS record as several records, cut at `cuts`.

    `cuts` are offsets into the record body. A handshake message is allowed to
    span several records, so servers accept this happily, while a DPI box has
    to reassemble handshake messages across records to recover the hostname.
    The record header is not covered by the handshake transcript, which is why
    re-framing is invisible to both ends of the TLS session.

    Returns a list of byte chunks, one per record; anything that followed the
    first record rides along on the last chunk. The last record is declared at
    its true length even if the tail of it has not been read from the client
    yet, so those bytes complete it when they are relayed afterwards.
    """
    if len(data) < 6 or data[0] != REC_HANDSHAKE:
        return [data]
    rec_len = int.from_bytes(data[3:5], "big")
    body = data[5:5 + rec_len]
    rest = data[5 + rec_len:]
    cuts = sorted({c for c in cuts if 0 < c < len(body)})
    if not cuts:
        return [data]
    hdr = data[0:3]
    out = []
    prev = 0
    for cut in cuts:
        out.append(hdr + (cut - prev).to_bytes(2, "big") + body[prev:cut])
        prev = cut
    out.append(hdr + (rec_len - prev).to_bytes(2, "big") + body[prev:] + rest)
    return out


def fragment_record(data: bytes, pos: int) -> bytes:
    """Re-encode the first TLS record as two records split at `pos`."""
    return b"".join(fragment_records(data, [pos]))


def with_record_version(data: bytes, version: bytes) -> bytes:
    """Rewrite the record-layer version of the first TLS record.

    This is the `legacy_record_version` field. RFC 8446 says it "MUST be
    ignored for all purposes" and it is not part of the handshake transcript,
    so a server negotiates exactly as before - the real version lives inside
    the ClientHello. A DPI box that recognises TLS by the literal bytes
    16 03 01..03 no longer sees a TLS record at all.
    """
    if len(data) < 5 or data[0] != REC_HANDSHAKE or len(version) != 2:
        return data
    return data[0:1] + version + data[3:]

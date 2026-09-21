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


def fragment_record(data: bytes, pos: int) -> bytes:
    """Re-encode the first TLS record as two records split at `pos`.

    A handshake message is allowed to span several records, so servers accept
    this happily while a DPI box that only parses the first record never sees a
    complete ClientHello.
    """
    if len(data) < 5 or data[0] != REC_HANDSHAKE:
        return data
    rec_len = int.from_bytes(data[3:5], "big")
    body = data[5:5 + rec_len]
    rest = data[5 + rec_len:]
    if not 0 < pos < len(body):
        return data
    hdr = data[0:3]
    first = hdr + len(body[:pos]).to_bytes(2, "big") + body[:pos]
    second = hdr + len(body[pos:]).to_bytes(2, "big") + body[pos:]
    return first + second + rest

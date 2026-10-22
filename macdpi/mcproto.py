"""Just enough of the Minecraft Java protocol to route a multiplayer connection.

Minecraft multiplayer is not HTTP and not TLS, so the SNI/Host machinery the
rest of the proxy relies on does not apply. But its very first packet - the
Handshake - carries, in the clear, the server address the player typed. That
is the one field a DPI box can filter on, and it is also what we need to route
the connection in transparent mode, where the original destination IP is not
recoverable.

Only the Handshake is parsed; everything after it is relayed untouched. See
https://minecraft.wiki/w/Java_Edition_protocol for the packet format.
"""


def _read_varint(data: bytes, pos: int):
    """Return (value, new_pos) for a Minecraft VarInt, or (None, pos) if short.

    A VarInt is little-endian base-128: each byte carries 7 bits, high bit set
    while more follow. Capped at 5 bytes, as the protocol requires.
    """
    value = 0
    for i in range(5):
        if pos + i >= len(data):
            return None, pos                      # not all here yet
        byte = data[pos + i]
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value, pos + i + 1
    return None, pos                              # malformed: too long


class Handshake:
    __slots__ = ("host", "port", "next_state", "addr_start", "addr_len")

    def __init__(self, host, port, next_state, addr_start, addr_len):
        # The hostname the client wants, with any BungeeCord/Forge suffix
        # (everything from the first NUL) stripped off.
        self.host = host
        self.port = port
        self.next_state = next_state           # 1 = status ping, 2 = login
        # Byte range of the address string's payload within the packet, so the
        # caller can split the first TCP segment through the middle of it.
        self.addr_start = addr_start
        self.addr_len = addr_len


def packet_length(data: bytes):
    """Total length of the first packet (prefix + body), or None if not yet known."""
    body_len, pos = _read_varint(data, 0)
    if body_len is None:
        return None
    return pos + body_len


def parse_handshake(data: bytes):
    """Parse a Minecraft Handshake packet. Returns a Handshake, or None.

    None means "this is not a Handshake we can route" - a legacy (pre-1.7)
    0xFE ping, a packet that has not fully arrived, or anything malformed. The
    caller drops those rather than guessing a destination.
    """
    # Legacy server-list ping: a single 0xFE byte, no VarInt framing.
    if data[:1] == b"\xfe":
        return None

    body_len, pos = _read_varint(data, 0)
    if body_len is None:
        return None
    end = pos + body_len
    if end > len(data):
        return None                                # handshake not all here yet

    packet_id, pos = _read_varint(data, pos)
    if packet_id != 0x00:                          # Handshake is always id 0
        return None
    _proto, pos = _read_varint(data, pos)
    if _proto is None:
        return None
    addr_len, pos = _read_varint(data, pos)
    if addr_len is None or addr_len <= 0 or pos + addr_len + 2 > end:
        return None
    addr_start = pos
    try:
        raw_addr = data[pos:pos + addr_len].decode("utf-8")
    except UnicodeDecodeError:
        return None
    pos += addr_len
    port = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    next_state, pos = _read_varint(data, pos)
    if next_state is None:
        return None

    # BungeeCord/Velocity and Forge append NUL-separated data to the address
    # ("host\0ip\0uuid..." or "host\0FML\0"); the real hostname is the first part.
    host = raw_addr.split("\x00", 1)[0].rstrip(".")
    if not host:
        return None
    return Handshake(host, port, next_state, addr_start, addr_len)


def split_position(hs: Handshake) -> int:
    """A byte offset inside the handshake that falls within the hostname.

    Splitting the first TCP segment here keeps the server address from
    appearing whole in any single packet, the same idea as the TLS SNI split,
    while the bytes the server receives are unchanged.
    """
    # The real hostname, not any BungeeCord/Forge suffix, so the cut lands in
    # the name a filter would match on.
    name_len = len(hs.host.encode("utf-8"))
    return hs.addr_start + max(1, min(name_len, hs.addr_len) // 2)

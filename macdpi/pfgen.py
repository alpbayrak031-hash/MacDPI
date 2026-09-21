"""Generate the pf ruleset for transparent ("all apps") interception.

The tricky part of transparent proxying on macOS is catching traffic the Mac
originates itself: a plain `rdr` only fires on packets arriving on an
interface, and locally-generated packets never arrive - they leave. The fix is
`route-to (lo0 127.0.0.1)`, which forces those packets onto the loopback, where
an `rdr on lo0` rule then redirects them to the engine's transparent listeners.

The engine's own upstream connections must be exempt or they would be
redirected straight back into the engine; they are identified by a reserved
source-port band (see netio.py) rather than by process, which pf cannot match.
"""

import ipaddress
import socket

from .netio import SRC_PORT_LOW, SRC_PORT_HIGH

# Destinations never redirected: this machine, the LAN, link-local, multicast,
# and carrier-grade NAT. Sending these through the evasion path would be
# pointless at best and would break local services at worst.
ALWAYS_BYPASS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]



def _classify(entry: str):
    """Return a list of IP/CIDR strings for a bypass entry, or [] if unusable.

    Accepts a literal IP, a CIDR block, or a hostname (resolved to its current
    addresses). Anything that does not parse or resolve is dropped rather than
    risking a malformed ruleset that pf would refuse wholesale.
    """
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return []
    try:
        return [str(ipaddress.ip_network(entry, strict=False))]
    except ValueError:
        pass
    ips = []
    try:
        for info in socket.getaddrinfo(entry, None, proto=socket.IPPROTO_TCP):
            ip = info[4][0]
            if info[0] == socket.AF_INET:                      # v4 only for now
                ips.append(ip)
    except OSError:
        return []
    return sorted(set(ips))


def resolve_bypass(entries):
    """Expand user bypass entries (IPs, CIDRs, hostnames) to IP/CIDR literals."""
    out = []
    for entry in entries:
        out.extend(_classify(entry))
    return out


def build_ruleset(entries, tls_port=8443, http_port=8480) -> str:
    """Produce the full pf.conf text for transparent interception."""
    bypass = ALWAYS_BYPASS + resolve_bypass(entries)
    # A pf table literal: one indented, backslash-continued list.
    table = ", \\\n    ".join(bypass)

    # pf demands rules grouped by class in a fixed order: normalization, then
    # translation (nat/rdr), then filtering. Apple's own anchors span all three
    # classes, so our rules have to be woven in beside the matching class rather
    # than appended after everything - otherwise pfctl rejects the file.
    return f"""\
# MacDPI transparent redirect - generated file, do not edit by hand.
# Remove it and reload pf to undo, or use the MacDPI menu.

# Destinations MacDPI must never touch.
table <macdpi_bypass> persist {{ \\
    {table} }}

# --- normalization ----------------------------------------------------------
scrub-anchor "com.apple/*"

# --- translation (nat/rdr) --------------------------------------------------
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
# Redirect everything on 80/443 to the transparent listeners. The route-to
# filter rules below push locally-originated packets onto lo0 first, where
# these rdr rules then catch them - that is what makes the Mac's own traffic
# covered, not just traffic forwarded from other devices.
rdr pass on lo0 inet proto tcp from any to !<macdpi_bypass> port 443 -> 127.0.0.1 port {tls_port}
rdr pass on lo0 inet proto tcp from any to !<macdpi_bypass> port 80  -> 127.0.0.1 port {http_port}

# --- filtering --------------------------------------------------------------
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
# The engine's own upstream sockets bind into this source-port band (below the
# macOS ephemeral range, so nothing else uses it). Pass them straight out so
# they are never redirected back into the engine.
pass out quick inet proto tcp from any port {SRC_PORT_LOW}:{SRC_PORT_HIGH} to any flags S/SA keep state
# Everything else on 80/443 is forced onto lo0, where the rdr rules above act.
pass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to !<macdpi_bypass> port 443 flags S/SA keep state
pass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to !<macdpi_bypass> port 80  flags S/SA keep state

load anchor "com.apple" from "/etc/pf.anchors/com.apple"
"""

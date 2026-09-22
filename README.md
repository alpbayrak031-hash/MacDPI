<div align="center">

# 🛡️ MacDPI

**A GoodbyeDPI-style DPI-circumvention tool for macOS.**

Unblock censored sites in *every* browser tab — and, optionally, in every app —
with no kernel extension, no root daemon for the network path, and **nothing to
install**: the app is fully self-contained, so a brand-new Mac just runs it.

![platform](https://img.shields.io/badge/platform-macOS%2012%2B-black)
![arch](https://img.shields.io/badge/arch-universal%20(Apple%20Silicon%20%2B%20Intel)-blue)
![python](https://img.shields.io/badge/engine-Python%203%20(stdlib%20only)-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## What it does

Many networks censor by inspecting the **hostname** you send in the clear at the
start of every HTTPS connection (the TLS *SNI*), or by tampering with **DNS**.
MacDPI defeats both, locally, on your Mac:

- **TLS/HTTP evasion** — it fragments the TLS ClientHello (and plays the classic
  `Host:` header tricks on plaintext HTTP) so a DPI box can't read the hostname,
  while the bytes the server receives stay identical. TLS remains fully
  end-to-end; there is **no man-in-the-middle**.
- **DNS over HTTPS** — it resolves names itself over DoH, so forged or blocked
  DNS answers don't apply. Your browser needs no DNS changes.

It runs as a small local proxy that macOS points every browser at, plus a native
menu-bar app to drive it.

> [!NOTE]
> MacDPI beats **DNS- and SNI-based** censorship. It **cannot** defeat
> IP-level blocking (where the route to the server is dropped) — that needs a
> VPN or Tor. The built-in network test tells you which one you're facing.

---

## Quick start

```bash
./build.sh          # builds a universal MacDPI.app with the engine inside it
open build          # drag MacDPI.app to /Applications
```

Launch **MacDPI**. It walks you through a one-time setup (asks for your password
once, to set the system proxy) and then lives in the menu bar as a shield.

That's the whole install — there's nothing to install alongside it.

---

## Features

- 🌐 **Covers every browser at once** — Safari, Chrome, Edge, Brave, Arc,
  Firefox — via the macOS system proxy, not a per-tab extension.
- 🧠 **`auto` mode verifies and adapts** — it probes every strategy at once and
  picks the one whose TLS certificate actually validates against the real CAs,
  so it can tell the true server from an intercepting firewall's forged cert and
  never caches a strategy that only reaches the middlebox. It re-checks when a
  network changes.
- 🧠 **learns per host** — once verified, the winning strategy is cached so
  later visits are instant; a host that's genuinely blocked on every strategy
  (packet drop or handshake reset) is detected fast and flagged as needing a VPN.
- 🕵️ **Resilient DNS-over-HTTPS** — Cloudflare, Google, Quad9, AdGuard; it falls
  through providers *and* evasion strategies until one resolves, verifying the
  resolver's own certificate, so a blocked resolver doesn't take DNS down.
- 📊 **Menu-bar dashboard** — live connection counts, data moved, per-strategy
  usage, recent sites, and the current DoH resolver.
- 🧪 **"Test This Network"** — probes each strategy against real sites and tells
  you which one this network needs (or that you're facing IP blocking).
- 🖥️ **Optional "Cover All Apps"** — a transparent `pf` redirect that routes
  *every* app's web traffic, not just proxy-aware ones. Fail-safe (see below).
- 🚫 **Exclusion list** — keep specific sites/IPs off the path (banks, work VPNs).
- ♻️ **Starts at login**, survives sleep/network changes, self-heals if moved.
- 🔒 **No root for the network path** — the proxy runs as your user; only
  changing the system proxy / firewall asks for a password.

---

## The evasion strategies

| Strategy | What it does |
|---|---|
| `tlsfrag` | Splits the ClientHello across two TLS records, cut through the middle of the hostname. Legal per the spec, so servers accept it; a filter must reassemble handshake messages across records to recover the name. |
| `oob` | Splits the hostname and sends one *urgent* (out-of-band) byte into the gap. The server's TCP stack removes it; most filters read it inline and see a corrupted hostname. The only technique here that also beats a middlebox which fully reassembles TCP. |
| `tlsfrag+oob` | Both at once. |
| `multisplit` | Chops the first packet into several small TCP segments around the hostname. |
| `split` | A single TCP split through the middle of the hostname. |
| `direct` | No evasion — the fallback for sites that aren't filtered. |

In **`auto`** mode (the default) these are probed **concurrently**, and the one
whose certificate validates against the real CAs wins — that's how it tells the
true server from an intercepting firewall, which answers with a valid-looking
handshake and a forged certificate. The winner is cached per host in
`~/.macdpi/learned.json`, and re-checked when it stops working.

> 📖 See **[docs/GUIDE.md](docs/GUIDE.md)** for the full reference — every menu
> item, all CLI flags, how the transparent mode works, and the honest limits.

---

## Covering every app, not just browsers

The system proxy already reaches more than browsers — any app using macOS's
normal networking honours it. What escapes it is apps that ignore the proxy, use
raw sockets, or use QUIC.

**Cover All Apps** closes that gap using the `pf` firewall to transparently
redirect all TCP traffic on ports 80/443 into MacDPI, whichever app opened it.
It routes purely by the **SNI / Host header** (resolved over DoH), so there's
still no man-in-the-middle and no need for the kernel headers Apple doesn't ship.

> [!IMPORTANT]
> Turning it on runs a **capture self-test and rolls the whole thing back if it
> fails** — a transparent redirect pointed at an engine that isn't capturing
> would black-hole all traffic, so MacDPI verifies it works before committing
> and reverts cleanly if it can't (e.g. another firewall/VPN already owns `pf`).

**Limits, honestly:**
- `pf` matches addresses, not apps, so you exclude **sites** (host/IP/CIDR), not
  individual apps. Private, local, link-local and multicast ranges are always
  excluded.
- Connections on 80/443 with **no SNI and no Host header** can't be routed by
  name and are dropped rather than guessed at (rare for real web traffic).
- **UDP is not covered** — QUIC/HTTP-3 falls back to TCP; game traffic and voice
  (Roblox, Discord voice, etc.) run over UDP and need a VPN, not this.

---

## Command line

Prefer a terminal? `dpictl` does everything the app does:

```bash
./dpictl start          # run the proxy in the background
./dpictl on             # route all of macOS through it   (asks for password)
./dpictl off            # restore normal networking        (asks for password)
./dpictl status         # what's running and what's routed
./dpictl test [hosts]   # probe which strategy this network needs
./dpictl install        # start automatically at login
./dpictl log            # follow the log
```

Run the engine directly for one-off use or debugging:

```bash
python3 -m macdpi -v                 # foreground, verbose
python3 -m macdpi --test             # probe strategies against a few sites
python3 -m macdpi --doh quad9        # switch resolver
python3 -m macdpi -m oob             # force one strategy instead of auto
```

---

## How it's built

```
MenuBar/            native Swift menu-bar app (universal binary)
  App.swift           UI, first-run setup, all-apps toggle, self-test
  Control.swift       client for the engine's Unix control socket
  System.swift        system-proxy, launchd, and pf handling
  Installer.swift     writes/repairs the launchd jobs
macdpi/             the engine (Python 3, standard library only)
  tls.py              ClientHello parsing + TLS record fragmentation
  desync.py           the evasion strategies
  netio.py            non-blocking sockets with MSG_OOB + source-port control
  tlsclient.py        MemoryBIO TLS client (so DoH gets evasion too)
  dns.py              DNS-over-HTTPS resolver with cache + fallback
  proxy.py            HTTP CONNECT + plaintext HTTP + SOCKS5 + transparent mode
  pfgen.py            generates the pf ruleset for "cover all apps"
  control.py          Unix-socket control channel for the menu bar
build.sh            builds the signed, universal MacDPI.app
dpictl              start/stop, system proxy, autostart (CLI)
```

The menu bar talks to the engine over a Unix socket at `~/.macdpi/control.sock`
(mode `0600`) rather than a TCP port — a web page can reach `127.0.0.1` through
the proxy it's already using, but it can't open a Unix socket.

---

## Requirements

- **macOS 12 or later**, Apple Silicon or Intel.
- **Nothing to install.** The app carries its own Python runtime inside the
  bundle (one per architecture), so a brand-new Mac needs no Python, no
  Command Line Tools, no `pip` — you download the app and run it.
- Building the app from source needs the **Command Line Tools**
  (`xcode-select --install`); `build.sh` downloads the bundled runtimes for you.

---

## Installing on another Mac

`./build.sh` also produces `build/MacDPI-<version>.zip`. The app is universal and
carries the engine inside it, so there's nothing else to ship.

> [!WARNING]
> The app is **ad-hoc signed but not notarised** (that needs a paid Apple
> Developer ID). On a Mac that *downloaded* it, the first launch must be
> **right-click → Open → Open**. After that it opens normally. Or:
> ```bash
> xattr -dr com.apple.quarantine /Applications/MacDPI.app
> ```

`build.sh` automatically uses a Developer ID if the build machine has one.

---

## Uninstall

From the menu bar: **Remove MacDPI…**, then drag the app to the Trash. Or:

```bash
./dpictl off
./dpictl uninstall
rm -rf ~/.macdpi
```

Either way your network settings are returned to normal.

---

## What it can't do

- **IP-level blocking** — if the route to a server is dropped, no first-packet
  trick helps. Use a VPN or Tor.
- **UDP** — QUIC, game traffic, and voice are out of scope; QUIC falls back to
  TCP, the rest needs a VPN.
- **A trusted interception device you're required to use** — if your Mac has a
  corporate root certificate installed, the network can decrypt regardless.
- **Apps that ignore both the system proxy and are excluded** — nothing to do.

---

## Acknowledgements

Inspired by [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI),
[zapret](https://github.com/bol-van/zapret),
[ByeDPI](https://github.com/hufrea/byedpi) and
[SpoofDPI](https://github.com/xvzc/SpoofDPI) — the same category of tool, built
natively for macOS.

## Legal

MacDPI is a censorship-circumvention tool. Using it on a network you don't
control (an employer's, a school's) may breach that network's acceptable-use
policy even where it's entirely legal. That's your call to make.

## License

MIT — see [LICENSE](LICENSE).

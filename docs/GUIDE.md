# macdpi

A GoodbyeDPI-style censorship-circumvention tool for macOS. It applies the same
DPI-evasion tricks GoodbyeDPI uses on Windows, and covers **every tab in every
browser at once** — Safari, Chrome, Edge, Brave, Arc, Firefox — not one tab and
not one extension.

Pure Python 3, no dependencies, no compiler, no kernel extension, no root for
the proxy itself.

## Quick start

Build the app and drag it to Applications:

```bash
./build.sh
open build
```

Launch **MacDPI**. It walks you through setup, asks for your password once to
change the system proxy, and then lives in the menu bar as a shield.

That's the whole install. Everything below is for people who prefer a terminal.

## The menu bar

The shield tells you where you stand at a glance — filled when every browser is
protected, hollow when the engine is running but macOS is not routed through it,
and an exclamation mark when the engine is down.

Opening it shows live state and the controls:

- **live counters** — active tunnels, total connections, data moved, how many
  sites have a learned strategy, uptime, and which DoH resolver is in use
- **Turn Protection On / Off** — flips the system proxy for every network
  service, asking for your password
- **Cover All Apps, Not Just Browsers** — turns on transparent interception so
  every app is covered, not only proxy-aware ones (see the next section)
- **Excluded Sites** — hosts, IPs or CIDR blocks that bypass MacDPI entirely,
  used when transparent coverage is on
- **Strategy** — pick `auto` or pin one technique, with a count beside each
  showing how many connections it has carried; changes apply immediately, with
  no restart
- **Recent Sites** — the last twenty hosts and which technique got each through
- **Test This Network** — runs the full probe grid and shows the results
- **Flush DNS Cache**, **Forget Learned Strategies**, **Open Log**,
  **Restart Engine**
- **Start at Login**, and **Remove MacDPI**, which puts your network settings
  back and unloads everything

If the engine ever stops while the system proxy is still pointed at it, the app
notices within about ten seconds and offers to restart it or turn protection
off. That state — routed through a proxy that is not answering — is the one way
this tool can leave you with no working browser at all, so it is worth catching
loudly rather than leaving you to wonder why nothing loads.

## Covering every app, not just browsers

The system proxy MacDPI sets covers a lot already — every app built on macOS's
normal networking honours it, not just browsers. What escapes it is apps that
deliberately ignore the proxy, use raw sockets, or use QUIC.

**Cover All Apps** closes that gap. It uses the `pf` firewall to transparently
redirect every TCP connection on ports 80 and 443 into MacDPI, whichever app
opened it. Turning it on:

1. gives the engine its transparent listeners (ports 8443 and 8480);
2. asks for your password once to load a `pf` rule that redirects local
   traffic to them — via `route-to (lo0 127.0.0.1)`, which is what makes the
   Mac's *own* traffic get caught, not just traffic forwarded from other
   devices;
3. installs a tiny root LaunchDaemon so the rule comes back at every boot;
4. **runs a capture self-test, and rolls the whole thing back if it fails.**

That last step matters. A transparent redirect pointed at an engine that isn't
capturing would black-hole all web traffic. So before committing, MacDPI sends
itself a probe through the redirect and checks it arrives; if it doesn't — for
instance because another firewall or VPN already owns `pf` — it undoes the
firewall change, reverts the engine, and tells you, leaving browsers working as
before.

**How it routes without decrypting.** MacDPI never needs the original
destination IP: it reads the hostname from the TLS SNI (or the HTTP Host
header) and resolves it itself over DoH. That is the same field a censor keys
on, and it means no `pf` NAT-lookup — which needs kernel headers Apple doesn't
ship — and no man-in-the-middle. TLS stays end-to-end; only the ClientHello is
fragmented, exactly as in proxy mode.

**Exclusions.** `pf` matches on addresses, not on which app opened a connection,
so individual apps can't be singled out — but you can exclude **sites**: add
hosts, IPs, or CIDR blocks under *Excluded Sites* and they bypass MacDPI
completely. Private, local, link-local and multicast ranges are always excluded.
Use this for anything that misbehaves when routed — a bank, a corporate VPN
endpoint — or to keep a specific service off the path.

**What still isn't covered.** Connections on 80/443 with no SNI and no Host
header can't be routed by name and are dropped rather than guessed at; these
are rare for real web traffic, and the exclude list handles any that matter.
QUIC/HTTP-3 (UDP) is not redirected; apps generally fall back to TCP. IPv6 is
left untouched for now.

**Turning it off** removes the `pf` rule, restores your normal `pf` ruleset
(pf is left enabled with Apple's defaults, so nothing else that relies on it
breaks), removes the boot daemon, and drops the engine back to browsers-only.
It's also undone by *Remove MacDPI*.

## Installing on another Mac

`./build.sh` produces `build/MacDPI-<version>.zip`. Send that anywhere.

The app is universal (Apple Silicon and Intel) and carries the engine inside it,
so there is nothing to install alongside it. It runs on Apple's own Python 3, so
a stock Mac needs no Python download; if a Mac somehow has none that works, the
app offers to install Apple's Command Line Tools.

**Gatekeeper will object the first time.** The app is ad-hoc signed but not
notarised — that needs a paid Apple Developer account, which this build does not
have. So on a Mac that downloaded it, the first launch has to be
**right-click (or Control-click) the app → Open → Open**. After that it opens
normally. Alternatively:

```bash
xattr -dr com.apple.quarantine /Applications/MacDPI.app
```

### Why it does not install into the system

Nothing here runs as root, and that is deliberate. The engine is an ordinary
user process with a LaunchAgent in `~/Library/LaunchAgents`; a network proxy
handling every page you load is the last thing that should hold root. The only
step that needs an administrator is changing the system proxy setting, which
`networksetup` requires — so the app asks for your password at that moment and
at no other time.

## Command line

If you would rather not use the app, `dpictl` does the same job:

## Why it isn't a port of GoodbyeDPI

GoodbyeDPI works by hooking the Windows packet driver (WinDivert) and rewriting
packets as they leave the machine. macOS has no equivalent you can install: the
old kernel extensions are gone, and the replacement (a NetworkExtension content
filter) needs an Apple Developer account and a notarized, signed system
extension before it will load at all.

So macdpi does the evasion one layer up, in a local proxy. Your browser talks to
`127.0.0.1`, and macdpi makes the real connection on your behalf, mangling the
first packet the same way. This turns out to have a real advantage: when the
filter injects a TCP reset to kill a connection, it kills *macdpi's* connection,
which the browser never sees — so macdpi can silently retry with a different
technique instead of showing you an error page.

## How it evades

Filters identify the site you are visiting from the **SNI** — the hostname sent
in the clear in the first packet of every HTTPS connection. Every strategy below
makes that hostname hard to read while leaving the bytes the server receives
completely unchanged.

| Strategy | What it does |
|---|---|
| `tlsfrag` | Splits the ClientHello across two TLS records, cut through the middle of the hostname. Legal per the TLS spec, so servers accept it, but a filter has to reassemble handshake messages across records to recover the name. |
| `oob` | Splits the hostname and sends one *urgent* (out-of-band) byte into the gap. The server's TCP stack pulls that byte back out; most filters ignore the urgent pointer and read it inline, so they see a corrupted hostname. The only technique here that beats a middlebox which fully reassembles TCP. |
| `tlsfrag+oob` | Both at once. |
| `multisplit` | Chops the first packet into several small TCP segments around the hostname. |
| `split` | A single TCP split through the middle of the hostname. |
| `direct` | No evasion — the fallback for sites that aren't filtered. |

Plaintext HTTP additionally gets GoodbyeDPI's classic header tricks (`hOSt:`
with padded whitespace), which servers treat identically and filter rules
usually don't match.

**DNS is handled too.** Blocking by forged DNS answers is at least as common as
SNI filtering, so macdpi resolves names itself over DNS-over-HTTPS, addressing
the resolver by IP so no plaintext lookup is ever needed. Your browser needs no
DNS changes.

### `auto` mode

By default macdpi doesn't make you pick. It tries each strategy in turn until
the server returns a genuine TLS ServerHello, then remembers the winner for that
hostname in `~/.macdpi/learned.json`, so later visits go straight there.

A reply that isn't a handshake record — a TLS alert, or the plaintext junk some
front-ends emit — counts as a failure and moves on. This matters: a few
front-ends (Azure's among them) deliver the urgent byte inline and mangle the
hello, and without that check the browser would inherit a broken connection.

## Finding out what your network does

```bash
./dpictl test
```

This completes a real TLS handshake to each host with every strategy and prints
a grid of what got through, then names the one that works best. Pass your own
hostnames to test specific sites:

```bash
./dpictl test example.com another.example
```

## Starting automatically

`./dpictl install` registers a launchd agent that starts macdpi at login and
keeps it running.

Connectivity is handled inside macdpi rather than by launchd. The obvious
mechanism — `KeepAlive` with `NetworkState` — is ignored by current versions of
launchd; it silently does nothing, so relying on it would leave the proxy dead
after the first restart. Instead:

- **At startup** macdpi waits for a genuinely working connection before it
  begins serving (up to 300s, `--wait-for-network`). It tests by opening a TCP
  connection to a known address rather than by resolving a name, because on a
  half-up or captive network DNS is precisely the thing that hangs.
- **While running** it watches the connection. When the link drops and comes
  back — a lid closed, a different Wi-Fi network — it flushes its DNS cache and
  re-arms DoH, so a laptop that wakes somewhere else doesn't keep using stale
  addresses.
- **If it ever dies** launchd restarts it.

Keeping the process alive while offline is deliberate. With the system proxy
enabled, a proxy that exits when Wi-Fi blips gives you "the proxy server refused
connections" in every tab; one that stays up gives you a page that fails and
then recovers on its own.

`./dpictl stop` stops it but leaves autostart in place, so it returns at next
login. Use `./dpictl uninstall` to remove autostart for good.

## Commands

```
./dpictl start [args]   run the proxy in the background
./dpictl stop           stop it
./dpictl restart
./dpictl on             route all of macOS through it   (asks for password)
./dpictl off            restore normal networking       (asks for password)
./dpictl status         what is running and what is routed
./dpictl test [hosts]   probe which strategy this network needs
./dpictl install        start automatically at login
./dpictl uninstall      undo that
./dpictl log            follow the log
```

Useful options to `start`:

```
-m, --mode STRATEGY   force one strategy instead of auto
    --delay 0.05      pause between split segments, if splitting alone fails
    --doh google      switch resolver (cloudflare, google, quad9, adguard, URL, or off)
    --port 8881       change the listen port
-v, --verbose         log every connection and the strategy it used
    --wait-for-network 300   wait N seconds for a connection before serving
    --no-watch-network       do not flush DNS when the connection returns
```

You can also run it in the foreground directly: `python3 -m macdpi -v`.

## What it cannot do

Worth being straight about:

- **IP-level blocking.** If the filter drops traffic to the address itself,
  nothing in the first packet will change that. You need a VPN or Tor. `dpictl
  test` will tell you when this is what you're facing.
- **A filter that terminates TLS and that you trust.** If your Mac has a
  corporate root certificate installed, the network can decrypt everything
  regardless. macdpi will still often slip past the interception (you'll see
  real certificates again instead of the firewall's), but on a managed device
  that is a policy question, not just a technical one.
- **Apps that ignore the system proxy.** Browsers all honour it. Some other
  apps don't; those keep working normally, just unproxied.
- **QUIC / HTTP-3.** Chrome sends HTTP/3 over UDP, which no HTTP proxy can
  carry. Chrome disables QUIC on its own when a system proxy is configured, so
  in practice it falls back to TCP and gets protected. Nothing to do.
- **Packet-level fakes.** GoodbyeDPI's "fake packet with a low TTL" trick can't
  be done honestly from userspace: the fake bytes occupy TCP sequence space, so
  the kernel retransmits them with a normal TTL and the real server ends up
  parsing the decoy. Doing it properly needs raw packet injection with sequence
  rewriting, i.e. the kernel extension macOS won't give us. It is deliberately
  not implemented rather than implemented broken.

## Files

```
MenuBar/App.swift     the menu bar UI and first-run setup
MenuBar/Control.swift client for the engine's control socket
MenuBar/System.swift  system proxy and launchd handling
MenuBar/Paths.swift   locating a Python that actually runs
MenuBar/Installer.swift  writing and repairing the launchd jobs
build.sh              builds the universal, self-contained MacDPI.app

macdpi/tls.py         ClientHello parsing, TLS record fragmentation
macdpi/desync.py      the evasion strategies
macdpi/netio.py       non-blocking sockets with MSG_OOB and TTL access
macdpi/tlsclient.py   MemoryBIO TLS client, so DoH gets evasion too
macdpi/dns.py         DNS-over-HTTPS resolver with cache and fallback
macdpi/proxy.py       HTTP CONNECT + plaintext HTTP + SOCKS5, retry ladder
macdpi/netcheck.py    reachability checks for startup and network changes
macdpi/control.py     Unix-socket control channel for the menu bar
macdpi/transparent... transparent routing lives in proxy.handle_transparent
macdpi/pfgen.py       generates the pf ruleset for 'cover all apps'
macdpi/probe.py       the --test grid
macdpi/config.py      options and logging
dpictl                start/stop, system proxy, autostart
```

State lives in `~/.macdpi/` (log, pid, learned strategies, control socket).

The menu bar talks to the engine over a Unix socket at
`~/.macdpi/control.sock`, mode `0600`, rather than a localhost port. A web page
can reach `127.0.0.1` through the very proxy it is already talking to, so a
control port would be reachable from any tab; a Unix socket is not.

## Uninstall

From the menu bar: **Remove MacDPI…**, then drag the app to the Trash.

From the terminal:

```bash
./dpictl off
./dpictl uninstall
./dpictl stop
rm -rf ~/.macdpi
```

## Legal note

This is a censorship-circumvention tool, the same category as GoodbyeDPI,
zapret, ByeDPI and SpoofDPI. Using it on a network you don't control — an
employer's, a school's — may breach that network's acceptable-use policy even
where it is entirely legal. That's your call to make.

# MacDPI Minecraft route agent

A tiny Java agent that makes a Minecraft (Java) client send its server
connections to a local port MacDPI controls, so MacDPI can apply its DPI
evasion to Minecraft traffic. It needs **no Minecraft mappings and no mod
loader** — it hooks Netty (`io.netty.bootstrap.Bootstrap.doResolveAndConnect`),
which keeps its real class names, so it works on any version (26.3 included).

It rewrites each outgoing connection's destination to `127.0.0.1:8425`,
MacDPI's always-on Minecraft route listener. MacDPI reads the server address
from Minecraft's own handshake, resolves it over DoH (SRV included), applies
evasion, and relays — the bytes the server receives are unchanged.

## Build
    ./build.sh        # needs a JDK 17+; downloads ByteBuddy; shades it in
Produces `build/macdpi-mcroute.jar`.

## Use
Copy the jar somewhere stable (MacDPI installs it at `~/.macdpi/macdpi-mcroute.jar`)
and add to the Minecraft launcher's JVM arguments:

    -javaagent:/Users/<you>/.macdpi/macdpi-mcroute.jar

Options: `=port=8425` to change the port, `=force` to skip the "is MacDPI up?"
check. If MacDPI isn't running, the agent disables itself and Minecraft
connects directly.

## Scope / honest limits
This routes Minecraft through MacDPI; it does not add new evasion power.
MacDPI still only disguises the first packet (the handshake) and relays the
rest unchanged, so this helps only where the network blocks on the handshake,
not where it throttles the ongoing game stream. UDP (Bedrock) is not covered.

## Port note
Run the route listener on **8426**, not 8425. 8425 is pf's `rdr` *target* for
port 25565 under "cover all apps", and macOS pf mangles direct connects to a
redirect-target port - so a listener on 8425 becomes unreachable whenever cover
all apps is on. 8426 is not a redirect target and stays reachable. The agent
defaults to 8426; run the engine's route process with `--tproxy-raw-port 8426`.

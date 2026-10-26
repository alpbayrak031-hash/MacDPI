package com.macdpi.mcroute;

import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;
import java.net.Socket;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * A java agent that makes a Minecraft client send its server connections to a
 * local port MacDPI controls, so MacDPI can apply its DPI evasion to them.
 *
 * It works one layer below Minecraft, on Netty - the networking library the
 * client is built on. Netty's classes keep their real names (they are not
 * obfuscated), so this needs none of the Minecraft mappings a Fabric mod would,
 * and so it works on any version, 26.3 included.
 *
 * The hook is a single method, {@code io.netty.bootstrap.Bootstrap
 * .doResolveAndConnect(SocketAddress, SocketAddress)} - every connect() the
 * client makes funnels through it. The agent rewrites the destination to
 * 127.0.0.1:&lt;port&gt; (MacDPI's transparent Minecraft listener, 8425 by
 * default). MacDPI then reads the server address out of Minecraft's own
 * handshake, resolves it over DoH, and relays with evasion. The bytes the
 * server receives are unchanged.
 *
 * Add it to the launcher's JVM arguments:
 *   -javaagent:/path/to/macdpi-mcroute.jar
 * optionally with =port=8425 (or =force to skip the "is MacDPI up?" check).
 */
public final class Agent {

    private Agent() {}

    public static void premain(String agentArgs, Instrumentation inst) {
        install(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        install(agentArgs, inst);
    }

    private static void install(String agentArgs, Instrumentation inst) {
        int port = 8425;
        boolean force = false;
        if (agentArgs != null) {
            for (String raw : agentArgs.split(",")) {
                String part = raw.trim();
                if (part.isEmpty()) continue;
                if (part.equals("force")) {
                    force = true;
                } else if (part.startsWith("port=")) {
                    port = parsePort(part.substring(5), port);
                } else {
                    port = parsePort(part, port);
                }
            }
        }

        // If MacDPI's listener is not up, do nothing: leave Minecraft to
        // connect directly rather than black-hole every server behind a dead
        // local port. (Pass "force" to skip this, e.g. when MacDPI starts late.)
        if (!force && !reachable(port)) {
            System.err.println("[MacDPI] route agent: nothing listening on 127.0.0.1:" + port
                    + " - leaving Minecraft to connect directly (routing off).");
            return;
        }

        System.setProperty("macdpi.mcroute.port", Integer.toString(port));
        try {
            new AgentBuilder.Default()
                    .type(named("io.netty.bootstrap.Bootstrap"))
                    .transform((builder, type, loader, module, pd) ->
                            builder.visit(Advice.to(ConnectAdvice.class)
                                    .on(named("doResolveAndConnect"))))
                    .installOn(inst);
            System.err.println("[MacDPI] route agent armed: Minecraft connections -> 127.0.0.1:" + port);
        } catch (Throwable t) {
            System.err.println("[MacDPI] route agent failed to install: " + t);
        }
    }

    private static int parsePort(String s, int fallback) {
        try {
            int p = Integer.parseInt(s.trim());
            return (p > 0 && p < 65536) ? p : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static boolean reachable(int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 1500);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

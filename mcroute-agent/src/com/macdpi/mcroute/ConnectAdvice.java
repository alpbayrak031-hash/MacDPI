package com.macdpi.mcroute;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

import net.bytebuddy.asm.Advice;

/**
 * Inlined into {@code Bootstrap.doResolveAndConnect} at load time. After
 * inlining it references only {@code java.net} and {@code System} - no Netty,
 * no ByteBuddy - so it resolves cleanly from whatever class loader loaded
 * Netty (Fabric's Knot, here), which is the whole reason this approach avoids
 * the class-loader trouble a bundled SOCKS handler would hit.
 */
public final class ConnectAdvice {

    private ConnectAdvice() {}

    @Advice.OnMethodEnter
    static void enter(@Advice.Argument(value = 0, readOnly = false) SocketAddress remote) {
        String p = System.getProperty("macdpi.mcroute.port");
        if (p == null) {
            return;                                  // agent not armed
        }
        if (!(remote instanceof InetSocketAddress)) {
            return;
        }
        InetSocketAddress isa = (InetSocketAddress) remote;

        // Never touch loopback connections - that includes MacDPI's own
        // listener, so a redirected connection is not redirected again.
        if (!isa.isUnresolved() && isa.getAddress() != null
                && isa.getAddress().isLoopbackAddress()) {
            return;
        }
        String host = isa.getHostString();
        if (host != null && (host.equals("localhost") || host.equals("::1")
                || host.startsWith("127."))) {
            return;
        }

        int port;
        try {
            port = Integer.parseInt(p);
        } catch (NumberFormatException e) {
            return;
        }
        remote = new InetSocketAddress("127.0.0.1", port);
    }
}

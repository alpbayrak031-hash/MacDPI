import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

public class RouteTest {
    public static void main(String[] a) throws Exception {
        int testPort = 19425;
        AtomicReference<String> gotOn = new AtomicReference<>("(none)");
        CountDownLatch accepted = new CountDownLatch(1);
        // dummy local "MacDPI listener" on testPort
        Thread srv = new Thread(() -> {
            try (java.net.ServerSocket ss = new java.net.ServerSocket(testPort, 50, java.net.InetAddress.getByName("127.0.0.1"))) {
                java.net.Socket s = ss.accept();
                gotOn.set("127.0.0.1:" + testPort + " (from " + s.getLocalPort() + ")");
                accepted.countDown();
                s.close();
            } catch (Exception e) { e.printStackTrace(); }
        });
        srv.setDaemon(true); srv.start();
        Thread.sleep(300);

        EventLoopGroup g = new NioEventLoopGroup(1);
        try {
            Bootstrap b = new Bootstrap();
            b.group(g).channel(NioSocketChannel.class)
             .handler(new ChannelInitializer<Channel>() { protected void initChannel(Channel c) {} });
            // Connect to a FAKE external Minecraft server. With the agent, this
            // must be redirected to 127.0.0.1:testPort.
            ChannelFuture f = b.connect("mc.fake-server.example", 25565).sync();
            SocketAddress remote = f.channel().remoteAddress();
            boolean hit = accepted.await(3, TimeUnit.SECONDS);
            System.out.println("channel.remoteAddress = " + remote);
            System.out.println("dummy listener hit     = " + hit + "  " + gotOn.get());
            boolean redirected = hit && remote instanceof InetSocketAddress
                    && ((InetSocketAddress) remote).getPort() == testPort
                    && ((InetSocketAddress) remote).getAddress().isLoopbackAddress();
            System.out.println("RESULT: " + (redirected ? "PASS - connection redirected to MacDPI port" : "FAIL - not redirected"));
            f.channel().close().sync();
            System.exit(redirected ? 0 : 1);
        } finally { g.shutdownGracefully(); }
    }
}

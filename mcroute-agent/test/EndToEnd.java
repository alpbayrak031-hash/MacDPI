import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.*;

// Mimics what the real client does: a Netty connect (which the agent redirects
// to MacDPI's 8425), then a Minecraft status handshake over that channel.
// If MacDPI reads the handshake, SRV-resolves the host and relays, we get the
// server's status JSON back - proving the whole chain on this network.
public class EndToEnd {
    static final String HOST = "uaamc.my.pebble.host";
    static byte[] vint(int v){ ByteArrayOutputStream o=new ByteArrayOutputStream(); while(true){int b=v&0x7F; v>>>=7; o.write(b|(v!=0?0x80:0)); if(v==0)break;} return o.toByteArray(); }
    public static void main(String[] a) throws Exception {
        ByteArrayOutputStream hs=new ByteArrayOutputStream();
        byte[] host=HOST.getBytes("UTF-8");
        hs.write(0x00); hs.write(vint(767)); hs.write(vint(host.length)); hs.write(host);
        hs.write((25565>>8)&0xFF); hs.write(25565&0xFF); hs.write(vint(1));
        ByteArrayOutputStream pkt=new ByteArrayOutputStream();
        pkt.write(vint(hs.size())); hs.writeTo(pkt);
        pkt.write(vint(1)); pkt.write(0x00);              // status request
        byte[] payload=pkt.toByteArray();

        CompletableFuture<String> resp=new CompletableFuture<>();
        ByteArrayOutputStream rx=new ByteArrayOutputStream();
        EventLoopGroup g=new NioEventLoopGroup(1);
        try {
            Bootstrap b=new Bootstrap();
            b.group(g).channel(NioSocketChannel.class).handler(new ChannelInitializer<Channel>(){
                protected void initChannel(Channel c){
                    c.pipeline().addLast(new ChannelInboundHandlerAdapter(){
                        public void channelRead(ChannelHandlerContext ctx,Object m){
                            ByteBuf buf=(ByteBuf)m; byte[] d=new byte[buf.readableBytes()]; buf.readBytes(d); buf.release();
                            rx.write(d,0,d.length);
                            String s=new String(rx.toByteArray());
                            if(s.contains("version")&&!resp.isDone()) resp.complete(s);
                        }
                    });
                }
            });
            // connect to the fake standard port; agent redirects to 8425; MacDPI SRV-resolves HOST
            Channel ch=b.connect(HOST,25565).sync().channel();
            System.out.println("redirected to: "+ch.remoteAddress());
            ch.writeAndFlush(Unpooled.wrappedBuffer(payload));
            String json=resp.get(12,TimeUnit.SECONDS);
            int i=json.indexOf("\"name\""); String ver=i<0?"?":json.substring(i,Math.min(i+40,json.length()));
            System.out.println("got status JSON ("+json.length()+" bytes) incl: "+ver.replaceAll("[\\n\\r]"," "));
            System.out.println("RESULT: PASS - agent->MacDPI->server end to end");
            ch.close(); System.exit(0);
        } catch(Exception e){ System.out.println("RESULT: FAIL - "+e); System.exit(1); }
        finally { g.shutdownGracefully(); }
    }
}

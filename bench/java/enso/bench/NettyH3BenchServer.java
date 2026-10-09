// ABOUTME: Netty HTTP/3 server used as a comparison point in enso's HTTP/3 benchmarks,
// ABOUTME: answering every request with the same 200 "nf" response as the enso bench handler.
package enso.bench;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.incubator.codec.http3.DefaultHttp3DataFrame;
import io.netty.incubator.codec.http3.DefaultHttp3HeadersFrame;
import io.netty.incubator.codec.http3.Http3;
import io.netty.incubator.codec.http3.Http3DataFrame;
import io.netty.incubator.codec.http3.Http3HeadersFrame;
import io.netty.incubator.codec.http3.Http3RequestStreamInboundHandler;
import io.netty.incubator.codec.http3.Http3ServerConnectionHandler;
import io.netty.incubator.codec.quic.InsecureQuicTokenHandler;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamChannel;

import java.io.File;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * Netty h3 server for bench comparisons against enso. Answers every
 * request 200 with the body "nf"; enso's bench handler
 * (enso.bench/plaintext-handler) sends the same body with status 404.
 */
public final class NettyH3BenchServer {

    private static final byte[] BODY = "nf".getBytes();

    private NettyH3BenchServer() {}

    public static Object start(int port, String certPem, String keyPem) throws Exception {
        EventLoopGroup group = new NioEventLoopGroup(1);
        QuicSslContext sslContext = QuicSslContextBuilder.forServer(
                new File(keyPem), null, new File(certPem))
                .applicationProtocols(Http3.supportedApplicationProtocols())
                .build();
        ChannelHandler codec = Http3.newQuicServerCodecBuilder()
                .sslContext(sslContext)
                .maxIdleTimeout(30_000, TimeUnit.MILLISECONDS)
                .initialMaxData(10_000_000)
                .initialMaxStreamDataBidirectionalLocal(1_000_000)
                .initialMaxStreamDataBidirectionalRemote(1_000_000)
                .initialMaxStreamsBidirectional(1000)
                .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
                .handler(new ChannelInitializer<QuicChannel>() {
                    @Override
                    protected void initChannel(QuicChannel ch) {
                        ch.pipeline().addLast(new Http3ServerConnectionHandler(
                            new ChannelInitializer<QuicStreamChannel>() {
                                @Override
                                protected void initChannel(QuicStreamChannel ch) {
                                    ch.pipeline().addLast(new Http3RequestStreamInboundHandler() {
                                        @Override
                                        protected void channelRead(
                                                ChannelHandlerContext ctx, Http3HeadersFrame frame) {
                                            io.netty.util.ReferenceCountUtil.release(frame);
                                        }
                                        @Override
                                        protected void channelRead(
                                                ChannelHandlerContext ctx, Http3DataFrame frame) {
                                            io.netty.util.ReferenceCountUtil.release(frame);
                                        }
                                        @Override
                                        protected void channelInputClosed(ChannelHandlerContext ctx) {
                                            Http3HeadersFrame h = new DefaultHttp3HeadersFrame();
                                            h.headers().status("200");
                                            h.headers().add("content-type", "text/plain");
                                            h.headers().addInt("content-length", BODY.length);
                                            ctx.write(h);
                                            ctx.writeAndFlush(new DefaultHttp3DataFrame(
                                                    Unpooled.wrappedBuffer(BODY)))
                                                .addListener(QuicStreamChannel.SHUTDOWN_OUTPUT);
                                        }
                                    });
                                }
                            }));
                    }
                }).build();
        Bootstrap bs = new Bootstrap();
        Channel channel = bs.group(group)
                .channel(NioDatagramChannel.class)
                .handler(codec)
                .bind(new InetSocketAddress(port)).sync().channel();
        return new Handle(group, channel);
    }

    public static void stop(Object h) throws Exception {
        Handle handle = (Handle) h;
        handle.channel.close().sync();
        handle.group.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS).sync();
    }

    public record Handle(EventLoopGroup group, Channel channel) {}
}

// ABOUTME: Jetty HTTP/3 server used as a comparison point in enso's HTTP/3 benchmarks,
// ABOUTME: answering every request with the same 200 "nf" response as the enso bench handler.
package enso.bench;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http3.server.HTTP3ServerConnectionFactory;
import org.eclipse.jetty.quic.server.QuicServerConnector;
import org.eclipse.jetty.quic.server.ServerQuicConfiguration;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import java.nio.ByteBuffer;
import java.nio.file.Path;

/**
 * Jetty h3 server for bench comparisons against enso. Answers every
 * request 200 with the body "nf", as the Netty bench server does (enso's
 * bench handler sends the same body with status 404).
 */
public final class JettyH3BenchServer {

    private static final byte[] BODY = "nf".getBytes();

    private JettyH3BenchServer() {}

    public static Object start(int port, String certPem, String keyPem,
                               String keystorePath, String keystorePassword)
            throws Exception {
        SslContextFactory.Server sslCtx = new SslContextFactory.Server();
        sslCtx.setKeyStorePath(keystorePath);
        sslCtx.setKeyStorePassword(keystorePassword);
        sslCtx.setSniRequired(false);

        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new SecureRequestCustomizer(false));

        Server server = new Server();
        ServerQuicConfiguration quicCfg = new ServerQuicConfiguration(
            sslCtx, Path.of(System.getProperty("java.io.tmpdir")));
        HTTP3ServerConnectionFactory h3 = new HTTP3ServerConnectionFactory(quicCfg, httpConfig);
        QuicServerConnector connector = new QuicServerConnector(
            server, quicCfg, h3);
        connector.setPort(port);
        server.addConnector(connector);
        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response,
                                   Callback callback) {
                response.setStatus(200);
                response.getHeaders().put(HttpHeader.CONTENT_TYPE, "text/plain");
                response.write(true, ByteBuffer.wrap(BODY), callback);
                return true;
            }
        });
        server.start();
        return server;
    }

    public static void stop(Object h) throws Exception {
        ((Server) h).stop();
    }
}

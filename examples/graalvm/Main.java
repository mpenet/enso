// ABOUTME: GraalVM native-image example entrypoint: an enso HTTP/1.1 + HTTP/2 server with HTTP/3
// ABOUTME: off. Plaintext by default; serves TLS when ENSO_TLS_CERT and ENSO_TLS_KEY are set.
package example;

import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.Response;
import java.util.Map;

public final class Main {

    public static void main(String[] args) throws Exception {
        String cert = System.getenv("ENSO_TLS_CERT");
        String key = System.getenv("ENSO_TLS_KEY");
        boolean tls = cert != null && key != null;

        int port = args.length > 0 ? Integer.parseInt(args[0]) : (tls ? 8443 : 8080);

        // http3 defaults to false, so the JNI shim is never loaded.
        Config.Builder config = new Config.Builder().host("127.0.0.1").port(port);
        if (tls) {
            config.sslCertPath(cert).sslKeyPath(key);
        }

        RingHandler handler = request ->
            new Response(200,
                         Map.of("content-type", "text/plain"),
                         "hello from native enso\n".getBytes());

        EnsoServer server = new EnsoServer(handler, config.build());
        server.start();
        System.out.println("enso listening on " + server.port() + (tls ? " (tls)" : ""));
        Thread.currentThread().join();
    }
}

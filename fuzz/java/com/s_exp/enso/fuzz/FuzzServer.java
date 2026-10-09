// ABOUTME: The started-but-idle EnsoServer whose config, timer and running state the connection
// ABOUTME: fuzz targets borrow; connections are driven directly on the fuzzing thread, never accepted.
package com.s_exp.enso.fuzz;

import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingHandler;
import java.io.IOException;
import java.io.UncheckedIOException;

final class FuzzServer {

    private FuzzServer() {}

    /** Starts a server on an ephemeral loopback port; it stays up until the JVM exits. */
    static EnsoServer start(RingHandler handler) {
        Config config = Config.builder()
            .host("127.0.0.1")
            .port(0)
            .maxRequestBodyBytes(1 << 20)
            .wsMaxMessageBytes(1 << 20)
            .wsCompression(true)
            .build();
        EnsoServer server = new EnsoServer(handler, config);
        try {
            server.start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return server;
    }
}

// ABOUTME: Graceful-shutdown contract every live connection implements, from accept to close:
// ABOUTME: begin draining (finish in-flight work, take no more), or force-close at the deadline.
package com.s_exp.enso.core;

/**
 * A connection the server can shut down. Registered with the server's
 * {@link ConnectionRegistry} from accept (before any TLS handshake) until
 * the connection is closed; leaving the registry is what "drained" means.
 *
 * <p>Both methods are called from the thread running
 * {@code EnsoServer.close()}, may race with the connection's own threads,
 * and must return promptly: anything that may block (a GOAWAY or CLOSE
 * frame queued behind a stalled writer) is handed to a virtual thread.
 */
public interface Drainable {

    /**
     * Stop accepting new requests / streams, let in-flight ones complete,
     * then close: HTTP/1.1 closes an idle connection at once and announces
     * Connection: close on the response in flight; HTTP/2 and HTTP/3 send
     * GOAWAY; a WebSocket starts the closing handshake with 1001. Called
     * once.
     */
    void beginDrain();

    /** Close now, without waiting for any writer (TLS: no close_notify). Idempotent. */
    void forceClose();
}

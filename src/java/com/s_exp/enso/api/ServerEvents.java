// ABOUTME: Optional observability hook: connection lifecycle, completed requests and protocol
// ABOUTME: errors, called from the connection threads; absent means no cost at all.
package com.s_exp.enso.api;

import java.net.InetAddress;

/**
 * Server event listener ({@code :server-events}). Every method runs on the
 * thread that owns the connection or request, in line with I/O: keep it
 * short and non-blocking (count, enqueue). Exceptions thrown here are
 * swallowed (and logged, rate-limited): a failing listener never affects a
 * connection. When no listener is configured the drivers skip the calls
 * and the timestamps they would need. Arguments are primitives or objects
 * the request already holds, so a call allocates nothing.
 *
 * <p>Protocol names: "http/1.1", "h2", "h2c" (cleartext HTTP/2,
 * {@code :http2c}), "h3" (the ALPN ids) for connections, requests and
 * their protocol errors; "websocket" for a
 * connection upgraded to WebSocket (opened at the 101, closed when the
 * WebSocket ends, inside the "http/1.1" connection's own open / close);
 * "tcp" for errors before any protocol runs (a TCP connection refused by
 * {@code :max-connections}); "tls" for TLS handshake errors. A refused
 * QUIC connection is an "h3" "connection-limit" error.
 */
public interface ServerEvents {

    /** A connection is ready to serve {@code protocol} (after TLS, if any). */
    default void connectionOpened(String protocol, InetAddress remote) {}

    /** The connection closed, {@code durationNanos} after it opened. */
    default void connectionClosed(String protocol, InetAddress remote, long durationNanos) {}

    /**
     * A response finished: {@code method} of the request (null when the
     * head was rejected before it was known), {@code status} sent (101 for
     * a WebSocket upgrade), {@code requestBytes} of request body received,
     * {@code responseBytes} of response body written, {@code durationNanos}
     * from the complete request head to the end of the response.
     */
    default void requestCompleted(String protocol, String method, int status, long requestBytes,
                                  long responseBytes, long durationNanos) {}

    /**
     * A peer broke the protocol or a limit; {@code kind} is a short stable
     * identifier ("bad-request", "header-timeout", "connection-limit", ...).
     */
    default void protocolError(String protocol, String kind) {}
}

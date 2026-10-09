// ABOUTME: Optional observability hook: connection lifecycle, completed requests and protocol
// ABOUTME: errors, delivered in order from one dedicated thread; absent means no cost at all.
package com.s_exp.enso.api;

import java.net.InetAddress;

/**
 * Server event listener ({@code :server-events}). Methods never run on a
 * server thread: the server queues each event (a bounded queue of
 * preallocated slots, nothing allocated per event) and one daemon thread,
 * {@code enso-events}, calls the listener in the order the events
 * happened. A slow listener therefore delays only later events; once
 * {@link com.s_exp.enso.core.GuardedEvents#DEFAULT_CAPACITY} events wait,
 * new ones are dropped and counted
 * ({@code EnsoServer.droppedEvents()}, a WARNING log record and a JFR
 * {@code com.s_exp.enso.EventsDropped} event). Exceptions thrown here are
 * swallowed (and logged, rate-limited). When no listener is configured the
 * drivers skip the calls and the timestamps they would need, and no thread
 * is started. Arguments are primitives or objects the request already
 * holds. Closing the server delivers what is still queued (waiting at
 * most a second for a stuck listener).
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
     * A response finished: {@code method} of the request, {@code status}
     * sent (101 for a WebSocket upgrade), {@code requestBytes} of request
     * body received, {@code responseBytes} of response body written,
     * {@code durationNanos} from the complete request head to the end of
     * the response. A request head refused before it was parsed is only a
     * {@link #protocolError}.
     */
    default void requestCompleted(String protocol, String method, int status, long requestBytes,
                                  long responseBytes, long durationNanos) {}

    /**
     * A peer broke the protocol or a limit; {@code kind} is a short stable
     * identifier ("bad-request", "header-timeout", "connection-limit", ...).
     */
    default void protocolError(String protocol, String kind) {}
}

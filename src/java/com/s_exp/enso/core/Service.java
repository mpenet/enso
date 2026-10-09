// ABOUTME: What a server serves, shared by all its protocol drivers: the Ring handler and error
// ABOUTME: handler, config, timer, guarded events, memory budget, and the response field policy.
package com.s_exp.enso.core;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.ServerEvents;
import java.net.InetAddress;

/**
 * One per server (and per standalone HTTP/3 listener), built at start.
 * Drivers reach the application and the server-wide policies through it,
 * so every protocol reports, limits and decorates responses the same way.
 */
public final class Service {

    public final RingHandler handler;
    /** May be null: errors then get a plain 500. */
    public final RingErrorHandler errorHandler;
    public final Config config;
    public final Timer timer;
    /** The {@code :server-events} listener behind a {@link GuardedEvents}, or null. */
    public final ServerEvents events;
    /** {@code :max-buffered-bytes}. */
    public final MemoryBudget budget;
    // Server and Alt-Svc values added to responses, or null.
    private final String server;
    private final String altSvc;

    public Service(RingHandler handler, RingErrorHandler errorHandler, Config config, Timer timer) {
        this.handler = handler;
        this.errorHandler = errorHandler;
        this.config = config;
        this.timer = timer;
        this.events = GuardedEvents.of(config.serverEvents);
        this.budget = new MemoryBudget(config.maxBufferedBytes > 0
                                       ? config.maxBufferedBytes : MemoryBudget.defaultLimit());
        this.server = config.serverHeader == null || config.serverHeader.isEmpty() ? null : config.serverHeader;
        this.altSvc = config.altSvcValue;
    }

    // ---- events ----------------------------------------------------------------

    /** Whether requests are traced (events or a JFR recording): only then take timestamps. */
    public boolean tracing() {
        return events != null || Jfr.requests();
    }

    /** A protocol error, to the listener and JFR. */
    public void protocolError(String protocol, String kind) {
        if (events != null) events.protocolError(protocol, kind);
        Jfr.protocolError(protocol, kind);
    }

    public void connectionOpened(String protocol, InetAddress remote) {
        if (events != null) events.connectionOpened(protocol, remote);
    }

    public void connectionClosed(String protocol, InetAddress remote, long durationNanos) {
        if (events != null) events.connectionClosed(protocol, remote, durationNanos);
    }

    // ---- response fields the server adds ------------------------------------------

    /** RFC 9110 §6.6.1: an origin server with a clock sends Date; a handler's Date wins. */
    public static boolean addsDate(ResponseHead h) {
        return !h.hasDate();
    }

    /** The {@code :server-header} value to add, or null (none configured, or the handler set one). */
    public String serverField(ResponseHead h) {
        return server != null && !h.hasServer() ? server : null;
    }

    /**
     * The Alt-Svc value advertising the HTTP/3 endpoint (RFC 7838) on an
     * HTTP/1.1 or HTTP/2 response, or null (not advertised, or the handler
     * set one). HTTP/3 responses never carry it.
     */
    public String altSvcField(ResponseHead h) {
        return altSvc != null && !h.hasAltSvc() ? altSvc : null;
    }

    /** Upper bound of the bytes {@link #serverField} and {@link #altSvcField} can add. */
    public int addedFieldsBound() {
        return (server == null ? 0 : 15 + 6 + server.length()) + (altSvc == null ? 0 : 15 + 7 + altSvc.length());
    }
}

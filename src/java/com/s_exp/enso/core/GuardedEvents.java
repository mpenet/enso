// ABOUTME: Wraps the user's ServerEvents listener once per server so a throwing listener can never
// ABOUTME: kill the acceptor, a connection or an event loop: failures are swallowed and logged.
package com.s_exp.enso.core;

import com.s_exp.enso.api.ServerEvents;
import java.net.InetAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The listener every driver calls. Each call runs the user's method and
 * swallows whatever it throws (logged at WARNING, at most one record per
 * second), so no call site needs its own guard and none can forget one.
 * Construct through {@link #of}, which keeps "no listener" as null so the
 * drivers still skip the calls and their timestamps entirely.
 */
public final class GuardedEvents implements ServerEvents {

    private static final Logger LOG = Logger.getLogger(GuardedEvents.class.getName());
    private static final LogLimiter FAILURES = new LogLimiter(LOG, Level.WARNING);

    private final ServerEvents listener;

    private GuardedEvents(ServerEvents listener) {
        this.listener = listener;
    }

    /** {@code listener} guarded, or null when there is none (already guarded ones are kept). */
    public static ServerEvents of(ServerEvents listener) {
        if (listener == null || listener instanceof GuardedEvents) return listener;
        return new GuardedEvents(listener);
    }

    @Override
    public void connectionOpened(String protocol, InetAddress remote) {
        try {
            listener.connectionOpened(protocol, remote);
        } catch (Throwable t) {
            failed("connectionOpened", t);
        }
    }

    @Override
    public void connectionClosed(String protocol, InetAddress remote, long durationNanos) {
        try {
            listener.connectionClosed(protocol, remote, durationNanos);
        } catch (Throwable t) {
            failed("connectionClosed", t);
        }
    }

    @Override
    public void requestCompleted(String protocol, String method, int status, long requestBytes,
                                 long responseBytes, long durationNanos) {
        try {
            listener.requestCompleted(protocol, method, status, requestBytes, responseBytes, durationNanos);
        } catch (Throwable t) {
            failed("requestCompleted", t);
        }
    }

    @Override
    public void protocolError(String protocol, String kind) {
        try {
            listener.protocolError(protocol, kind);
        } catch (Throwable t) {
            failed("protocolError", t);
        }
    }

    private static void failed(String method, Throwable t) {
        FAILURES.log(":server-events " + method + " threw; ignored", t);
    }
}

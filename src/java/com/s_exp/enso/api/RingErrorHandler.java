// ABOUTME: User hook turning a failed request (handler threw or returned nil) into a response,
// ABOUTME: plus the shared policy every driver uses to log such failures.
package com.s_exp.enso.api;

import com.s_exp.enso.core.Causes;
import com.s_exp.enso.core.LogLimiter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public interface RingErrorHandler {
    Response handle(Request request, Throwable throwable);

    /**
     * The response for a request whose handler threw {@code t} (or returned
     * nil): {@code eh}'s, or null when there is no error handler, it
     * returned nil or it threw itself; null means the caller sends its own
     * 500. Failures caused by an I/O error (the client went away while the
     * handler read the body) log at FINE; others at WARNING, rate-limited.
     */
    static Response respond(RingErrorHandler eh, Request request, Throwable t) {
        LogLimiter log = Logs.limiter(t);
        if (eh == null) {
            log.log("unhandled handler exception", t);
            return null;
        }
        try {
            Response r = eh.handle(request, t);
            if (r == null) {
                log.log("error handler returned nil", t);
            }
            return r;
        } catch (Throwable inner) {
            inner.addSuppressed(t);
            Logs.WARNINGS.log("error handler itself threw (original exception suppressed)", inner);
            return null;
        }
    }

    /** Per-level limiters of {@link #respond}'s call sites. */
    final class Logs {
        private static final Logger LOG = Logger.getLogger(RingErrorHandler.class.getName());
        static final LogLimiter WARNINGS = new LogLimiter(LOG, Level.WARNING);
        static final LogLimiter CLIENT_FAILURES = new LogLimiter(LOG, Level.FINE);

        private Logs() {}

        static LogLimiter limiter(Throwable t) {
            return Causes.find(t, IOException.class) != null ? CLIENT_FAILURES : WARNINGS;
        }
    }
}

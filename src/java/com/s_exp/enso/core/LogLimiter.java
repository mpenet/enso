// ABOUTME: Rate-limited logging for one call site: at most one record per interval, later
// ABOUTME: records report how many were suppressed, so floods can't drown or slow the log.
package com.s_exp.enso.core;

import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Guards one logging call site against floods. {@link #log} emits at most
 * one record per interval; the next record that passes carries the number
 * of records suppressed in between. Use one instance per call site, held
 * in a static final field.
 *
 * <p>Policy for the server: failures a client can cause on purpose
 * (malformed requests, resets, timeouts, peers that vanish) log at
 * {@link Level#FINE}; WARNING is reserved for server-side faults (handler
 * bugs, internal errors) and goes through a limiter so even those can't
 * be turned into a log flood.
 */
public final class LogLimiter {

    private final Logger logger;
    private final Level level;
    private final long intervalNanos;
    private final AtomicLong nextAllowedNanos;
    private final AtomicLong suppressed = new AtomicLong();

    public LogLimiter(Logger logger, Level level, long intervalMillis) {
        this.logger = logger;
        this.level = level;
        this.intervalNanos = intervalMillis * 1_000_000L;
        this.nextAllowedNanos = new AtomicLong(System.nanoTime());
    }

    /** One record per second at {@code level}. */
    public LogLimiter(Logger logger, Level level) {
        this(logger, level, 1000);
    }

    /** Whether a record would be emitted at all, so callers skip building messages. */
    public boolean isLoggable() {
        return logger.isLoggable(level);
    }

    public void log(String message, Throwable thrown) {
        if (!logger.isLoggable(level)) return;
        long now = System.nanoTime();
        long next = nextAllowedNanos.get();
        if (now - next < 0 || !nextAllowedNanos.compareAndSet(next, now + intervalNanos)) {
            suppressed.incrementAndGet();
            return;
        }
        long dropped = suppressed.getAndSet(0);
        String text = dropped == 0 ? message
            : message + " (" + dropped + " similar records suppressed)";
        // Explicit source: inferred, it would always name this class.
        logger.logp(level, logger.getName(), null, text, thrown);
    }

    public void log(String message) {
        log(message, null);
    }
}

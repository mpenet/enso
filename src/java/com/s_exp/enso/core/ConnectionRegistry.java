// ABOUTME: The set of live connections of a server, used by shutdown to drain them all under
// ABOUTME: one deadline and force-close whatever is left.
package com.s_exp.enso.core;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Live {@link Drainable} connections. One map node per connection, added
 * at accept and removed at close: no per-request cost. A connection
 * leaves only once nothing of it runs any more (its handler threads
 * included), so waiting for the registry to empty joins them all.
 *
 * <p>Shutdown loops visit every entry whatever one of them throws: a
 * failing connection is logged and the next one still drains.
 */
public final class ConnectionRegistry {

    private static final Logger LOG = Logger.getLogger(ConnectionRegistry.class.getName());
    private static final LogLimiter FAILURES = new LogLimiter(LOG, Level.WARNING);
    private static final long POLL_MILLIS = 10;

    private final Set<Drainable> live = ConcurrentHashMap.newKeySet();

    public void register(Drainable c) {
        live.add(c);
    }

    public void unregister(Drainable c) {
        live.remove(c);
    }

    public int size() {
        return live.size();
    }

    /** {@link Drainable#beginDrain} on every live connection. */
    public void beginDrainAll() {
        for (Drainable c : live) {
            try {
                c.beginDrain();
            } catch (Throwable t) {
                FAILURES.log("connection failed to begin draining", t);
            }
        }
    }

    /** {@link Drainable#forceClose} on every connection still live. */
    public void forceCloseAll() {
        for (Drainable c : live) {
            try {
                c.forceClose();
            } catch (Throwable t) {
                FAILURES.log("connection failed to force-close", t);
            }
        }
    }

    /** Waits until no connection is live or {@code deadlineNanos} (System.nanoTime) passes. */
    public boolean awaitEmpty(long deadlineNanos) {
        while (!live.isEmpty()) {
            if (System.nanoTime() - deadlineNanos >= 0) return false;
            try {
                Thread.sleep(POLL_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return live.isEmpty();
            }
        }
        return true;
    }
}

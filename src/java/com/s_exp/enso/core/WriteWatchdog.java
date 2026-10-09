// ABOUTME: Detects blocking writes that make no progress for the write timeout (a peer that
// ABOUTME: stopped reading) with a progress counter and one reusable timer node per connection.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Write-progress watchdog for one connection (or one writer).
 *
 * <p>Drivers bracket every blocking write with {@link #enter} /
 * {@link #exit} (or write through a {@link WatchedOutputStream}). Both
 * bump a progress counter; the timer node, armed by the first write after
 * an idle period, checks on expiry whether a write is in progress and the
 * counter hasn't moved for a whole period. If so the peer stopped reading:
 * {@link #onStall} force-closes the transport, which fails the blocked
 * write. A write younger than the timeout is never declared stalled; a
 * stalled one is caught within two timeouts.
 *
 * <p>Cost per write: two volatile increments and a volatile flag; no
 * allocation, no timer operation unless the node is disarmed (once per
 * timeout period at most). Calls to enter/exit must not overlap: one
 * writer at a time (the drivers' write lock or single writer thread).
 */
public abstract class WriteWatchdog extends Timer.Task {

    private static final VarHandle ARMED;

    static {
        try {
            ARMED = MethodHandles.lookup().findVarHandle(WriteWatchdog.class, "armed", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final Timer timer;
    private final long timeoutMillis;
    private volatile long progress;
    private volatile boolean writing;
    @SuppressWarnings("unused") // accessed through ARMED
    private volatile int armed;
    // Timer thread only: progress seen at the previous expiry.
    private long seen = -1;

    protected WriteWatchdog(Timer timer, long timeoutMillis) {
        this.timer = timer;
        this.timeoutMillis = timeoutMillis;
    }

    /** A blocking write starts. */
    public final void enter() {
        progress = progress + 1;
        writing = true;
        if ((int) ARMED.getVolatile(this) == 0 && ARMED.compareAndSet(this, 0, 1)) {
            timer.schedule(this, timeoutMillis);
        }
    }

    /** The write returned (normally or not). */
    public final void exit() {
        writing = false;
        progress = progress + 1;
    }

    /**
     * Called on the timer thread once a write made no progress for a whole
     * timeout. Must not block: close the transport from a virtual thread
     * (see {@link #forceCloseAsync}).
     */
    protected abstract void onStall();

    @Override
    protected final void onTimeout() {
        if (writing) {
            long p = progress;
            if (p != seen) {
                seen = p;
                timer.schedule(this, timeoutMillis);
            } else {
                onStall();
            }
            return;
        }
        // Idle: disarm, unless a write began meanwhile and saw the node
        // still armed (it then relies on this expiry to watch it).
        ARMED.setVolatile(this, 0);
        if (writing && ARMED.compareAndSet(this, 0, 1)) {
            seen = progress;
            timer.schedule(this, timeoutMillis);
        }
    }

    /** Force-closes {@code socket} from a virtual thread: closing may block (SO_LINGER). */
    public static void forceCloseAsync(java.net.Socket socket) {
        Thread.startVirtualThread(() -> {
            try {
                TlsSocket.forceClose(socket);
            } catch (java.io.IOException ignored) {
            }
        });
    }
}

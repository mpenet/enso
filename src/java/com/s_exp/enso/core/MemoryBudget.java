// ABOUTME: Accountant for bytes buffered on behalf of peers (request bodies, HTTP/2 response rings, WebSocket
// ABOUTME: sends and messages), server-wide or per HTTP/3 connection: one atomic counter, plus waiter wake-ups.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Bounds the memory peers can make the server hold, across every
 * connection and protocol. Buffers charge the bytes they hold and give
 * them back when the bytes leave (read by the handler, written, dropped).
 * Allocation-free: one atomic add per charge or release.
 *
 * <p>Two ways to charge, matching what the caller can do about it:
 * <ul>
 *   <li>{@link #tryReserve}: refuse when the budget can't take it (a queue
 *       that can turn a send down, e.g. WebSocket asynchronous sends).
 *   <li>{@link #charge}: bytes that already arrived and must be kept (the
 *       peer was entitled to send them); the budget may go over. The
 *       caller applies backpressure instead: while {@link #exhausted} it
 *       stops granting flow-control credit or stops reading, and registers
 *       a {@link Waiter} to resume once enough was released.
 * </ul>
 *
 * <p>Overshoot is bounded by the credit already granted when the budget
 * filled (stream and connection windows), so the limit holds to within
 * one window per active stream.
 */
public final class MemoryBudget {

    /**
     * Something that stopped (credit, reads) because the budget was
     * exhausted. {@link #budgetAvailable} runs on whichever thread released
     * the bytes, so it must not block: queue a WINDOW_UPDATE, signal a loop.
     * The node links are the budget's.
     */
    public abstract static class Waiter {
        // 1 while on the stack; set by the pushing thread, cleared by the waker.
        @SuppressWarnings("unused") // accessed through QUEUED
        private volatile int queued;
        private Waiter next;

        /** The budget has room again. Must not block. */
        protected abstract void budgetAvailable();
    }

    private static final LogLimiter FAILURES =
        new LogLimiter(Logger.getLogger(MemoryBudget.class.getName()), Level.WARNING);
    private static final VarHandle QUEUED;
    private static final VarHandle WAITERS;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            QUEUED = l.findVarHandle(Waiter.class, "queued", int.class);
            WAITERS = l.findVarHandle(MemoryBudget.class, "waiters", Waiter.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final long limit;
    private final AtomicLong used = new AtomicLong();
    @SuppressWarnings("unused") // accessed through WAITERS
    private volatile Waiter waiters;

    /** {@code limit} bytes; {@link Long#MAX_VALUE} for no limit. */
    public MemoryBudget(long limit) {
        if (limit <= 0) throw new IllegalArgumentException("budget limit must be positive: " + limit);
        this.limit = limit;
    }

    /**
     * The default for {@code :max-buffered-bytes} 0: a quarter of the
     * maximum heap. Peer-driven buffers are transient; the rest of the
     * heap stays for handlers and the application.
     */
    public static long defaultLimit() {
        return Math.max(1L << 20, Runtime.getRuntime().maxMemory() / 4);
    }

    public long limit() {
        return limit;
    }

    public long used() {
        return used.get();
    }

    /** True while the budget is at or over its limit: stop granting credit / reading. */
    public boolean exhausted() {
        return used.get() >= limit;
    }

    /** Charges {@code n} bytes unless that would pass the limit; true when charged. */
    public boolean tryReserve(long n) {
        while (true) {
            long u = used.get();
            if (u + n > limit && n > 0) return false;
            if (used.compareAndSet(u, u + n)) return true;
        }
    }

    /** Charges {@code n} bytes that are already held, even past the limit. */
    public void charge(long n) {
        used.addAndGet(n);
    }

    /** Gives back {@code n} charged bytes; wakes the waiters when that left room. */
    public void release(long n) {
        if (n <= 0) return;
        long u = used.addAndGet(-n);
        if (u < limit && WAITERS.getVolatile(this) != null) {
            wakeAll();
        }
    }

    /**
     * Registers {@code w} to be told when the budget has room again. If it
     * already has room, {@code w} is told at once (on this thread), so a
     * wake-up can't be lost between a caller's check and its registration.
     */
    public void await(Waiter w) {
        if (QUEUED.compareAndSet(w, 0, 1)) {
            Waiter top;
            do {
                top = (Waiter) WAITERS.getVolatile(this);
                w.next = top;
            } while (!WAITERS.compareAndSet(this, top, w));
        }
        if (!exhausted()) {
            wakeAll();
        }
    }

    private void wakeAll() {
        Waiter w = (Waiter) WAITERS.getAndSet(this, null);
        while (w != null) {
            Waiter next = w.next;
            w.next = null;
            QUEUED.setVolatile(w, 0);
            try {
                w.budgetAvailable();
            } catch (Throwable t) {
                FAILURES.log("memory budget waiter failed", t);
            }
            w = next;
        }
    }
}

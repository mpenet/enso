// ABOUTME: Accountant for bytes buffered or promised to peers (request bodies and the flow-control credit
// ABOUTME: granted for them, HTTP/2 response rings, WebSocket sends): atomic counters, fair shares, waiters.
package com.s_exp.enso.core;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Bounds the memory peers can make the server hold, across every
 * connection and protocol.
 *
 * <p>What counts: bytes held for a peer (buffered request bodies, response
 * bytes waiting for it) and flow-control credit granted to it, which is a
 * promise to hold that many more. A credit-granting path reserves before
 * it grants ({@link #tryReserve}, or {@link Account#tryReserve} for a
 * connection), so the limit is a real bound: what a peer may still send
 * was paid for. Bytes that arrive within credit the protocol grants
 * without asking (the RFC 9113 initial 65535-octet windows) are
 * {@link #charge}d, which may pass the limit; the overshoot is bounded by
 * those defaults. Everything is given back with {@link #release} once the
 * bytes leave (read, written, dropped) or the credit is abandoned (the
 * stream or connection closed).
 *
 * <p>Pressure: {@link #exhausted} at the limit, {@link #pressured} from the
 * low-water mark (three quarters of it). Under pressure an
 * {@link Account} over its fair share (the limit divided by the accounts
 * holding bytes) is refused and {@link Account#throttled}, while smaller
 * ones may still reserve up to the limit: one client can't freeze every
 * other connection's uploads.
 *
 * <p>Waiters: something that stopped (credit, reads) registers a
 * {@link Waiter} with {@link #await}. Waiters are woken once usage falls
 * below the low-water mark (hysteresis, so they don't flap around the
 * limit), and never on the releasing thread: a short-lived virtual thread
 * runs them, holding no lock, so a release under one connection's lock
 * can't run another connection's callback (which takes its locks) inline.
 * Waiters are removable ({@link #cancel}) so a closed stream or connection
 * doesn't stay reachable from the budget.
 *
 * <p>Allocation-free on every path but a wake-up (one virtual thread per
 * episode of pressure relief, not per byte or request).
 */
public final class MemoryBudget {

    /**
     * Something that stopped (credit, reads) because the budget was under
     * pressure. {@link #budgetAvailable} runs on the budget's waker thread,
     * with no lock held; it should not block for long (queue a
     * WINDOW_UPDATE, signal a loop): other waiters wait behind it. The
     * node links are the budget's.
     */
    public abstract static class Waiter {
        // Guarded by the budget's waiter lock.
        private Waiter prev;
        private Waiter next;
        private boolean queued;
        // Waker thread only: the detached list being woken.
        private Waiter wakeNext;

        /** Usage fell below the low-water mark. */
        protected abstract void budgetAvailable();
    }

    private static final LogLimiter FAILURES =
        new LogLimiter(Logger.getLogger(MemoryBudget.class.getName()), Level.WARNING);
    // An account's held count once closed.
    private static final long CLOSED = Long.MIN_VALUE;

    private final long limit;
    private final long lowWater;
    private final AtomicLong used = new AtomicLong();
    // Accounts holding bytes (fair shares).
    private final AtomicInteger active = new AtomicInteger();
    private final ReentrantLock waiterLock = new ReentrantLock();
    private Waiter head;
    private Waiter tail;
    private volatile int waiterCount;
    // 1 while a waker thread runs.
    private final AtomicInteger waking = new AtomicInteger();
    private final Runnable waker = this::wakeLoop;

    /** {@code limit} bytes; {@link Long#MAX_VALUE} for no limit. */
    public MemoryBudget(long limit) {
        if (limit <= 0) throw new IllegalArgumentException("budget limit must be positive: " + limit);
        this.limit = limit;
        this.lowWater = limit - limit / 4;
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

    /** Usage below which waiters are woken: three quarters of the limit. */
    public long lowWater() {
        return lowWater;
    }

    public long used() {
        return used.get();
    }

    /** Accounts currently holding bytes. */
    public int activeAccounts() {
        return active.get();
    }

    /** True while the budget is at or over its limit: nothing more may be reserved. */
    public boolean exhausted() {
        return used.get() >= limit;
    }

    /** True from the low-water mark up: accounts over their fair share are throttled. */
    public boolean pressured() {
        return used.get() >= lowWater;
    }

    /** Charges {@code n} bytes unless that would pass the limit; true when charged. */
    public boolean tryReserve(long n) {
        if (n <= 0) return true;
        while (true) {
            long u = used.get();
            if (u + n > limit) return false;
            if (used.compareAndSet(u, u + n)) return true;
        }
    }

    /** Charges {@code n} bytes that are already held (or promised by the protocol), even past the limit. */
    public void charge(long n) {
        used.addAndGet(n);
    }

    /** Gives back {@code n} charged bytes; below the low-water mark, waiters are woken (on another thread). */
    public void release(long n) {
        if (n <= 0) return;
        long u = used.addAndGet(-n);
        if (u < lowWater && waiterCount > 0) {
            wake();
        }
    }

    /** A per-connection share of this budget. */
    public Account account() {
        return new Account();
    }

    /**
     * Registers {@code w} to be told once usage is below the low-water
     * mark. Returns false, registering nothing, when it already is: the
     * caller goes on itself (so a wake-up can't be lost between its check
     * and this call, and no callback runs on the caller's thread). True:
     * registered (or being woken right now); {@code budgetAvailable} will
     * run once.
     */
    public boolean await(Waiter w) {
        if (used.get() < lowWater) return false;
        waiterLock.lock();
        try {
            if (!w.queued) {
                w.queued = true;
                w.prev = tail;
                w.next = null;
                if (tail == null) head = w; else tail.next = w;
                tail = w;
                waiterCount = waiterCount + 1;
            }
        } finally {
            waiterLock.unlock();
        }
        if (used.get() < lowWater) {
            // Room came back meanwhile: take the registration back unless a
            // waker already has it (then it will be told).
            return !cancel(w);
        }
        return true;
    }

    /**
     * Unregisters {@code w}. True when it was registered and will not be
     * told; false when it wasn't, or a waker already took it.
     */
    public boolean cancel(Waiter w) {
        waiterLock.lock();
        try {
            if (!w.queued) return false;
            unlink(w);
            return true;
        } finally {
            waiterLock.unlock();
        }
    }

    // Waiter lock held.
    private void unlink(Waiter w) {
        if (w.prev == null) head = w.next; else w.prev.next = w.next;
        if (w.next == null) tail = w.prev; else w.next.prev = w.prev;
        w.prev = null;
        w.next = null;
        w.queued = false;
        waiterCount = waiterCount - 1;
    }

    private void wake() {
        if (waking.compareAndSet(0, 1)) {
            try {
                Thread.startVirtualThread(waker);
            } catch (Throwable t) {
                waking.set(0);
                FAILURES.log("memory budget waker failed to start", t);
            }
        }
    }

    /** The waker thread: tells every waiter, again while more registered and there is room. */
    private void wakeLoop() {
        while (true) {
            while (waiterCount > 0 && used.get() < lowWater) {
                Waiter w = detachAll();
                while (w != null) {
                    Waiter next = w.wakeNext;
                    w.wakeNext = null;
                    try {
                        w.budgetAvailable();
                    } catch (Throwable t) {
                        FAILURES.log("memory budget waiter failed", t);
                    }
                    w = next;
                }
            }
            waking.set(0);
            // A waiter that registered after the last check, with room left,
            // would wait for a release that may never come.
            if (waiterCount == 0 || used.get() >= lowWater || !waking.compareAndSet(0, 1)) {
                return;
            }
        }
    }

    private Waiter detachAll() {
        waiterLock.lock();
        try {
            Waiter first = head;
            Waiter w = first;
            while (w != null) {
                Waiter next = w.next;
                w.wakeNext = next;
                w.prev = null;
                w.next = null;
                w.queued = false;
                w = next;
            }
            head = null;
            tail = null;
            waiterCount = 0;
            return first;
        } finally {
            waiterLock.unlock();
        }
    }

    /**
     * One connection's share: what it holds is part of the budget, and
     * under pressure it may only reserve up to its fair share (the limit
     * divided by the accounts holding bytes). Closing it gives back what
     * it still holds (credit abandoned with the connection) and makes
     * every later call a no-op. Allocation-free; any thread.
     */
    public final class Account {

        private final AtomicLong held = new AtomicLong();

        private Account() {}

        /** The budget this account is a share of. */
        public MemoryBudget budget() {
            return MemoryBudget.this;
        }

        /** Bytes this account holds. */
        public long held() {
            long h = held.get();
            return h == CLOSED ? 0 : h;
        }

        /**
         * Reserves {@code n} bytes unless that would pass the limit, or pass
         * this account's fair share while the budget is under pressure.
         */
        public boolean tryReserve(long n) {
            if (n <= 0) return true;
            long h = held.get();
            if (h == CLOSED) return false;
            while (true) {
                long u = used.get();
                if (u + n > limit) return false;
                if (u + n > lowWater && h + n > fairShare(h)) return false;
                if (used.compareAndSet(u, u + n)) break;
            }
            if (!add(n)) {
                MemoryBudget.this.release(n);
                return false;
            }
            return true;
        }

        /** Charges {@code n} bytes this account already holds, even past the limit. */
        public void charge(long n) {
            if (n <= 0 || !add(n)) return;
            used.addAndGet(n);
        }

        /** Gives back {@code n} bytes this account held. */
        public void release(long n) {
            if (n <= 0) return;
            while (true) {
                long h = held.get();
                if (h == CLOSED) return;
                long next = h - n;
                if (held.compareAndSet(h, next)) {
                    if (h > 0 && next <= 0) active.decrementAndGet();
                    break;
                }
            }
            MemoryBudget.this.release(n);
        }

        /**
         * True when this account should stop growing: the budget is at its
         * limit, or under pressure with this account over its fair share.
         */
        public boolean throttled() {
            long u = used.get();
            if (u >= limit) return true;
            if (u < lowWater) return false;
            long h = held.get();
            return h != CLOSED && h > fairShare(h);
        }

        /** Gives back everything still held; later calls do nothing. */
        public void close() {
            long h = held.getAndSet(CLOSED);
            if (h == CLOSED) return;
            if (h > 0) {
                active.decrementAndGet();
                MemoryBudget.this.release(h);
            }
        }

        private long fairShare(long held) {
            // An account not yet holding anything would be one more.
            int n = active.get() + (held > 0 ? 0 : 1);
            return limit / Math.max(1, n);
        }

        // False when closed.
        private boolean add(long n) {
            while (true) {
                long h = held.get();
                if (h == CLOSED) return false;
                if (held.compareAndSet(h, h + n)) {
                    if (h <= 0 && h + n > 0) active.incrementAndGet();
                    return true;
                }
            }
        }
    }
}

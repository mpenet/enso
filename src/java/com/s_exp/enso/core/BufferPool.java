// ABOUTME: Striped pool of same-size heap ByteBuffers that connections borrow while busy and give
// ABOUTME: back as they wait; keeps what is given back until unused for a trim pass; never blocks.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Lets waiting connections hold small buffers without paying an allocation
 * each time they need a large one again: the large buffer comes from here
 * and goes back when the connection waits for input.
 *
 * <p>Buffers sit on stripes, each a stack behind a one-CAS lock. A thread
 * starts at the stripe its thread id picks (a connection runs on one
 * virtual thread, so it borrows and returns on the same stripe) and tries
 * one more. Nothing waits: a locked stripe moves on, an acquire that finds
 * none allocates, a release that finds every tried stripe locked drops the
 * buffer for the GC. A stripe grows to hold whatever is given back. A
 * pool capped at a fixed count drops what is given back past it, and then
 * allocates whenever more connections turn busy at once than it holds,
 * which a server with many connections waiting does on every burst.
 *
 * <p>What is kept is bounded in time instead: {@link #trim} drops the
 * buffers given back before its previous pass, so with a pass every
 * {@code p} ({@link #trimEvery}) a buffer unused for between {@code p} and
 * {@code 2p} goes to the GC. Busy connections reuse theirs within that, so
 * only quiet ones lose them, as if they had kept them that long. The pass
 * is armed only while buffers are kept, since a timer with any task armed
 * wakes every tick. Each
 * release is stamped with the current pass number, so stacks are ordered
 * oldest at the bottom and a pass drops a prefix.
 *
 * <p>Only heap buffers of exactly {@link #bufferBytes} are kept; a larger
 * request is allocated to fit and dropped on release.
 */
public final class BufferPool {

    /** Period of the servers' trim passes: a buffer unused for 0.5 to 1 s goes to the GC. */
    public static final long TRIM_PERIOD_MILLIS = 500;
    private static final int PROBES = 2;
    private static final int DEFAULT_SLOTS = 8;
    private static final VarHandle LOCK;
    private static final VarHandle TRIM_ARMED;

    static {
        try {
            LOCK = MethodHandles.lookup().findVarHandle(Stripe.class, "lock", int.class);
            TRIM_ARMED = MethodHandles.lookup().findVarHandle(BufferPool.class, "trimArmed", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final int bufferBytes;
    private final int initialSlots;
    private final Stripe[] stripes;
    private final int mask;
    // Number of the current trim pass, stamped on each release.
    private volatile int epoch = 1;
    // The trim pass (trimEvery): armed only while buffers are kept, since a
    // timer with any task armed wakes every tick.
    private Timer trimTimer;
    private long trimPeriodMillis;
    private Timer.Task trimTask;
    @SuppressWarnings("unused") // accessed through TRIM_ARMED
    private volatile int trimArmed;

    /** One stripe per CPU (rounded up to a power of two), starting with {@value #DEFAULT_SLOTS} slots each. */
    public BufferPool(int bufferBytes) {
        this(bufferBytes, Runtime.getRuntime().availableProcessors(), DEFAULT_SLOTS);
    }

    /** {@code stripes} is rounded up to a power of two; each starts with {@code slots} slots and grows. */
    public BufferPool(int bufferBytes, int stripes, int slots) {
        if (bufferBytes < 1) throw new IllegalArgumentException("bufferBytes must be >= 1");
        if (slots < 1) throw new IllegalArgumentException("slots must be >= 1");
        int n = stripes <= 1 ? 1 : Integer.highestOneBit(stripes - 1) << 1;
        this.bufferBytes = bufferBytes;
        this.initialSlots = slots;
        this.stripes = new Stripe[n];
        for (int i = 0; i < n; i++) {
            this.stripes[i] = new Stripe(slots);
        }
        this.mask = n - 1;
    }

    /** Size of the buffers this pool keeps. */
    public int bufferBytes() {
        return bufferBytes;
    }

    /**
     * A cleared heap buffer of at least {@code minBytes}: a pooled one when
     * it fits in {@link #bufferBytes} and one is free, otherwise new.
     */
    public ByteBuffer acquire(int minBytes) {
        if (minBytes <= bufferBytes) {
            int start = stripeIndex();
            for (int i = 0; i < PROBES; i++) {
                Stripe s = stripes[(start + i) & mask];
                if (s.tryLock()) {
                    ByteBuffer b = null;
                    try {
                        if (s.size > 0) {
                            b = s.slots[--s.size];
                            s.slots[s.size] = null;
                        }
                    } finally {
                        s.unlock();
                    }
                    if (b != null) {
                        return b.clear();
                    }
                }
            }
            return ByteBuffer.allocate(bufferBytes);
        }
        return ByteBuffer.allocate(minBytes);
    }

    /**
     * Gives {@code b} back. The caller must not touch it afterwards. A
     * buffer of another size, a direct one, or one that finds every tried
     * stripe locked is dropped.
     */
    public void release(ByteBuffer b) {
        if (b == null || b.capacity() != bufferBytes || b.isDirect() || b.isReadOnly()) {
            return;
        }
        int stamp = epoch;
        int start = stripeIndex();
        for (int i = 0; i < PROBES; i++) {
            Stripe s = stripes[(start + i) & mask];
            if (s.tryLock()) {
                try {
                    s.push(b, stamp);
                } finally {
                    s.unlock();
                }
                // After the push: either this sees the pass disarmed and
                // arms it, or the pass, disarming, sees this buffer (see
                // onTrim).
                if (trimTask != null && (int) TRIM_ARMED.getVolatile(this) == 0) {
                    armTrim();
                }
                return;
            }
        }
    }

    /**
     * One trim pass: drops the buffers given back before the previous pass
     * (unused since), and shrinks a stripe left mostly empty. A stripe
     * locked at that moment is left to the next pass. Never blocks.
     * Returns whether buffers may be left (kept, or on a skipped stripe).
     */
    public synchronized boolean trim() {
        int e = epoch + 1;
        epoch = e;
        int cutoff = e - 2;
        boolean left = false;
        for (Stripe s : stripes) {
            if (s.tryLock()) {
                try {
                    s.dropOlderThan(cutoff, initialSlots);
                    left |= s.size > 0;
                } finally {
                    s.unlock();
                }
            } else {
                left = true;
            }
        }
        return left;
    }

    /**
     * Runs {@link #trim} on {@code timer} every {@code periodMillis} while
     * the pool keeps buffers, until the timer closes. Call once, before the
     * pool is shared.
     */
    public void trimEvery(Timer timer, long periodMillis) {
        trimTimer = timer;
        trimPeriodMillis = periodMillis;
        trimTask = new Timer.Task() {
            @Override
            protected void onTimeout() {
                onTrim();
            }
        };
    }

    private void armTrim() {
        if (TRIM_ARMED.compareAndSet(this, 0, 1)) {
            trimTimer.schedule(trimTask, trimPeriodMillis);
        }
    }

    /**
     * Timer thread. Disarmed before the last look: a release pushing
     * meanwhile either sees it disarmed (and arms it) or, holding the
     * stripe lock first, is seen by that look.
     */
    private void onTrim() {
        if (trim()) {
            trimTimer.schedule(trimTask, trimPeriodMillis);
            return;
        }
        TRIM_ARMED.setVolatile(this, 0);
        if (mayHoldBuffers()) {
            armTrim();
        }
    }

    /** Whether any stripe holds a buffer (or is locked, so may). Never blocks. */
    private boolean mayHoldBuffers() {
        for (Stripe s : stripes) {
            if (!s.tryLock()) {
                return true;
            }
            try {
                if (s.size > 0) {
                    return true;
                }
            } finally {
                s.unlock();
            }
        }
        return false;
    }

    /** Buffers currently kept (a moment's snapshot, for monitoring and tests). */
    public int pooled() {
        int n = 0;
        for (Stripe s : stripes) {
            while (!s.tryLock()) {
                Thread.onSpinWait();
            }
            try {
                n += s.size;
            } finally {
                s.unlock();
            }
        }
        return n;
    }

    private int stripeIndex() {
        return (int) Thread.currentThread().threadId() & mask;
    }

    /** A stack of buffers behind a one-CAS lock, padded off its neighbours' cache lines. */
    private static final class Stripe {
        @SuppressWarnings("unused") private long p0, p1, p2, p3, p4, p5, p6;
        @SuppressWarnings("unused") // accessed through LOCK
        private volatile int lock;
        private int size;
        private ByteBuffer[] slots;
        // Trim pass each slot's buffer was given back in.
        private int[] stamps;
        @SuppressWarnings("unused") private long q0, q1, q2, q3, q4, q5, q6;

        Stripe(int slots) {
            this.slots = new ByteBuffer[slots];
            this.stamps = new int[slots];
        }

        boolean tryLock() {
            return LOCK.compareAndSet(this, 0, 1);
        }

        void unlock() {
            LOCK.setRelease(this, 0);
        }

        /** Under the lock. */
        void push(ByteBuffer b, int stamp) {
            if (size == slots.length) {
                slots = Arrays.copyOf(slots, size * 2);
                stamps = Arrays.copyOf(stamps, size * 2);
            }
            slots[size] = b;
            stamps[size] = stamp;
            size++;
        }

        /** Under the lock: drops the bottom buffers stamped at or before {@code cutoff}. */
        void dropOlderThan(int cutoff, int minSlots) {
            int k = 0;
            while (k < size && stamps[k] <= cutoff) {
                k++;
            }
            if (k > 0) {
                System.arraycopy(slots, k, slots, 0, size - k);
                System.arraycopy(stamps, k, stamps, 0, size - k);
                Arrays.fill(slots, size - k, size, null);
                size -= k;
            }
            if (slots.length > minSlots && size <= slots.length / 4) {
                int n = Math.max(minSlots, slots.length / 2);
                slots = Arrays.copyOf(slots, n);
                stamps = Arrays.copyOf(stamps, n);
            }
        }
    }
}

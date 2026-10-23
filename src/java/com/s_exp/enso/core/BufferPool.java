// ABOUTME: Bounded, striped pool of same-size heap ByteBuffers that connections borrow while a
// ABOUTME: request is in flight and give back as they go idle; never blocks, falls back to allocating.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;

/**
 * Lets idle connections hold small buffers without paying an allocation
 * each time a request needs a large one again: the large buffer comes from
 * here and goes back when the connection goes idle.
 *
 * <p>Buffers sit on stripes, each a small stack behind a one-CAS lock. A
 * thread starts at the stripe its thread id picks (a connection runs on
 * one virtual thread, so it borrows and returns on the same stripe) and
 * tries one more. Nothing waits: a stripe that is locked, empty (acquire)
 * or full (release) moves on, and after both tries an acquire allocates
 * and a release drops the buffer for the GC. So the pool keeps at most
 * {@code stripes * slots} buffers, and contention costs a missed reuse,
 * never a stall.
 *
 * <p>Only heap buffers of exactly {@link #bufferBytes} are kept; a larger
 * request is allocated to fit and dropped on release.
 */
public final class BufferPool {

    private static final int PROBES = 2;
    private static final int DEFAULT_SLOTS = 8;
    private static final VarHandle LOCK;

    static {
        try {
            LOCK = MethodHandles.lookup().findVarHandle(Stripe.class, "lock", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final int bufferBytes;
    private final Stripe[] stripes;
    private final int mask;

    /** One stripe per CPU (rounded up to a power of two), {@value #DEFAULT_SLOTS} buffers each. */
    public BufferPool(int bufferBytes) {
        this(bufferBytes, Runtime.getRuntime().availableProcessors(), DEFAULT_SLOTS);
    }

    /** {@code stripes} is rounded up to a power of two. */
    public BufferPool(int bufferBytes, int stripes, int slots) {
        if (bufferBytes < 1) throw new IllegalArgumentException("bufferBytes must be >= 1");
        if (slots < 1) throw new IllegalArgumentException("slots must be >= 1");
        int n = stripes <= 1 ? 1 : Integer.highestOneBit(stripes - 1) << 1;
        this.bufferBytes = bufferBytes;
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
     * buffer of another size, a direct one, or one that finds no room is
     * dropped.
     */
    public void release(ByteBuffer b) {
        if (b == null || b.capacity() != bufferBytes || b.isDirect() || b.isReadOnly()) {
            return;
        }
        int start = stripeIndex();
        for (int i = 0; i < PROBES; i++) {
            Stripe s = stripes[(start + i) & mask];
            if (s.tryLock()) {
                try {
                    if (s.size < s.slots.length) {
                        s.slots[s.size++] = b;
                        return;
                    }
                } finally {
                    s.unlock();
                }
            }
        }
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
        private final ByteBuffer[] slots;
        @SuppressWarnings("unused") private long q0, q1, q2, q3, q4, q5, q6;

        Stripe(int slots) {
            this.slots = new ByteBuffer[slots];
        }

        boolean tryLock() {
            return LOCK.compareAndSet(this, 0, 1);
        }

        void unlock() {
            LOCK.setRelease(this, 0);
        }
    }
}

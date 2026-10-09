// ABOUTME: Delivers the user's ServerEvents off the server's threads: calls fill preallocated slots of
// ABOUTME: a bounded queue that one daemon thread drains into the listener, failures swallowed and logged.
package com.s_exp.enso.core;

import com.s_exp.enso.api.ServerEvents;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The listener every driver calls. A call never runs user code: it copies
 * its arguments into a preallocated slot of a bounded multi-producer queue
 * and returns, so the timer, the acceptor, an HTTP/3 event loop or an
 * HTTP/2 writer can't be stalled by a slow listener. One daemon thread
 * ({@code enso-events}) drains the queue in call order and runs the
 * listener, swallowing whatever it throws (logged at WARNING, at most one
 * record per second).
 *
 * <p>A call costs a CAS on the queue's tail, a few field writes and, when
 * the delivering thread is parked, an unpark; it allocates nothing (the
 * arguments are primitives and objects the caller already holds). When
 * the queue is full the event is dropped and counted
 * ({@link #droppedEvents}, a WARNING record and a JFR
 * {@code com.s_exp.enso.EventsDropped} event from the delivering thread).
 * Construct through {@link #of}, which keeps "no listener" as null so the
 * drivers still skip the calls and their timestamps entirely, and start no
 * thread.
 */
public final class GuardedEvents implements ServerEvents, AutoCloseable {

    /** Slots in the queue: events waiting for a listener that fell behind. */
    public static final int DEFAULT_CAPACITY = 8192;

    private static final Logger LOG = Logger.getLogger(GuardedEvents.class.getName());
    private static final LogLimiter FAILURES = new LogLimiter(LOG, Level.WARNING);
    private static final LogLimiter DROPS = new LogLimiter(LOG, Level.WARNING);
    // Spins before the delivering thread parks, so a steady stream of
    // events doesn't cost the producers an unpark each.
    private static final int SPINS = 512;
    private static final long CLOSE_WAIT_MILLIS = 1000;

    private static final int CONNECTION_OPENED = 0;
    private static final int CONNECTION_CLOSED = 1;
    private static final int REQUEST_COMPLETED = 2;
    private static final int PROTOCOL_ERROR = 3;

    private static final VarHandle SEQ;
    private static final VarHandle TAIL;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            SEQ = l.findVarHandle(Slot.class, "seq", long.class);
            TAIL = l.findVarHandle(GuardedEvents.class, "tail", long.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * One queued event. {@code seq} is the slot's turn (Vyukov's bounded
     * queue): equal to the position for a producer to claim, position + 1
     * once filled, position + capacity once delivered.
     */
    private static final class Slot {
        @SuppressWarnings("unused") // accessed through SEQ
        private volatile long seq;
        int kind;
        String protocol;
        // The method (request) or the error kind.
        String text;
        InetAddress remote;
        int status;
        long a;
        long b;
        long c;
    }

    private final ServerEvents listener;
    private final Slot[] slots;
    private final int mask;
    private final Thread thread;
    @SuppressWarnings("unused") // accessed through TAIL
    private volatile long tail;
    // Delivering thread only.
    private long head;
    private long reportedDrops;
    private final AtomicLong dropped = new AtomicLong();
    private volatile boolean parked;
    private volatile boolean closed;

    private GuardedEvents(ServerEvents listener, int capacity) {
        this.listener = listener;
        int size = Integer.highestOneBit(Math.max(2, capacity - 1)) << 1;
        this.slots = new Slot[size];
        for (int i = 0; i < size; i++) {
            Slot s = new Slot();
            SEQ.setRelease(s, (long) i);
            slots[i] = s;
        }
        this.mask = size - 1;
        this.thread = Thread.ofPlatform().name("enso-events").daemon(true).unstarted(this::run);
        this.thread.start();
    }

    /** {@code listener} guarded, or null when there is none (already guarded ones are kept). */
    public static GuardedEvents of(ServerEvents listener) {
        return of(listener, DEFAULT_CAPACITY);
    }

    /** {@link #of(ServerEvents)} with a queue of {@code capacity} events (rounded up to a power of two). */
    public static GuardedEvents of(ServerEvents listener, int capacity) {
        if (listener == null) return null;
        if (listener instanceof GuardedEvents g) return g;
        return new GuardedEvents(listener, capacity);
    }

    /** Events dropped because the queue was full (the listener fell behind). */
    public long droppedEvents() {
        return dropped.get();
    }

    @Override
    public void connectionOpened(String protocol, InetAddress remote) {
        Slot s = claim();
        if (s == null) return;
        s.kind = CONNECTION_OPENED;
        s.protocol = protocol;
        s.remote = remote;
        publish(s);
    }

    @Override
    public void connectionClosed(String protocol, InetAddress remote, long durationNanos) {
        Slot s = claim();
        if (s == null) return;
        s.kind = CONNECTION_CLOSED;
        s.protocol = protocol;
        s.remote = remote;
        s.a = durationNanos;
        publish(s);
    }

    @Override
    public void requestCompleted(String protocol, String method, int status, long requestBytes,
                                 long responseBytes, long durationNanos) {
        Slot s = claim();
        if (s == null) return;
        s.kind = REQUEST_COMPLETED;
        s.protocol = protocol;
        s.text = method;
        s.status = status;
        s.a = requestBytes;
        s.b = responseBytes;
        s.c = durationNanos;
        publish(s);
    }

    @Override
    public void protocolError(String protocol, String kind) {
        Slot s = claim();
        if (s == null) return;
        s.kind = PROTOCOL_ERROR;
        s.protocol = protocol;
        s.text = kind;
        publish(s);
    }

    /**
     * Delivers what is queued, then stops the delivering thread (waiting
     * at most a second for a listener that is stuck). Later events are
     * ignored.
     */
    @Override
    public void close() {
        closed = true;
        LockSupport.unpark(thread);
        if (Thread.currentThread() != thread) {
            try {
                thread.join(CLOSE_WAIT_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ---- queue ------------------------------------------------------------------------

    /** A slot to fill at the tail, or null (closed, or full: counted as dropped). */
    private Slot claim() {
        if (closed) return null;
        long pos = (long) TAIL.getVolatile(this);
        while (true) {
            Slot s = slots[(int) pos & mask];
            long seq = (long) SEQ.getAcquire(s);
            long dif = seq - pos;
            if (dif == 0) {
                if (TAIL.compareAndSet(this, pos, pos + 1)) return s;
                pos = (long) TAIL.getVolatile(this);
            } else if (dif < 0) {
                dropped.incrementAndGet();
                return null;
            } else {
                pos = (long) TAIL.getVolatile(this);
            }
        }
    }

    private void publish(Slot s) {
        // The slot's position is its seq: claimed at seq, filled at seq + 1.
        // A volatile store, so the read of parked below can't move before
        // it (the delivering thread writes parked, then reads seq).
        SEQ.setVolatile(s, (long) SEQ.getOpaque(s) + 1);
        if (parked) {
            LockSupport.unpark(thread);
        }
    }

    // ---- delivering thread --------------------------------------------------------------

    private void run() {
        while (true) {
            try {
                if (drain() > 0) {
                    reportDrops();
                    continue;
                }
                if (closed) {
                    drain();
                    reportDrops();
                    return;
                }
                int spins = SPINS;
                while (!ready() && --spins > 0) {
                    Thread.onSpinWait();
                }
                if (ready()) continue;
                parked = true;
                if (!ready() && !closed) {
                    LockSupport.park(this);
                }
                parked = false;
            } catch (Throwable t) {
                // Only an Error in this loop's own bookkeeping gets here.
                FAILURES.log(":server-events delivery failed", t);
            }
        }
    }

    private boolean ready() {
        return (long) SEQ.getVolatile(slots[(int) head & mask]) == head + 1;
    }

    /** Delivers every filled slot from the head; returns how many. */
    private int drain() {
        int n = 0;
        while (true) {
            Slot s = slots[(int) head & mask];
            if ((long) SEQ.getAcquire(s) != head + 1) return n;
            int kind = s.kind;
            String protocol = s.protocol;
            String text = s.text;
            InetAddress remote = s.remote;
            int status = s.status;
            long a = s.a;
            long b = s.b;
            long c = s.c;
            s.protocol = null;
            s.text = null;
            s.remote = null;
            SEQ.setRelease(s, head + slots.length);
            head++;
            n++;
            deliver(kind, protocol, text, remote, status, a, b, c);
        }
    }

    private void deliver(int kind, String protocol, String text, InetAddress remote, int status,
                         long a, long b, long c) {
        try {
            switch (kind) {
                case CONNECTION_OPENED -> listener.connectionOpened(protocol, remote);
                case CONNECTION_CLOSED -> listener.connectionClosed(protocol, remote, a);
                case REQUEST_COMPLETED -> listener.requestCompleted(protocol, text, status, a, b, c);
                default -> listener.protocolError(protocol, text);
            }
        } catch (Throwable t) {
            FAILURES.log(":server-events " + methodName(kind) + " threw; ignored", t);
        }
    }

    private void reportDrops() {
        long d = dropped.get();
        if (d == reportedDrops) return;
        long delta = d - reportedDrops;
        reportedDrops = d;
        DROPS.log(":server-events listener fell behind; " + delta + " event(s) dropped");
        Jfr.eventsDropped(delta);
    }

    private static String methodName(int kind) {
        return switch (kind) {
            case CONNECTION_OPENED -> "connectionOpened";
            case CONNECTION_CLOSED -> "connectionClosed";
            case REQUEST_COMPLETED -> "requestCompleted";
            default -> "protocolError";
        };
    }
}

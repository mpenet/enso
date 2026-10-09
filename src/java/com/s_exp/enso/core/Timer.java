// ABOUTME: Hashed timing wheel on one daemon thread, shared by every protocol driver of a
// ABOUTME: server: O(1), allocation-free arm/re-arm/cancel through intrusive Timer.Task nodes.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Coarse-grained timeouts for connections and streams.
 *
 * <p>A {@link Task} is an intrusive node: the object that needs a timeout
 * (a connection, a stream) extends it or holds one, allocated once and
 * re-armed for every request. Arming and cancelling are one CAS each on
 * the caller's thread and allocate nothing; only the timer thread touches
 * the wheel's bucket lists. Expiry is lazy: re-arming a task to a later
 * deadline only moves its deadline, and the timer thread re-buckets it
 * when it reaches the old slot, so a busy keep-alive connection costs the
 * timer thread one visit per timeout period rather than one per request.
 *
 * <p>Contract:
 * <ul>
 *   <li>{@link #schedule} arms or re-arms; a task has at most one pending
 *       expiry. Expiry happens no earlier than the delay, and at most about
 *       one tick later (10 ms by default).
 *   <li>{@link #cancel} returns true when it disarmed the task before it
 *       fired. False means it wasn't armed, or that it fired (or is firing
 *       right now): exactly one of cancel and expiry wins.
 *   <li>{@link Task#onTimeout} runs on the timer thread and must never
 *       block: flip state, interrupt a thread, enqueue, or hand the work to
 *       a virtual thread. It may re-arm its own task.
 *   <li>A task belongs to one timer for its whole life.
 * </ul>
 */
public final class Timer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Timer.class.getName());
    private static final LogLimiter CALLBACK_FAILURES = new LogLimiter(LOG, Level.WARNING);

    public static final long DEFAULT_TICK_MILLIS = 10;
    public static final int DEFAULT_WHEEL_SIZE = 512;
    // Keeps deadline arithmetic far from overflow.
    private static final long MAX_DELAY_MILLIS = 365L * 24 * 3600 * 1000;

    private static final VarHandle DEADLINE;
    private static final VarHandle QUEUED;
    private static final VarHandle INCOMING;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            DEADLINE = l.findVarHandle(Task.class, "deadline", long.class);
            QUEUED = l.findVarHandle(Task.class, "queued", int.class);
            INCOMING = l.findVarHandle(Timer.class, "incoming", Task.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** A timeout node. Extend it, or hold one per connection / stream. */
    public abstract static class Task {
        // Tick at which the task expires; 0 = disarmed. Any thread, by CAS.
        @SuppressWarnings("unused") // accessed through DEADLINE
        private volatile long deadline;
        // 1 while on the incoming stack. Set by arming threads, cleared by
        // the timer thread before it reads the deadline.
        @SuppressWarnings("unused") // accessed through QUEUED
        private volatile int queued;
        // Incoming stack link, written before the push publishes it.
        private Task stackNext;
        // Bucket list links: timer thread only.
        private Task prev;
        private Task next;
        private int bucket = -1;

        /** Runs on the timer thread when the task expires. Must not block. */
        protected abstract void onTimeout();

        /** Whether an expiry is pending. */
        public final boolean isArmed() {
            return (long) DEADLINE.getVolatile(this) != 0;
        }
    }

    private final long origin = System.nanoTime();
    private final long tickNanos;
    private final Task[] buckets;
    private final int mask;
    private final Thread thread;
    // Treiber stack of tasks the timer thread must (re)bucket.
    @SuppressWarnings("unused") // accessed through INCOMING
    private volatile Task incoming;
    private volatile boolean idleParked;
    private volatile boolean running = true;
    // Timer thread only.
    private int linked;
    private long processedTick;

    public Timer() {
        this("enso-timer", DEFAULT_TICK_MILLIS, DEFAULT_WHEEL_SIZE);
    }

    /** {@code wheelSize} is rounded up to a power of two. */
    public Timer(String threadName, long tickMillis, int wheelSize) {
        if (tickMillis < 1) throw new IllegalArgumentException("tickMillis must be >= 1");
        this.tickNanos = tickMillis * 1_000_000L;
        int size = Integer.highestOneBit(Math.max(2, wheelSize - 1)) << 1;
        this.buckets = new Task[size];
        this.mask = size - 1;
        this.thread = Thread.ofPlatform().name(threadName).daemon(true).unstarted(this::run);
        this.thread.start();
    }

    /** Arms {@code task} to expire after {@code delayMillis} (at least one tick), replacing any pending expiry. */
    public void schedule(Task task, long delayMillis) {
        long delay = Math.min(Math.max(delayMillis, 0), MAX_DELAY_MILLIS) * 1_000_000L;
        long deadline = (System.nanoTime() - origin + delay) / tickNanos + 1;
        long current;
        do {
            current = (long) DEADLINE.getVolatile(task);
        } while (!DEADLINE.compareAndSet(task, current, deadline));
        // A disarmed task may be off the wheel, and a sooner deadline would
        // be found late in its old bucket: both need the timer thread.
        // A later deadline is picked up lazily when the old slot comes up.
        if (current == 0 || deadline < current) {
            enqueue(task);
        }
    }

    /** Disarms {@code task}. True when it was armed and has not fired. */
    public boolean cancel(Task task) {
        long current;
        do {
            current = (long) DEADLINE.getVolatile(task);
            if (current == 0) return false;
        } while (!DEADLINE.compareAndSet(task, current, 0L));
        return true;
    }

    /**
     * {@link #cancel} for a task that won't be armed again (a per-request
     * object, or a connection's node at close): the wheel also drops its
     * reference on the next tick instead of when it reaches the task's
     * slot, so the task can be collected young. That holds for a task
     * cancelled earlier too, which may still sit in its slot. One extra CAS
     * on the shared incoming stack, so a task re-armed afterwards should
     * use {@link #cancel}. Returns what {@link #cancel} would.
     */
    public boolean retire(Task task) {
        boolean disarmed = cancel(task);
        enqueue(task);
        return disarmed;
    }

    /** Stops the timer thread. Pending tasks never fire. */
    @Override
    public void close() {
        running = false;
        LockSupport.unpark(thread);
        if (Thread.currentThread() != thread) {
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void enqueue(Task task) {
        if (!QUEUED.compareAndSet(task, 0, 1)) return;
        Task head;
        do {
            head = (Task) INCOMING.getVolatile(this);
            task.stackNext = head;
        } while (!INCOMING.compareAndSet(this, head, task));
        if (idleParked) {
            LockSupport.unpark(thread);
        }
    }

    private void run() {
        while (running) {
            long nowTick = (System.nanoTime() - origin) / tickNanos;
            if (linked == 0) {
                // Nothing on the wheel, so no slot in between needs a visit.
                processedTick = nowTick;
            }
            drainIncoming();
            while (processedTick < nowTick) {
                processedTick++;
                expire(processedTick);
            }
            if (linked == 0) {
                idleParked = true;
                if (INCOMING.getVolatile(this) == null && running) {
                    LockSupport.park(this);
                }
                idleParked = false;
            } else {
                long wait = origin + (processedTick + 1) * tickNanos - System.nanoTime();
                if (wait > 0) {
                    LockSupport.parkNanos(this, wait);
                }
            }
        }
    }

    private void drainIncoming() {
        Task t = (Task) INCOMING.getAndSet(this, null);
        while (t != null) {
            Task nextQueued = t.stackNext;
            t.stackNext = null;
            // Cleared before the deadline is read: a schedule that lands
            // after that read sees the flag down and queues the task again.
            QUEUED.setVolatile(t, 0);
            long deadline = (long) DEADLINE.getVolatile(t);
            if (deadline == 0) {
                if (t.bucket >= 0) unlink(t);
            } else {
                // A deadline already behind the wheel's position expires on
                // the next tick instead of a full rotation late.
                int target = (int) (Math.max(deadline, processedTick + 1) & mask);
                if (t.bucket != target) {
                    if (t.bucket >= 0) unlink(t);
                    link(t, target);
                }
            }
            t = nextQueued;
        }
    }

    private void expire(long tick) {
        int b = (int) (tick & mask);
        Task t = buckets[b];
        while (t != null) {
            Task nextInBucket = t.next;
            while (true) {
                long deadline = (long) DEADLINE.getVolatile(t);
                if (deadline == 0) {
                    unlink(t);
                    break;
                }
                if (deadline > tick) {
                    int target = (int) (deadline & mask);
                    if (target != b) {
                        unlink(t);
                        link(t, target);
                    }
                    break;
                }
                if (DEADLINE.compareAndSet(t, deadline, 0L)) {
                    unlink(t);
                    fire(t);
                    break;
                }
            }
            t = nextInBucket;
        }
    }

    private static void fire(Task t) {
        try {
            t.onTimeout();
        } catch (Throwable e) {
            CALLBACK_FAILURES.log("timer task failed", e);
        }
    }

    private void link(Task t, int b) {
        Task head = buckets[b];
        t.prev = null;
        t.next = head;
        if (head != null) head.prev = t;
        buckets[b] = t;
        t.bucket = b;
        linked++;
    }

    private void unlink(Task t) {
        if (t.prev != null) {
            t.prev.next = t.next;
        } else {
            buckets[t.bucket] = t.next;
        }
        if (t.next != null) t.next.prev = t.prev;
        t.prev = null;
        t.next = null;
        t.bucket = -1;
        linked--;
    }
}

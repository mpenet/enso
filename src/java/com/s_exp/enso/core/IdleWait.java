// ABOUTME: A connection's untimed wait for input, with what happens along it (an idle close, a
// ABOUTME: buffer release, a keepalive ping) run on the server's Timer under a claim on the wait.
package com.s_exp.enso.core;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Lets a connection's thread wait for input with an untimed read. A timed
 * read on a virtual thread parks through the JDK's delay scheduler, a
 * single thread for the whole process, and one per wait would cap a large
 * machine's request or message rate. The timeouts of the wait run on the
 * server's {@link Timer} instead, through this node.
 *
 * <p>One node per connection, armed by {@link #begin} for each wait but
 * never cancelled: the next wait only moves its deadline, one CAS on this
 * node with no timer thread visit per wait. So an expiry may come after the
 * wait it was armed for ended; {@link #since} tells: when the current wait
 * began, or {@link #NONE}. An expiry claims the wait with one CAS on it,
 * then runs {@link #expired} with the time waited. The waiting thread ends
 * a wait ({@link #end}) or begins the next one only once no claim is in
 * progress, and claims never block, so {@link #expired} may touch what the
 * waiting thread owns while it waits, as long as the blocked read itself
 * doesn't use it.
 */
public abstract class IdleWait extends Timer.Task {

    private static final long NONE = 0;
    private static final long CLAIMED = Long.MIN_VALUE;
    private static final VarHandle SINCE;

    static {
        try {
            SINCE = MethodHandles.lookup().findVarHandle(IdleWait.class, "since", long.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final Timer timer;
    @SuppressWarnings("unused") // also accessed through SINCE
    private volatile long since;

    protected IdleWait(Timer timer) {
        this.timer = timer;
    }

    /**
     * The waiting thread is about to wait: {@link #expired} runs after
     * {@code firstDelayMillis} unless the wait ends first (none when
     * negative). State {@link #expired} reads must be written before this.
     */
    public final void begin(long firstDelayMillis) {
        long now = System.nanoTime();
        if (now == NONE || now == CLAIMED) {
            now++;
        }
        // A CAS from the value seen, not a plain write: a caller that never
        // ends its waits leaves the last one's start here, and an expiry may
        // claim it between a check and a write (the claim would be lost and
        // the expiry would judge the new wait by the old one's start).
        while (true) {
            long s = since;
            if (s == CLAIMED) {
                Thread.onSpinWait();
            } else if (SINCE.compareAndSet(this, s, now)) {
                break;
            }
        }
        if (firstDelayMillis >= 0) {
            timer.schedule(this, firstDelayMillis);
        }
    }

    /**
     * The wait ended (input arrived, EOF or a failure): no expiry acts on it
     * any more. Waits for one in progress to finish. Waiting thread;
     * idempotent.
     */
    public final void end() {
        long s = since;
        while (s != NONE) {
            if (s != CLAIMED && SINCE.compareAndSet(this, s, NONE)) {
                return;
            }
            Thread.onSpinWait();
            s = since;
        }
    }

    /**
     * The wait has lasted {@code waitedMillis}: does what is due, on the
     * timer thread, while the waiting thread can't end the wait. Must not
     * block: work that writes or takes a lock goes to a virtual thread.
     * Returns the milliseconds until it should run again in this wait, or a
     * negative value for never.
     */
    protected abstract long expired(long waitedMillis);

    @Override
    protected final void onTimeout() {
        long s = since;
        if (s == NONE || s == CLAIMED || !SINCE.compareAndSet(this, s, CLAIMED)) {
            return;
        }
        try {
            long next = expired((System.nanoTime() - s) / 1_000_000L);
            // Re-armed under the claim, so a wait beginning meanwhile (it
            // waits for the claim) arms last and its deadline wins.
            if (next >= 0) {
                timer.schedule(this, Math.max(1, next));
            }
        } finally {
            since = s;
        }
    }
}

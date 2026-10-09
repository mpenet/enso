// ABOUTME: Request-body pipe between the HTTP/3 event loop (appends DATA payload, never blocks) and
// ABOUTME: the handler's virtual thread (blocking reads with the read timeout and truncation).
package com.s_exp.enso.http3;

import com.s_exp.enso.core.DataRate;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.RequestBodyException;
import com.s_exp.enso.core.RequestBodyTimeoutException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Per-stream request-body pipe. The connection's event loop appends
 * body bytes as DATA frames arrive; the Ring worker vthread reads them
 * through {@link #inputStream}, which blocks until bytes, EOF or
 * truncation.
 *
 * <p>The writer side never blocks: the event loop drives every stream
 * of the connection and must not wait on one handler. Instead it asks
 * {@link #room} before pulling more stream data from quiche and reads at
 * most that much; at zero it stops reading that stream, so QUIC flow
 * control pushes back on the peer, and registers a wake-up via
 * {@link #resumeWhenDrained}, run once the handler consumed enough.
 *
 * <p>Bytes moved from quiche into a pipe give the peer its flow-control
 * credit back, so the pipes, not quiche's windows, bound what unread
 * bodies hold: a pipe at most {@link #HIGH_WATER} bytes, the pipes of one
 * connection together at most its connection window (the connection's
 * {@link MemoryBudget}), every pipe of the server within
 * {@code :max-buffered-bytes} (the server's, through the connection's
 * {@link MemoryBudget.Account}: under pressure a connection over its fair
 * share stops first). Buffered bytes are charged to both until read or
 * discarded. quiche itself holds at most a connection window more
 * (native memory, counted by {@code Http3Listener.nativeCreditBytes()}).
 *
 * <p>Failures a reader sees: over {@code :max-request-body-bytes} a
 * {@link RequestBodyException} (413), no byte within {@code :read-timeout}
 * a {@link RequestBodyTimeoutException} (408), both answered with their
 * status by the exchange; a truncated body (reset, connection gone) a
 * plain IOException. The first one is kept ({@link #failure}).
 */
public final class Http3BodyPipe {

    /** Unread bytes above which the loop stops reading the stream. */
    static final int HIGH_WATER = 64 * 1024;

    private static final byte[] EMPTY = new byte[0];
    private static final int OPEN = 0, END = 1, TRUNCATED = 2, TOO_LARGE = 3;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition readable = lock.newCondition();
    private final InputStream input = new PipeInputStream();
    private final long maxBytes;
    // Event loop only: content-length from the request (-1 = none) and
    // body bytes accepted so far.
    private final long declaredLength;
    private long received;
    // Longest wait for body bytes (:read-timeout); 0 = none.
    private final long readTimeoutNanos;
    // :min-data-rate-bytes (0 = off) and its grace period.
    private final long minDataRate;
    private final long minDataRateGraceNanos;
    // Reader side, for the rate: bytes read and time spent waiting for them.
    private long readBytes;
    private long waitedNanos;
    // Unread bytes live in buf[rpos, wpos). Guarded by lock.
    private byte[] buf = EMPTY;
    private int rpos;
    private int wpos;
    private int state = OPEN;
    private Runnable onDrain;
    // The connection's share of :max-buffered-bytes, or null (no accounting).
    private final MemoryBudget.Account account;
    // The connection's share (its window), or null.
    private final MemoryBudget connectionBudget;
    // Wake a loop paused on either budget; allocated on first need.
    private MemoryBudget.Waiter budgetWaiter;
    private MemoryBudget.Waiter connectionWaiter;
    // Buffered bytes dropped unread by discard(): later reads fail.
    private boolean discarded;
    // The first failure a read raised (reader thread).
    private volatile IOException failure;

    /**
     * @param maxBytes cap on cumulative body bytes ({@code :max-request-body-bytes});
     *   past it {@link #offer} returns {@link #OVER_CAP} and readers fail with a 413.
     *   0 disables it
     * @param declaredLength the request's content-length, or -1; see
     *   {@link #offer} / {@link #matchesDeclaredLength}
     * @param readTimeoutMillis longest a read waits for bytes before it
     *   throws {@link java.net.SocketTimeoutException}; 0 waits forever
     * @param minDataRate {@code :min-data-rate-bytes}: least bytes per
     *   second a reader may wait for, once {@code minDataRateGraceMillis}
     *   of waiting is spent; 0 = off
     * @param account the connection's share of the server's
     *   {@code :max-buffered-bytes}, or null
     * @param connectionBudget what the pipes of this pipe's connection may
     *   hold together (its connection window), or null
     */
    public Http3BodyPipe(long maxBytes, long declaredLength, long readTimeoutMillis, long minDataRate,
                         long minDataRateGraceMillis, MemoryBudget.Account account,
                         MemoryBudget connectionBudget) {
        this.maxBytes = maxBytes;
        this.declaredLength = declaredLength;
        this.readTimeoutNanos = readTimeoutMillis * 1_000_000L;
        this.minDataRate = minDataRate;
        this.minDataRateGraceNanos = minDataRateGraceMillis * 1_000_000L;
        this.account = account;
        this.connectionBudget = connectionBudget;
    }

    /** {@link #offer} results. */
    public static final int ACCEPTED = 0;
    public static final int OVER_CAP = 1;
    public static final int OVER_DECLARED_LENGTH = 2;

    /**
     * Appends {@code src[off, off + len)} (copied) unless it would pass the
     * request's content-length or the body size cap. Over the cap, readers
     * fail with a 413 once the buffered bytes are read and the caller stops
     * feeding the pipe. Never blocks.
     */
    public int offer(byte[] src, int off, int len) {
        if (declaredLength >= 0 && received + len > declaredLength) return OVER_DECLARED_LENGTH;
        received += len;
        if (maxBytes > 0 && received > maxBytes) {
            finish(TOO_LARGE);
            return OVER_CAP;
        }
        append(src, off, len);
        return ACCEPTED;
    }

    /** Body bytes accepted so far (event loop). */
    public long received() {
        return received;
    }

    /** True once the body went over the size cap: nothing more is read for it. */
    public boolean rejected() {
        lock.lock();
        try {
            return state == TOO_LARGE;
        } finally {
            lock.unlock();
        }
    }

    /** The first failure a read raised, or null. */
    public IOException failure() {
        return failure;
    }

    /**
     * The exchange is over: buffered bytes nobody will read are dropped
     * and their budget given back, a pending wake-up leaves the budgets; a
     * later read fails.
     */
    public void discard() {
        int unread;
        MemoryBudget.Waiter onServer;
        MemoryBudget.Waiter onConnection;
        lock.lock();
        try {
            onServer = budgetWaiter;
            onConnection = connectionWaiter;
            if (state == OPEN) state = TRUNCATED;
            unread = wpos - rpos;
            if (unread > 0) {
                discarded = true;
                rpos = 0;
                wpos = 0;
                buf = EMPTY;
            }
            readable.signalAll();
        } finally {
            lock.unlock();
        }
        if (onServer != null) account.budget().cancel(onServer);
        if (onConnection != null) connectionBudget.cancel(onConnection);
        if (unread > 0) release(unread);
    }

    private void release(int n) {
        if (account != null) account.release(n);
        if (connectionBudget != null) connectionBudget.release(n);
    }

    /** True unless a content-length was declared and the body differs. */
    public boolean matchesDeclaredLength() {
        return declaredLength < 0 || received == declaredLength;
    }

    /**
     * Body bytes the loop may move into this pipe now (event loop): what
     * keeps the pipe within {@link #HIGH_WATER} and the connection within
     * its window; 0 while the connection's share of the server's budget is
     * throttled (the budget exhausted, or under pressure with this
     * connection over its fair share).
     */
    public int room() {
        int unread;
        lock.lock();
        try {
            unread = wpos - rpos;
        } finally {
            lock.unlock();
        }
        long room = HIGH_WATER - unread;
        if (connectionBudget != null) room = Math.min(room, connectionBudget.limit() - connectionBudget.used());
        if (account != null && account.throttled()) room = 0;
        return (int) Math.max(0, room);
    }

    /**
     * Arranges for {@code wake} to run once {@link #room} may be positive
     * again: this pipe drained below {@link #HIGH_WATER} (on the reader's
     * thread), or the budget it waits on fell below its low-water mark (on
     * the budget's waker thread). Runs it immediately if that already
     * happened, so a wake-up can't be lost.
     */
    public void resumeWhenDrained(Runnable wake) {
        MemoryBudget.Waiter waiter = null;
        MemoryBudget on = null;
        lock.lock();
        try {
            if (wpos - rpos >= HIGH_WATER && state == OPEN) {
                onDrain = wake;
                return;
            }
            if (state == OPEN && account != null && account.throttled()) {
                // Paused on the server-wide budget, not on this pipe.
                if (budgetWaiter == null) budgetWaiter = waiter(wake);
                waiter = budgetWaiter;
                on = account.budget();
            } else if (state == OPEN && connectionBudget != null && connectionBudget.exhausted()) {
                // Paused on the connection's window: other streams hold it.
                if (connectionWaiter == null) connectionWaiter = waiter(wake);
                waiter = connectionWaiter;
                on = connectionBudget;
            }
        } finally {
            lock.unlock();
        }
        if (waiter == null || !on.await(waiter)) {
            wake.run();
        }
    }

    private static MemoryBudget.Waiter waiter(Runnable wake) {
        return new MemoryBudget.Waiter() {
            @Override
            protected void budgetAvailable() {
                wake.run();
            }
        };
    }

    /** The body is complete: readers get EOF after the buffered bytes. */
    public void signalEnd() {
        finish(END);
    }

    /**
     * The body is incomplete (stream reset, connection closed, size cap
     * exceeded). Readers get an IOException after the buffered bytes, so
     * a handler can't mistake a truncated body for a complete one.
     */
    public void signalTruncated() {
        finish(TRUNCATED);
    }

    public InputStream inputStream() {
        return input;
    }

    private void append(byte[] src, int off, int len) {
        lock.lock();
        try {
            if (state != OPEN) return;
            if (buf.length - wpos < len) makeRoom(len);
            System.arraycopy(src, off, buf, wpos, len);
            wpos += len;
            if (account != null) account.charge(len);
            if (connectionBudget != null) connectionBudget.charge(len);
            readable.signal();
        } finally {
            lock.unlock();
        }
    }

    // Compacts unread bytes to the front, growing the array if they still
    // don't leave room for len more. Called with lock held.
    private void makeRoom(int len) {
        int unread = wpos - rpos;
        byte[] dst = buf;
        if (buf.length - unread < len) {
            dst = new byte[Math.max(unread + len, Math.min(2 * buf.length, HIGH_WATER * 2))];
        }
        System.arraycopy(buf, rpos, dst, 0, unread);
        buf = dst;
        rpos = 0;
        wpos = unread;
    }

    private void finish(int terminal) {
        lock.lock();
        try {
            if (state != OPEN) return;
            state = terminal;
            readable.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private final class PipeInputStream extends InputStream {
        // InputStreams aren't shared between reader threads, so one
        // scratch byte serves read().
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            Runnable wake;
            int n;
            lock.lock();
            try {
                if (!awaitBytes()) return -1;
                n = Math.min(len, wpos - rpos);
                System.arraycopy(buf, rpos, b, off, n);
                rpos += n;
                readBytes += n;
                wake = drained();
            } catch (IOException e) {
                if (failure == null) failure = e;
                throw e;
            } finally {
                lock.unlock();
            }
            release(n);
            if (wake != null) wake.run();
            return n;
        }

        @Override
        public int available() {
            lock.lock();
            try {
                return wpos - rpos;
            } finally {
                lock.unlock();
            }
        }

        // Blocks until bytes are buffered. False at clean EOF; throws when
        // the body was truncated or no byte came within the read timeout.
        // Called with lock held.
        private boolean awaitBytes() throws IOException {
            long left = readTimeoutNanos;
            while (rpos == wpos && state == OPEN) {
                try {
                    if (readTimeoutNanos > 0 && left <= 0) {
                        throw new RequestBodyTimeoutException();
                    }
                    long wait = readTimeoutNanos > 0 ? left : Long.MAX_VALUE;
                    if (minDataRate > 0) {
                        long allowance = DataRate.allowanceNanos(minDataRate, minDataRateGraceNanos,
                                                                 readBytes, waitedNanos);
                        if (allowance <= 0) {
                            throw RequestBodyTimeoutException.minDataRate();
                        }
                        wait = Math.min(wait, allowance);
                    }
                    if (wait == Long.MAX_VALUE) {
                        readable.await();
                    } else {
                        long remaining = readable.awaitNanos(wait);
                        long waited = wait - remaining;
                        waitedNanos += waited;
                        if (readTimeoutNanos > 0) left -= waited;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while reading HTTP/3 body");
                }
            }
            if (rpos < wpos) return true;
            if (state == END && !discarded) return false;
            if (state == TOO_LARGE) throw RequestBodyException.tooLarge();
            throw new IOException(
                "HTTP/3 request body truncated (stream reset or connection closed)");
        }

        // After a read: reset indices when empty and hand back the pending
        // drain callback once below the mark. Called with lock held.
        private Runnable drained() {
            if (rpos == wpos) {
                rpos = 0;
                wpos = 0;
            }
            Runnable wake = onDrain;
            if (wake != null && wpos - rpos < HIGH_WATER) {
                onDrain = null;
                return wake;
            }
            return null;
        }
    }
}

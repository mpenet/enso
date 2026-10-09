// ABOUTME: The request body of one HTTP/2 stream: a byte ring the framer fills from DATA frames
// ABOUTME: and the handler reads, bounded by the stream's receive window, returning credit as read.
package com.s_exp.enso.http2;

import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.RequestBodyException;
import com.s_exp.enso.core.RequestBodyTimeoutException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Body bytes are copied out of each DATA frame into one ring per stream,
 * so a peer sending tiny frames costs the bytes it sent and nothing per
 * frame. The ring grows on demand and never beyond what the receive
 * window lets the peer send: the framer charges every frame against
 * {@link #recvWindow} before copying it, and credit only goes back (a
 * WINDOW_UPDATE) once the handler has read the bytes. A ring grown large
 * is dropped once read empty, so a long upload keeps only what is buffered.
 *
 * <p>One producer (the framer) and one consumer (the handler thread),
 * under a lock of their own; the consumer parks with
 * {@link LockSupport#park} (no allocation) until bytes, the end, or
 * {@code :read-timeout}.
 *
 * <p>Buffered bytes are charged to the server's {@link MemoryBudget}
 * ({@code :max-buffered-bytes}) until read or dropped. While the budget is
 * exhausted, read bytes earn no WINDOW_UPDATE: the credit is held back and
 * granted once the budget has room again, so peers are slowed down by
 * flow control rather than refused.
 */
final class RequestBody extends InputStream {

    private static final int INITIAL_CAPACITY = 1024;
    // A ring grown past this (a burst the handler fell behind on, up to the
    // stream window) is dropped once read empty; the next DATA regrows it.
    private static final int RETAINED_CAPACITY = 16 * 1024;

    private static final int OPEN = 0;
    private static final int ENDED = 1;
    private static final int TOO_LARGE = 2;
    private static final int ABORTED = 3;

    private final Http2Connection conn;
    private final Http2Stream stream;
    private final MemoryBudget budget;
    private final ReentrantLock lock = new ReentrantLock();
    private final long readTimeoutNanos;
    // Credit returned in one WINDOW_UPDATE once this much was read.
    private final int creditThreshold;

    // All guarded by lock.
    private byte[] ring;
    private int head;
    private int count;
    private int end = OPEN;
    private Thread waiter;
    // Bytes the peer may still send on this stream.
    private long recvWindow;
    // Read bytes not yet credited back to the stream window.
    private long uncredited;
    // The stream is gone (reset, connection closed): nobody reads any more.
    private boolean abandoned;
    // Grants held-back credit once the budget has room; allocated on first need.
    private MemoryBudget.Waiter creditWaiter;

    // Consumer-side failure already reported: later reads fail the same way.
    private IOException failed;
    private boolean eof;
    private final byte[] one = new byte[1];

    RequestBody(Http2Connection conn, Http2Stream stream, long recvWindow,
                long readTimeoutMillis, int creditThreshold) {
        this.conn = conn;
        this.stream = stream;
        this.budget = conn.service().budget;
        this.recvWindow = recvWindow;
        this.readTimeoutNanos = readTimeoutMillis * 1_000_000L;
        this.creditThreshold = creditThreshold;
    }

    // ---- Framer side --------------------------------------------------------------

    /**
     * Charges a DATA frame of {@code frameLen} octets (padding included,
     * §6.9.1) against the stream window. False when the peer overran it.
     */
    boolean charge(int frameLen) {
        lock.lock();
        try {
            recvWindow -= frameLen;
            return recvWindow >= 0;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Appends body bytes. False when nobody will read them (the stream or
     * its handler is gone, the body is over the cap): the caller returns
     * their connection credit.
     */
    boolean append(byte[] src, int off, int len) {
        lock.lock();
        try {
            if (abandoned || end != OPEN) {
                return false;
            }
            if (ring == null || count + len > ring.length) {
                grow(count + len);
            }
            int tail = (head + count) % ring.length;
            int first = Math.min(len, ring.length - tail);
            System.arraycopy(src, off, ring, tail, first);
            if (first < len) {
                System.arraycopy(src, off + first, ring, 0, len - first);
            }
            count += len;
            // The peer was entitled to send these: kept even over budget.
            budget.charge(len);
            wake();
            return true;
        } finally {
            lock.unlock();
        }
    }

    private void grow(int need) {
        int cap = ring == null ? INITIAL_CAPACITY : ring.length;
        while (cap < need) {
            cap <<= 1;
        }
        byte[] bigger = new byte[cap];
        if (count > 0) {
            int first = Math.min(count, ring.length - head);
            System.arraycopy(ring, head, bigger, 0, first);
            System.arraycopy(ring, 0, bigger, first, count - first);
        }
        ring = bigger;
        head = 0;
    }

    /** The peer ended the body: reads return EOF after the buffered bytes. */
    void end() {
        finish(ENDED);
    }

    /** The body went over max-request-body-bytes: reads fail after the buffered bytes. */
    void tooLarge() {
        finish(TOO_LARGE);
    }

    private void finish(int how) {
        lock.lock();
        try {
            if (end == OPEN) {
                end = how;
                wake();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * The body will never complete (stream reset, connection closed):
     * reads fail at once and the buffered bytes are dropped. Returns how
     * many bytes were dropped, still charged to the connection window.
     */
    int abort() {
        int dropped;
        lock.lock();
        try {
            if (end == OPEN || end == TOO_LARGE) {
                end = ABORTED;
            }
            dropped = dropLocked();
        } finally {
            lock.unlock();
        }
        // Outside the lock: a release may run budget waiters, which take
        // other bodies' locks.
        budget.release(dropped);
        return dropped;
    }

    private int dropLocked() {
        abandoned = true;
        int dropped = count;
        count = 0;
        ring = null;
        wake();
        return dropped;
    }

    private void wake() {
        Thread t = waiter;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    // ---- Handler side ---------------------------------------------------------------

    @Override
    public int read() throws IOException {
        int n = read(one, 0, 1);
        return n < 0 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        java.util.Objects.checkFromIndexSize(off, len, b.length);
        if (eof) return -1;
        if (failed != null) throw failed;
        if (len == 0) return 0;
        if (stream.continuePending) {
            // Expect: 100-continue: the client waits for this before it
            // sends the body (RFC 9113 §8.6, RFC 9110 §10.1.1).
            stream.continuePending = false;
            conn.sendContinue(stream);
        }
        int n;
        lock.lock();
        try {
            long deadline = 0;
            while (count == 0) {
                if (end == ENDED) {
                    eof = true;
                    return -1;
                }
                if (end == TOO_LARGE) {
                    throw fail(RequestBodyException.tooLarge());
                }
                if (end == ABORTED || abandoned) {
                    throw fail(new IOException("HTTP/2 request body aborted before END_STREAM"));
                }
                if (readTimeoutNanos > 0) {
                    long now = System.nanoTime();
                    if (deadline == 0) {
                        deadline = now + readTimeoutNanos;
                    } else if (now - deadline >= 0) {
                        throw fail(new RequestBodyTimeoutException());
                    }
                }
                waiter = Thread.currentThread();
                lock.unlock();
                try {
                    if (readTimeoutNanos > 0) {
                        LockSupport.parkNanos(this, deadline - System.nanoTime());
                    } else {
                        LockSupport.park(this);
                    }
                } finally {
                    lock.lock();
                    waiter = null;
                }
                if (Thread.interrupted()) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted while reading HTTP/2 body");
                }
            }
            n = Math.min(len, count);
            int first = Math.min(n, ring.length - head);
            System.arraycopy(ring, head, b, off, first);
            if (first < n) {
                System.arraycopy(ring, 0, b, off + first, n - first);
            }
            head = (head + n) % ring.length;
            count -= n;
            if (count == 0 && ring.length > RETAINED_CAPACITY) {
                ring = null;
                head = 0;
            }
        } finally {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
        budget.release(n);
        credit(n);
        return n;
    }

    private IOException fail(IOException e) {
        failed = e;
        return e;
    }

    /** The first failure a read raised (handler thread), or null. */
    IOException failure() {
        return failed;
    }

    @Override
    public int available() {
        lock.lock();
        try {
            return count;
        } finally {
            lock.unlock();
        }
    }

    /**
     * {@code n} body octets left the server's hands (read by the handler,
     * or padding): hands their credit back, the stream's share only while
     * the peer may still send on it. WINDOW_UPDATEs are batched, one per
     * half window.
     */
    void credit(int n) {
        int increment = 0;
        boolean held = false;
        lock.lock();
        try {
            if (!abandoned && !stream.remoteEnded()) {
                uncredited += n;
                if (uncredited >= creditThreshold) {
                    if (budget.exhausted()) {
                        held = true;
                    } else {
                        increment = (int) uncredited;
                        uncredited = 0;
                        recvWindow += increment;
                    }
                }
            }
        } finally {
            lock.unlock();
        }
        if (increment > 0) {
            conn.sendWindowUpdate(stream.id, increment);
        }
        if (held) {
            budget.await(creditWaiter());
        }
        conn.creditConnection(n);
    }

    private MemoryBudget.Waiter creditWaiter() {
        lock.lock();
        try {
            MemoryBudget.Waiter w = creditWaiter;
            if (w == null) {
                w = new MemoryBudget.Waiter() {
                    @Override
                    protected void budgetAvailable() {
                        grantHeldCredit();
                    }
                };
                creditWaiter = w;
            }
            return w;
        } finally {
            lock.unlock();
        }
    }

    /** The budget has room again: the credit held back goes out, whatever its size. */
    private void grantHeldCredit() {
        int increment = 0;
        lock.lock();
        try {
            if (!abandoned && !stream.remoteEnded() && uncredited > 0) {
                increment = (int) uncredited;
                uncredited = 0;
                recvWindow += increment;
            }
        } finally {
            lock.unlock();
        }
        if (increment > 0) {
            conn.sendWindowUpdate(stream.id, increment);
        }
    }
}

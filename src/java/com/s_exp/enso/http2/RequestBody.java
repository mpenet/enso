// ABOUTME: The request body of one HTTP/2 stream: a byte ring the framer fills from DATA frames
// ABOUTME: and the handler reads, bounded by the stream's receive window, returning credit as read.
package com.s_exp.enso.http2;

import com.s_exp.enso.core.DataRate;
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
 * WINDOW_UPDATE) once the handler has read the bytes. Up to
 * {@link #SMALL_MAX} buffered bytes (a small body) live in a ring of the
 * stream's own; past it, in a chain of full-size rings
 * ({@link Http2Writer#RING_MAX}) from the pool streamed responses use,
 * each given back as soon as the handler has read it, so a long upload
 * costs no allocation per burst however far the handler falls behind (up
 * to the stream window) and a stream holds less than one full-size ring
 * beyond its bytes, which are what the connection's memory account is
 * charged.
 *
 * <p>One producer (the framer) and one consumer (the handler thread),
 * under a lock of their own; the consumer parks with
 * {@link LockSupport#park} (no allocation) until bytes, the end, or
 * {@code :read-timeout}.
 *
 * <p>Memory is accounted per connection, not here: the connection pays
 * for every DATA byte when it arrives (from the credit it reserved before
 * granting it) and gets it back when the bytes leave this ring (read or
 * dropped, through {@link Http2Connection#creditConnection}), where it
 * decides whether to grant that credit again. The connection window
 * bounds what all of a connection's bodies hold, so stream credit is
 * granted as bytes are read.
 */
final class RequestBody extends InputStream {

    private static final int INITIAL_CAPACITY = 1024;
    // Most bytes the stream's own ring holds; more go to pooled segments.
    private static final int SMALL_MAX = 8 * 1024;
    private static final int SEGMENT = Http2Writer.RING_MAX;

    private static final int OPEN = 0;
    private static final int ENDED = 1;
    private static final int TOO_LARGE = 2;
    private static final int ABORTED = 3;

    private static final int RECEIVING = 1;
    private static final int RECEIVED = 2;

    /**
     * Credit granted past a declared body's remaining octets: one frame's
     * padding (pad-length octet and up to 255 octets), which counts
     * against flow control, so a peer that pads can always send its next
     * frame.
     */
    static final int PADDING_ALLOWANCE = 256;

    private final Http2Connection conn;
    private final Http2Stream stream;
    private final ReentrantLock lock = new ReentrantLock();
    private final long readTimeoutNanos;
    // :min-data-rate-bytes (0 = off) and its grace period.
    private final long minDataRate;
    private final long minDataRateGraceNanos;
    // Most windowSize grows to.
    private final long maxWindow;

    // All guarded by lock. Bytes are in ring (circular, from head) while
    // segmentCount is 0, else in the segmentCount pooled segments from
    // segments[firstSegment] on (a circular array), from offset head of
    // the first.
    private byte[] ring;
    private byte[][] segments;
    private int firstSegment;
    private int segmentCount;
    private int head;
    private int count;
    private int end = OPEN;
    private Thread waiter;
    // Bytes the peer may still send on this stream.
    private long recvWindow;
    // Read bytes not yet credited back to the stream window.
    private long uncredited;
    // The window credit is granted back up to, returned in one
    // WINDOW_UPDATE once half of it was read; doubled up to maxWindow when
    // that took less than Http2Connection#windowMayGrow allows since the
    // previous one, at epochNanos (0: none yet).
    private long windowSize;
    private long epochNanos;
    // The stream is gone (reset, connection closed): nobody reads any more.
    private boolean abandoned;
    // Counted in the connection's open bodies: from the first DATA
    // (RECEIVING) to the end or abort (RECEIVED).
    private int receiving;
    // Content-Length octets still to come, -1 when none was declared:
    // stream credit never goes past them (and PADDING_ALLOWANCE).
    private long declaredLeft = -1;

    // Handler side, for :min-data-rate-bytes: bytes read and time spent
    // waiting for them.
    private long readBytes;
    private long waitedNanos;

    // Consumer-side failure already reported: later reads fail the same way.
    private IOException failed;
    private boolean eof;
    private final byte[] one = new byte[1];

    RequestBody(Http2Connection conn, Http2Stream stream, long recvWindow,
                long readTimeoutMillis, long maxWindow) {
        this.conn = conn;
        this.stream = stream;
        this.recvWindow = recvWindow;
        this.windowSize = recvWindow;
        this.maxWindow = maxWindow;
        this.readTimeoutNanos = readTimeoutMillis * 1_000_000L;
        this.minDataRate = conn.service().config.minDataRateBytes;
        this.minDataRateGraceNanos = conn.service().config.minDataRateGraceMillis * 1_000_000L;
    }

    // ---- Framer side --------------------------------------------------------------

    /** Framer, before any DATA: the request declared a Content-Length of {@code length}. */
    void declare(long length) {
        lock.lock();
        try {
            declaredLeft = length;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Charges a DATA frame of {@code frameLen} octets (padding included,
     * §6.9.1), {@code len} of them body, against the stream window. False
     * when the peer overran it.
     */
    boolean charge(int frameLen, int len) {
        lock.lock();
        try {
            if (receiving == 0) {
                receiving = RECEIVING;
                conn.bodyOpened(declaredLeft);
            }
            if (declaredLeft > 0 && receiving == RECEIVING) {
                long n = Math.min(len, declaredLeft);
                declaredLeft -= n;
                conn.declaredArrived(n);
            }
            recvWindow -= frameLen;
            return recvWindow >= 0;
        } finally {
            lock.unlock();
        }
    }

    /** Lock held: the peer sends no more on this body. */
    private void receivedLocked() {
        if (receiving == RECEIVING) {
            conn.bodyClosed(declaredLeft);
        }
        receiving = RECEIVED;
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
            if (segmentCount == 0 && count + len <= SMALL_MAX) {
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
            } else {
                if (segmentCount == 0 && count > 0) {
                    // The small ring's bytes move to the first segment.
                    byte[] seg = addSegment();
                    int first = Math.min(count, ring.length - head);
                    System.arraycopy(ring, head, seg, 0, first);
                    System.arraycopy(ring, 0, seg, first, count - first);
                    head = 0;
                }
                appendSegments(src, off, len);
            }
            wake();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** Lock held: the small ring grown to hold {@code need} (at most SMALL_MAX) bytes. */
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

    /** Lock held: copies {@code src[off, off+len)} past the last buffered byte, taking segments as needed. */
    private void appendSegments(byte[] src, int off, int len) {
        while (len > 0) {
            long pos = (long) head + count;
            int index = (int) (pos / SEGMENT);
            byte[] seg = index == segmentCount
                ? addSegment()
                : segments[(firstSegment + index) & (segments.length - 1)];
            int at = (int) (pos - (long) index * SEGMENT);
            int n = Math.min(len, SEGMENT - at);
            System.arraycopy(src, off, seg, at, n);
            off += n;
            len -= n;
            count += n;
        }
    }

    /** Lock held: a pooled segment appended to the chain. */
    private byte[] addSegment() {
        if (segments == null) {
            segments = new byte[4][];
        } else if (segmentCount == segments.length) {
            byte[][] bigger = new byte[segments.length * 2][];
            for (int i = 0; i < segmentCount; i++) {
                bigger[i] = segments[(firstSegment + i) & (segments.length - 1)];
            }
            segments = bigger;
            firstSegment = 0;
        }
        byte[] seg = Http2Writer.borrowRing();
        segments[(firstSegment + segmentCount) & (segments.length - 1)] = seg;
        segmentCount++;
        return seg;
    }

    /** Lock held: the first segment goes back to the pool. */
    private void dropFirstSegment() {
        Http2Writer.recycleRing(segments[firstSegment]);
        segments[firstSegment] = null;
        firstSegment = (firstSegment + 1) & (segments.length - 1);
        segmentCount--;
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
            if (how == ENDED) {
                receivedLocked();
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
        lock.lock();
        try {
            if (end == OPEN || end == TOO_LARGE) {
                end = ABORTED;
            }
            receivedLocked();
            return dropLocked();
        } finally {
            lock.unlock();
        }
    }

    private int dropLocked() {
        abandoned = true;
        int dropped = count;
        count = 0;
        while (segmentCount > 0) {
            dropFirstSegment();
        }
        ring = null;
        head = 0;
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
                long now = readTimeoutNanos > 0 || minDataRate > 0 ? System.nanoTime() : 0;
                if (readTimeoutNanos > 0) {
                    if (deadline == 0) {
                        deadline = now + readTimeoutNanos;
                    } else if (now - deadline >= 0) {
                        throw fail(new RequestBodyTimeoutException());
                    }
                }
                long wait = readTimeoutNanos > 0 ? deadline - now : Long.MAX_VALUE;
                if (minDataRate > 0) {
                    long allowance = DataRate.allowanceNanos(minDataRate, minDataRateGraceNanos, readBytes, waitedNanos);
                    if (allowance <= 0) {
                        throw fail(RequestBodyTimeoutException.minDataRate());
                    }
                    wait = Math.min(wait, allowance);
                }
                waiter = Thread.currentThread();
                lock.unlock();
                try {
                    if (wait != Long.MAX_VALUE) {
                        LockSupport.parkNanos(this, wait);
                    } else {
                        LockSupport.park(this);
                    }
                } finally {
                    lock.lock();
                    waiter = null;
                    if (minDataRate > 0) {
                        waitedNanos += System.nanoTime() - now;
                    }
                }
                if (Thread.interrupted()) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted while reading HTTP/2 body");
                }
            }
            n = Math.min(len, count);
            if (segmentCount == 0) {
                int first = Math.min(n, ring.length - head);
                System.arraycopy(ring, head, b, off, first);
                if (first < n) {
                    System.arraycopy(ring, 0, b, off + first, n - first);
                }
                head = (head + n) % ring.length;
                count -= n;
            } else {
                for (int done = 0; done < n; ) {
                    int k = Math.min(n - done, SEGMENT - head);
                    System.arraycopy(segments[firstSegment], head, b, off + done, k);
                    done += k;
                    head += k;
                    count -= k;
                    if (head == SEGMENT || count == 0) {
                        dropFirstSegment();
                    }
                }
            }
            readBytes += n;
        } finally {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
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
     * the peer may still send on it, the connection's through
     * {@link Http2Connection#creditConnection} (which pays for it again or
     * holds it back). WINDOW_UPDATEs are batched, one per half window,
     * and carry the window's growth when the handler keeps up.
     */
    void credit(int n) {
        int increment = 0;
        long now = 0;
        lock.lock();
        try {
            if (!abandoned && !stream.remoteEnded()) {
                uncredited += n;
                if (uncredited >= windowSize >> 1) {
                    now = System.nanoTime();
                    long grow = 0;
                    if (windowSize < maxWindow && epochNanos != 0
                        && conn.windowMayGrow(now - epochNanos, uncredited, windowSize)) {
                        grow = Math.min(windowSize, maxWindow - windowSize);
                        windowSize += grow;
                    }
                    epochNanos = now;
                    long credit = uncredited + grow;
                    if (declaredLeft >= 0) {
                        credit = Math.max(0, Math.min(credit, declaredLeft + PADDING_ALLOWANCE - recvWindow));
                    }
                    increment = (int) credit;
                    uncredited = 0;
                    recvWindow += increment;
                }
            }
        } finally {
            lock.unlock();
        }
        if (increment > 0) {
            conn.sendWindowUpdate(stream.id, increment, now);
        }
        conn.creditConnection(n);
    }
}

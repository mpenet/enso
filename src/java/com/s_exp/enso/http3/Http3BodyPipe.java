package com.s_exp.enso.http3;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Per-stream request-body pipe. The connection's owner thread appends
 * body bytes as DATA frames arrive; the Ring worker vthread reads them
 * through {@link #inputStream}, which blocks until bytes, EOF or
 * truncation.
 *
 * <p>The writer side never blocks: the owner thread drives every stream
 * of the connection and must not wait on one handler. Instead it asks
 * {@link #hasRoom} before pulling more stream data from quiche; past
 * {@link #HIGH_WATER} unread bytes it stops reading that stream, so QUIC
 * flow control pushes back on the peer, and registers a wake-up via
 * {@link #resumeWhenDrained}. The reader runs that callback once it has
 * consumed enough to drop below the mark. One {@code stream_recv} call
 * (≤ its buffer size) may land after the check, so this buffer peaks
 * around {@code HIGH_WATER + recv buffer}. That is not the whole cost of
 * an unread body: quiche keeps accepting stream data up to the stream's
 * flow-control window (QuicheConfig: 1 MiB by default, autotuned up to
 * 16 MiB while the reader keeps up), and the connection window bounds
 * the sum over all streams.
 */
public final class Http3BodyPipe {

    /** Unread bytes above which the owner stops reading the stream. */
    static final int HIGH_WATER = 64 * 1024;

    private static final byte[] EMPTY = new byte[0];
    private static final int OPEN = 0, END = 1, TRUNCATED = 2;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition readable = lock.newCondition();
    private final InputStream input = new PipeInputStream();
    private final long maxBytes;
    // Owner-thread only: content-length from the request (-1 = none) and
    // body bytes accepted so far.
    private final long declaredLength;
    private long received;
    // Unread bytes live in buf[rpos, wpos). Guarded by lock.
    private byte[] buf = EMPTY;
    private int rpos;
    private int wpos;
    private int state = OPEN;
    private Runnable onDrain;

    public Http3BodyPipe() {
        this(0, -1);
    }

    /**
     * @param maxBytes hard cap on cumulative body bytes; 0 disables. When
     *   exceeded, {@link #enqueueChecked} returns false so the caller can
     *   reset the stream instead of pushing more bytes.
     */
    public Http3BodyPipe(long maxBytes) {
        this(maxBytes, -1);
    }

    /**
     * @param declaredLength the request's content-length, or -1; see
     *   {@link #exceedsDeclaredLength} / {@link #matchesDeclaredLength}.
     */
    public Http3BodyPipe(long maxBytes, long declaredLength) {
        this.maxBytes = maxBytes;
        this.declaredLength = declaredLength;
    }

    /** True if {@code n} more body bytes would overrun the content-length. */
    public boolean exceedsDeclaredLength(int n) {
        return declaredLength >= 0 && received + n > declaredLength;
    }

    /** True unless a content-length was declared and the body differs. */
    public boolean matchesDeclaredLength() {
        return declaredLength < 0 || received == declaredLength;
    }

    /** Appends {@code chunk}. Never blocks. */
    public void enqueue(byte[] chunk) {
        append(chunk, 0, chunk.length);
    }

    /**
     * Appends {@code chunk} unless it would push the body past
     * {@link #maxBytes}. Never blocks.
     *
     * @return false (nothing appended) when the cap is exceeded; callers
     *   then reset the stream and {@link #signalTruncated()}.
     */
    public boolean enqueueChecked(byte[] chunk) {
        received += chunk.length;
        if (maxBytes > 0 && received > maxBytes) return false;
        append(chunk, 0, chunk.length);
        return true;
    }

    /** True while fewer than {@link #HIGH_WATER} bytes wait unread. */
    public boolean hasRoom() {
        lock.lock();
        try {
            return wpos - rpos < HIGH_WATER;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Arranges for {@code wake} to run (on the reader's thread) once the
     * unread bytes drop below {@link #HIGH_WATER}. Runs it immediately if
     * that already happened, so a wake-up can't be lost.
     */
    public void resumeWhenDrained(Runnable wake) {
        lock.lock();
        try {
            if (wpos - rpos >= HIGH_WATER && state == OPEN) {
                onDrain = wake;
                return;
            }
        } finally {
            lock.unlock();
        }
        wake.run();
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
                wake = drained();
            } finally {
                lock.unlock();
            }
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
        // the body was truncated. Called with lock held.
        private boolean awaitBytes() throws IOException {
            while (rpos == wpos && state == OPEN) {
                try {
                    readable.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while reading HTTP/3 body");
                }
            }
            if (rpos < wpos) return true;
            if (state == END) return false;
            throw new IOException(
                "HTTP/3 request body truncated (stream reset, connection closed "
                    + "or body exceeded size cap)");
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

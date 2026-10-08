// ABOUTME: Zero-copy handoff of a streamed HTTP/3 response body from the
// ABOUTME: handler's virtual thread to the connection's owner thread.
package com.s_exp.enso.http3;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Hands a streamed response body from the handler's virtual thread (the
 * producer: it reads the File / InputStream or runs the StreamingBody)
 * to the connection's owner thread, which only ever sends. Nothing
 * blocking runs on the owner, so one slow body source can't stall the
 * other streams of the connection.
 *
 * <p>Zero-copy rendezvous: {@link #write} offers a slice of the
 * producer's buffer and blocks until the owner has handed all of it to
 * quiche (bounded by QUIC flow control), so the producer can then reuse
 * its buffer. Memory per streamed response is the producer's buffer;
 * backpressure comes for free. The owner frames each slice as one DATA
 * frame (header, then payload straight from the producer's array).
 *
 * <p>The lock is held by the owner while it reads the slice, so a
 * producer can never return (and overwrite its buffer) mid-send — even
 * when interrupted.
 */
final class Http3ResponseBody {

    /** {@link #pump} results. */
    static final int SENDING = 0;
    static final int COMPLETE = 1;
    static final int ABORTED = 2;

    private static final byte[] EMPTY = new byte[0];

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition consumed = lock.newCondition();
    private final Runnable wakeOwner;
    private final OutputStream outputStream = new BodyOutputStream();

    // Offered slice, guarded by lock. `offered` is volatile so the owner
    // can skip the lock when nothing is pending.
    private volatile boolean offered;
    private byte[] buf;
    private int off;
    private int len;
    private boolean fin;
    private volatile boolean failed;
    private volatile boolean cancelled;

    // Owner-only: DATA frame header of the current slice, sent first.
    private final ByteBuffer frameHeader = ByteBuffer.allocate(16);
    private boolean headerPending;

    Http3ResponseBody(Runnable wakeOwner) {
        this.wakeOwner = wakeOwner;
    }

    // ---- producer side (handler virtual thread) -----------------------

    /** Send {@code b[off, off+len)} as one DATA frame; blocks until sent. */
    void write(byte[] b, int off, int len) throws IOException {
        if (len > 0) offer(b, off, len, false);
    }

    /** End the body (FIN); blocks until handed to quiche. */
    void finish() throws IOException {
        offer(EMPTY, 0, 0, true);
    }

    /** The producer failed: the owner resets the stream (no clean FIN). */
    void fail() {
        failed = true;
        wakeOwner.run();
    }

    /** OutputStream view for StreamingBody / ChunkedWriter. */
    OutputStream outputStream() {
        return outputStream;
    }

    private void offer(byte[] b, int o, int l, boolean f) throws IOException {
        lock.lock();
        try {
            if (cancelled) throw closed();
            buf = b;
            off = o;
            len = l;
            fin = f;
            offered = true;
            wakeOwner.run();
            while (offered) {
                if (cancelled) throw closed();
                try {
                    consumed.await();
                } catch (InterruptedException e) {
                    // We hold the lock again, so the owner isn't reading
                    // the slice: safe to abandon it.
                    offered = false;
                    cancelled = true;
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted while sending HTTP/3 body");
                }
            }
            if (cancelled) throw closed();
        } finally {
            lock.unlock();
        }
    }

    private static IOException closed() {
        return new IOException("HTTP/3 response stream closed");
    }

    // ---- owner side ---------------------------------------------------

    /**
     * Push as much of the offered slice as quiche accepts. Owner thread
     * only; called every loop iteration while the body is registered.
     * With {@code checkStopped} (packets arrived), a body with nothing to
     * send asks quiche whether the peer stopped the stream: no send would
     * reveal it while the producer is idle.
     *
     * @return {@link #SENDING}, {@link #COMPLETE} once FIN went out, or
     *   {@link #ABORTED} when the stream is gone or the producer failed
     *   (the caller resets the stream).
     */
    int pump(Http3Session session, long streamId, boolean checkStopped) {
        if (failed || cancelled) {
            cancel();
            return ABORTED;
        }
        // Earlier bytes (HEADERS) still deferred: keep stream order.
        if (!offered || session.hasPendingWrites(streamId)) {
            if (checkStopped && session.sendStopped(streamId)) {
                cancel();
                return ABORTED;
            }
            return SENDING;
        }
        lock.lock();
        try {
            if (!offered) return cancelled ? ABORTED : SENDING;
            if (fin) {
                if (session.sendStreamBytes(streamId, EMPTY, 0, 0, true) < 0) {
                    cancelLocked();
                    return ABORTED;
                }
                release();
                return COMPLETE;
            }
            if (!headerPending) {
                frameHeader.clear();
                Http3Varint.encode(frameHeader, Http3FrameType.DATA);
                Http3Varint.encode(frameHeader, len);
                frameHeader.flip();
                headerPending = true;
            }
            if (frameHeader.hasRemaining()) {
                int n = session.sendStreamBytes(streamId, frameHeader.array(),
                    frameHeader.position(), frameHeader.remaining(), false);
                if (n < 0) {
                    cancelLocked();
                    return ABORTED;
                }
                frameHeader.position(frameHeader.position() + n);
                if (frameHeader.hasRemaining()) return SENDING;
            }
            int n = session.sendStreamBytes(streamId, buf, off, len, false);
            if (n < 0) {
                cancelLocked();
                return ABORTED;
            }
            off += n;
            len -= n;
            if (len == 0) release();
            return SENDING;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Abandon the body (stream reset by the peer, connection closing):
     * a blocked or later {@link #write} throws.
     */
    void cancel() {
        lock.lock();
        try {
            cancelLocked();
        } finally {
            lock.unlock();
        }
    }

    private void cancelLocked() {
        cancelled = true;
        offered = false;
        buf = null;
        consumed.signalAll();
    }

    private void release() {
        offered = false;
        headerPending = false;
        buf = null;
        consumed.signal();
    }

    private final class BodyOutputStream extends OutputStream {
        private final byte[] one = new byte[1];

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            Http3ResponseBody.this.write(one, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            Http3ResponseBody.this.write(b, off, len);
        }
    }
}

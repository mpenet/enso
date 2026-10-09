// ABOUTME: Zero-copy handoff of a streamed HTTP/3 response body from the
// ABOUTME: handler's virtual thread to the connection's event loop.
package com.s_exp.enso.http3;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Hands a streamed response body from the handler's virtual thread (the
 * producer: it reads the File / InputStream or runs the StreamingBody)
 * to the event loop, which only ever sends. Nothing blocking runs on the
 * loop, so one slow body source can't stall other streams.
 *
 * <p>Zero-copy rendezvous: {@link #write} offers a slice of the
 * producer's buffer and blocks until the loop has handed all of it to
 * quiche (bounded by QUIC flow control), so the producer can then reuse
 * its buffer. Memory per streamed response is the producer's buffer;
 * backpressure comes for free. The loop frames each slice as one DATA
 * frame (header, then payload straight from the producer's array); a
 * slice offered as the last one carries the stream's FIN.
 *
 * <p>The lock is held by the loop while it reads the slice, so a producer
 * can never return (and overwrite its buffer) mid-send, even when
 * interrupted. A handler Content-Length ({@code declaredLength}) is
 * enforced: more bytes, or fewer at the end, fail the body.
 */
final class Http3ResponseBody {

    /** {@link #pump} results. */
    static final int IDLE = 0;
    static final int SENDING = 1;
    static final int COMPLETE = 2;
    static final int ABORTED = 3;

    /** The loop's direct path into quiche for this stream. */
    interface Sender {
        /** Bytes accepted (possibly 0), or -1 once the stream can't take data. */
        int send(byte[] b, int off, int len, boolean fin);
    }

    private static final byte[] EMPTY = new byte[0];

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition consumed = lock.newCondition();
    private final Http3Exchange exchange;
    private final long declaredLength;
    private final OutputStream outputStream = new BodyOutputStream();

    // Offered slice, guarded by lock. `offered` is volatile so the loop
    // can skip the lock when nothing is pending.
    private volatile boolean offered;
    private byte[] buf;
    private int off;
    private int len;
    private boolean fin;
    private volatile boolean failed;
    private volatile boolean cancelled;
    // Producer only.
    private long produced;

    // Loop only: DATA frame header of the current slice, sent first.
    private final byte[] frameHeader = new byte[16];
    private int headerOff;
    private int headerEnd;
    private boolean headerPending;
    // Loop only: bytes of the slice the last pump left waiting, and those
    // charged to the connection's budget share (see Http3Connection.bodyHeld).
    private int held;
    int charged;

    Http3ResponseBody(Http3Exchange exchange, long declaredLength) {
        this.exchange = exchange;
        this.declaredLength = declaredLength;
    }

    long declaredLength() {
        return declaredLength;
    }

    // ---- producer side (handler virtual thread) -----------------------

    /** Sends {@code b[off, off+len)} as one DATA frame, the last one when {@code last}; blocks until sent. */
    void write(byte[] b, int off, int len, boolean last) throws IOException {
        produced += len;
        if (declaredLength >= 0 && (produced > declaredLength || (last && produced != declaredLength))) {
            throw new IOException("response body length differs from its Content-Length " + declaredLength);
        }
        if (len > 0 || last) offer(b, off, len, last);
    }

    /** Ends the body (FIN); blocks until handed to quiche. */
    void finish() throws IOException {
        if (declaredLength >= 0 && produced != declaredLength) {
            throw new IOException("response body shorter than its Content-Length " + declaredLength);
        }
        offer(EMPTY, 0, 0, true);
    }

    /** The producer failed: the loop resets the stream (no clean FIN). */
    void fail() {
        failed = true;
        exchange.signal(Http3Exchange.EV_BODY);
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
            exchange.signal(Http3Exchange.EV_BODY);
            while (offered) {
                if (cancelled) throw closed();
                try {
                    consumed.await();
                } catch (InterruptedException e) {
                    // We hold the lock again, so the loop isn't reading
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

    // ---- loop side ------------------------------------------------------

    /** True while a slice waits for the loop. */
    boolean hasOffer() {
        return offered;
    }

    /** Bytes of the producer's slice the last {@link #pump} left waiting for flow control (loop only). */
    int held() {
        return held;
    }

    boolean failed() {
        return failed || cancelled;
    }

    /**
     * Pushes as much of the offered slice as quiche accepts. Loop only;
     * called on {@link Http3Exchange#EV_BODY} and when the stream's send
     * capacity grows.
     *
     * @return {@link #IDLE} (nothing offered), {@link #SENDING} (a slice
     *   is waiting on flow control), {@link #COMPLETE} once the FIN went
     *   out, or {@link #ABORTED} when the stream is gone or the producer
     *   failed (the caller resets the stream)
     */
    int pump(Sender sender) {
        held = 0;
        if (failed || cancelled) {
            cancel();
            return ABORTED;
        }
        if (!offered) return IDLE;
        lock.lock();
        try {
            if (!offered) return cancelled ? ABORTED : IDLE;
            if (len == 0) {
                if (sender.send(EMPTY, 0, 0, fin) < 0) {
                    cancelLocked();
                    return ABORTED;
                }
                return release(fin);
            }
            if (!headerPending) {
                headerOff = 0;
                headerEnd = Http3Varint.encode(frameHeader, 0, Http3FrameType.DATA);
                headerEnd = Http3Varint.encode(frameHeader, headerEnd, len);
                headerPending = true;
            }
            if (headerOff < headerEnd) {
                int n = sender.send(frameHeader, headerOff, headerEnd - headerOff, false);
                if (n < 0) {
                    cancelLocked();
                    return ABORTED;
                }
                headerOff += n;
                if (headerOff < headerEnd) {
                    held = len;
                    return SENDING;
                }
            }
            int n = sender.send(buf, off, len, fin);
            if (n < 0) {
                cancelLocked();
                return ABORTED;
            }
            off += n;
            len -= n;
            if (len > 0) {
                held = len;
                return SENDING;
            }
            return release(fin);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Abandons the body (stream reset, connection closing): a blocked or
     * later {@link #write} throws.
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

    private int release(boolean last) {
        offered = false;
        headerPending = false;
        buf = null;
        consumed.signal();
        return last ? COMPLETE : IDLE;
    }

    private final class BodyOutputStream extends OutputStream {
        private final byte[] one = new byte[1];

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            Http3ResponseBody.this.write(one, 0, 1, false);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            Http3ResponseBody.this.write(b, off, len, false);
        }
    }
}

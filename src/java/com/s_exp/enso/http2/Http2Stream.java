package com.s_exp.enso.http2;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Per-stream state for the HTTP/2 driver. Owns the request body pipe, the
 * stream-lifecycle flags, and the send/receive flow-control windows.
 *
 * <p>The framer thread writes DATA chunks into {@link #enqueueBody}; the
 * per-stream worker vthread reads them through {@link #bodyInputStream}, which
 * blocks on {@link #queue}. The sentinel {@link #END_MARKER} carries the
 * end-of-stream signal to the reader without special-casing every
 * {@code queue.take()}.
 */
final class Http2Stream {

    enum State { IDLE, OPEN, HALF_CLOSED_REMOTE, HALF_CLOSED_LOCAL, CLOSED }

    static final byte[] END_MARKER = new byte[0];
    // Ends the body with BodyTooLargeException instead of EOF.
    static final byte[] TOO_LARGE_MARKER = new byte[0];
    // Ends the body with an IOException: the stream was reset or the
    // connection closed before the peer's END_STREAM.
    static final byte[] ABORT_MARKER = new byte[0];

    final int id;
    volatile State state = State.IDLE;

    // Send-side flow-control window (bytes we may still send). Initialised to
    // peer's SETTINGS_INITIAL_WINDOW_SIZE by the connection; adjusted by
    // WINDOW_UPDATE frames.
    volatile long sendWindow;
    // Receive-side flow control, all guarded by the connection's flowLock.
    // recvWindow: bytes we still let the peer send. bufferedBytes: DATA
    // bytes charged against the windows but not yet credited back (queued
    // for, or being read by, the handler). recvUncredited: consumed bytes
    // not yet returned via a stream WINDOW_UPDATE. abandoned: the stream
    // is gone and its buffered bytes were returned to the connection.
    long recvWindow;
    long bufferedBytes;
    long recvUncredited;
    boolean abandoned;

    // Optional declared Content-Length + running body byte count for §8.1.2.6
    // validation. -1 means "no Content-Length header".
    long declaredContentLength = -1;
    long receivedBodyBytes = 0;
    // Consecutive empty non-final DATA frames (framer-confined).
    int emptyDataFrames = 0;
    // The body exceeded max-request-body-bytes: further DATA is discarded
    // and the handler's read fails. Set by the framer, read by the worker.
    volatile boolean bodyTooLarge;

    // First-writer-wins gate between the handler vthread and the
    // per-request timeout task. Whichever CAS-flips true first owns the
    // response for this stream; the other side must silently drop its
    // work. Prevents a double-response race when the handler completes
    // just as the timeout fires.
    final AtomicBoolean responded = new AtomicBoolean(false);
    // Handler thread reference for interruption on timeout.
    volatile Thread handlerThread;

    // Body handling. The queue is bounded in bytes by the receive window:
    // credit only goes back to the peer as the handler consumes chunks.
    private final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private final InputStream bodyIn;
    private final Http2Connection conn;

    Http2Stream(Http2Connection conn, int id, long initialSendWindow, long initialRecvWindow) {
        this.conn = conn;
        this.id = id;
        this.sendWindow = initialSendWindow;
        this.recvWindow = initialRecvWindow;
        this.bodyIn = new BodyInputStream(this);
    }

    void enqueueBody(byte[] chunk) {
        queue.add(chunk);
    }

    /**
     * Enqueues the end-of-body sentinel so any reader parked on
     * {@link LinkedBlockingQueue#take} wakes up and returns EOF. Called by
     * the framer thread when the peer ends the body (END_STREAM on HEADERS,
     * DATA or trailers).
     */
    void signalEndOfBody() {
        queue.add(END_MARKER);
    }

    /**
     * The body will never be completed (stream reset, connection closed):
     * once the bytes already queued are read, the reader gets an
     * IOException rather than a truncated body ending in EOF. A body that
     * already ended is unaffected, its END_MARKER being read first. Not
     * idempotent — every call enqueues another marker, left to be
     * garbage-collected with the queue.
     */
    void signalAbort() {
        queue.add(ABORT_MARKER);
    }

    /**
     * Marks the body as over the size cap: the handler's next read past the
     * bytes already queued throws {@link BodyTooLargeException}.
     */
    void signalBodyTooLarge() {
        bodyTooLarge = true;
        queue.add(TOO_LARGE_MARKER);
    }

    /** Request body exceeded {@code max-request-body-bytes}. */
    static final class BodyTooLargeException extends IOException {
        BodyTooLargeException() {
            super("request body exceeds max-request-body-bytes");
        }
    }

    InputStream bodyInputStream() {
        return bodyIn;
    }

    /**
     * Blocking InputStream backed by the stream's chunk queue. Reads block on
     * {@link LinkedBlockingQueue#take}; encountering {@link #END_MARKER}
     * returns EOF, {@link #ABORT_MARKER} throws.
     */
    private static final class BodyInputStream extends InputStream {
        private final Http2Stream stream;
        private byte[] current;
        private int pos;
        private boolean eof;
        // The failure marker read, if any: nothing more will be queued, so
        // every later read fails the same way instead of blocking.
        private byte[] failed;
        private final byte[] one = new byte[1];

        BodyInputStream(Http2Stream stream) {
            this.stream = stream;
        }

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (eof) return -1;
            if (failed != null) throw failure(failed);
            if (len == 0) return 0;
            if (current == null || pos == current.length) {
                try {
                    current = stream.queue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while reading HTTP/2 body");
                }
                if (current == END_MARKER) {
                    eof = true;
                    return -1;
                }
                if (current == TOO_LARGE_MARKER || current == ABORT_MARKER) {
                    failed = current;
                    current = null;
                    throw failure(failed);
                }
                pos = 0;
            }
            int n = Math.min(len, current.length - pos);
            System.arraycopy(current, pos, b, off, n);
            pos += n;
            if (pos == current.length) {
                // Chunk fully handed to the handler: return its credit.
                stream.conn.creditConsumed(stream, current.length);
            }
            return n;
        }

        private static IOException failure(byte[] marker) {
            return marker == TOO_LARGE_MARKER
                ? new BodyTooLargeException()
                : new IOException("HTTP/2 request body aborted before END_STREAM");
        }
    }
}

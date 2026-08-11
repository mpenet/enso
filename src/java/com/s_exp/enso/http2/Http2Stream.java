package com.s_exp.enso.http2;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.LinkedBlockingQueue;

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

    final int id;
    volatile State state = State.IDLE;

    // Send-side flow-control window (bytes we may still send). Initialised to
    // peer's SETTINGS_INITIAL_WINDOW_SIZE by the connection; adjusted by
    // WINDOW_UPDATE frames.
    volatile long sendWindow;
    // Receive-side flow-control window (bytes we still let peer send).
    // Mutated only from the framer thread (both DATA-consume and
    // WINDOW_UPDATE-back paths run there), so plain long is safe. No
    // other reader — kept non-volatile so a wide read isn't torn between
    // -= and += back-to-back.
    long recvWindow;

    // Optional declared Content-Length + running body byte count for §8.1.2.6
    // validation. -1 means "no Content-Length header".
    long declaredContentLength = -1;
    long receivedBodyBytes = 0;

    // Body handling.
    private final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private final InputStream bodyIn;

    Http2Stream(int id, long initialSendWindow, long initialRecvWindow) {
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
     * {@link LinkedBlockingQueue#take} wakes up and returns EOF. Called from
     * (a) the framer thread on END_STREAM, RST_STREAM, or on connection
     * teardown, and (b) worker/error paths that abandon the stream. Not
     * idempotent — every call enqueues another marker, so callers must
     * arrange to only invoke it as many times as consumers can drain. In
     * practice this is fine because a well-behaved reader stops calling
     * {@code read} after the first EOF, leaving any trailing markers to be
     * garbage-collected with the queue.
     */
    void signalEndOfBody() {
        queue.add(END_MARKER);
    }

    InputStream bodyInputStream() {
        return bodyIn;
    }

    /**
     * Blocking InputStream backed by the stream's chunk queue. Reads block on
     * {@link LinkedBlockingQueue#take}; encountering {@link #END_MARKER}
     * returns EOF. Cancelling the stream (RST_STREAM) enqueues END_MARKER too.
     */
    private static final class BodyInputStream extends InputStream {
        private final Http2Stream stream;
        private byte[] current;
        private int pos;
        private boolean eof;

        BodyInputStream(Http2Stream stream) {
            this.stream = stream;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (eof) return -1;
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
                pos = 0;
            }
            int n = Math.min(len, current.length - pos);
            System.arraycopy(current, pos, b, off, n);
            pos += n;
            return n;
        }
    }
}

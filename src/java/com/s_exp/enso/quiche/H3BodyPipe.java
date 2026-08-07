package com.s_exp.enso.quiche;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Per-stream request-body pipe. The owner thread pushes decrypted body
 * chunks via {@link #enqueue}; the Ring worker vthread reads them through
 * {@link #inputStream}, which blocks on the queue until FIN.
 *
 * <p>Mirrors {@code Http2Stream}'s pattern: an END_MARKER sentinel signals
 * EOF, so the reader never has to special-case the terminal chunk.
 */
public final class H3BodyPipe {

    private static final byte[] END_MARKER = new byte[0];

    private final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private final InputStream input = new PipeInputStream();
    private final long maxBytes;
    private long received = 0;

    public H3BodyPipe() {
        this(0);
    }

    /**
     * @param maxBytes hard cap on cumulative body bytes; 0 disables. When
     *   exceeded, {@link #enqueueChecked} returns false so the caller can
     *   reset the stream instead of pushing more chunks.
     */
    public H3BodyPipe(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    public void enqueue(byte[] chunk) {
        queue.add(chunk);
    }

    /**
     * @return true if the chunk was accepted, false if it would exceed
     *   {@link #maxBytes}. On overflow, callers should reset the stream +
     *   {@link #signalEnd()} to unblock the reader.
     */
    public boolean enqueueChecked(byte[] chunk) {
        if (maxBytes > 0) {
            received += chunk.length;
            if (received > maxBytes) return false;
        }
        queue.add(chunk);
        return true;
    }

    public void signalEnd() {
        queue.add(END_MARKER);
    }

    public InputStream inputStream() {
        return input;
    }

    private final class PipeInputStream extends InputStream {
        private byte[] current;
        private int pos;
        private boolean eof;

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
                    current = queue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while reading HTTP/3 body");
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

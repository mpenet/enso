package com.s_exp.enso.quiche;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

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

    // Small ring — typical Ring bodies are 0..2 chunks. Under a body
    // burst larger than cap, enqueue briefly blocks the owner thread
    // until the reader vthread drains. Cap kept small because the
    // backing Object[] alloc scales linearly with capacity and dominates
    // per-pipe cost per alloc profile.
    private static final int QUEUE_CAP = 8;
    private final BlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(QUEUE_CAP);
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
        putUninterruptibly(chunk);
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
        putUninterruptibly(chunk);
        return true;
    }

    public void signalEnd() {
        putUninterruptibly(END_MARKER);
    }

    /**
     * Blocking put that must not drop the chunk on interrupt. Retries in
     * a loop while restoring the interrupted status at the end — matches
     * Guava's {@code Uninterruptibles.putUninterruptibly} pattern. Task
     * #135 fixed the prior version that swallowed the chunk on the
     * first InterruptedException, which stranded END_MARKER and hung
     * worker vthreads reading the pipe.
     */
    private void putUninterruptibly(byte[] chunk) {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    queue.put(chunk);
                    return;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
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

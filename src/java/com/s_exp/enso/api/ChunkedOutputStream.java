// ABOUTME: OutputStream over a ChunkedWriter, handed to ring.core.protocols StreamableResponseBody
// ABOUTME: bodies; closing it ends an asynchronous handler's body, a sync body ends when it returns.
package com.s_exp.enso.api;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.concurrent.locks.LockSupport;

/**
 * The stream a {@code StreamableResponseBody} writes to. Writes go to the
 * response's {@link ChunkedWriter} (buffered, sent as HTTP/1.1 chunks or
 * HTTP/2 / HTTP/3 DATA); {@link #flush} pushes them to the client.
 *
 * <p>When the body ends follows Ring's contract: for a synchronous handler
 * once {@code write-body-to-stream} returns (the server ends the body
 * itself, so {@link #close} only marks the stream); an asynchronous
 * handler's body may be written from other threads after it returns, and
 * ends when it closes the stream ({@link #awaitClose}).
 */
public final class ChunkedOutputStream extends OutputStream {

    private final ChunkedWriter writer;
    private volatile boolean closed;
    // The thread in awaitClose, unparked by close.
    private volatile Thread waiter;

    public ChunkedOutputStream(ChunkedWriter writer) {
        this.writer = writer;
    }

    @Override
    public void write(int b) throws IOException {
        writer.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        writer.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        writer.flush();
    }

    @Override
    public void close() {
        closed = true;
        Thread t = waiter;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    /**
     * Waits until the body closed this stream. The connection's teardown
     * (server stop, a reset stream) interrupts the waiting thread, which
     * ends the wait with an {@link InterruptedIOException}.
     */
    public void awaitClose() throws InterruptedIOException {
        // waiter is published before closed is read, and close sets closed
        // before reading waiter: one of them sees the other.
        waiter = Thread.currentThread();
        try {
            while (!closed) {
                LockSupport.park(this);
                if (Thread.interrupted()) {
                    throw new InterruptedIOException("response ended before the body closed its stream");
                }
            }
        } finally {
            waiter = null;
        }
    }
}

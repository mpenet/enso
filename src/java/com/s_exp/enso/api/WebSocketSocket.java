// ABOUTME: Server-side handle to a WebSocket connection: synchronous and queued sends, pings,
// ABOUTME: pongs and the closing handshake, usable from any thread.
package com.s_exp.enso.api;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Server-side handle to a WebSocket connection. Every operation is
 * thread-safe; frames go out in call order, each message as one frame.
 *
 * <p>Once the server's CLOSE is out (or the connection is gone), sends
 * throw {@link IOException} "WebSocket closed" and asynchronous sends call
 * {@link SendCallback#onFailure}.
 */
public interface WebSocketSocket {

    /** False once the server sent its CLOSE or the connection is gone. */
    boolean isOpen();

    /**
     * Sends a text message and returns once it is written. Blocks while a
     * peer that stopped reading holds the connection up, at most about
     * {@code :write-timeout}, after which the connection is dropped.
     */
    void sendText(CharSequence message) throws IOException;

    /**
     * Sends the remaining bytes of {@code message} as a binary message and
     * returns once they are written; {@code message}'s position is not
     * moved. Blocks like {@link #sendText}.
     */
    void sendBinary(ByteBuffer message) throws IOException;

    /**
     * Queues a text message and returns at once; a writer thread sends it,
     * then calls {@code callback}. Fails immediately (through the callback)
     * when the queue already holds {@code :ws-max-queued-bytes}.
     */
    void sendTextAsync(CharSequence message, SendCallback callback);

    /**
     * {@link #sendTextAsync} for binary. {@code message} is sent as it is
     * when written: don't modify it before the callback ran.
     */
    void sendBinaryAsync(ByteBuffer message, SendCallback callback);

    /** Outcome of an asynchronous send, called once, on the writer thread or the caller's. */
    interface SendCallback {
        /** The message was written. */
        void onSuccess();

        /** The message could not be sent (closed, queue full, write failure). */
        void onFailure(Throwable t);
    }

    /**
     * Sends a ping now, or queued right behind a write in progress: never
     * waits for a stalled writer.
     *
     * @throws IllegalArgumentException if {@code data} has more than 125
     *         bytes remaining (RFC 6455 §5.5)
     */
    void sendPing(ByteBuffer data) throws IOException;

    /**
     * Sends a pong like {@link #sendPing}.
     *
     * @throws IllegalArgumentException if {@code data} has more than 125
     *         bytes remaining (RFC 6455 §5.5)
     */
    void sendPong(ByteBuffer data) throws IOException;

    /**
     * Sends a close frame with the given RFC 6455 code and reason (after
     * anything already queued), then closes the underlying TCP connection
     * once the peer answers with its own close frame, or after
     * {@code :ws-close-timeout}. A no-op once a close frame was sent.
     *
     * @throws IllegalArgumentException if {@code code} is not one that may
     *         be sent (1000-1003, 1007-1014, 3000-4999) or {@code reason}
     *         exceeds 123 UTF-8 bytes
     */
    void close(int code, String reason) throws IOException;
}

// ABOUTME: Server-side WebSocket event listener: open, messages, ping/pong, errors and close,
// ABOUTME: all called on the connection's read thread.
package com.s_exp.enso.api;

import java.nio.ByteBuffer;

/**
 * Server-side WebSocket event listener. All callbacks run on the WebSocket's
 * reader virtual thread; a listener may block or spawn its own vthreads for
 * heavy work. {@link #onPing} defaults to sending a pong with the same
 * payload; override only when you need to inspect ping frames.
 */
public interface WebSocketListener {

    void onOpen(WebSocketSocket socket);

    /** message is either a String (text frame) or a ByteBuffer (binary frame). */
    void onMessage(WebSocketSocket socket, Object message);

    default void onPing(WebSocketSocket socket, ByteBuffer data) {
        try {
            socket.sendPong(data);
        } catch (Exception ignored) {
        }
    }

    default void onPong(WebSocketSocket socket, ByteBuffer data) {
    }

    /**
     * The connection failed: {@code t} is a {@link WebSocketException}
     * (with the CLOSE code sent) for a protocol failure, an I/O error for a
     * dropped connection, or what a callback of this listener threw.
     * {@link #onClose} follows.
     */
    default void onError(WebSocketSocket socket, Throwable t) {
    }

    void onClose(WebSocketSocket socket, int code, String reason);
}

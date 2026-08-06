package com.s_exp.enso;

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

    default void onError(WebSocketSocket socket, Throwable t) {
    }

    void onClose(WebSocketSocket socket, int code, String reason);
}

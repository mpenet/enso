package com.s_exp.enso.websocket;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Server-side handle to a WebSocket connection. All send operations are
 * thread-safe and serialize onto the wire.
 */
public interface WebSocketSocket {

    boolean isOpen();

    void sendText(CharSequence message) throws IOException;

    void sendBinary(ByteBuffer message) throws IOException;

    /**
     * @throws IllegalArgumentException if {@code data} has more than 125
     *         bytes remaining (RFC 6455 §5.5)
     */
    void sendPing(ByteBuffer data) throws IOException;

    /**
     * @throws IllegalArgumentException if {@code data} has more than 125
     *         bytes remaining (RFC 6455 §5.5)
     */
    void sendPong(ByteBuffer data) throws IOException;

    /**
     * Sends a close frame with the given RFC 6455 code and reason, then
     * closes the underlying TCP connection once the peer answers with its
     * own close frame, or after a bounded wait. Subsequent send calls are
     * silently ignored.
     *
     * @throws IllegalArgumentException if {@code code} is not one that may
     *         be sent (1000-1003, 1007-1014, 3000-4999) or {@code reason}
     *         exceeds 123 UTF-8 bytes
     */
    void close(int code, String reason) throws IOException;
}

package com.s_exp.enso;

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

    void sendPing(ByteBuffer data) throws IOException;

    void sendPong(ByteBuffer data) throws IOException;

    /**
     * Sends a close frame with the given RFC 6455 code and reason then closes
     * the underlying TCP connection. Subsequent send calls are silently
     * ignored.
     */
    void close(int code, String reason) throws IOException;
}

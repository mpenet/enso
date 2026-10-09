// ABOUTME: Failure of a WebSocket connection (RFC 6455 §7.1.7) carrying the CLOSE status code
// ABOUTME: the server sent; listeners receive it in onError.
package com.s_exp.enso.api;

import java.io.IOException;

/**
 * The connection was failed with {@link #code()} as its CLOSE status:
 * 1002 protocol error, 1007 invalid payload data (UTF-8, compression),
 * 1008 a message that took longer than {@code :read-timeout}, 1009 a
 * message over {@code :ws-max-message-bytes}. Handed to
 * {@link WebSocketListener#onError} before {@link WebSocketListener#onClose}.
 */
public final class WebSocketException extends IOException {

    private final int code;

    public WebSocketException(int code, String message) {
        super(message);
        this.code = code;
    }

    /** The CLOSE status code sent to the peer. */
    public int code() {
        return code;
    }
}

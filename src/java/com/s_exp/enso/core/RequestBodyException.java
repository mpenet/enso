// ABOUTME: A request body the client got wrong (malformed framing 400, over the size cap 413),
// ABOUTME: thrown by every protocol's body stream and answered with its status whatever the handler did.
package com.s_exp.enso.core;

import java.io.IOException;

/**
 * Thrown by a request body's {@code read} when the client broke it:
 * {@link #status} 400 (malformed or truncated framing) or 413 (over
 * {@code :max-request-body-bytes}). A read timeout is the separate
 * {@link RequestBodyTimeoutException} (a {@code SocketTimeoutException}).
 * The body remembers the failure; the {@link Exchange} answers its status
 * after the handler returns, whether the handler rethrew, wrapped or
 * swallowed it. Stackless: a client can cause any number of them.
 */
public final class RequestBodyException extends IOException {

    public final int status;

    public RequestBodyException(int status, String message) {
        super(message);
        this.status = status;
    }

    /** Body over {@code :max-request-body-bytes}. */
    public static RequestBodyException tooLarge() {
        return new RequestBodyException(413, "request body exceeds :max-request-body-bytes");
    }

    /** Body framing broken or cut short. */
    public static RequestBodyException malformed(String why) {
        return new RequestBodyException(400, why);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}

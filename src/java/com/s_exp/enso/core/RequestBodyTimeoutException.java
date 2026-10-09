// ABOUTME: No request body bytes arrived for :read-timeout: a SocketTimeoutException, answered 408
// ABOUTME: on every protocol whatever the handler made of it.
package com.s_exp.enso.core;

import java.net.SocketTimeoutException;

/**
 * Thrown by a request body's {@code read} after {@code :read-timeout}
 * without progress. A {@link SocketTimeoutException}, so handlers that
 * already catch that keep working; the {@link Exchange} answers 408.
 * Stackless.
 */
public final class RequestBodyTimeoutException extends SocketTimeoutException {

    public RequestBodyTimeoutException() {
        super("request body read timed out (:read-timeout)");
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}

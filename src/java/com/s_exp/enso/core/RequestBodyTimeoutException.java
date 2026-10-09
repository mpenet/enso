// ABOUTME: No request body bytes arrived for :read-timeout, or too few for :min-data-rate-bytes: a
// ABOUTME: SocketTimeoutException, answered 408 on every protocol whatever the handler made of it.
package com.s_exp.enso.core;

import java.net.SocketTimeoutException;

/**
 * Thrown by a request body's {@code read} after {@code :read-timeout}
 * without progress, or once the body fell below
 * {@code :min-data-rate-bytes} ({@link #belowMinDataRate}). A
 * {@link SocketTimeoutException}, so handlers that already catch that keep
 * working; the {@link Exchange} answers 408. Stackless.
 */
public final class RequestBodyTimeoutException extends SocketTimeoutException {

    private final boolean belowMinDataRate;

    /** {@code :read-timeout} passed without a byte. */
    public RequestBodyTimeoutException() {
        this(false);
    }

    private RequestBodyTimeoutException(boolean belowMinDataRate) {
        super(belowMinDataRate ? "request body arrived slower than :min-data-rate-bytes"
              : "request body read timed out (:read-timeout)");
        this.belowMinDataRate = belowMinDataRate;
    }

    /** The body arrived slower than {@code :min-data-rate-bytes}. */
    public static RequestBodyTimeoutException minDataRate() {
        return new RequestBodyTimeoutException(true);
    }

    /** Whether the body fell below {@code :min-data-rate-bytes} rather than stalling. */
    public boolean belowMinDataRate() {
        return belowMinDataRate;
    }

    /** The protocol-error kind reported for it. */
    public String kind() {
        return belowMinDataRate ? "min-data-rate" : "read-timeout";
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}

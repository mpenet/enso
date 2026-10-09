// ABOUTME: Signals an HTTP/3 stream error: only the offending request
// ABOUTME: stream is reset with the carried error code; the connection lives on.
package com.s_exp.enso.http3;

/**
 * Stream-level HTTP/3 error (RFC 9114 §8), e.g. a malformed request
 * (H3_MESSAGE_ERROR, §4.1.2). {@link Http3Connection} resets the request
 * stream in both directions with {@link #errorCode()}; contrast with
 * {@link Http3ConnectionException}, which closes the whole connection.
 */
public final class Http3StreamException extends RuntimeException {

    private final long errorCode;

    public Http3StreamException(long errorCode, String message) {
        super(message, null, false, false);
        this.errorCode = errorCode;
    }

    public long errorCode() { return errorCode; }
}

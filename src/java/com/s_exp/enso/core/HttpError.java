// ABOUTME: Stackless exception carrying an HTTP status code, thrown by the HTTP/1.1 request reader
// ABOUTME: so the connection can answer with that status (400, 408, ...) and close.
package com.s_exp.enso.core;

public final class HttpError extends RuntimeException {

    public final int status;

    public HttpError(int status, String message) {
        super(message, null, false, false);
        this.status = status;
    }
}

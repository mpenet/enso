package com.s_exp.enso.core;

public final class HttpError extends RuntimeException {

    public final int status;

    public HttpError(int status, String message) {
        super(message, null, false, false);
        this.status = status;
    }
}

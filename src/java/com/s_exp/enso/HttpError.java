package com.s_exp.enso;

final class HttpError extends RuntimeException {

    final int status;

    HttpError(int status, String message) {
        super(message, null, false, false);
        this.status = status;
    }
}

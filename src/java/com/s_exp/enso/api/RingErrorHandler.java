package com.s_exp.enso.api;

public interface RingErrorHandler {
    Response handle(Request request, Throwable throwable);
}

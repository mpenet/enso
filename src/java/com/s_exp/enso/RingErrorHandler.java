package com.s_exp.enso;

public interface RingErrorHandler {
    Response handle(Request request, Throwable throwable);
}

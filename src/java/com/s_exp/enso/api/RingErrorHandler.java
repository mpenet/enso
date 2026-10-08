package com.s_exp.enso.api;

import java.util.logging.Level;
import java.util.logging.Logger;

public interface RingErrorHandler {
    Response handle(Request request, Throwable throwable);

    /**
     * The response for a request whose handler threw {@code t} (or returned
     * nil): {@code eh}'s, or null when there is no error handler, it
     * returned nil or it threw itself. Every case is logged; null means the
     * caller sends its own 500.
     */
    static Response respond(RingErrorHandler eh, Request request, Throwable t) {
        Logger log = Logger.getLogger(RingErrorHandler.class.getName());
        if (eh == null) {
            log.log(Level.WARNING, "unhandled handler exception", t);
            return null;
        }
        try {
            Response r = eh.handle(request, t);
            if (r == null) {
                log.log(Level.WARNING, "error handler returned nil", t);
            }
            return r;
        } catch (Throwable inner) {
            log.log(Level.WARNING, "original handler exception", t);
            log.log(Level.WARNING, "error handler itself threw", inner);
            return null;
        }
    }
}

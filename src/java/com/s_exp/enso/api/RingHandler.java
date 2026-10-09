// ABOUTME: Java-side handler contract: maps a Request to a Response; the Clojure layer adapts
// ABOUTME: Ring handler functions to it and every protocol connection invokes it.
package com.s_exp.enso.api;

public interface RingHandler {
    Response handle(Request request);
}

// ABOUTME: Bounded walks of an exception's cause chain, safe against cycles and pathological depth,
// ABOUTME: used to classify failures (client I/O, typed request errors) without risking a hang.
package com.s_exp.enso.core;

/**
 * {@link Throwable#getCause} chains are user data: a handler can build a
 * cycle ({@code a.initCause(b); b.initCause(a)}) or an absurdly deep
 * chain. Every walk here stops after {@link #MAX_DEPTH} links, so
 * classifying an exception always terminates.
 */
public final class Causes {

    /** Links followed at most; real chains are a handful deep. */
    public static final int MAX_DEPTH = 32;

    private Causes() {}

    /** The first throwable in {@code t}'s cause chain (itself included) that is a {@code type}, or null. */
    public static <T extends Throwable> T find(Throwable t, Class<T> type) {
        Throwable c = t;
        for (int i = 0; c != null && i < MAX_DEPTH; i++) {
            if (type.isInstance(c)) return type.cast(c);
            Throwable next = c.getCause();
            if (next == c) return null;
            c = next;
        }
        return null;
    }
}

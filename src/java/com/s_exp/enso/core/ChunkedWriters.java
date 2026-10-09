// ABOUTME: Driver-side operations on api.ChunkedWriter that handlers must not reach: ending a
// ABOUTME: streamed body. ChunkedWriter registers its private implementation when it loads.
package com.s_exp.enso.core;

import com.s_exp.enso.api.ChunkedWriter;
import java.io.IOException;

/**
 * Ends a {@link ChunkedWriter}'s body: emits what is pending, the
 * terminating zero-length chunk on HTTP/1.1, and flushes. Kept off
 * ChunkedWriter's public API (handlers get the writer) by having
 * ChunkedWriter register a private method here when its class is
 * initialised, which happens before any writer exists.
 */
public final class ChunkedWriters {

    /** Implemented by ChunkedWriter. */
    public interface Finisher {
        void finish(ChunkedWriter writer) throws IOException;
    }

    private static volatile Finisher finisher;

    private ChunkedWriters() {}

    /** Called once, by ChunkedWriter's static initialiser. */
    public static void register(Finisher f) {
        if (finisher != null) {
            throw new IllegalStateException("ChunkedWriter finisher already registered");
        }
        finisher = f;
    }

    /** Ends {@code writer}'s body; idempotent. Server use only. */
    public static void finish(ChunkedWriter writer) throws IOException {
        finisher.finish(writer);
    }
}

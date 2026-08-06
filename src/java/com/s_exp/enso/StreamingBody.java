package com.s_exp.enso;

import java.io.IOException;

/**
 * Response body type that pushes bytes to the client over time via a
 * {@link ChunkedWriter}. Used for Server-Sent Events, long-polling, and other
 * long-lived streaming responses. The handler runs on a virtual thread and may
 * block indefinitely between writes.
 */
public interface StreamingBody {
    void write(ChunkedWriter writer) throws IOException;
}

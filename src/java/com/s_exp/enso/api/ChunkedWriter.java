package com.s_exp.enso.api;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Writer that emits HTTP/1.1 chunked-transfer-encoded chunks to the client.
 * Buffers small writes and emits them as a chunk whenever the buffer fills,
 * so memory stays bounded by the buffer size; {@link #flush()} forces the
 * accumulated bytes out as a single chunk. Do not touch a writer after the
 * handler returns — the server emits the terminating zero-length chunk
 * itself.
 */
public final class ChunkedWriter {

    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CHUNK_END = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] HEX = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

    private final OutputStream out;
    private final boolean framed;
    private final byte[] buf;
    // Chunk-size line scratch: up to 8 hex digits for an int, then CRLF.
    private final byte[] sizeLine = new byte[10];
    private int len;
    private boolean closed;

    public ChunkedWriter(OutputStream out, int bufferSize, boolean framed) {
        this.out = out;
        this.framed = framed;
        this.buf = new byte[Math.max(bufferSize, 512)];
    }

    /** Writes bytes into the pending chunk buffer. */
    public void write(byte[] data) throws IOException {
        write(data, 0, data.length);
    }

    /**
     * Writes a single byte into the pending chunk buffer. Used by
     * {@code java.io.OutputStream} wrappers to avoid a per-byte
     * {@code byte[]} allocation on the Clojure adapter side.
     */
    public void write(int b) throws IOException {
        ensureOpen();
        if (len == buf.length) {
            flushPending();
        }
        buf[len++] = (byte) b;
    }

    /**
     * Writes a range of bytes into the pending chunk buffer. A range that
     * doesn't fit emits the pending chunk first; one at least as large as
     * the buffer goes out as its own chunk without being copied.
     */
    public void write(byte[] data, int off, int length) throws IOException {
        ensureOpen();
        Objects.checkFromIndexSize(off, length, data.length);
        if (length > buf.length - len) {
            flushPending();
            if (length >= buf.length) {
                emitChunk(data, off, length);
                return;
            }
        }
        System.arraycopy(data, off, buf, len, length);
        len += length;
    }

    /** Writes a UTF-8 encoded string into the pending chunk buffer. */
    public void write(String s) throws IOException {
        write(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fast path for strings known to contain only 7-bit ASCII characters.
     * Skips the UTF-8 encoder + intermediate byte[] allocation. Throws
     * {@link IllegalArgumentException} on the first non-ASCII character rather
     * than silently corrupting the output — use {@link #write(String)} for
     * arbitrary text. A rejected string writes nothing.
     */
    public void writeAscii(String s) throws IOException {
        ensureOpen();
        int n = s.length();
        // Validated up front: once the buffer fills mid-string, part of it
        // is already on its way out and can't be taken back.
        for (int i = 0; i < n; i++) {
            if (s.charAt(i) > 127) {
                throw new IllegalArgumentException(
                    "writeAscii: non-ASCII character at index " + i);
            }
        }
        int i = 0;
        while (i < n) {
            if (len == buf.length) {
                flushPending();
            }
            int m = Math.min(n - i, buf.length - len);
            for (int j = 0; j < m; j++) {
                buf[len + j] = (byte) s.charAt(i + j);
            }
            len += m;
            i += m;
        }
    }

    /**
     * Emits any pending bytes as a single chunk and forces them onto the wire.
     * A no-op if nothing is pending. Handlers call this to guarantee client
     * visibility of an event.
     */
    public void flush() throws IOException {
        ensureOpen();
        flushPending();
        out.flush();
    }

    /** How many bytes are queued in the pending chunk (not yet written). */
    public int buffered() {
        return len;
    }

    public void closeInternal() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        flushPending();
        if (framed) {
            out.write(CHUNK_END);
        }
        out.flush();
    }

    private void flushPending() throws IOException {
        if (len == 0) {
            return;
        }
        emitChunk(buf, 0, len);
        len = 0;
    }

    private void emitChunk(byte[] data, int off, int length) throws IOException {
        if (length == 0) {
            return;
        }
        if (framed) {
            writeSizeLine(length);
            out.write(data, off, length);
            out.write(CRLF);
        } else {
            out.write(data, off, length);
        }
    }

    private void writeSizeLine(int v) throws IOException {
        // 4-byte int in hex is at most 8 digits, followed by CRLF
        int i = 8;
        do {
            sizeLine[--i] = HEX[v & 0xF];
            v >>>= 4;
        } while (v != 0);
        sizeLine[8] = '\r';
        sizeLine[9] = '\n';
        out.write(sizeLine, i, 10 - i);
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("ChunkedWriter is closed");
        }
    }
}

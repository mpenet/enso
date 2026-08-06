package com.s_exp.enso;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Writer that emits HTTP/1.1 chunked-transfer-encoded chunks to the client.
 * Buffers small writes; {@link #flush()} forces the accumulated bytes out as a
 * single chunk. Do not touch a writer after the handler returns — the server
 * emits the terminating zero-length chunk itself.
 */
public final class ChunkedWriter {

    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CHUNK_END = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] HEX = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

    private final OutputStream out;
    private final boolean framed;
    private byte[] buf;
    private int len;
    private boolean closed;

    ChunkedWriter(OutputStream out, int initialBufferSize, boolean framed) {
        this.out = out;
        this.framed = framed;
        this.buf = new byte[Math.max(initialBufferSize, 512)];
    }

    /** Writes bytes into the pending chunk buffer. */
    public void write(byte[] data) {
        write(data, 0, data.length);
    }

    /** Writes a range of bytes into the pending chunk buffer. */
    public void write(byte[] data, int off, int length) {
        ensureOpen();
        ensureCapacity(length);
        System.arraycopy(data, off, buf, len, length);
        len += length;
    }

    /** Writes a UTF-8 encoded string into the pending chunk buffer. */
    public void write(String s) {
        write(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fast path for strings known to contain only 7-bit ASCII characters.
     * Skips the UTF-8 encoder + intermediate byte[] allocation. Throws
     * {@link IllegalArgumentException} on the first non-ASCII character rather
     * than silently corrupting the output — use {@link #write(String)} for
     * arbitrary text.
     */
    public void writeAscii(String s) {
        ensureOpen();
        int n = s.length();
        ensureCapacity(n);
        int start = len;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c > 127) {
                len = start;
                throw new IllegalArgumentException(
                    "writeAscii: non-ASCII character at index " + i);
            }
            buf[len++] = (byte) c;
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

    void closeInternal() throws IOException {
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
        if (framed) {
            writeHex(len);
            out.write(CRLF);
            out.write(buf, 0, len);
            out.write(CRLF);
        } else {
            out.write(buf, 0, len);
        }
        len = 0;
    }

    private void writeHex(int v) throws IOException {
        // 4-byte int in hex is at most 8 digits
        byte[] tmp = new byte[8];
        int i = 8;
        do {
            tmp[--i] = HEX[v & 0xF];
            v >>>= 4;
        } while (v != 0);
        out.write(tmp, i, 8 - i);
    }

    private void ensureCapacity(int extra) {
        if (len + extra > buf.length) {
            int newLen = Math.max(buf.length * 2, len + extra);
            byte[] bigger = new byte[newLen];
            System.arraycopy(buf, 0, bigger, 0, len);
            buf = bigger;
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("ChunkedWriter is closed");
        }
    }
}

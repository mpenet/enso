// ABOUTME: Buffered writer for streamed response bodies (SSE, long-poll): HTTP/1.1 chunked
// ABOUTME: framing, or raw bytes for drivers that frame themselves (HTTP/2 DATA, HTTP/3).
package com.s_exp.enso.api;

import com.s_exp.enso.core.ChunkedWriters;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Writer for a streamed response body. On HTTP/1.1 it emits
 * chunked-transfer-encoded chunks (or raw bytes for a close-delimited or
 * fixed-length body); on HTTP/2 and HTTP/3 it writes raw bytes that the
 * driver frames as DATA. Buffers small writes and emits them whenever the
 * buffer fills, so memory stays bounded by the buffer size; {@link #flush()}
 * forces the accumulated bytes out. Do not touch a writer after the body
 * fn ({@link StreamingBody#write}) returns — the server then ends the body
 * itself (the terminating zero-length chunk on HTTP/1.1).
 */
public final class ChunkedWriter {

    static {
        ChunkedWriters.register(ChunkedWriter::finish);
    }

    /** Pending-chunk buffer size the drivers use for streamed bodies. */
    public static final int DEFAULT_BUFFER_BYTES = 8192;
    /**
     * Room kept in front of chunk data for its size line: up to 8 hex
     * digits for an int, then CRLF. See {@link #frame}.
     */
    public static final int SIZE_LINE_ROOM = 10;

    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CHUNK_END = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] HEX = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

    private final OutputStream out;
    private final boolean framed;
    // Pending chunk data sits at [dataStart, dataStart + len); when framed,
    // the size line is written in place in front of it and CRLF behind it,
    // so a chunk leaves in one write.
    private final byte[] buf;
    private final int dataStart;
    private final int capacity;
    // Chunk-size line scratch for chunks written without copying.
    private byte[] sizeLine;
    private int len;
    private boolean closed;
    private Charset charset = StandardCharsets.UTF_8;
    private long bytesWritten;

    public ChunkedWriter(OutputStream out, int bufferSize, boolean framed) {
        this(out, new byte[Math.max(bufferSize, 512)], framed);
    }

    /**
     * A writer over a caller-owned buffer (a connection reuses one for every
     * streamed response): used until the driver ends the body
     * ({@code ChunkedWriters.finish}), never after. At least 512 bytes.
     */
    public ChunkedWriter(OutputStream out, byte[] buffer, boolean framed) {
        if (buffer.length < 512) {
            throw new IllegalArgumentException("ChunkedWriter buffer below 512 bytes");
        }
        this.out = out;
        this.framed = framed;
        this.buf = buffer;
        this.dataStart = framed ? SIZE_LINE_ROOM : 0;
        this.capacity = buffer.length - (framed ? SIZE_LINE_ROOM + 2 : 0);
    }

    /**
     * Frames {@code len} bytes of chunk data at {@code buf[dataStart..]} in
     * place: the size line right before it (needs {@link #SIZE_LINE_ROOM}
     * bytes there) and CRLF right after it (2 bytes). Returns where the
     * framed chunk starts; it ends at {@code dataStart + len + 2}.
     */
    public static int frame(byte[] buf, int dataStart, int len) {
        buf[dataStart + len] = '\r';
        buf[dataStart + len + 1] = '\n';
        return sizeLine(buf, dataStart, len);
    }

    /** Writes the size line of a {@code len}-byte chunk ending at {@code end}; returns its start. */
    private static int sizeLine(byte[] buf, int end, int len) {
        int i = end - 2;
        buf[i] = '\r';
        buf[i + 1] = '\n';
        int v = len;
        do {
            buf[--i] = HEX[v & 0xF];
            v >>>= 4;
        } while (v != 0);
        return i;
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
        if (len == capacity) {
            flushPending();
        }
        buf[dataStart + len++] = (byte) b;
    }

    /**
     * Writes a range of bytes into the pending chunk buffer. A range that
     * doesn't fit emits the pending chunk first; one at least as large as
     * the buffer goes out as its own chunk without being copied.
     */
    public void write(byte[] data, int off, int length) throws IOException {
        ensureOpen();
        Objects.checkFromIndexSize(off, length, data.length);
        if (length > capacity - len) {
            flushPending();
            if (length >= capacity) {
                emitChunk(data, off, length);
                return;
            }
        }
        System.arraycopy(data, off, buf, dataStart + len, length);
        len += length;
    }

    /**
     * Writes a string, encoded with {@link #charset(Charset)} (UTF-8 unless
     * set), into the pending chunk buffer.
     */
    public void write(String s) throws IOException {
        write(s.getBytes(charset));
    }

    /**
     * Sets the charset {@link #write(String)} encodes with. The Clojure
     * adapter sets the response's ({@code Content-Type}) charset before the
     * body runs, as for String and seq bodies.
     */
    public void charset(Charset charset) {
        this.charset = Objects.requireNonNull(charset);
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
            if (len == capacity) {
                flushPending();
            }
            int m = Math.min(n - i, capacity - len);
            int at = dataStart + len;
            for (int j = 0; j < m; j++) {
                buf[at + j] = (byte) s.charAt(i + j);
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

    /** Body bytes handed to the output so far, framing excluded. */
    public long bytesWritten() {
        return bytesWritten;
    }

    // Ends the body; reached by drivers through ChunkedWriters.finish.
    private void finish() throws IOException {
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
        bytesWritten += len;
        if (framed) {
            int start = frame(buf, dataStart, len);
            out.write(buf, start, dataStart + len + 2 - start);
        } else {
            out.write(buf, 0, len);
        }
        len = 0;
    }

    /** A chunk at least as large as the buffer, written from the caller's array. */
    private void emitChunk(byte[] data, int off, int length) throws IOException {
        bytesWritten += length;
        if (framed) {
            byte[] line = sizeLine;
            if (line == null) {
                line = new byte[SIZE_LINE_ROOM];
                sizeLine = line;
            }
            int start = sizeLine(line, SIZE_LINE_ROOM, length);
            out.write(line, start, SIZE_LINE_ROOM - start);
            out.write(data, off, length);
            out.write(CRLF);
        } else {
            out.write(data, off, length);
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("ChunkedWriter is closed");
        }
    }
}

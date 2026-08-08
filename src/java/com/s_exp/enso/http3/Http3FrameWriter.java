package com.s_exp.enso.http3;

import java.nio.ByteBuffer;

/**
 * HTTP/3 frame serializer. Every {@code write*} method writes
 * {@code type-varint, length-varint, payload-bytes} into a
 * caller-supplied {@link ByteBuffer}. The caller then hands the
 * buffer's bytes to {@code quiche_conn_stream_send}.
 *
 * <p>The caller-owned-buffer shape lets {@link Http3Session} keep a single
 * per-connection scratch buffer and avoid per-frame allocations on the
 * hot response path. Two convenience methods that return a freshly
 * allocated buffer remain for one-shot init sites (SETTINGS, GOAWAY).
 */
public final class Http3FrameWriter {

    private Http3FrameWriter() {}

    /**
     * Write a HEADERS frame into {@code out}. Returns the buffer flipped
     * for reading; caller must {@code clear()} before reusing.
     */
    public static ByteBuffer writeHeaders(ByteBuffer out, byte[] encoded) {
        return writeFrame(out, Http3FrameType.HEADERS, encoded, 0, encoded.length);
    }

    /**
     * Encode QPACK headers directly into {@code out} as a HEADERS frame,
     * avoiding the intermediate byte[] that {@link #writeHeaders(ByteBuffer, byte[])}
     * would need. Uses a fixed 9-byte prefix (1-byte HEADERS type varint
     * + 8-byte fixed length varint) that gets back-patched with the
     * actual QPACK payload length after encoding. Wire overhead ≤ 7
     * bytes per HEADERS frame — trivial vs eliminating one allocation +
     * memcpy per response (task #123).
     *
     * <p>Note: clears {@code out} before writing and flips at the end.
     * Callers that want to concatenate a DATA frame after should use
     * {@link #appendHeadersFrom(ByteBuffer, Iterable)} +
     * {@link #appendData(ByteBuffer, byte[])} instead.
     */
    public static ByteBuffer writeHeadersFrom(
            ByteBuffer out, Iterable<String[]> headers) {
        out.clear();
        appendHeadersFrom(out, headers);
        out.flip();
        return out;
    }

    /**
     * Append a HEADERS frame at {@code out}'s current position. Does NOT
     * clear or flip — used to concatenate HEADERS + DATA into a single
     * buffer for one stream_send (task #143). Same fixed-8-byte length
     * back-patch as {@link #writeHeadersFrom}.
     */
    public static void appendHeadersFrom(
            ByteBuffer out, Iterable<String[]> headers) {
        out.put((byte) Http3FrameType.HEADERS);
        int lengthPos = out.position();
        out.position(lengthPos + 8);
        int bodyStart = out.position();
        com.s_exp.enso.http3.qpack.QpackFieldSection.encodeInto(out, headers);
        int bodyLen = out.position() - bodyStart;
        Http3Varint.encodeFixed8(out, lengthPos, bodyLen);
    }

    /** Write a DATA frame into {@code out}. Returns flipped buffer. */
    public static ByteBuffer writeData(ByteBuffer out, byte[] data) {
        return writeFrame(out, Http3FrameType.DATA, data, 0, data.length);
    }

    /**
     * Append a DATA frame at {@code out}'s current position. Does NOT
     * clear or flip. Companion to {@link #appendHeadersFrom}.
     */
    public static void appendData(ByteBuffer out, byte[] data) {
        Http3Varint.encode(out, Http3FrameType.DATA);
        Http3Varint.encode(out, data.length);
        out.put(data);
    }

    private static ByteBuffer writeFrame(ByteBuffer out, long type,
                                          byte[] payload, int off, int len) {
        int total = Http3Varint.size(type) + Http3Varint.size(len) + len;
        if (out.capacity() < total) {
            throw new IllegalArgumentException(
                "Http3FrameWriter buffer too small: need " + total
                + " have " + out.capacity());
        }
        out.clear();
        Http3Varint.encode(out, type);
        Http3Varint.encode(out, len);
        out.put(payload, off, len);
        out.flip();
        return out;
    }

    // -----------------------------------------------------------------
    // Convenience: fresh-buffer variants for cold init paths.
    // -----------------------------------------------------------------

    /** Encode a SETTINGS frame from a flat {id1, val1, id2, val2, ...} array. */
    public static ByteBuffer settings(long[] idValuePairs) {
        if ((idValuePairs.length & 1) != 0) {
            throw new IllegalArgumentException("settings must be id/value pairs");
        }
        int payloadSize = 0;
        for (long v : idValuePairs) payloadSize += Http3Varint.size(v);
        int total = Http3Varint.size(Http3FrameType.SETTINGS) + Http3Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Http3Varint.encode(out, Http3FrameType.SETTINGS);
        Http3Varint.encode(out, payloadSize);
        for (long v : idValuePairs) Http3Varint.encode(out, v);
        out.flip();
        return out;
    }

    /**
     * Convenience: allocate a fresh buffer + write HEADERS. Prefer
     * {@link #writeHeaders(ByteBuffer, byte[])} on the hot response path;
     * this variant exists for tests and other cold-path callers.
     */
    public static ByteBuffer headers(byte[] encoded) {
        return writeHeaders(ByteBuffer.allocate(16 + encoded.length), encoded);
    }

    /** Convenience: allocate + write DATA. See {@link #headers} caveat. */
    public static ByteBuffer data(byte[] payload) {
        return writeData(ByteBuffer.allocate(16 + payload.length), payload);
    }

    /** Encode a GOAWAY frame carrying the given stream/push ID. */
    public static ByteBuffer goaway(long id) {
        int payloadSize = Http3Varint.size(id);
        int total = Http3Varint.size(Http3FrameType.GOAWAY) + Http3Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Http3Varint.encode(out, Http3FrameType.GOAWAY);
        Http3Varint.encode(out, payloadSize);
        Http3Varint.encode(out, id);
        out.flip();
        return out;
    }
}

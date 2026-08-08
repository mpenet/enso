package com.s_exp.enso.quiche.h3;

import java.nio.ByteBuffer;

/**
 * HTTP/3 frame serializer. Every {@code write*} method writes
 * {@code type-varint, length-varint, payload-bytes} into a
 * caller-supplied {@link ByteBuffer}. The caller then hands the
 * buffer's bytes to {@code quiche_conn_stream_send}.
 *
 * <p>The caller-owned-buffer shape lets {@link H3Session} keep a single
 * per-connection scratch buffer and avoid per-frame allocations on the
 * hot response path. Two convenience methods that return a freshly
 * allocated buffer remain for one-shot init sites (SETTINGS, GOAWAY).
 */
public final class H3FrameWriter {

    private H3FrameWriter() {}

    /**
     * Write a HEADERS frame into {@code out}. Returns the buffer flipped
     * for reading; caller must {@code clear()} before reusing.
     */
    public static ByteBuffer writeHeaders(ByteBuffer out, byte[] encoded) {
        return writeFrame(out, H3FrameType.HEADERS, encoded, 0, encoded.length);
    }

    /**
     * Encode QPACK headers directly into {@code out} as a HEADERS frame,
     * avoiding the intermediate byte[] that {@link #writeHeaders(ByteBuffer, byte[])}
     * would need. Uses a fixed 9-byte prefix (1-byte HEADERS type varint
     * + 8-byte fixed length varint) that gets back-patched with the
     * actual QPACK payload length after encoding. Wire overhead ≤ 7
     * bytes per HEADERS frame — trivial vs eliminating one allocation +
     * memcpy per response (task #123).
     */
    public static ByteBuffer writeHeadersFrom(
            ByteBuffer out, Iterable<String[]> headers) {
        out.clear();
        int prefixStart = out.position();
        // HEADERS type = 0x01 → single-byte varint.
        out.put((byte) H3FrameType.HEADERS);
        int lengthPos = out.position();
        // Reserve 8 bytes for the length varint (fixed 8-byte form).
        out.position(lengthPos + 8);
        int bodyStart = out.position();
        com.s_exp.enso.quiche.qpack.QpackFieldSection.encodeInto(out, headers);
        int bodyLen = out.position() - bodyStart;
        Varint.encodeFixed8(out, lengthPos, bodyLen);
        out.flip();
        out.position(prefixStart);
        return out;
    }

    /** Write a DATA frame into {@code out}. Returns flipped buffer. */
    public static ByteBuffer writeData(ByteBuffer out, byte[] data) {
        return writeFrame(out, H3FrameType.DATA, data, 0, data.length);
    }

    private static ByteBuffer writeFrame(ByteBuffer out, long type,
                                          byte[] payload, int off, int len) {
        int total = Varint.size(type) + Varint.size(len) + len;
        if (out.capacity() < total) {
            throw new IllegalArgumentException(
                "H3FrameWriter buffer too small: need " + total
                + " have " + out.capacity());
        }
        out.clear();
        Varint.encode(out, type);
        Varint.encode(out, len);
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
        for (long v : idValuePairs) payloadSize += Varint.size(v);
        int total = Varint.size(H3FrameType.SETTINGS) + Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Varint.encode(out, H3FrameType.SETTINGS);
        Varint.encode(out, payloadSize);
        for (long v : idValuePairs) Varint.encode(out, v);
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
        int payloadSize = Varint.size(id);
        int total = Varint.size(H3FrameType.GOAWAY) + Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Varint.encode(out, H3FrameType.GOAWAY);
        Varint.encode(out, payloadSize);
        Varint.encode(out, id);
        out.flip();
        return out;
    }
}

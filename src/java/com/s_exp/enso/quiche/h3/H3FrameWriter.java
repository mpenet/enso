package com.s_exp.enso.quiche.h3;

import java.nio.ByteBuffer;

/**
 * HTTP/3 frame serializer. Frames are written as {@code type-varint,
 * length-varint, payload-bytes} into a caller-provided {@link ByteBuffer}.
 * The caller then hands the buffer's bytes to
 * {@code quiche_conn_stream_send} for wire transmission.
 *
 * <p>Frames are small on-wire; we allocate a fresh buffer per encode
 * rather than accepting one, then let the caller drain it.
 */
public final class H3FrameWriter {

    private H3FrameWriter() {}

    /** Encode a HEADERS frame with the QPACK-encoded field section. */
    public static ByteBuffer headers(byte[] encodedFieldSection) {
        return frame(H3FrameType.HEADERS, encodedFieldSection);
    }

    /** Encode a DATA frame. Zero-copy over {@code data}. */
    public static ByteBuffer data(byte[] data) {
        return frame(H3FrameType.DATA, data);
    }

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

    private static ByteBuffer frame(long type, byte[] payload) {
        int total = Varint.size(type) + Varint.size(payload.length) + payload.length;
        ByteBuffer out = ByteBuffer.allocate(total);
        Varint.encode(out, type);
        Varint.encode(out, payload.length);
        out.put(payload);
        out.flip();
        return out;
    }
}

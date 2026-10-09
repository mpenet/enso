// ABOUTME: QUIC variable-length integer encoder/decoder (RFC 9000 section 16) used by
// ABOUTME: HTTP/3 framing and stream-type prefixes.
package com.s_exp.enso.http3;

import java.nio.ByteBuffer;

/**
 * QUIC variable-length integer codec (RFC 9000 §16). Values 0..2^62-1
 * encoded in 1/2/4/8 bytes; the high two bits of the first byte carry
 * the length exponent (00 → 1 byte, 01 → 2, 10 → 4, 11 → 8).
 *
 * <p>Used everywhere in H3: frame type + length prefixes, stream type
 * prefixes on uni streams, header field index bases, etc.
 */
public final class Http3Varint {

    public static final long MAX_VALUE = (1L << 62) - 1;

    private Http3Varint() {}

    /** Bytes needed to encode {@code v}. */
    public static int size(long v) {
        if (v < 0) throw new IllegalArgumentException("negative varint: " + v);
        if (v < 64) return 1;
        if (v < 16384) return 2;
        if (v < 1073741824L) return 4;
        if (v <= MAX_VALUE) return 8;
        throw new IllegalArgumentException("varint too big: " + v);
    }

    /**
     * Force-encode {@code v} in exactly 8 bytes at absolute position
     * {@code pos}. Used by writers that need a fixed-size length prefix
     * they can back-patch after producing the payload — RFC 9000 §16
     * permits non-minimal encodings on the write side. Costs at most
     * 7 extra wire bytes vs the minimal form.
     */
    public static void encodeFixed8(ByteBuffer buf, int pos, long v) {
        if (v > MAX_VALUE) throw new IllegalArgumentException("varint too big: " + v);
        if (v < 0) throw new IllegalArgumentException("negative varint: " + v);
        buf.putLong(pos, v | 0xC000000000000000L);
    }

    /** Encode {@code v} into {@code buf} at the current position. */
    public static void encode(ByteBuffer buf, long v) {
        int n = size(v);
        switch (n) {
            case 1 -> buf.put((byte) v);
            case 2 -> buf.putShort((short) (v | 0x4000));
            case 4 -> buf.putInt((int) (v | 0x80000000L));
            case 8 -> buf.putLong(v | 0xC000000000000000L);
            default -> throw new AssertionError(n);
        }
    }

    /** Encodes {@code v} into {@code b} at {@code off}; returns the offset after it. */
    public static int encode(byte[] b, int off, long v) {
        int n = size(v);
        switch (n) {
            case 1 -> b[off] = (byte) v;
            case 2 -> {
                b[off] = (byte) ((v >>> 8) | 0x40);
                b[off + 1] = (byte) v;
            }
            case 4 -> {
                b[off] = (byte) ((v >>> 24) | 0x80);
                b[off + 1] = (byte) (v >>> 16);
                b[off + 2] = (byte) (v >>> 8);
                b[off + 3] = (byte) v;
            }
            default -> {
                b[off] = (byte) ((v >>> 56) | 0xC0);
                for (int i = 1; i < 8; i++) b[off + i] = (byte) (v >>> (56 - 8 * i));
            }
        }
        return off + n;
    }

    /**
     * Length of the varint whose first byte is {@code first} (1, 2, 4 or 8).
     */
    public static int length(int first) {
        return 1 << ((first & 0xFF) >>> 6);
    }

    /** Decodes the varint at {@code b[off]}; the caller checked {@link #length} bytes are there. */
    public static long decode(byte[] b, int off) {
        int first = b[off] & 0xFF;
        long v = first & 0x3F;
        int n = 1 << (first >>> 6);
        for (int i = 1; i < n; i++) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
    }

    /**
     * Decode a varint from {@code buf} at the current position, advancing.
     * @throws java.nio.BufferUnderflowException if fewer than the required 1/2/4/8
     *   bytes remain.
     */
    public static long decode(ByteBuffer buf) {
        int first = buf.get() & 0xFF;
        int prefix = first >>> 6;
        long value = first & 0x3F;
        return switch (prefix) {
            case 0 -> value;
            case 1 -> (value << 8) | (buf.get() & 0xFF);
            case 2 -> (value << 24)
                | ((long) (buf.get() & 0xFF) << 16)
                | ((long) (buf.get() & 0xFF) << 8)
                | (buf.get() & 0xFF);
            case 3 -> (value << 56)
                | ((long) (buf.get() & 0xFF) << 48)
                | ((long) (buf.get() & 0xFF) << 40)
                | ((long) (buf.get() & 0xFF) << 32)
                | ((long) (buf.get() & 0xFF) << 24)
                | ((long) (buf.get() & 0xFF) << 16)
                | ((long) (buf.get() & 0xFF) << 8)
                | (buf.get() & 0xFF);
            default -> throw new AssertionError(prefix);
        };
    }

    /**
     * Peek the total byte length of the varint starting at
     * {@code buf.position()} without advancing. Returns -1 if fewer than
     * one byte remains.
     */
    public static int peekLength(ByteBuffer buf) {
        if (!buf.hasRemaining()) return -1;
        int first = buf.get(buf.position()) & 0xFF;
        return 1 << (first >>> 6);
    }
}

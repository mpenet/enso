package com.s_exp.enso.quiche.h3;

import java.nio.ByteBuffer;

/**
 * QUIC variable-length integer codec (RFC 9000 §16). Values 0..2^62-1
 * encoded in 1/2/4/8 bytes; the high two bits of the first byte carry
 * the length exponent (00 → 1 byte, 01 → 2, 10 → 4, 11 → 8).
 *
 * <p>Used everywhere in H3: frame type + length prefixes, stream type
 * prefixes on uni streams, header field index bases, etc.
 */
public final class Varint {

    public static final long MAX_VALUE = (1L << 62) - 1;

    private Varint() {}

    /** Bytes needed to encode {@code v}. */
    public static int size(long v) {
        if (v < 0) throw new IllegalArgumentException("negative varint: " + v);
        if (v < 64) return 1;
        if (v < 16384) return 2;
        if (v < 1073741824L) return 4;
        if (v <= MAX_VALUE) return 8;
        throw new IllegalArgumentException("varint too big: " + v);
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

    /**
     * Decode a varint from {@code buf} at the current position, advancing.
     * @throws BufferUnderflowException if fewer than the required 1/2/4/8
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

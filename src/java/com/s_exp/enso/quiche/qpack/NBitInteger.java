package com.s_exp.enso.quiche.qpack;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * N-bit integer codec used throughout QPACK / HPACK (RFC 7541 §5.1, carried
 * into RFC 9204). A value is stored using an {@code n}-bit prefix in the
 * first byte; when it exceeds {@code 2^n - 1} the byte's low N bits are all
 * set and the remainder is emitted as continuation bytes (7 bits each,
 * high-bit set on non-terminal bytes).
 *
 * <p>Encoding APIs take the initial byte's high {@code 8-n} bits from the
 * caller (packed as {@code prefixBits}) so the caller can stuff instruction
 * type flags into those bits ahead of time.
 */
public final class NBitInteger {

    private NBitInteger() {}

    /**
     * @return the number of bytes an {@code n}-bit encoding of {@code value}
     *   would occupy.
     */
    public static int size(int n, long value) {
        if (value < 0) throw new IllegalArgumentException("negative: " + value);
        long mask = (1L << n) - 1;
        if (value < mask) return 1;
        int bytes = 1;
        long v = value - mask;
        while (v >= 128) {
            bytes++;
            v >>>= 7;
        }
        return bytes + 1;
    }

    /**
     * Encode {@code value} using an {@code n}-bit prefix. The high {@code 8-n}
     * bits of the first byte are OR'd with {@code prefixBits} — callers use
     * that space for instruction type markers (e.g. QPACK "S" indicator bit).
     */
    public static void encode(ByteBuffer out, int n, int prefixBits, long value) {
        if (value < 0) throw new IllegalArgumentException("negative: " + value);
        long mask = (1L << n) - 1;
        if (value < mask) {
            out.put((byte) (prefixBits | (int) value));
            return;
        }
        out.put((byte) (prefixBits | (int) mask));
        long v = value - mask;
        while (v >= 128) {
            out.put((byte) ((v & 0x7F) | 0x80));
            v >>>= 7;
        }
        out.put((byte) v);
    }

    /**
     * Decode an N-bit integer starting at {@code buf.position()}. The caller
     * must have already stripped any prefix-bit flags from {@code firstByte}
     * (i.e. passed only the low {@code n} bits).
     *
     * <p>{@code firstByte} is the low {@code n} bits of the byte that has
     * already been consumed by the caller. The continuation bytes (if any)
     * are consumed from {@code buf}.
     */
    public static long decode(ByteBuffer buf, int n, int firstByte) {
        long mask = (1L << n) - 1;
        long value = firstByte & mask;
        if (value < mask) return value;
        // Continuation.
        long m = 0;
        int b;
        do {
            b = buf.get() & 0xFF;
            value += ((long) (b & 0x7F)) << m;
            m += 7;
            if (m > 63) throw new IllegalStateException("N-bit int overflow");
        } while ((b & 0x80) != 0);
        return value;
    }
}

package com.s_exp.enso.http3.qpack;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * QPACK string literal codec (RFC 9204 §4.1.2). A length-prefixed byte
 * string; the {@code H} bit sitting in the same prefix byte as the length
 * varint signals Huffman encoding. Widely reused for header names AND
 * values across all QPACK instruction types.
 */
public final class NBitString {

    private NBitString() {}

    /**
     * Encode {@code str} into {@code out}. The N-bit length prefix uses
     * {@code n} bits at the start of the first byte; caller supplies any
     * type/flag bits to OR into the remaining {@code 8 - n} high bits via
     * {@code prefixBits}. The {@code H} (Huffman) bit sits at position
     * {@code 1 << n}; the caller determines whether to include it (usually
     * driven by {@code huffman}).
     */
    public static void encode(ByteBuffer out, int n, int prefixBits, String str,
                              boolean huffman) {
        byte[] utf8 = str.getBytes(StandardCharsets.UTF_8);
        int hBit = huffman ? (1 << n) : 0;
        int prefix = prefixBits | hBit;
        if (huffman) {
            int len = QpackHuffman.encodedLength(utf8, 0, utf8.length);
            NBitInteger.encode(out, n, prefix, len);
            // Encode into a temporary buffer at position; simplest path.
            byte[] tmp = new byte[len];
            QpackHuffman.encode(utf8, 0, utf8.length, tmp, 0);
            out.put(tmp);
        } else {
            NBitInteger.encode(out, n, prefix, utf8.length);
            out.put(utf8);
        }
    }

    /**
     * Decode a length-prefixed string given the first byte's low bits.
     * @param firstByte the low {@code n+1} bits of the byte already consumed
     *   (the H bit at {@code 1 << n} plus the length prefix bits).
     * @param n number of length prefix bits (the H bit at {@code 1 << n}
     *   sits above them).
     */
    public static String decode(ByteBuffer buf, int n, int firstByte) {
        boolean huffman = (firstByte & (1 << n)) != 0;
        long len = NBitInteger.decode(buf, n, firstByte);
        // Belt-and-suspenders: N-bit decode now guards against overflow
        // (task #137), but if a future refactor loses that guard a
        // negative len would silently produce NegativeArraySizeException
        // that escapes the QPACK error path.
        if (len < 0 || len > Integer.MAX_VALUE) {
            throw new IllegalStateException("string length out of range: " + len);
        }
        int l = (int) len;
        // Non-huffman path: pull directly from the ByteBuffer's backing
        // array into the String constructor — no intermediate byte[].
        if (!huffman) {
            String s;
            if (buf.hasArray()) {
                s = new String(buf.array(),
                    buf.arrayOffset() + buf.position(), l, StandardCharsets.UTF_8);
                buf.position(buf.position() + l);
            } else {
                byte[] raw = new byte[l];
                buf.get(raw);
                s = new String(raw, StandardCharsets.UTF_8);
            }
            return s;
        }
        // Huffman path: read into a per-thread scratch, then decode into
        // a second per-thread scratch. Both grow monotonically to fit
        // the largest header seen on this thread — task #128. String
        // ctor still copies out of scratch, so callers get their own
        // immutable String.
        byte[] rawScratch = ensureCap(RAW_TL.get(), l);
        if (rawScratch != RAW_TL.get()) RAW_TL.set(rawScratch);
        buf.get(rawScratch, 0, l);
        try {
            int decodedLen = QpackHuffman.decodedLength(rawScratch, 0, l);
            byte[] outScratch = ensureCap(OUT_TL.get(), decodedLen);
            if (outScratch != OUT_TL.get()) OUT_TL.set(outScratch);
            int actual = QpackHuffman.decodeInto(rawScratch, 0, l, outScratch);
            return new String(outScratch, 0, actual, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] ensureCap(byte[] buf, int need) {
        if (buf == null || buf.length < need) {
            return new byte[Math.max(64, Integer.highestOneBit(need - 1) << 1)];
        }
        return buf;
    }

    // Per-thread scratch used by the huffman decode path. Owner threads
    // (one per h3 conn) hit this repeatedly; each keeps its own scratch
    // sized to the largest header on that thread.
    private static final ThreadLocal<byte[]> RAW_TL = ThreadLocal.withInitial(() -> new byte[64]);
    private static final ThreadLocal<byte[]> OUT_TL = ThreadLocal.withInitial(() -> new byte[128]);
}

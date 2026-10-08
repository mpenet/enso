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
     * Encode {@code str} into {@code out} as ISO-8859-1 octets, the same
     * field-byte mapping h1 and h2 use; chars above U+00FF become
     * {@code '?'}. The N-bit length
     * prefix uses {@code n} bits at the start of the first byte; caller
     * supplies any type/flag bits to OR into the remaining {@code 8 - n}
     * high bits via {@code prefixBits}. With {@code allowHuffman}, the
     * Huffman form (H bit at {@code 1 << n}) is used only when it is
     * strictly shorter, so the encoded string never exceeds
     * {@link #maxEncodedLength}.
     */
    public static void encode(ByteBuffer out, int n, int prefixBits, String str,
                              boolean allowHuffman) {
        int rawLen = str.length();
        byte[] raw = ENC_TL.get();
        if (raw.length < rawLen) {
            raw = ensureCap(raw, rawLen);
            ENC_TL.set(raw);
        }
        for (int i = 0; i < rawLen; i++) {
            char c = str.charAt(i);
            raw[i] = c <= 0xFF ? (byte) c : (byte) '?';
        }
        int huffLen = allowHuffman ? QpackHuffman.encodedLength(raw, 0, rawLen) : Integer.MAX_VALUE;
        if (huffLen < rawLen) {
            NBitInteger.encode(out, n, prefixBits | (1 << n), huffLen);
            if (out.remaining() < huffLen) throw new java.nio.BufferOverflowException();
            if (out.hasArray()) {
                QpackHuffman.encode(raw, 0, rawLen, out.array(), out.arrayOffset() + out.position());
                out.position(out.position() + huffLen);
            } else {
                byte[] tmp = new byte[huffLen];
                QpackHuffman.encode(raw, 0, rawLen, tmp, 0);
                out.put(tmp);
            }
        } else {
            NBitInteger.encode(out, n, prefixBits, rawLen);
            out.put(raw, 0, rawLen);
        }
    }

    /**
     * Upper bound on what {@link #encode} writes for {@code str}: length
     * prefix (≤ 6 bytes for any int) plus one octet per char, which
     * Huffman output never exceeds.
     */
    public static int maxEncodedLength(String str) {
        return 6 + str.length();
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
        // The length is peer-controlled: check it against the bytes
        // actually present before sizing any scratch or String from it.
        if (len > buf.remaining()) {
            throw new IllegalStateException("string length " + len
                + " exceeds remaining " + buf.remaining());
        }
        int l = (int) len;
        // Non-huffman path: pull directly from the ByteBuffer's backing
        // array into the String constructor — no intermediate byte[].
        if (!huffman) {
            String s;
            if (buf.hasArray()) {
                s = new String(buf.array(),
                    buf.arrayOffset() + buf.position(), l, StandardCharsets.ISO_8859_1);
                buf.position(buf.position() + l);
            } else {
                byte[] raw = new byte[l];
                buf.get(raw);
                s = new String(raw, StandardCharsets.ISO_8859_1);
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
            return new String(outScratch, 0, actual, StandardCharsets.ISO_8859_1);
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
    // Per-thread scratch for the encode path's ASCII bytes.
    private static final ThreadLocal<byte[]> ENC_TL = ThreadLocal.withInitial(() -> new byte[256]);
}

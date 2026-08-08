package com.s_exp.enso.quiche.qpack;

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
        if (len > Integer.MAX_VALUE) {
            throw new IllegalStateException("string too long: " + len);
        }
        int l = (int) len;
        byte[] raw = new byte[l];
        buf.get(raw);
        byte[] bytes;
        if (huffman) {
            try {
                bytes = QpackHuffman.decode(raw, 0, l);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        } else {
            bytes = raw;
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }
}

package com.s_exp.enso.http3.qpack;

import com.s_exp.enso.HpackHuffman;
import java.io.IOException;

/**
 * QPACK Huffman codec — trivial facade over {@link HpackHuffman}. Per RFC
 * 9204 §5.2 QPACK uses the same 257-code static Huffman table as HPACK
 * (RFC 7541 Appendix B), so there is nothing to re-implement here beyond
 * providing a QPACK-namespaced entry point.
 */
public final class QpackHuffman {

    private QpackHuffman() {}

    /** Bytes needed to Huffman-encode {@code src[off..off+len]}. */
    public static int encodedLength(byte[] src, int off, int len) {
        return HpackHuffman.encodedLength(src, off, len);
    }

    /** Encode {@code src[off..off+len]} into {@code dst} at {@code dstOff}. */
    public static int encode(byte[] src, int off, int len, byte[] dst, int dstOff) {
        return HpackHuffman.encode(src, off, len, dst, dstOff);
    }

    /** Decode {@code src[off..off+len]} to a fresh byte[]. */
    public static byte[] decode(byte[] src, int off, int len) throws IOException {
        return HpackHuffman.decode(src, off, len);
    }

    /**
     * Upper bound on the decoded byte count. Uses the HPACK formula
     * {@code (len * 8) / 5 + 1} which is the theoretical worst case for
     * the 5-bit shortest Huffman code.
     */
    public static int decodedLength(byte[] src, int off, int len) {
        return Math.max(16, (len * 8) / 5 + 1);
    }

    /**
     * Decode into caller-supplied {@code dst}, returning bytes written.
     * {@code dst} must be at least {@link #decodedLength(byte[], int, int)}
     * bytes. Zero-allocation path for hot QPACK decoders (task #128).
     */
    public static int decodeInto(byte[] src, int off, int len, byte[] dst)
            throws IOException {
        return HpackHuffman.decodeInto(src, off, len, dst);
    }
}

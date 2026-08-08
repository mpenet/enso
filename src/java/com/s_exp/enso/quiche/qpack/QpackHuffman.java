package com.s_exp.enso.quiche.qpack;

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
}

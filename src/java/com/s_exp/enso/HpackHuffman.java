package com.s_exp.enso;

import java.io.IOException;

/**
 * HPACK Huffman codec per RFC 7541 Appendix B.
 *
 * <p>Encoding: iterate each byte, look up its (code, bit-length), pack into
 * the output buffer.
 *
 * <p>Decoding: walk a canonical binary tree bit-by-bit. Simple, correct;
 * table-driven acceleration can come later if profiling shows Huffman decode
 * as a hotspot.
 */
public final class HpackHuffman {

    private HpackHuffman() {
    }

    /**
     * Canonical Huffman codes from RFC 7541 Appendix B, indexed by symbol value
     * (0-256). Entry format: code stored in the high 32 bits, bit-length in the
     * low 8 bits.
     */
    private static final long[] CODES = new long[257];
    private static final int EOS_SYMBOL = 256;

    static {
        // Symbol → (code, bit-length). Manually transcribed from RFC 7541 Appendix B.
        put(  0, 0x1ff8,     13); put(  1, 0x7fffd8,   23); put(  2, 0xfffffe2,  28); put(  3, 0xfffffe3,  28);
        put(  4, 0xfffffe4,  28); put(  5, 0xfffffe5,  28); put(  6, 0xfffffe6,  28); put(  7, 0xfffffe7,  28);
        put(  8, 0xfffffe8,  28); put(  9, 0xffffea,   24); put( 10, 0x3ffffffc, 30); put( 11, 0xfffffe9,  28);
        put( 12, 0xfffffea,  28); put( 13, 0x3ffffffd, 30); put( 14, 0xfffffeb,  28); put( 15, 0xfffffec,  28);
        put( 16, 0xfffffed,  28); put( 17, 0xfffffee,  28); put( 18, 0xfffffef,  28); put( 19, 0xffffff0,  28);
        put( 20, 0xffffff1,  28); put( 21, 0xffffff2,  28); put( 22, 0x3ffffffe, 30); put( 23, 0xffffff3,  28);
        put( 24, 0xffffff4,  28); put( 25, 0xffffff5,  28); put( 26, 0xffffff6,  28); put( 27, 0xffffff7,  28);
        put( 28, 0xffffff8,  28); put( 29, 0xffffff9,  28); put( 30, 0xffffffa,  28); put( 31, 0xffffffb,  28);
        put( 32, 0x14,        6); put( 33, 0x3f8,     10); put( 34, 0x3f9,     10); put( 35, 0xffa,     12);
        put( 36, 0x1ff9,     13); put( 37, 0x15,       6); put( 38, 0xf8,       8); put( 39, 0x7fa,     11);
        put( 40, 0x3fa,      10); put( 41, 0x3fb,     10); put( 42, 0xf9,       8); put( 43, 0x7fb,     11);
        put( 44, 0xfa,        8); put( 45, 0x16,       6); put( 46, 0x17,       6); put( 47, 0x18,       6);
        put( 48, 0x0,         5); put( 49, 0x1,        5); put( 50, 0x2,        5); put( 51, 0x19,       6);
        put( 52, 0x1a,        6); put( 53, 0x1b,       6); put( 54, 0x1c,       6); put( 55, 0x1d,       6);
        put( 56, 0x1e,        6); put( 57, 0x1f,       6); put( 58, 0x5c,       7); put( 59, 0xfb,       8);
        put( 60, 0x7ffc,     15); put( 61, 0x20,       6); put( 62, 0xffb,     12); put( 63, 0x3fc,     10);
        put( 64, 0x1ffa,     13); put( 65, 0x21,       6); put( 66, 0x5d,       7); put( 67, 0x5e,       7);
        put( 68, 0x5f,        7); put( 69, 0x60,       7); put( 70, 0x61,       7); put( 71, 0x62,       7);
        put( 72, 0x63,        7); put( 73, 0x64,       7); put( 74, 0x65,       7); put( 75, 0x66,       7);
        put( 76, 0x67,        7); put( 77, 0x68,       7); put( 78, 0x69,       7); put( 79, 0x6a,       7);
        put( 80, 0x6b,        7); put( 81, 0x6c,       7); put( 82, 0x6d,       7); put( 83, 0x6e,       7);
        put( 84, 0x6f,        7); put( 85, 0x70,       7); put( 86, 0x71,       7); put( 87, 0x72,       7);
        put( 88, 0xfc,        8); put( 89, 0x73,       7); put( 90, 0xfd,       8); put( 91, 0x1ffb,    13);
        put( 92, 0x7fff0,    19); put( 93, 0x1ffc,    13); put( 94, 0x3ffc,    14); put( 95, 0x22,       6);
        put( 96, 0x7ffd,     15); put( 97, 0x3,        5); put( 98, 0x23,       6); put( 99, 0x4,        5);
        put(100, 0x24,        6); put(101, 0x5,        5); put(102, 0x25,       6); put(103, 0x26,       6);
        put(104, 0x27,        6); put(105, 0x6,        5); put(106, 0x74,       7); put(107, 0x75,       7);
        put(108, 0x28,        6); put(109, 0x29,       6); put(110, 0x2a,       6); put(111, 0x7,        5);
        put(112, 0x2b,        6); put(113, 0x76,       7); put(114, 0x2c,       6); put(115, 0x8,        5);
        put(116, 0x9,         5); put(117, 0x2d,       6); put(118, 0x77,       7); put(119, 0x78,       7);
        put(120, 0x79,        7); put(121, 0x7a,       7); put(122, 0x7b,       7); put(123, 0x7ffe,    15);
        put(124, 0x7fc,      11); put(125, 0x3ffd,    14); put(126, 0x1ffd,    13); put(127, 0xffffffc,  28);
        put(128, 0xfffe6,    20); put(129, 0x3fffd2,  22); put(130, 0xfffe7,   20); put(131, 0xfffe8,   20);
        put(132, 0x3fffd3,   22); put(133, 0x3fffd4,  22); put(134, 0x3fffd5,  22); put(135, 0x7fffd9,  23);
        put(136, 0x3fffd6,   22); put(137, 0x7fffda,  23); put(138, 0x7fffdb,  23); put(139, 0x7fffdc,  23);
        put(140, 0x7fffdd,   23); put(141, 0x7fffde,  23); put(142, 0xffffeb,  24); put(143, 0x7fffdf,  23);
        put(144, 0xffffec,   24); put(145, 0xffffed,  24); put(146, 0x3fffd7,  22); put(147, 0x7fffe0,  23);
        put(148, 0xffffee,   24); put(149, 0x7fffe1,  23); put(150, 0x7fffe2,  23); put(151, 0x7fffe3,  23);
        put(152, 0x7fffe4,   23); put(153, 0x1fffdc,  21); put(154, 0x3fffd8,  22); put(155, 0x7fffe5,  23);
        put(156, 0x3fffd9,   22); put(157, 0x7fffe6,  23); put(158, 0x7fffe7,  23); put(159, 0xffffef,  24);
        put(160, 0x3fffda,   22); put(161, 0x1fffdd,  21); put(162, 0xfffe9,   20); put(163, 0x3fffdb,  22);
        put(164, 0x3fffdc,   22); put(165, 0x7fffe8,  23); put(166, 0x7fffe9,  23); put(167, 0x1fffde,  21);
        put(168, 0x7fffea,   23); put(169, 0x3fffdd,  22); put(170, 0x3fffde,  22); put(171, 0xfffff0,  24);
        put(172, 0x1fffdf,   21); put(173, 0x3fffdf,  22); put(174, 0x7fffeb,  23); put(175, 0x7fffec,  23);
        put(176, 0x1fffe0,   21); put(177, 0x1fffe1,  21); put(178, 0x3fffe0,  22); put(179, 0x1fffe2,  21);
        put(180, 0x7fffed,   23); put(181, 0x3fffe1,  22); put(182, 0x7fffee,  23); put(183, 0x7fffef,  23);
        put(184, 0xfffea,    20); put(185, 0x3fffe2,  22); put(186, 0x3fffe3,  22); put(187, 0x3fffe4,  22);
        put(188, 0x7ffff0,   23); put(189, 0x3fffe5,  22); put(190, 0x3fffe6,  22); put(191, 0x7ffff1,  23);
        put(192, 0x3ffffe0,  26); put(193, 0x3ffffe1, 26); put(194, 0xfffeb,   20); put(195, 0x7fff1,   19);
        put(196, 0x3fffe7,   22); put(197, 0x7ffff2,  23); put(198, 0x3fffe8,  22); put(199, 0x1ffffec, 25);
        put(200, 0x3ffffe2,  26); put(201, 0x3ffffe3, 26); put(202, 0x3ffffe4, 26); put(203, 0x7ffffde, 27);
        put(204, 0x7ffffdf,  27); put(205, 0x3ffffe5, 26); put(206, 0xfffff1,  24); put(207, 0x1ffffed, 25);
        put(208, 0x7fff2,    19); put(209, 0x1fffe3,  21); put(210, 0x3ffffe6, 26); put(211, 0x7ffffe0, 27);
        put(212, 0x7ffffe1,  27); put(213, 0x3ffffe7, 26); put(214, 0x7ffffe2, 27); put(215, 0xfffff2,  24);
        put(216, 0x1fffe4,   21); put(217, 0x1fffe5,  21); put(218, 0x3ffffe8, 26); put(219, 0x3ffffe9, 26);
        put(220, 0xffffffd,  28); put(221, 0x7ffffe3, 27); put(222, 0x7ffffe4, 27); put(223, 0x7ffffe5, 27);
        put(224, 0xfffec,    20); put(225, 0xfffff3,  24); put(226, 0xfffed,   20); put(227, 0x1fffe6,  21);
        put(228, 0x3fffe9,   22); put(229, 0x1fffe7,  21); put(230, 0x1fffe8,  21); put(231, 0x7ffff3,  23);
        put(232, 0x3fffea,   22); put(233, 0x3fffeb,  22); put(234, 0x1ffffee, 25); put(235, 0x1ffffef, 25);
        put(236, 0xfffff4,   24); put(237, 0xfffff5,  24); put(238, 0x3ffffea, 26); put(239, 0x7ffff4,  23);
        put(240, 0x3ffffeb,  26); put(241, 0x7ffffe6, 27); put(242, 0x3ffffec, 26); put(243, 0x3ffffed, 26);
        put(244, 0x7ffffe7,  27); put(245, 0x7ffffe8, 27); put(246, 0x7ffffe9, 27); put(247, 0x7ffffea, 27);
        put(248, 0x7ffffeb,  27); put(249, 0xffffffe, 28); put(250, 0x7ffffec, 27); put(251, 0x7ffffed, 27);
        put(252, 0x7ffffee,  27); put(253, 0x7ffffef, 27); put(254, 0x7fffff0, 27); put(255, 0x3ffffee, 26);
        put(EOS_SYMBOL, 0x3fffffff, 30);
    }

    private static void put(int symbol, long code, int bits) {
        CODES[symbol] = (code << 8) | bits;
    }

    // ---- Encoder --------------------------------------------------------

    /** Returns the encoded length in bytes for {@code bytes}. */
    static int encodedLength(byte[] bytes, int off, int len) {
        long bits = 0;
        for (int i = 0; i < len; i++) {
            bits += CODES[bytes[off + i] & 0xFF] & 0xFF;
        }
        return (int) ((bits + 7) >>> 3);
    }

    /** Encodes {@code bytes[off..off+len]} into {@code out} at {@code outOff}. Returns bytes written. */
    static int encode(byte[] bytes, int off, int len, byte[] out, int outOff) {
        long buffer = 0;
        int bits = 0;
        int written = 0;
        for (int i = 0; i < len; i++) {
            long entry = CODES[bytes[off + i] & 0xFF];
            int codeBits = (int) (entry & 0xFF);
            long code = entry >>> 8;
            buffer = (buffer << codeBits) | code;
            bits += codeBits;
            while (bits >= 8) {
                bits -= 8;
                out[outOff + written++] = (byte) ((buffer >>> bits) & 0xFF);
            }
        }
        if (bits > 0) {
            // Pad the last byte with the most-significant bits of the EOS
            // symbol per RFC 7541 §5.2 (all-ones works because EOS starts
            // with a run of 1s).
            buffer = (buffer << (8 - bits)) | ((1L << (8 - bits)) - 1);
            out[outOff + written++] = (byte) (buffer & 0xFF);
        }
        return written;
    }

    // ---- Decoder --------------------------------------------------------

    /**
     * Binary tree of Huffman codes; leaves encode the symbol value (or EOS
     * marker) in the {@code symbol} field. Internal nodes hold left/right
     * child indices into the same array. Built lazily on first decode.
     */
    private static final int[] TREE_LEFT;
    private static final int[] TREE_RIGHT;
    private static final int[] TREE_SYMBOL;

    static {
        // Upper bound on node count: 257 leaves + up to 30 internal per branch.
        int cap = 4096;
        int[] left  = new int[cap];
        int[] right = new int[cap];
        int[] symbol = new int[cap];
        for (int i = 0; i < cap; i++) {
            left[i] = -1;
            right[i] = -1;
            symbol[i] = -1;
        }
        int next = 1; // node 0 is the root

        for (int s = 0; s < CODES.length; s++) {
            long entry = CODES[s];
            int bits = (int) (entry & 0xFF);
            long code = entry >>> 8;
            int node = 0;
            for (int b = bits - 1; b >= 0; b--) {
                int bit = (int) ((code >>> b) & 1);
                int[] arr = (bit == 0) ? left : right;
                int child = arr[node];
                if (child == -1) {
                    child = next++;
                    if (child >= cap) {
                        int newCap = cap * 2;
                        left = java.util.Arrays.copyOf(left, newCap);
                        right = java.util.Arrays.copyOf(right, newCap);
                        symbol = java.util.Arrays.copyOf(symbol, newCap);
                        for (int j = cap; j < newCap; j++) {
                            left[j] = right[j] = symbol[j] = -1;
                        }
                        cap = newCap;
                        arr = (bit == 0) ? left : right;
                    }
                    arr[node] = child;
                }
                node = child;
            }
            symbol[node] = s;
        }
        TREE_LEFT = left;
        TREE_RIGHT = right;
        TREE_SYMBOL = symbol;
    }

    /**
     * Decodes Huffman-encoded {@code src[off..off+len]} into a fresh byte[].
     * Trailing padding of up to 7 bits of the EOS symbol prefix (all 1s) is
     * accepted; anything longer is a COMPRESSION_ERROR.
     */
    public static byte[] decode(byte[] src, int off, int len) throws IOException {
        // Allocate a fresh output sized to the encoded worst case. Test path
        // and one-shot callers use this. Hot decoders should call
        // {@link #decodeInto} with a reusable scratch buffer.
        byte[] out = new byte[Math.max(16, (len * 8) / 5 + 1)];
        int outLen = decodeInto(src, off, len, out);
        return java.util.Arrays.copyOf(out, outLen);
    }

    /**
     * Decode into a caller-supplied scratch byte[]. Returns the number of
     * bytes written. Throws {@link IOException} if the scratch is too small —
     * caller should grow (upper bound is {@code (len * 8) / 5 + 1}) and retry.
     */
    public static int decodeInto(byte[] src, int off, int len, byte[] dst) throws IOException {
        int outLen = 0;
        int node = 0;
        int bitsSeen = 0;
        for (int i = 0; i < len; i++) {
            int b = src[off + i] & 0xFF;
            for (int bit = 7; bit >= 0; bit--) {
                int taken = (b >>> bit) & 1;
                node = (taken == 0) ? TREE_LEFT[node] : TREE_RIGHT[node];
                bitsSeen++;
                if (node == -1) {
                    throw new IOException("HPACK Huffman: invalid code");
                }
                int sym = TREE_SYMBOL[node];
                if (sym != -1) {
                    if (sym == EOS_SYMBOL) {
                        throw new IOException("HPACK Huffman: EOS symbol in stream");
                    }
                    if (outLen == dst.length) {
                        throw new IOException("HPACK Huffman: output buffer overflow");
                    }
                    dst[outLen++] = (byte) sym;
                    node = 0;
                    bitsSeen = 0;
                }
            }
        }
        // Trailing bits must be a prefix of the EOS symbol (all 1s), at most 7 bits.
        if (bitsSeen > 7) {
            throw new IOException("HPACK Huffman: incomplete symbol at end of stream");
        }
        if (bitsSeen > 0) {
            // Check trailing bits were all 1s by walking from the current node —
            // it must be reachable from root by following only 'right' links.
            int check = 0;
            for (int i = 0; i < bitsSeen; i++) {
                check = TREE_RIGHT[check];
                if (check == -1) {
                    throw new IOException("HPACK Huffman: invalid padding");
                }
            }
            if (check != node) {
                throw new IOException("HPACK Huffman: invalid padding");
            }
        }
        return outLen;
    }
}

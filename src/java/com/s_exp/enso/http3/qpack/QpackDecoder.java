// ABOUTME: Reusable QPACK field-section decoder reading straight from a byte range and handing each
// ABOUTME: field to a sink: no intermediate lists or pairs, interned names, Huffman scratch reused.
package com.s_exp.enso.http3.qpack;

import com.s_exp.enso.core.HeaderNames;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Decodes a field section (RFC 9204 §4.5) under a dynamic-table capacity
 * of 0, exactly like {@link QpackFieldSection#decode(byte[], long)}, but
 * from {@code buf[off, off + len)} into a {@link FieldSink}. Names from
 * the static table, and literal names matching a well-known header byte
 * for byte, are shared String constants; values from the static table too.
 * Every other name and value is one new String.
 *
 * <p>Strings repeat across requests (authority, user-agent, accept,
 * cookies of one client...): a direct-mapped cache keyed by the encoded
 * bytes of short literals returns the String decoded last time, so a
 * repeated value costs a hash and a byte comparison instead of a Huffman
 * decode and an allocation. Strings are immutable, so sharing them across
 * requests is safe; a collision only costs a miss.
 *
 * <p>One instance per thread (it keeps a cursor, Huffman scratch and the
 * cache). Errors are {@link QpackException}s with the same codes and
 * levels as the list decoder.
 */
public final class QpackDecoder {

    /** Receives each decoded field in wire order. */
    public interface FieldSink {
        void field(String name, String value);
    }

    private static final int CACHE_SIZE = 512;
    private static final int CACHE_MAX_LEN = 64;

    private byte[] buf;
    private int pos;
    private int end;
    private byte[] huffman = new byte[256];
    // Decoded-string cache: encoded bytes (and Huffman flag) → String.
    // Keys live in one fixed array, so a miss allocates nothing but the
    // String itself.
    private final byte[] cacheKeys = new byte[CACHE_SIZE * CACHE_MAX_LEN];
    private final int[] cacheLengths = new int[CACHE_SIZE];
    private final boolean[] cacheHuffman = new boolean[CACHE_SIZE];
    private final String[] cacheValues = new String[CACHE_SIZE];

    /** Decodes {@code buf[off, off + len)}; {@code maxDecodedSize <= 0} disables the size cap. */
    public void decode(byte[] buf, int off, int len, long maxDecodedSize, FieldSink sink) {
        this.buf = buf;
        this.pos = off;
        this.end = off + len;
        try {
            int b0 = next();
            long requiredInsertCount = integer(8, b0);
            int b1 = next();
            integer(7, b1 & 0x7F);
            if (requiredInsertCount != 0) {
                throw failed("peer used dynamic table (RIC=" + requiredInsertCount
                    + ") but advertised capacity is 0");
            }
            long decodedSize = 0;
            while (pos < end) {
                int b = next();
                String name;
                String value;
                if ((b & 0x80) != 0) {
                    // Indexed Field Line: 1 T XXXXXX
                    if ((b & 0x40) == 0) throw failed("dynamic indexed field line but capacity is 0");
                    String[] entry = staticEntry(integer(6, b & 0x3F));
                    name = entry[0];
                    value = entry[1];
                } else if ((b & 0xC0) == 0x40) {
                    // Literal Field Line with Name Reference: 0 1 N T XXXX
                    if ((b & 0x10) == 0) throw failed("dynamic name reference but capacity is 0");
                    name = staticEntry(integer(4, b & 0x0F))[0];
                    value = string(7, next(), false);
                } else if ((b & 0xE0) == 0x20) {
                    // Literal Field Line with Literal Name: 0 0 1 N H XXX.
                    // Names are kept verbatim: an uppercase name makes the
                    // request malformed (RFC 9114 §4.2), checked by the caller.
                    name = string(3, b & 0x0F, true);
                    value = string(7, next(), false);
                } else if ((b & 0xF0) == 0x10) {
                    throw failed("post-base indexed field line but capacity is 0");
                } else {
                    throw failed("post-base literal field line but capacity is 0");
                }
                if (maxDecodedSize > 0) {
                    decodedSize += name.length() + value.length() + 32L;
                    if (decodedSize > maxDecodedSize) {
                        throw new QpackException(QpackException.H3_EXCESSIVE_LOAD, true,
                            "field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE " + maxDecodedSize);
                    }
                }
                sink.field(name, value);
            }
        } finally {
            this.buf = null;
        }
    }

    private static QpackException failed(String why) {
        return new QpackException(QpackException.QPACK_DECOMPRESSION_FAILED, false, why);
    }

    private int next() {
        if (pos >= end) throw failed("truncated QPACK field section");
        return buf[pos++] & 0xFF;
    }

    private static String[] staticEntry(long idx) {
        if (idx >= QpackStaticTable.size()) throw failed("static index out of range: " + idx);
        return QpackStaticTable.get((int) idx);
    }

    /** RFC 7541 §5.1 integer with an {@code n}-bit prefix whose bits are {@code first}. */
    private long integer(int n, int first) {
        long mask = (1L << n) - 1;
        long value = first & mask;
        if (value < mask) return value;
        int m = 0;
        int b;
        do {
            if (m >= 63) throw failed("malformed N-bit int in QPACK field section");
            b = next();
            value += (long) (b & 0x7F) << m;
            if (value < 0) throw failed("malformed N-bit int in QPACK field section");
            m += 7;
        } while ((b & 0x80) != 0);
        return value;
    }

    /** A string literal whose prefix byte's low bits are {@code first} (H at {@code 1 << n}). */
    private String string(int n, int first, boolean name) {
        boolean huff = (first & (1 << n)) != 0;
        long len = integer(n, first);
        // Peer-controlled: checked against the bytes present before use.
        if (len > end - pos) throw failed("string length " + len + " exceeds remaining " + (end - pos));
        int l = (int) len;
        int from = pos;
        pos += l;
        int slot = -1;
        if (l <= CACHE_MAX_LEN) {
            slot = slot(buf, from, l, huff);
            int k = slot * CACHE_MAX_LEN;
            String cached = cacheValues[slot];
            if (cached != null && cacheLengths[slot] == l && cacheHuffman[slot] == huff
                    && java.util.Arrays.equals(cacheKeys, k, k + l, buf, from, from + l)) {
                return cached;
            }
        }
        String decoded = decodeString(from, l, huff, name);
        if (slot >= 0) {
            System.arraycopy(buf, from, cacheKeys, slot * CACHE_MAX_LEN, l);
            cacheLengths[slot] = l;
            cacheHuffman[slot] = huff;
            cacheValues[slot] = decoded;
        }
        return decoded;
    }

    private static int slot(byte[] b, int off, int len, boolean huff) {
        int h = huff ? 0x2D51 : 0x1B87;
        for (int i = 0; i < len; i++) h = (h ^ b[off + i]) * 0x01000193;
        h ^= h >>> 15;
        return h & (CACHE_SIZE - 1);
    }

    private String decodeString(int from, int l, boolean huff, boolean name) {
        if (!huff) {
            if (name) {
                String known = exactName(buf, from, l);
                if (known != null) return known;
            }
            return new String(buf, from, l, StandardCharsets.ISO_8859_1);
        }
        int cap = QpackHuffman.decodedLength(buf, from, l);
        if (huffman.length < cap) huffman = new byte[Math.max(cap, huffman.length * 2)];
        int decoded;
        try {
            decoded = QpackHuffman.decodeInto(buf, from, l, huffman);
        } catch (IOException | RuntimeException e) {
            throw new QpackException(QpackException.QPACK_DECOMPRESSION_FAILED, false,
                "malformed string in QPACK field section", e);
        }
        if (name) {
            String known = exactName(huffman, 0, decoded);
            if (known != null) return known;
        }
        return new String(huffman, 0, decoded, StandardCharsets.ISO_8859_1);
    }

    /** The shared constant for a well-known header name spelled exactly (lowercase) as in {@code b}. */
    private static String exactName(byte[] b, int off, int len) {
        if (len == 0) return null;
        String n = HeaderNames.lookup(b, off, off + len);
        if (n == null) return null;
        for (int i = 0; i < len; i++) {
            if (b[off + i] != (byte) n.charAt(i)) return null;
        }
        return n;
    }
}

package com.s_exp.enso.quiche.qpack;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * QPACK field section codec (RFC 9204 §4.5). A field section is the
 * payload of an HTTP/3 HEADERS frame: a two-byte prefix (Required Insert
 * Count + Delta Base) followed by a sequence of field line
 * representations.
 *
 * <p>Minimum-viable-server subset: our decoder announces
 * {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0}, so peers cannot insert
 * into our dynamic table. Every field line therefore arrives as either
 *
 * <ul>
 *   <li>Indexed with T=1 (static-table reference) — §4.5.2,
 *   <li>Literal with static name reference — §4.5.4, or
 *   <li>Literal with literal name — §4.5.6.
 * </ul>
 *
 * <p>Encoding mirrors: static exact-match → Indexed; static name-match →
 * Literal Name Ref; otherwise Literal Literal. We do not insert into any
 * dynamic table so the peer's decoder is untouched. Dynamic-table support
 * is a v2 concern (RFC 9204 §3.2 explicitly allows capacity 0).
 */
public final class QpackFieldSection {

    private QpackFieldSection() {}

    /**
     * Decode a field section into a list of {name, value} pairs. Throws on
     * dynamic-table references (we announced capacity 0 so peer must not
     * emit them).
     */
    public static List<String[]> decode(byte[] payload) {
        ByteBuffer buf = ByteBuffer.wrap(payload);
        // Prefix: Required Insert Count (8-bit NBit int) + S bit + Delta
        // Base (7-bit NBit int). Under capacity=0 both are zero.
        int b0 = buf.get() & 0xFF;
        long requiredInsertCount = NBitInteger.decode(buf, 8, b0);
        int b1 = buf.get() & 0xFF;
        // Ignore S (sign) bit + Delta Base — we don't use dynamic table.
        NBitInteger.decode(buf, 7, b1 & 0x7F);
        if (requiredInsertCount != 0) {
            throw new IllegalStateException(
                "peer used dynamic table (RIC=" + requiredInsertCount
                    + ") but our advertised capacity is 0");
        }

        List<String[]> out = new ArrayList<>();
        while (buf.hasRemaining()) {
            int b = buf.get() & 0xFF;
            if ((b & 0x80) != 0) {
                // Indexed Field Line: 1 T XXXXXX
                boolean fromStatic = (b & 0x40) != 0;
                long idx = NBitInteger.decode(buf, 6, b & 0x3F);
                if (!fromStatic) {
                    throw new IllegalStateException(
                        "dynamic indexed field line but capacity is 0");
                }
                if (idx >= QpackStaticTable.size()) {
                    throw new IllegalStateException(
                        "static index out of range: " + idx);
                }
                out.add(QpackStaticTable.get((int) idx));
            } else if ((b & 0xC0) == 0x40) {
                // Literal Field Line with Name Reference: 0 1 N T XXXX
                boolean fromStatic = (b & 0x10) != 0;
                long nameIdx = NBitInteger.decode(buf, 4, b & 0x0F);
                if (!fromStatic) {
                    throw new IllegalStateException(
                        "dynamic name reference but capacity is 0");
                }
                if (nameIdx >= QpackStaticTable.size()) {
                    throw new IllegalStateException(
                        "static name index out of range: " + nameIdx);
                }
                String name = QpackStaticTable.get((int) nameIdx)[0];
                int vb = buf.get() & 0xFF;
                String value = NBitString.decode(buf, 7, vb & 0x7F | (vb & 0x80));
                out.add(new String[]{name, value});
            } else if ((b & 0xE0) == 0x20) {
                // Literal Field Line with Literal Name: 0 0 1 N H XXX
                int prefixConsumed = b & 0x0F; // low 4 bits (H bit + 3 length bits)
                String name = NBitString.decode(buf, 3, prefixConsumed);
                int vb = buf.get() & 0xFF;
                String value = NBitString.decode(buf, 7, vb & 0x7F | (vb & 0x80));
                out.add(new String[]{name.toLowerCase(), value});
            } else if ((b & 0xF0) == 0x10) {
                // Indexed Post-Base — dynamic only, disallowed under cap 0.
                throw new IllegalStateException(
                    "post-base indexed field line but capacity is 0");
            } else if ((b & 0xF0) == 0x00) {
                // Literal Post-Base Name Ref — dynamic only, disallowed.
                throw new IllegalStateException(
                    "post-base literal field line but capacity is 0");
            } else {
                throw new IllegalStateException(
                    "unknown QPACK field line prefix: 0x" + Integer.toHexString(b));
            }
        }
        return out;
    }

    /**
     * Encode a list of {@code {name, value}} pairs into a byte[] field
     * section. Always emits a zero-prefix (RIC=0, Base=0) since we don't
     * insert into any dynamic table.
     */
    public static byte[] encode(Iterable<String[]> headers) {
        // Estimate 128 bytes/header is generous; will grow if needed.
        ByteBuffer out = ByteBuffer.allocate(512);
        // Prefix: RIC = 0, S = 0, Delta Base = 0 → two 0x00 bytes.
        out.put((byte) 0x00);
        out.put((byte) 0x00);
        for (String[] hf : headers) {
            String name = hf[0].toLowerCase();
            String value = hf[1] == null ? "" : hf[1];
            out = ensureRoom(out, name.length() + value.length() + 8);
            int exact = QpackStaticTable.findExact(name, value);
            if (exact >= 0) {
                // Indexed static: 1 1 XXXXXX with NBit(6) index, prefix 0xC0.
                NBitInteger.encode(out, 6, 0xC0, exact);
                continue;
            }
            int nameIdx = QpackStaticTable.findName(name);
            if (nameIdx >= 0) {
                // Literal Name Ref static: 0 1 N T XXXX
                // N=0 (allow indexing — doesn't matter, we never insert),
                // T=1 (static), prefix bits = 0101 0000 = 0x50.
                out = ensureRoom(out, value.length() + 4);
                NBitInteger.encode(out, 4, 0x50, nameIdx);
                NBitString.encode(out, 7, 0, value, shouldHuffman(value));
                continue;
            }
            // Literal Literal: 0 0 1 N H XXX (H sits in NBitString prefix)
            // N=0, prefix bits = 0010 0000 = 0x20.
            out = ensureRoom(out, name.length() + value.length() + 4);
            NBitString.encode(out, 3, 0x20, name, shouldHuffman(name));
            NBitString.encode(out, 7, 0, value, shouldHuffman(value));
        }
        byte[] result = new byte[out.position()];
        out.flip();
        out.get(result);
        return result;
    }

    private static ByteBuffer ensureRoom(ByteBuffer buf, int need) {
        if (buf.remaining() >= need) return buf;
        int newCap = Math.max(buf.capacity() * 2, buf.position() + need);
        ByteBuffer bigger = ByteBuffer.allocate(newCap);
        buf.flip();
        bigger.put(buf);
        return bigger;
    }

    // Huffman-encode any string long enough that the compression is likely
    // to save bytes; below ~4 bytes overhead usually outweighs savings.
    private static boolean shouldHuffman(String s) {
        return s.length() >= 5;
    }
}

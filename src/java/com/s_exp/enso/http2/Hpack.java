package com.s_exp.enso.http2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HPACK (RFC 7541) — one encoder and one decoder per connection. Not
 * thread-safe: each direction has its own instance owned by the connection's
 * framer thread.
 *
 * <p>Encoder emission priority:
 * <ol>
 *   <li>§6.1 Indexed Header Field when (name, value) is already in the
 *       static or dynamic table — cheapest possible on-wire form (1–2 bytes).
 *   <li>§6.2.1 Literal with Incremental Indexing when only the name is
 *       indexed, or the field is new — adds an entry to the dynamic table.
 *   <li>§6.2.3 Literal Never Indexed for fields flagged sensitive.
 * </ol>
 * Values are sent as raw octets (no Huffman on egress) — decoders parse both
 * forms; Huffman would trade CPU for a few percent of wire bytes.
 */
public final class Hpack {

    static final int DEFAULT_MAX_TABLE_SIZE = 4096;

    // ---- Static table (RFC 7541 Appendix A) ----------------------------
    //
    // Entries 1..61. Entry 0 is unused so table index arithmetic matches the
    // spec directly.

    private static final String[] STATIC_NAMES = new String[62];
    private static final String[] STATIC_VALUES = new String[62];

    static {
        set( 1, ":authority",                   "");
        set( 2, ":method",                      "GET");
        set( 3, ":method",                      "POST");
        set( 4, ":path",                        "/");
        set( 5, ":path",                        "/index.html");
        set( 6, ":scheme",                      "http");
        set( 7, ":scheme",                      "https");
        set( 8, ":status",                      "200");
        set( 9, ":status",                      "204");
        set(10, ":status",                      "206");
        set(11, ":status",                      "304");
        set(12, ":status",                      "400");
        set(13, ":status",                      "404");
        set(14, ":status",                      "500");
        set(15, "accept-charset",               "");
        set(16, "accept-encoding",              "gzip, deflate");
        set(17, "accept-language",              "");
        set(18, "accept-ranges",                "");
        set(19, "accept",                       "");
        set(20, "access-control-allow-origin",  "");
        set(21, "age",                          "");
        set(22, "allow",                        "");
        set(23, "authorization",                "");
        set(24, "cache-control",                "");
        set(25, "content-disposition",          "");
        set(26, "content-encoding",             "");
        set(27, "content-language",             "");
        set(28, "content-length",               "");
        set(29, "content-location",             "");
        set(30, "content-range",                "");
        set(31, "content-type",                 "");
        set(32, "cookie",                       "");
        set(33, "date",                         "");
        set(34, "etag",                         "");
        set(35, "expect",                       "");
        set(36, "expires",                      "");
        set(37, "from",                         "");
        set(38, "host",                         "");
        set(39, "if-match",                     "");
        set(40, "if-modified-since",            "");
        set(41, "if-none-match",                "");
        set(42, "if-range",                     "");
        set(43, "if-unmodified-since",          "");
        set(44, "last-modified",                "");
        set(45, "link",                         "");
        set(46, "location",                     "");
        set(47, "max-forwards",                 "");
        set(48, "proxy-authenticate",           "");
        set(49, "proxy-authorization",          "");
        set(50, "range",                        "");
        set(51, "referer",                      "");
        set(52, "refresh",                      "");
        set(53, "retry-after",                  "");
        set(54, "server",                       "");
        set(55, "set-cookie",                   "");
        set(56, "strict-transport-security",    "");
        set(57, "transfer-encoding",            "");
        set(58, "user-agent",                   "");
        set(59, "vary",                         "");
        set(60, "via",                          "");
        set(61, "www-authenticate",             "");
    }

    private static void set(int idx, String name, String value) {
        STATIC_NAMES[idx] = name;
        STATIC_VALUES[idx] = value;
    }

    static final int STATIC_TABLE_SIZE = STATIC_NAMES.length - 1; // 61

    /**
     * Precomputed name→index map for the static table. Populated with the
     * *first* matching index per name (spec allows any match), so the encoder
     * lookup is O(1) instead of a linear scan through 61 entries per header.
     */
    private static final Map<String, Integer> STATIC_NAME_INDEX;

    static {
        Map<String, Integer> m = new HashMap<>(STATIC_TABLE_SIZE * 2);
        for (int i = 1; i <= STATIC_TABLE_SIZE; i++) {
            m.putIfAbsent(STATIC_NAMES[i], i);
        }
        STATIC_NAME_INDEX = m;
    }

    // ---- Dynamic table --------------------------------------------------

    static final class Entry {
        final String name;
        final String value;
        final int size; // per RFC 7541 §4.1: 32 + len(name) + len(value)

        Entry(String name, String value) {
            this.name = name;
            this.value = value;
            this.size = 32
                + name.getBytes(StandardCharsets.UTF_8).length
                + value.getBytes(StandardCharsets.UTF_8).length;
        }
    }

    /**
     * Circular-buffer dynamic table. Indexes are RFC 7541 §2.3.3 style — 0 is
     * the newest entry. Both {@link #at} and {@link #insert} are O(1) amortised.
     * The buffer grows on demand up to whatever count fits inside {@code maxSize},
     * so pathological entry mixes don't cause repeated reallocations.
     */
    static final class DynamicTable {
        Entry[] buf = new Entry[16];
        int head = 0;   // index of newest entry (grows down mod buf.length)
        int size = 0;   // number of live entries
        int currentSize = 0;
        int maxSize;

        // Encoder walks entries in insertion order; keep the deque view for that
        // path since it's not a hot lookup.
        final Deque<Entry> entries = new ArrayDeque<>();

        DynamicTable(int maxSize) {
            this.maxSize = maxSize;
        }

        Entry at(int i) {
            if (i < 0 || i >= size) {
                return null;
            }
            return buf[(head + i) % buf.length];
        }

        void insert(Entry e) {
            while (currentSize + e.size > maxSize && size > 0) {
                dropOldest();
            }
            if (e.size > maxSize) {
                // Entry alone exceeds the table capacity — spec-legal, results
                // in an empty table (§4.4).
                for (int i = 0; i < buf.length; i++) buf[i] = null;
                head = size = 0;
                currentSize = 0;
                entries.clear();
                return;
            }
            if (size == buf.length) {
                grow();
            }
            head = (head - 1 + buf.length) % buf.length;
            buf[head] = e;
            size++;
            currentSize += e.size;
            entries.addFirst(e);
        }

        void resize(int newMax) {
            this.maxSize = newMax;
            while (currentSize > maxSize && size > 0) {
                dropOldest();
            }
        }

        private void dropOldest() {
            int idx = (head + size - 1) % buf.length;
            Entry removed = buf[idx];
            buf[idx] = null;
            size--;
            currentSize -= removed.size;
            entries.pollLast();
        }

        private void grow() {
            int newCap = buf.length * 2;
            Entry[] fresh = new Entry[newCap];
            for (int i = 0; i < size; i++) {
                fresh[i] = buf[(head + i) % buf.length];
            }
            buf = fresh;
            head = 0;
        }
    }

    // ---- HeaderField (name/value pair, sensitive flag for §6.2.3) -----

    public static final class HeaderField {
        public final String name;
        public final String value;
        public final boolean sensitive;

        public HeaderField(String name, String value, boolean sensitive) {
            this.name = name;
            this.value = value;
            this.sensitive = sensitive;
        }

        public HeaderField(String name, String value) {
            this(name, value, false);
        }
    }

    // ---- Decoder --------------------------------------------------------

    public static final class Decoder {
        final DynamicTable table;
        int maxTableSizeSetting; // last value we advertised in SETTINGS
        // Scratch for Huffman decode output. Reused across every string
        // decoded on this connection; grows on demand. Decoder is thread-
        // confined (owned by the framer vthread), so no locking needed.
        private byte[] huffmanScratch = new byte[128];

        public Decoder(int maxTableSize) {
            this.table = new DynamicTable(maxTableSize);
            this.maxTableSizeSetting = maxTableSize;
        }

        void setMaxTableSizeSetting(int newMax) {
            this.maxTableSizeSetting = newMax;
            // If the peer never sends a Dynamic Table Size Update, we still
            // reflect it locally — but a strict spec impl would wait for the
            // update. Passing the setting is enough for now.
            if (table.maxSize > newMax) {
                table.resize(newMax);
            }
        }

        public List<HeaderField> decode(byte[] block, int off, int len) throws IOException {
            List<HeaderField> out = new ArrayList<>(16);
            Cursor c = new Cursor(block, off, len);
            // Per RFC 7541 §4.2: any dynamic table size update representations
            // MUST appear at the very beginning of the header block, before any
            // header field. Once we've seen a non-size-update, further size
            // updates are a decoding error.
            boolean sawHeaderField = false;

            while (c.remaining() > 0) {
                int first = c.peek();

                if ((first & 0x80) != 0) {
                    // 1xxxxxxx — Indexed Header Field (§6.1)
                    int idx = decodeInteger(c, 7);
                    if (idx == 0) {
                        throw new IOException("HPACK: index 0 is reserved");
                    }
                    Entry e = lookup(idx);
                    if (e == null) {
                        throw new IOException("HPACK: index " + idx + " out of range");
                    }
                    out.add(new HeaderField(e.name, e.value));
                    sawHeaderField = true;
                } else if ((first & 0xC0) == 0x40) {
                    // 01xxxxxx — Literal with Incremental Indexing (§6.2.1)
                    int idx = decodeInteger(c, 6);
                    String name;
                    if (idx == 0) {
                        name = decodeString(c);
                    } else {
                        Entry e = lookup(idx);
                        if (e == null) {
                            throw new IOException("HPACK: name-index " + idx + " out of range");
                        }
                        name = e.name;
                    }
                    String value = decodeString(c);
                    out.add(new HeaderField(name, value));
                    table.insert(new Entry(name, value));
                    sawHeaderField = true;
                } else if ((first & 0xE0) == 0x20) {
                    // 001xxxxx — Dynamic Table Size Update (§6.3). Must precede
                    // all header fields per §4.2.
                    if (sawHeaderField) {
                        throw new IOException(
                            "HPACK: size update after header field");
                    }
                    int newMax = decodeInteger(c, 5);
                    if (newMax > maxTableSizeSetting) {
                        throw new IOException("HPACK: size update exceeds SETTINGS advertisement");
                    }
                    table.resize(newMax);
                } else if ((first & 0xF0) == 0x10) {
                    // 0001xxxx — Literal Never Indexed (§6.2.3)
                    int idx = decodeInteger(c, 4);
                    String name;
                    if (idx == 0) {
                        name = decodeString(c);
                    } else {
                        Entry e = lookup(idx);
                        if (e == null) {
                            throw new IOException("HPACK: name-index " + idx + " out of range");
                        }
                        name = e.name;
                    }
                    String value = decodeString(c);
                    out.add(new HeaderField(name, value, true));
                    sawHeaderField = true;
                } else {
                    // 0000xxxx — Literal without Indexing (§6.2.2)
                    int idx = decodeInteger(c, 4);
                    String name;
                    if (idx == 0) {
                        name = decodeString(c);
                    } else {
                        Entry e = lookup(idx);
                        if (e == null) {
                            throw new IOException("HPACK: name-index " + idx + " out of range");
                        }
                        name = e.name;
                    }
                    String value = decodeString(c);
                    out.add(new HeaderField(name, value));
                    sawHeaderField = true;
                }
            }
            return out;
        }

        /**
         * Read one HPACK-encoded string from the cursor. Non-Huffman strings
         * are constructed straight from the underlying frame buffer — the
         * intermediate {@code byte[length]} is skipped. Huffman-encoded
         * strings decode into a per-decoder scratch buffer that grows on
         * demand, avoiding a fresh allocation per header on the common path.
         */
        private String decodeString(Cursor c) throws IOException {
            int first = c.peek();
            boolean huffman = (first & 0x80) != 0;
            int length = decodeInteger(c, 7);
            if (length > c.remaining()) {
                throw new IOException("HPACK: string length exceeds buffer");
            }
            if (!huffman) {
                String s = new String(c.buf, c.off + c.pos, length,
                                      StandardCharsets.UTF_8);
                c.pos += length;
                return s;
            }
            // Huffman worst case: 5 bits per symbol → 8*len/5 output bytes.
            int worst = (length * 8) / 5 + 1;
            if (huffmanScratch.length < worst) {
                huffmanScratch = new byte[Math.max(worst, huffmanScratch.length * 2)];
            }
            int written = HpackHuffman.decodeInto(
                c.buf, c.off + c.pos, length, huffmanScratch);
            c.pos += length;
            return new String(huffmanScratch, 0, written, StandardCharsets.UTF_8);
        }

        Entry lookup(int idx) {
            if (idx >= 1 && idx <= STATIC_TABLE_SIZE) {
                return new Entry(STATIC_NAMES[idx], STATIC_VALUES[idx]);
            }
            return table.at(idx - STATIC_TABLE_SIZE - 1);
        }
    }

    // ---- Encoder --------------------------------------------------------

    public static final class Encoder {
        // Encoder-side dynamic table is separate from decoder's; peer maintains
        // its own view. We keep it only to compute indexed-name references.
        final DynamicTable table;

        public Encoder(int maxTableSize) {
            this.table = new DynamicTable(maxTableSize);
        }

        /** Encode a list of header fields into a fresh byte[]. */
        public byte[] encode(List<HeaderField> fields) {
            // Rough upper bound: 3 bytes overhead + name + value per field.
            int cap = 16;
            for (HeaderField hf : fields) {
                cap += 8 + hf.name.length() + hf.value.length();
            }
            byte[] buf = new byte[cap];
            int p = 0;
            for (HeaderField hf : fields) {
                if (!hf.sensitive) {
                    int fullIdx = findFullIndex(hf.name, hf.value);
                    if (fullIdx > 0) {
                        // §6.1 Indexed Header Field — 1-byte emit for small
                        // indexes, no dynamic-table mutation.
                        p = encodeInteger(buf, p, 7, 0x80, fullIdx);
                        if (p > buf.length - 32) {
                            buf = java.util.Arrays.copyOf(buf, buf.length * 2);
                        }
                        continue;
                    }
                }
                int nameIdx = findNameIndex(hf.name);
                if (hf.sensitive) {
                    p = writeLiteralNeverIndexed(buf, p, nameIdx, hf.name, hf.value);
                } else {
                    p = writeLiteralIncremental(buf, p, nameIdx, hf.name, hf.value);
                    table.insert(new Entry(hf.name, hf.value));
                }
                if (p > buf.length - 32) {
                    buf = java.util.Arrays.copyOf(buf, buf.length * 2);
                }
            }
            return java.util.Arrays.copyOf(buf, p);
        }

        private int findNameIndex(String name) {
            Integer staticIdx = STATIC_NAME_INDEX.get(name);
            if (staticIdx != null) {
                return staticIdx;
            }
            int j = 0;
            for (Entry e : table.entries) {
                if (e.name.equals(name)) return STATIC_TABLE_SIZE + 1 + j;
                j++;
            }
            return 0;
        }

        // Full (name+value) match — returns the index for a §6.1 indexed
        // emission, or 0 if no exact match. Static-table entries with a
        // non-empty value are checked inline (only a handful of names carry
        // canned values in the static table; a HashMap lookup here would need
        // a concatenated key and allocate per call). Dynamic table follows
        // with a linear scan; typically small.
        private int findFullIndex(String name, String value) {
            int staticIdx = staticFullIndex(name, value);
            if (staticIdx > 0) {
                return staticIdx;
            }
            int j = 0;
            for (Entry e : table.entries) {
                if (e.name.equals(name) && e.value.equals(value)) {
                    return STATIC_TABLE_SIZE + 1 + j;
                }
                j++;
            }
            return 0;
        }

        // Zero-alloc static-table full-match. Covers every (name, value) pair
        // in RFC 7541 Appendix A whose value is non-empty.
        private static int staticFullIndex(String name, String value) {
            return switch (name) {
                case ":method" -> value.equals("GET") ? 2
                                : value.equals("POST") ? 3 : 0;
                case ":path" -> value.equals("/") ? 4
                              : value.equals("/index.html") ? 5 : 0;
                case ":scheme" -> value.equals("http") ? 6
                                : value.equals("https") ? 7 : 0;
                case ":status" -> switch (value) {
                    case "200" -> 8;
                    case "204" -> 9;
                    case "206" -> 10;
                    case "304" -> 11;
                    case "400" -> 12;
                    case "404" -> 13;
                    case "500" -> 14;
                    default -> 0;
                };
                case "accept-encoding" -> value.equals("gzip, deflate") ? 16 : 0;
                default -> 0;
            };
        }

        private int writeLiteralIncremental(byte[] buf, int p, int nameIdx, String name, String value) {
            if (nameIdx > 0) {
                p = encodeInteger(buf, p, 6, 0x40, nameIdx);
            } else {
                buf[p++] = 0x40;
                p = writeString(buf, p, name);
            }
            return writeString(buf, p, value);
        }

        private int writeLiteralNeverIndexed(byte[] buf, int p, int nameIdx, String name, String value) {
            if (nameIdx > 0) {
                p = encodeInteger(buf, p, 4, 0x10, nameIdx);
            } else {
                buf[p++] = 0x10;
                p = writeString(buf, p, name);
            }
            return writeString(buf, p, value);
        }

        private int writeString(byte[] buf, int p, String s) {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            // High bit = 0 → raw literal; length uses 7-bit prefix.
            p = encodeInteger(buf, p, 7, 0x00, bytes.length);
            System.arraycopy(bytes, 0, buf, p, bytes.length);
            return p + bytes.length;
        }
    }

    // ---- Integer codec (RFC 7541 §5.1) ---------------------------------

    /**
     * Decode an integer whose N-bit prefix sits in the low bits of the current
     * byte. Advances the cursor. N ∈ [1, 8].
     */
    public static int decodeInteger(Cursor c, int prefixBits) throws IOException {
        int mask = (1 << prefixBits) - 1;
        int first = c.readByte();
        int value = first & mask;
        if (value < mask) {
            return value;
        }
        int shift = 0;
        while (true) {
            int b = c.readByte();
            value += (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return value;
            }
            shift += 7;
            if (shift >= 32) {
                throw new IOException("HPACK: integer overflow");
            }
        }
    }

    /**
     * Encode {@code value} into {@code buf} using an N-bit prefix. {@code high}
     * pre-populates the top (8-N) bits of the first byte (e.g. the pattern
     * that identifies the representation type). Returns new cursor position.
     */
    public static int encodeInteger(byte[] buf, int p, int prefixBits, int high, int value) {
        int mask = (1 << prefixBits) - 1;
        if (value < mask) {
            buf[p++] = (byte) (high | value);
            return p;
        }
        buf[p++] = (byte) (high | mask);
        value -= mask;
        while (value >= 128) {
            buf[p++] = (byte) ((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        buf[p++] = (byte) value;
        return p;
    }

    // ---- Cursor helper --------------------------------------------------

    public static final class Cursor {
        final byte[] buf;
        final int off;
        final int limit;
        int pos;

        public Cursor(byte[] buf, int off, int len) {
            this.buf = buf;
            this.off = off;
            this.limit = len;
            this.pos = 0;
        }

        int remaining() {
            return limit - pos;
        }

        int peek() throws IOException {
            if (pos >= limit) {
                throw new IOException("HPACK: unexpected end of block");
            }
            return buf[off + pos] & 0xFF;
        }

        int readByte() throws IOException {
            if (pos >= limit) {
                throw new IOException("HPACK: unexpected end of block");
            }
            return buf[off + pos++] & 0xFF;
        }
    }
}

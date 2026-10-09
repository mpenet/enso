// ABOUTME: HPACK (RFC 7541) header compression: one encoder and one decoder per HTTP/2
// ABOUTME: connection, with decoded-size limits and an allocation-free streaming encoder.
package com.s_exp.enso.http2;

import com.s_exp.enso.core.RequestHead;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HPACK (RFC 7541) — one encoder and one decoder per connection. Not
 * thread-safe: the decoder is confined to the connection's framer thread,
 * the encoder is used under the connection writer's lock (blocks are
 * encoded while output is packed, so they reach the wire in encoding order).
 *
 * <p>Encoder emission priority:
 * <ol>
 *   <li>§6.1 Indexed Header Field when (name, value) is already in the
 *       static or dynamic table — cheapest possible on-wire form (1–2 bytes).
 *   <li>§6.2.1 Literal with Incremental Indexing when only the name is
 *       indexed, or the field is new — adds an entry to the dynamic table.
 *   <li>§6.2.2 Literal without Indexing for per-response values
 *       (content-length, etag, ...) that would only churn the table.
 *   <li>§6.2.3 Literal Never Indexed for credentials and fields flagged
 *       sensitive.
 * </ol>
 * Values are sent as raw octets (no Huffman on egress) — decoders parse both
 * forms; Huffman would trade CPU for a few percent of wire bytes.
 *
 * <p>The connection drives both directions without intermediate lists:
 * {@link Decoder#decode(byte[], int, int, FieldSink, long, long)} hands each
 * field to a sink and enforces the decoded-size limits as it goes, and the
 * encoder writes a block field by field into its own reusable buffer
 * ({@link Encoder#beginBlock}, {@link Encoder#field}, ...).
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

    // Decoder view of the static table, built once.
    private static final Entry[] STATIC_ENTRIES = new Entry[STATIC_NAMES.length];

    static {
        for (int i = 1; i <= STATIC_TABLE_SIZE; i++) {
            STATIC_ENTRIES[i] = new Entry(STATIC_NAMES[i], STATIC_VALUES[i],
                                          RequestHead.hasValidChars(STATIC_NAMES[i], STATIC_VALUES[i]));
        }
    }

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

    /**
     * A table entry is also the decoded field handed out for an indexed
     * representation, so decoding an indexed field allocates nothing.
     */
    static final class Entry extends HeaderField {
        final int size; // per RFC 7541 §4.1: 32 + len(name) + len(value)
        // The name's hash, compared before the name itself on encoder lookups.
        final int nameHash;
        // Decoder entries: the field passed RequestHead.hasValidChars when
        // inserted, so referencing it again needs no character scan.
        final boolean validChars;

        Entry(String name, String value) {
            this(name, value, false);
        }

        Entry(String name, String value, boolean validChars) {
            super(name, value, false);
            // Field strings are octets carried one per char (ISO-8859-1),
            // so char count is the octet length.
            this.size = 32 + name.length() + value.length();
            this.nameHash = name.hashCode();
            this.validChars = validChars;
        }
    }

    /**
     * Circular-buffer dynamic table. Indexes are RFC 7541 §2.3.3 style — 0 is
     * the newest entry. Both {@link #at} and {@link #insert} are O(1) amortised.
     * The buffer grows on demand up to whatever count fits inside {@code maxSize},
     * so pathological entry mixes don't cause repeated reallocations. Its
     * length is a power of two, so positions wrap with a mask.
     */
    static final class DynamicTable {
        Entry[] buf = new Entry[16];
        int head = 0;   // index of newest entry (grows down mod buf.length)
        int size = 0;   // number of live entries
        int currentSize = 0;
        int maxSize;

        DynamicTable(int maxSize) {
            this.maxSize = maxSize;
        }

        Entry at(int i) {
            if (i < 0 || i >= size) {
                return null;
            }
            return buf[(head + i) & (buf.length - 1)];
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
                return;
            }
            if (size == buf.length) {
                grow();
            }
            head = (head - 1) & (buf.length - 1);
            buf[head] = e;
            size++;
            currentSize += e.size;
        }

        void resize(int newMax) {
            this.maxSize = newMax;
            while (currentSize > maxSize && size > 0) {
                dropOldest();
            }
        }

        private void dropOldest() {
            int idx = (head + size - 1) & (buf.length - 1);
            Entry removed = buf[idx];
            buf[idx] = null;
            size--;
            currentSize -= removed.size;
        }

        private void grow() {
            int newCap = buf.length * 2;
            Entry[] fresh = new Entry[newCap];
            for (int i = 0; i < size; i++) {
                fresh[i] = buf[(head + i) & (buf.length - 1)];
            }
            buf = fresh;
            head = 0;
        }
    }

    // ---- HeaderField (name/value pair, sensitive flag for §6.2.3) -----

    public static class HeaderField {
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

    /** Receives decoded fields in block order. */
    public interface FieldSink {
        void field(String name, String value);

        /**
         * {@link #field}; {@code validChars}: the field is known to pass
         * {@link RequestHead#hasValidChars} (checked when its table entry
         * was inserted). Defaults to {@link #field}.
         */
        default void field(String name, String value, boolean validChars) {
            field(name, value);
        }

        /**
         * A Literal Never Indexed field (§6.2.3): an intermediary must
         * re-encode it the same way. Defaults to {@link #field}.
         */
        default void sensitiveField(String name, String value) {
            field(name, value);
        }
    }

    /**
     * The decoded field section passed the decoder's hard limit: decoding
     * stopped mid-block, so the dynamic table is out of step and the
     * connection must end.
     */
    public static final class HeaderListTooLarge extends IOException {
        HeaderListTooLarge(long limit) {
            super("HPACK: decoded header list exceeds " + limit + " bytes");
        }
    }

    private static final int HUFFMAN_SCRATCH_INITIAL = 128;
    private static final int ENCODER_BUFFER_INITIAL = 256;

    public static final class Decoder {
        final DynamicTable table;
        // The table size our SETTINGS allow: a size update may not exceed it.
        final int maxTableSizeSetting;
        // Scratch for Huffman decode output. Reused across every string
        // decoded on this connection; grows on demand. Decoder is thread-
        // confined (owned by the framer vthread), so no locking needed.
        private byte[] huffmanScratch = new byte[HUFFMAN_SCRATCH_INITIAL];
        private final Cursor cursor = new Cursor(null, 0, 0);

        public Decoder(int maxTableSize) {
            this.table = new DynamicTable(maxTableSize);
            this.maxTableSizeSetting = maxTableSize;
        }

        /** Gives back a Huffman scratch grown by a long string (connection idle). */
        void releaseScratch() {
            if (huffmanScratch.length > HUFFMAN_SCRATCH_INITIAL) {
                huffmanScratch = new byte[HUFFMAN_SCRATCH_INITIAL];
            }
        }

        /** Decodes a whole block into a fresh list, without size limits. */
        public List<HeaderField> decode(byte[] block, int off, int len) throws IOException {
            List<HeaderField> out = new ArrayList<>(16);
            decode(block, off, len, new FieldSink() {
                @Override
                public void field(String name, String value) {
                    out.add(new HeaderField(name, value));
                }

                @Override
                public void sensitiveField(String name, String value) {
                    out.add(new HeaderField(name, value, true));
                }
            }, Long.MAX_VALUE, Long.MAX_VALUE);
            return out;
        }

        /**
         * Decodes a block, handing each field to {@code sink} while the
         * decoded size (RFC 9113 §6.5.2: 32 + name + value octets per field)
         * stays within {@code softLimit}. Past it decoding goes on, keeping
         * the dynamic table in step, but fields are no longer handed out;
         * past {@code hardLimit} it stops with {@link HeaderListTooLarge}.
         * Returns the decoded size: above {@code softLimit} means the sink
         * saw only a prefix of the section.
         */
        public long decode(byte[] block, int off, int len, FieldSink sink,
                           long softLimit, long hardLimit) throws IOException {
            Cursor c = cursor;
            c.reset(block, off, len);
            long size = 0;
            // Per RFC 7541 §4.2: any dynamic table size update representations
            // MUST appear at the very beginning of the header block, before any
            // header field. Once we've seen a non-size-update, further size
            // updates are a decoding error.
            boolean sawHeaderField = false;

            while (c.remaining() > 0) {
                int first = c.peek();
                String name;
                String value;
                boolean sensitive = false;
                boolean validChars = false;
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
                    name = e.name;
                    value = e.value;
                    validChars = e.validChars;
                } else if ((first & 0xC0) == 0x40) {
                    // 01xxxxxx — Literal with Incremental Indexing (§6.2.1)
                    name = literalName(c, decodeInteger(c, 6));
                    value = decodeString(c);
                    validChars = RequestHead.hasValidChars(name, value);
                    table.insert(new Entry(name, value, validChars));
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
                    continue;
                } else {
                    // 0001xxxx — Literal Never Indexed (§6.2.3), or
                    // 0000xxxx — Literal without Indexing (§6.2.2). Neither
                    // touches the table.
                    sensitive = (first & 0xF0) == 0x10;
                    name = literalName(c, decodeInteger(c, 4));
                    value = decodeString(c);
                }
                sawHeaderField = true;
                // Field strings are octets, one per char.
                size += 32L + name.length() + value.length();
                if (size > hardLimit) {
                    throw new HeaderListTooLarge(hardLimit);
                }
                if (size <= softLimit) {
                    if (sensitive) {
                        sink.sensitiveField(name, value);
                    } else {
                        sink.field(name, value, validChars);
                    }
                }
            }
            return size;
        }

        private String literalName(Cursor c, int idx) throws IOException {
            if (idx == 0) {
                return decodeString(c);
            }
            Entry e = lookup(idx);
            if (e == null) {
                throw new IOException("HPACK: name-index " + idx + " out of range");
            }
            return e.name;
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
            // Field strings are octets (RFC 9110 §5.5); ISO-8859-1 maps
            // each to one char losslessly, matching the HTTP/1.1 parser.
            if (!huffman) {
                String s = new String(c.buf, c.off + c.pos, length,
                                      StandardCharsets.ISO_8859_1);
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
            return new String(huffmanScratch, 0, written, StandardCharsets.ISO_8859_1);
        }

        Entry lookup(int idx) {
            if (idx >= 1 && idx <= STATIC_TABLE_SIZE) {
                return STATIC_ENTRIES[idx];
            }
            return table.at(idx - STATIC_TABLE_SIZE - 1);
        }
    }

    // ---- Encoder --------------------------------------------------------

    public static final class Encoder {
        // Encoder-side dynamic table is separate from decoder's; peer maintains
        // its own view. We keep it only to compute indexed-name references.
        final DynamicTable table;
        // Peer's most-recent SETTINGS_HEADER_TABLE_SIZE. We MUST NOT let
        // our table exceed this. -1 = no pending update to emit.
        private int pendingSizeUpdate = -1;
        // Smallest size set since the last block (§4.2); -1 = none.
        private int pendingMinSize = -1;
        // The block being encoded, reused for every block: [0, len).
        private byte[] buf = new byte[ENCODER_BUFFER_INITIAL];
        private int len;

        public Encoder(int maxTableSize) {
            this.table = new DynamicTable(maxTableSize);
        }

        /**
         * Apply peer's SETTINGS_HEADER_TABLE_SIZE. Per RFC 7541 §6.3 the
         * next encoded block must begin with a Dynamic Table Size Update
         * that carries the new cap so the peer's decoder stays in sync.
         */
        public void setMaxTableSize(int newMax) {
            if (newMax < 0) return;
            // Clamp our table to the new cap immediately (evicts entries
            // as needed) and mark a size-update to emit on next block.
            table.resize(newMax);
            pendingSizeUpdate = newMax;
            pendingMinSize = pendingMinSize < 0 ? newMax : Math.min(pendingMinSize, newMax);
        }

        /** Encode a list of header fields into a fresh byte[]. */
        public byte[] encode(List<HeaderField> fields) {
            beginBlock();
            for (HeaderField hf : fields) {
                field(hf.name, hf.value, hf.sensitive);
            }
            return java.util.Arrays.copyOf(buf, len);
        }

        /** Gives back a buffer grown by a large block, between blocks (connection idle). */
        void releaseBuffer() {
            if (buf.length > ENCODER_BUFFER_INITIAL) {
                buf = new byte[ENCODER_BUFFER_INITIAL];
                len = 0;
            }
        }

        /** The block encoded since {@link #beginBlock}: {@code buffer()[0, length())}. */
        public byte[] buffer() {
            return buf;
        }

        public int length() {
            return len;
        }

        /**
         * Starts a block in the reused buffer, beginning with any pending
         * Dynamic Table Size Update. Every block started must reach the peer
         * in order: the table changes as fields are encoded.
         */
        public void beginBlock() {
            len = 0;
            if (pendingSizeUpdate >= 0) {
                ensure(10);
                // §6.3: 001xxxxx pattern, 5-bit prefix. When the size dipped
                // below the final value since the last block, signal the
                // minimum first (§4.2) so the peer evicts as we did.
                if (pendingMinSize < pendingSizeUpdate) {
                    len = encodeInteger(buf, len, 5, 0x20, pendingMinSize);
                }
                len = encodeInteger(buf, len, 5, 0x20, pendingSizeUpdate);
                pendingSizeUpdate = -1;
                pendingMinSize = -1;
            }
        }

        /** Most octets {@link #field} can emit for this field. */
        public static int maxFieldLength(String name, String value) {
            // Strings are one octet per char, plus at most 5 octets for each
            // of the three prefixed integers (index, name length, value length).
            return 15 + name.length() + value.length();
        }

        /** Appends {@code :status}. */
        public void status(int status) {
            int idx = switch (status) {
                case 200 -> 8;
                case 204 -> 9;
                case 206 -> 10;
                case 304 -> 11;
                case 400 -> 12;
                case 404 -> 13;
                case 500 -> 14;
                default -> 0;
            };
            if (idx > 0) {
                ensure(1);
                buf[len++] = (byte) (0x80 | idx);
            } else {
                field(":status", statusString(status), false);
            }
        }

        public void field(String name, String value) {
            field(name, value, false);
        }

        /**
         * Appends a field whose value is a number, written as decimal
         * digits without building a String unless the policy indexes it.
         */
        public void field(String name, long value) {
            if (value < 0 || indexingPolicy(name) == INCREMENTAL) {
                field(name, Long.toString(value), false);
                return;
            }
            Integer staticName = STATIC_NAME_INDEX.get(name);
            int nameIdx = staticName == null ? dynamicNameIndex(name) : staticName;
            int pattern = indexingPolicy(name) == NEVER_INDEXED ? 0x10 : 0x00;
            ensure(15 + name.length() + 20);
            if (nameIdx > 0) {
                len = encodeInteger(buf, len, 4, pattern, nameIdx);
            } else {
                buf[len++] = (byte) pattern;
                len = writeString(buf, len, name);
            }
            int digits = digits(value);
            buf[len++] = (byte) digits;
            for (int i = len + digits - 1; i >= len; i--) {
                buf[i] = (byte) ('0' + (int) (value % 10));
                value /= 10;
            }
            len += digits;
        }

        private static int digits(long v) {
            int n = 1;
            while (v >= 10) {
                v /= 10;
                n++;
            }
            return n;
        }

        private void field(String name, String value, boolean sensitive) {
            ensure(maxFieldLength(name, value));
            int policy = sensitive ? NEVER_INDEXED : indexingPolicy(name);
            if (policy == INCREMENTAL && 32 + name.length() + value.length() > table.maxSize / 4 * 3) {
                // An entry this large would evict most of the table (and an
                // entry over the whole table empties it): as nghttp2 does,
                // it isn't indexed.
                policy = WITHOUT_INDEXING;
            }
            int fullIdx = policy == NEVER_INDEXED ? 0 : staticFullIndex(name, value);
            Integer staticName = STATIC_NAME_INDEX.get(name);
            int nameIdx = staticName == null ? 0 : staticName;
            // One pass over the dynamic table (at most 128 entries, a few
            // dozen in practice), comparing cached name hashes first: exact
            // (name, value) match, else the newest entry with this name. A
            // hash index would cost a value hash per field and upkeep per
            // insert and eviction, more than this scan at these sizes.
            if (fullIdx == 0 && table.size > 0) {
                int h = name.hashCode();
                Entry[] entries = table.buf;
                int mask = entries.length - 1;
                int head = table.head;
                for (int i = 0; i < table.size; i++) {
                    Entry e = entries[(head + i) & mask];
                    if (e.nameHash == h && e.name.equals(name)) {
                        if (policy != NEVER_INDEXED && e.value.equals(value)) {
                            fullIdx = STATIC_TABLE_SIZE + 1 + i;
                            break;
                        } else if (nameIdx == 0) {
                            nameIdx = STATIC_TABLE_SIZE + 1 + i;
                        }
                    }
                }
            }
            if (fullIdx > 0) {
                // §6.1 Indexed Header Field — 1-byte emit for small
                // indexes, no dynamic-table mutation.
                len = encodeInteger(buf, len, 7, 0x80, fullIdx);
            } else if (policy == INCREMENTAL) {
                len = writeLiteral(buf, len, 6, 0x40, nameIdx, name, value);
                table.insert(new Entry(name, value));
            } else if (policy == WITHOUT_INDEXING) {
                len = writeLiteral(buf, len, 4, 0x00, nameIdx, name, value);
            } else {
                len = writeLiteral(buf, len, 4, 0x10, nameIdx, name, value);
            }
        }

        private int dynamicNameIndex(String name) {
            int h = name.hashCode();
            Entry[] entries = table.buf;
            int mask = entries.length - 1;
            for (int i = 0; i < table.size; i++) {
                Entry e = entries[(table.head + i) & mask];
                if (e.nameHash == h && e.name.equals(name)) {
                    return STATIC_TABLE_SIZE + 1 + i;
                }
            }
            return 0;
        }

        private void ensure(int n) {
            if (len + n > buf.length) {
                buf = java.util.Arrays.copyOf(buf, Math.max(len + n, buf.length * 2));
            }
        }

        private static final int INCREMENTAL = 0;
        private static final int WITHOUT_INDEXING = 1;
        private static final int NEVER_INDEXED = 2;

        // Credentials are never indexed (§7.1.3: low-entropy secrets in a
        // shared table invite compression-based guessing); per-response
        // values (lengths, validators, request and trace ids) would only
        // churn the dynamic table, evicting entries that do repeat. Close
        // to nghttp2's policy.
        private static int indexingPolicy(String name) {
            return switch (name) {
                case "authorization", "proxy-authorization", "cookie", "set-cookie" ->
                    NEVER_INDEXED;
                case "content-length", "content-range", "etag", "location",
                     "x-request-id", "request-id", "x-correlation-id", "x-trace-id",
                     "traceparent", "tracestate", "x-amzn-trace-id",
                     "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid" ->
                    WITHOUT_INDEXING;
                default -> INCREMENTAL;
            };
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

        // §6.2 literal representations: N-bit prefix + pattern, then either
        // an indexed name or a literal one, then the value.
        private int writeLiteral(byte[] buf, int p, int prefixBits, int pattern,
                                 int nameIdx, String name, String value) {
            if (nameIdx > 0) {
                p = encodeInteger(buf, p, prefixBits, pattern, nameIdx);
            } else {
                buf[p++] = (byte) pattern;
                p = writeString(buf, p, name);
            }
            return writeString(buf, p, value);
        }

        // Field strings are octets, one per char (ISO-8859-1) as on the
        // decode side. Chars above U+00FF have no octet form and become
        // '?' — truncating them could forge CR/LF/NUL octets.
        private static int writeString(byte[] buf, int p, String s) {
            int n = s.length();
            // High bit = 0 → raw literal; length uses 7-bit prefix.
            p = encodeInteger(buf, p, 7, 0x00, n);
            for (int i = 0; i < n; i++) {
                char ch = s.charAt(i);
                buf[p++] = ch <= 0xFF ? (byte) ch : (byte) '?';
            }
            return p;
        }
    }

    // Codes 100..599 pre-formatted so a :status outside the static table
    // skips Integer.toString per response.
    private static final int STATUS_MIN = 100;
    private static final String[] STATUS_STRINGS = buildStatusStrings();

    private static String[] buildStatusStrings() {
        String[] s = new String[500];
        for (int i = 0; i < s.length; i++) s[i] = Integer.toString(STATUS_MIN + i);
        return s;
    }

    static String statusString(int code) {
        int idx = code - STATUS_MIN;
        if (idx >= 0 && idx < STATUS_STRINGS.length) return STATUS_STRINGS[idx];
        return Integer.toString(code);
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
        // Accumulate in a long so a 5th continuation byte can't wrap the
        // result negative; anything past Integer.MAX_VALUE is rejected.
        long acc = value;
        int shift = 0;
        while (true) {
            int b = c.readByte();
            acc += (long) (b & 0x7F) << shift;
            if (acc > Integer.MAX_VALUE) {
                throw new IOException("HPACK: integer overflow");
            }
            if ((b & 0x80) == 0) {
                return (int) acc;
            }
            shift += 7;
            if (shift > 28) {
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
        byte[] buf;
        int off;
        int limit;
        int pos;

        public Cursor(byte[] buf, int off, int len) {
            reset(buf, off, len);
        }

        void reset(byte[] buf, int off, int len) {
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

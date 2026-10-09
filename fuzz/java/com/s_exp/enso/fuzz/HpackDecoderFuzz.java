// ABOUTME: Jazzer target for the HPACK decoder as HTTP/2 connections use it (sink API, header-list
// ABOUTME: limits, dynamic table carried across blocks); accepted blocks must survive a re-encode.
package com.s_exp.enso.fuzz;

import com.s_exp.enso.http2.Hpack;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Input layout: byte 0 picks how many blocks (1-4) the rest is split
 * into, evenly, all decoded by one connection's decoder so dynamic-table
 * state carries over. Only {@link IOException} (COMPRESSION_ERROR or a
 * header list over the hard limit) may escape. A block decoded within
 * the soft limit must decode to the same fields after a fresh encoder
 * re-encodes them.
 */
public final class HpackDecoderFuzz {

    private static final long SOFT_LIMIT = 8192;
    private static final long HARD_LIMIT = 65536;

    private HpackDecoderFuzz() {}

    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length == 0) return;
        int blocks = 1 + (data[0] & 0x03);
        int bodyLen = data.length - 1;
        int per = Math.max(1, bodyLen / blocks);
        Hpack.Decoder decoder = new Hpack.Decoder(4096);
        int off = 1;
        for (int i = 0; i < blocks && off <= data.length; i++) {
            int len = i == blocks - 1 ? data.length - off : Math.min(per, data.length - off);
            List<Hpack.HeaderField> fields = new ArrayList<>();
            long size;
            try {
                size = decoder.decode(data, off, len, new Hpack.FieldSink() {
                    @Override
                    public void field(String name, String value) {
                        fields.add(new Hpack.HeaderField(name, value));
                    }

                    @Override
                    public void sensitiveField(String name, String value) {
                        fields.add(new Hpack.HeaderField(name, value, true));
                    }
                }, SOFT_LIMIT, HARD_LIMIT);
            } catch (IOException e) {
                return;
            }
            if (size <= SOFT_LIMIT) {
                checkRoundTrip(fields);
            }
            off += len;
        }
    }

    private static void checkRoundTrip(List<Hpack.HeaderField> fields) {
        byte[] encoded = new Hpack.Encoder(4096).encode(fields);
        List<Hpack.HeaderField> again;
        try {
            again = new Hpack.Decoder(4096).decode(encoded, 0, encoded.length);
        } catch (IOException e) {
            throw new IllegalStateException("re-encoded block rejected: " + e.getMessage(), e);
        }
        if (again.size() != fields.size()) {
            throw new IllegalStateException("re-encode changed field count " + fields.size() + " -> " + again.size());
        }
        for (int i = 0; i < fields.size(); i++) {
            Hpack.HeaderField a = fields.get(i);
            Hpack.HeaderField b = again.get(i);
            if (!a.name.equals(b.name) || !a.value.equals(b.value)) {
                throw new IllegalStateException("re-encode changed field " + i + ": "
                    + Arrays.asList(a.name, a.value) + " -> " + Arrays.asList(b.name, b.value));
            }
        }
    }
}

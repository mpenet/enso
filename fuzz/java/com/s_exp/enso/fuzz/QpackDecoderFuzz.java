// ABOUTME: Jazzer target for the production QPACK decoder (QpackDecoder, used by Http3Loop): it must
// ABOUTME: agree with QpackFieldSection.decode and give the same answer when its string cache is warm.
package com.s_exp.enso.fuzz;

import com.s_exp.enso.http3.qpack.QpackDecoder;
import com.s_exp.enso.http3.qpack.QpackException;
import com.s_exp.enso.http3.qpack.QpackFieldSection;
import java.util.ArrayList;
import java.util.List;

/**
 * Input layout: byte 0 picks the field-section size cap (0 = none), the
 * rest is the field section. One decoder instance is reused across
 * inputs, as one event loop's is across requests. Only
 * {@link QpackException} may escape either decoder, and both must reject
 * an input with the same error code and level or accept it with the same
 * fields; decoding the same input twice must give the same fields.
 */
public final class QpackDecoderFuzz {

    private static final QpackDecoder DECODER = new QpackDecoder();

    private QpackDecoderFuzz() {}

    private static List<String> decode(byte[] data, long cap) {
        List<String> out = new ArrayList<>();
        DECODER.decode(data, 1, data.length - 1, cap, (name, value) -> {
            out.add(name);
            out.add(value);
        });
        return out;
    }

    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length == 0) return;
        long cap = (data[0] & 0xFF) * 16L;
        byte[] section = java.util.Arrays.copyOfRange(data, 1, data.length);
        List<String> reference = null;
        QpackException referenceError = null;
        try {
            reference = new ArrayList<>();
            for (String[] f : QpackFieldSection.decode(section, cap)) {
                reference.add(f[0]);
                reference.add(f[1]);
            }
        } catch (QpackException e) {
            referenceError = e;
        }
        List<String> first;
        try {
            first = decode(data, cap);
        } catch (QpackException e) {
            if (referenceError == null) {
                throw new IllegalStateException("QpackDecoder rejected a section QpackFieldSection accepts: " + e, e);
            }
            if (e.errorCode() != referenceError.errorCode() || e.isStreamLevel() != referenceError.isStreamLevel()) {
                throw new IllegalStateException("decoders disagree on the error: " + e + " vs " + referenceError, e);
            }
            return;
        }
        if (referenceError != null) {
            throw new IllegalStateException("QpackDecoder accepted a section QpackFieldSection rejects: "
                + referenceError, referenceError);
        }
        if (!first.equals(reference)) {
            throw new IllegalStateException("decoders disagree: " + first + " vs " + reference);
        }
        List<String> second = decode(data, cap);
        if (!second.equals(first)) {
            throw new IllegalStateException("warm-cache decode differs: " + second + " vs " + first);
        }
    }
}

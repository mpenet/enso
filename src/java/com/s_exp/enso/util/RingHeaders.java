package com.s_exp.enso.util;

/**
 * Shared helpers for building the Ring headers map from a raw list of
 * (name, value) pairs parsed off the wire.
 */
public final class RingHeaders {

    private RingHeaders() {}

    /**
     * Dedup name/value pairs in {@code arr[0..len]} (interleaved names +
     * values). Duplicate names get their values joined per HTTP list-value
     * combining: "; " for "cookie" (RFC 9113 §8.2.3), ", " otherwise
     * (RFC 9110 §5.3). Returns an exact-fit {@code Object[]} with no
     * repeated keys so a downstream
     * {@code PersistentArrayMap.createAsIfByAssoc} won't throw.
     */
    public static Object[] mergeDuplicates(Object[] arr, int len) {
        boolean dup = false;
        outer:
        for (int i = 0; i < len; i += 2) {
            String a = (String) arr[i];
            for (int j = i + 2; j < len; j += 2) {
                if (a.equals(arr[j])) { dup = true; break outer; }
            }
        }
        if (!dup) {
            if (arr.length == len) return arr;
            Object[] fit = new Object[len];
            System.arraycopy(arr, 0, fit, 0, len);
            return fit;
        }
        Object[] out = new Object[len];
        int op = 0;
        for (int i = 0; i < len; i += 2) {
            String name = (String) arr[i];
            String value = (String) arr[i + 1];
            int existing = -1;
            for (int j = 0; j < op; j += 2) {
                if (name.equals(out[j])) { existing = j; break; }
            }
            if (existing < 0) {
                out[op++] = name;
                out[op++] = value;
            } else {
                String sep = name.equals("cookie") ? "; " : ", ";
                out[existing + 1] = out[existing + 1] + sep + value;
            }
        }
        if (op == out.length) return out;
        Object[] fit = new Object[op];
        System.arraycopy(out, 0, fit, 0, op);
        return fit;
    }
}

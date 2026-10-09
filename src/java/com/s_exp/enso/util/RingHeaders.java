// ABOUTME: Builds the Ring request header map from wire (name, value) pairs for every protocol:
// ABOUTME: duplicates joined per RFC 9110 / RFC 9113, then an array or hash map by size.
package com.s_exp.enso.util;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import clojure.lang.PersistentHashMap;
import java.util.HashMap;

/**
 * Shared helpers for building the Ring headers map from a raw list of
 * (name, value) pairs parsed off the wire.
 */
public final class RingHeaders {

    private RingHeaders() {}

    // Clojure's own threshold (PersistentArrayMap.HASHTABLE_THRESHOLD):
    // array maps hold at most 8 entries.
    private static final int ARRAY_MAP_MAX_LENGTH = 16;

    /**
     * The header map over {@code kv}, an exact-fit array of unique names
     * and their values as {@link #mergeDuplicates} returns it (taken over,
     * not copied). Up to 8 fields an array map over the array itself (no
     * duplicate scan: the names are already unique), beyond a hash map,
     * so building and looking up stay linear in the field count.
     */
    public static IPersistentMap toMap(Object[] kv) {
        if (kv.length == 0) return PersistentArrayMap.EMPTY;
        if (kv.length <= ARRAY_MAP_MAX_LENGTH) return new PersistentArrayMap(kv);
        return PersistentHashMap.create(kv);
    }

    // Up to this many fields, pairwise name comparison beats hashing.
    // Above it a hash index keeps merging linear: one HTTP/3 HEADERS
    // block can decode to tens of thousands of fields.
    private static final int SCAN_MAX_PAIRS = 16;

    /**
     * Dedup name/value pairs in {@code arr[0..len]} (interleaved names +
     * values). Duplicate names get their values joined per HTTP list-value
     * combining: "; " for "cookie" (RFC 9113 §8.2.3), ", " otherwise
     * (RFC 9110 §5.3). Returns an exact-fit {@code Object[]} with no
     * repeated keys so a downstream
     * {@code PersistentArrayMap.createAsIfByAssoc} won't throw. Names keep
     * the order of their first occurrence.
     */
    public static Object[] mergeDuplicates(Object[] arr, int len) {
        if (len > SCAN_MAX_PAIRS * 2) {
            return mergeIndexed(arr, len);
        }
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
                out[existing + 1] = out[existing + 1] + separator(name) + value;
            }
        }
        return fit(out, op);
    }

    private static Object[] mergeIndexed(Object[] arr, int len) {
        HashMap<String, Integer> index = new HashMap<>(len);
        Object[] out = new Object[len];
        // Per output pair, a builder for names seen more than once, so
        // joining N values costs O(total length) rather than O(N^2).
        StringBuilder[] joined = null;
        int op = 0;
        for (int i = 0; i < len; i += 2) {
            String name = (String) arr[i];
            String value = (String) arr[i + 1];
            Integer existing = index.putIfAbsent(name, op);
            if (existing == null) {
                out[op++] = name;
                out[op++] = value;
            } else {
                int pair = existing >>> 1;
                if (joined == null) {
                    joined = new StringBuilder[len >>> 1];
                }
                StringBuilder sb = joined[pair];
                if (sb == null) {
                    sb = new StringBuilder((String) out[existing + 1]);
                    joined[pair] = sb;
                }
                sb.append(separator(name)).append(value);
            }
        }
        if (joined == null) {
            return arr.length == len ? arr : fit(out, op);
        }
        for (int pair = 0; pair < joined.length; pair++) {
            if (joined[pair] != null) {
                out[(pair << 1) + 1] = joined[pair].toString();
            }
        }
        return fit(out, op);
    }

    private static String separator(String name) {
        return name.equals("cookie") ? "; " : ", ";
    }

    private static Object[] fit(Object[] out, int op) {
        if (op == out.length) return out;
        Object[] fit = new Object[op];
        System.arraycopy(out, 0, fit, 0, op);
        return fit;
    }
}

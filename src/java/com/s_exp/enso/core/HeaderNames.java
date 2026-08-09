package com.s_exp.enso.core;

/**
 * Interning table for common request header names. Matching is done directly
 * against the raw buffer bytes, case-insensitively, so the hot path allocates
 * no String for well-known headers.
 */
public final class HeaderNames {

    private static final String[] NAMES = {
        "accept", "accept-charset", "accept-datetime", "accept-encoding",
        "accept-language", "authorization", "cache-control", "connection",
        "content-encoding", "content-length", "content-type", "cookie", "dnt",
        "expect", "host", "if-match", "if-modified-since", "if-none-match",
        "if-range", "if-unmodified-since", "origin", "pragma", "priority",
        "range", "referer", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
        "te", "trailer", "transfer-encoding", "upgrade",
        "upgrade-insecure-requests", "user-agent", "x-forwarded-for",
        "x-forwarded-proto", "x-real-ip"
    };

    private static final String[][] BY_LENGTH;
    private static final byte[][][] BYTES_BY_LENGTH;

    static {
        int max = 0;
        for (String n : NAMES) {
            max = Math.max(max, n.length());
        }
        int[] counts = new int[max + 1];
        for (String n : NAMES) {
            counts[n.length()]++;
        }
        String[][] groups = new String[max + 1][];
        byte[][][] byteGroups = new byte[max + 1][][];
        for (int len = 0; len <= max; len++) {
            if (counts[len] > 0) {
                groups[len] = new String[counts[len]];
                byteGroups[len] = new byte[counts[len]][];
            }
        }
        int[] fill = new int[max + 1];
        for (String n : NAMES) {
            int len = n.length();
            groups[len][fill[len]] = n;
            byteGroups[len][fill[len]++] = n.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        }
        BY_LENGTH = groups;
        BYTES_BY_LENGTH = byteGroups;
    }

    private HeaderNames() {
    }

    /** Returns the interned lowercase name, or null if not a known header. */
    public static String lookup(byte[] buf, int from, int to) {
        int len = to - from;
        if (len >= BY_LENGTH.length) {
            return null;
        }
        byte[][] byteGroup = BYTES_BY_LENGTH[len];
        if (byteGroup == null) {
            return null;
        }
        // | 0x20 lowercases ASCII letters, leaves '-' and digits alone
        int first = buf[from] | 0x20;
        outer:
        for (int g = 0; g < byteGroup.length; g++) {
            byte[] name = byteGroup[g];
            if (first != name[0]) {
                continue;
            }
            for (int i = 1; i < len; i++) {
                if ((buf[from + i] | 0x20) != name[i]) {
                    continue outer;
                }
            }
            return BY_LENGTH[len][g];
        }
        return null;
    }
}

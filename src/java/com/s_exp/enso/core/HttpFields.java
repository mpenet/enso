// ABOUTME: RFC 9110 field grammar shared by the HTTP/1.1, HTTP/2 and HTTP/3 drivers:
// ABOUTME: token checks for request parsing and validation of handler response fields.
package com.s_exp.enso.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * RFC 9110 field grammar shared by the HTTP/1.1, HTTP/2 and HTTP/3
 * drivers: token membership for names and methods, and the checks applied
 * to handler-supplied response fields before any byte reaches the wire.
 */
public final class HttpFields {

    private HttpFields() {}

    /** RFC 9110 §5.6.2 tchar membership, indexed by octet value. */
    private static final boolean[] TCHAR = new boolean[256];

    static {
        for (int c = 0; c < 256; c++) {
            TCHAR[c] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || c == '!' || c == '#' || c == '$' || c == '%' || c == '&'
                || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.'
                || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
        }
    }

    /** Whether octet or char {@code c} is an RFC 9110 tchar. */
    public static boolean isTchar(int c) {
        return c >= 0 && c < 256 && TCHAR[c];
    }

    /** Non-empty RFC 9110 token. */
    public static boolean isToken(String s) {
        int n = s.length();
        if (n == 0) return false;
        for (int i = 0; i < n; i++) {
            if (!isTchar(s.charAt(i))) return false;
        }
        return true;
    }

    /**
     * Token without uppercase letters from index {@code from} on, with at
     * least one char there: HTTP/2 and HTTP/3 field names (RFC 9113 §8.2.1,
     * RFC 9114 §4.2), {@code from = 1} skipping a pseudo-header's ':'.
     */
    public static boolean isLowercaseToken(String s, int from) {
        int n = s.length();
        if (n <= from) return false;
        for (int i = from; i < n; i++) {
            char c = s.charAt(i);
            if (!isTchar(c) || (c >= 'A' && c <= 'Z')) return false;
        }
        return true;
    }

    /**
     * Rejects a response field name that isn't a token. Response fields are
     * written as ISO-8859-1 octets, so a char above U+00FF could otherwise
     * truncate to a delimiter (U+010D → CR).
     */
    public static void checkResponseName(String s) {
        if (!isToken(s)) {
            throw new IllegalArgumentException(
                "response header name is empty or contains a non-token character");
        }
    }

    /**
     * Charset for encoding String and seq response bodies: the charset
     * parameter of the Content-Type header (token or quoted, matched
     * case-insensitively, as ring.core.protocols reads it), else UTF-8.
     * Allocation-free unless a charset other than UTF-8 is named.
     *
     * @throws IllegalArgumentException when the named charset is unknown
     */
    public static Charset responseCharset(Map<?, ?> headers) {
        if (headers == null) return StandardCharsets.UTF_8;
        // The usual spellings are looked up directly: walking entrySet
        // allocates an entry per header on Clojure maps.
        Object v = headers.get("content-type");
        if (v == null) v = headers.get("Content-Type");
        if (v == null) {
            for (Map.Entry<?, ?> e : headers.entrySet()) {
                if (e.getKey() instanceof String k && k.length() == 12
                    && k.equalsIgnoreCase("content-type")) {
                    v = e.getValue();
                    break;
                }
            }
        }
        return v instanceof String ct ? charsetParam(ct) : StandardCharsets.UTF_8;
    }

    private static Charset charsetParam(String ct) {
        int n = ct.length();
        int semi = ct.indexOf(';');
        while (semi >= 0) {
            int p = semi + 1;
            while (p < n && (ct.charAt(p) == ' ' || ct.charAt(p) == '\t')) p++;
            if (ct.regionMatches(true, p, "charset=", 0, 8)) {
                int start = p + 8;
                int end;
                if (start < n && ct.charAt(start) == '"') {
                    start++;
                    end = ct.indexOf('"', start);
                    if (end < 0) end = n;
                } else {
                    end = start;
                    while (end < n && ct.charAt(end) != ';' && ct.charAt(end) != ' '
                           && ct.charAt(end) != '\t') {
                        end++;
                    }
                }
                if (end - start == 5 && ct.regionMatches(true, start, "utf-8", 0, 5)) {
                    return StandardCharsets.UTF_8;
                }
                String name = ct.substring(start, end);
                try {
                    return Charset.forName(name);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("unsupported response charset: " + name, e);
                }
            }
            semi = ct.indexOf(';', p);
        }
        return StandardCharsets.UTF_8;
    }

    /** Rejects a response field value outside RFC 9110 §5.5: VCHAR / obs-text / SP / HTAB. */
    public static void checkResponseValue(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c > 0xFF || (c < 0x20 && c != '\t') || c == 0x7F) {
                throw new IllegalArgumentException(
                    "response header value contains illegal character");
            }
        }
    }
}

// ABOUTME: Request-head validation shared by HTTP/2 and HTTP/3 (pseudo-headers, field rules) and
// ABOUTME: the host / authority grammar and absolute-form request-target parsing used by HTTP/1.1.
package com.s_exp.enso.core;

/**
 * Validates a decoded HTTP/2 or HTTP/3 request field section as it is fed
 * field by field (RFC 9113 §8.2-8.3, RFC 9114 §4.2-4.3), with no
 * allocation. One instance per connection, {@link #reset} per request.
 *
 * <p>{@link #add} classifies each field: {@link #PSEUDO} (consumed here),
 * {@link #FIELD} (the driver puts it in the Ring header map), {@link #HOST}
 * (a Host header: kept here, the driver puts {@link #authority} under
 * "host" once) or {@link #MALFORMED}. {@link #finish} then checks the
 * section as a whole: {@link #OK}, {@link #MALFORMED}, or
 * {@link #NOT_IMPLEMENTED} for a well-formed CONNECT, which the driver
 * answers with 501 since tunnels aren't served. A malformed request is a
 * stream error (h2 RST_STREAM PROTOCOL_ERROR, h3 H3_MESSAGE_ERROR);
 * {@link #failure} names the broken rule for logs.
 *
 * <p>Rules: pseudo-headers precede regular fields, appear once and are one
 * of :method :scheme :authority :path; :method is a token; :scheme is http
 * or https; :path is origin-form, or "*" for OPTIONS; :authority is
 * host[:port] without userinfo; :authority or Host is present, and equal
 * (ignoring case) when both are; field names are lowercase tokens; values
 * carry no CTL but HTAB and no leading/trailing whitespace; connection-
 * specific fields are forbidden; TE may only be "trailers"; Content-Length
 * is 1*DIGIT and appears once. A repeated Content-Length is malformed even
 * when the values agree, as on HTTP/1.1 (RFC 9110 §8.6 lets a recipient
 * reject it; one rule on every protocol).
 *
 * <p>{@link #uri} and {@link #query} split :path for the Ring request,
 * the one place HTTP/2 and HTTP/3 do it.
 */
public final class RequestHead {

    // add() results.
    public static final int FIELD = 0;
    public static final int PSEUDO = 1;
    public static final int HOST = 2;
    public static final int MALFORMED = 3;
    // finish() results.
    public static final int OK = 0;
    public static final int NOT_IMPLEMENTED = 4;

    private String method;
    private String scheme;
    private String authority;
    private String path;
    private String uri;
    private String query;
    private String host;
    private long contentLength = -1;
    private boolean seenRegular;
    private String failure;

    public void reset() {
        method = null;
        scheme = null;
        authority = null;
        path = null;
        uri = null;
        query = null;
        host = null;
        contentLength = -1;
        seenRegular = false;
        failure = null;
    }

    /** Classifies and validates one field. */
    public int add(String name, String value) {
        return add(name, value, false);
    }

    /**
     * {@link #add(String, String)}; {@code charsChecked}: the caller already
     * knows {@link #hasValidChars} holds (an HPACK table entry checked when
     * it was inserted), so the character scans are skipped.
     */
    public int add(String name, String value, boolean charsChecked) {
        int n = name.length();
        if (n == 0) return malformed("empty field name");
        if (!charsChecked && !isFieldValue(value)) return malformed("invalid field value");
        if (name.charAt(0) == ':') {
            if (seenRegular) return malformed("pseudo-header after regular field");
            switch (name) {
                case ":method" -> {
                    if (method != null) return malformed("duplicate :method");
                    if (!HttpFields.isToken(value)) return malformed("invalid :method");
                    method = value;
                }
                case ":scheme" -> {
                    if (scheme != null) return malformed("duplicate :scheme");
                    scheme = value;
                }
                case ":authority" -> {
                    if (authority != null) return malformed("duplicate :authority");
                    if (!isValidAuthority(value)) return malformed("invalid :authority");
                    authority = value;
                }
                case ":path" -> {
                    if (path != null) return malformed("duplicate :path");
                    path = value;
                }
                default -> {
                    return malformed("unknown pseudo-header");
                }
            }
            return PSEUDO;
        }
        seenRegular = true;
        if (!charsChecked && !HttpFields.isLowercaseToken(name, 0)) {
            return malformed("field name is not a lowercase token");
        }
        switch (n) {
            case 2 -> {
                if (name.equals("te") && !value.equalsIgnoreCase("trailers")) {
                    return malformed("TE other than trailers");
                }
            }
            case 4 -> {
                if (name.equals("host")) {
                    if (host != null) return malformed("duplicate host");
                    if (!isValidAuthority(value)) return malformed("invalid host");
                    host = value;
                    return HOST;
                }
            }
            case 7 -> {
                if (name.equals("upgrade")) return malformed("connection-specific field");
            }
            case 10 -> {
                if (name.equals("connection") || name.equals("keep-alive")) {
                    return malformed("connection-specific field");
                }
            }
            case 14 -> {
                if (name.equals("content-length")) {
                    if (contentLength >= 0) return malformed("repeated content-length");
                    long cl = HttpFields.parseDigits(value);
                    if (cl < 0) return malformed("invalid content-length");
                    contentLength = cl;
                }
            }
            case 16 -> {
                if (name.equals("proxy-connection")) return malformed("connection-specific field");
            }
            case 17 -> {
                if (name.equals("transfer-encoding")) return malformed("connection-specific field");
            }
            default -> {
            }
        }
        return FIELD;
    }

    /** Whole-section checks, once every field was added. */
    public int finish() {
        if (method == null) return malformed("missing :method");
        if (method.equals("CONNECT")) {
            if (scheme != null || path != null || authority == null) {
                return malformed("malformed CONNECT");
            }
            return NOT_IMPLEMENTED;
        }
        if (scheme == null || path == null) return malformed("missing :scheme or :path");
        if (!scheme.equals("https") && !scheme.equals("http")) return malformed("unsupported :scheme");
        if (authority == null && host == null) return malformed("missing :authority and host");
        if (authority != null && host != null && !authority.equalsIgnoreCase(host)) {
            return malformed(":authority and host differ");
        }
        if (path.equals("*")) {
            if (!method.equals("OPTIONS")) return malformed("asterisk-form outside OPTIONS");
        } else if (!isOriginForm(path)) {
            return malformed("invalid :path");
        }
        return OK;
    }

    private int malformed(String why) {
        failure = why;
        return MALFORMED;
    }

    public String method() { return method; }

    public String scheme() { return scheme; }

    /** :path as sent: origin-form or "*". */
    public String path() { return path; }

    /** The path of :path, before any '?' ("" for CONNECT); valid once {@link #finish} accepted the head. */
    public String uri() {
        if (uri == null) splitPath();
        return uri;
    }

    /** The query of :path after '?', or null; valid once {@link #finish} accepted the head. */
    public String query() {
        if (uri == null) splitPath();
        return query;
    }

    private void splitPath() {
        if (path == null) {
            uri = "";
            return;
        }
        int q = path.indexOf('?');
        if (q < 0) {
            uri = path;
        } else {
            uri = path.substring(0, q);
            query = path.substring(q + 1);
        }
    }

    /** The request authority: :authority, else the Host header. */
    public String authority() { return authority != null ? authority : host; }

    /** Content-Length, or -1 when absent. */
    public long contentLength() { return contentLength; }

    /** The rule the last MALFORMED result broke. */
    public String failure() { return failure; }

    /**
     * The character rules {@link #add} checks on every field: a valid value
     * ({@link #isFieldValue}) and a name that is a lowercase token or starts
     * with ':' (pseudo-headers are then checked by name).
     */
    public static boolean hasValidChars(String name, String value) {
        if (name.isEmpty() || !isFieldValue(value)) return false;
        return name.charAt(0) == ':' || HttpFields.isLowercaseToken(name, 0);
    }

    // ---- Grammar shared with HTTP/1.1 ---------------------------------------

    /**
     * RFC 9110 field value as carried by HTTP/2 and HTTP/3: no CTL but
     * HTAB, nothing above U+00FF, no leading or trailing SP / HTAB.
     */
    public static boolean isFieldValue(String v) {
        int n = v.length();
        if (n == 0) return true;
        if (HttpFields.isOws(v.charAt(0)) || HttpFields.isOws(v.charAt(n - 1))) return false;
        for (int i = 0; i < n; i++) {
            char c = v.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7F || c > 0xFF) return false;
        }
        return true;
    }

    /** origin-form: "/" then no CTL, SP, DEL or char above U+00FF (RFC 9112 §3.2.1). */
    public static boolean isOriginForm(String p) {
        int n = p.length();
        if (n == 0 || p.charAt(0) != '/') return false;
        for (int i = 1; i < n; i++) {
            char c = p.charAt(i);
            if (c <= 0x20 || c == 0x7F || c > 0xFF) return false;
        }
        return true;
    }

    /**
     * RFC 3986 authority without userinfo, as required of :authority, Host
     * and absolute-form targets: host [ ":" port ] with host an IP-literal,
     * IPv4 address or reg-name (non-empty) and port up to five digits. An
     * IPv6 literal is checked for its alphabet and shape, not every rule
     * of the address grammar.
     */
    public static boolean isValidAuthority(String s) {
        return isValidAuthority(s, 0, s.length());
    }

    static boolean isValidAuthority(String s, int from, int to) {
        if (from >= to) return false;
        int hostEnd;
        if (s.charAt(from) == '[') {
            int close = s.indexOf(']', from);
            if (close < 0 || close >= to || !isIpLiteral(s, from + 1, close)) return false;
            hostEnd = close + 1;
            if (hostEnd < to && s.charAt(hostEnd) != ':') return false;
        } else {
            hostEnd = from;
            while (hostEnd < to && s.charAt(hostEnd) != ':') hostEnd++;
            if (hostEnd == from || !isRegName(s, from, hostEnd)) return false;
        }
        if (hostEnd == to) return true;
        int digits = to - hostEnd - 1;
        if (digits > 5) return false;
        for (int i = hostEnd + 1; i < to; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static boolean isRegName(String s, int from, int to) {
        for (int i = from; i < to; i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= to || !isHex(s.charAt(i + 1)) || !isHex(s.charAt(i + 2))) return false;
                i += 2;
            } else if (!isUnreserved(c) && !isSubDelim(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpLiteral(String s, int from, int to) {
        if (from >= to) return false;
        char first = s.charAt(from);
        if (first == 'v' || first == 'V') {
            // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
            int i = from + 1;
            int hexStart = i;
            while (i < to && isHex(s.charAt(i))) i++;
            if (i == hexStart || i >= to || s.charAt(i) != '.') return false;
            i++;
            if (i >= to) return false;
            for (; i < to; i++) {
                char c = s.charAt(i);
                if (!isUnreserved(c) && !isSubDelim(c) && c != ':') return false;
            }
            return true;
        }
        boolean colon = false;
        for (int i = from; i < to; i++) {
            char c = s.charAt(i);
            if (c == ':') {
                colon = true;
            } else if (!isHex(c) && c != '.') {
                return false;
            }
        }
        return colon && to - from <= 45;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isUnreserved(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~';
    }

    private static boolean isSubDelim(char c) {
        return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')'
            || c == '*' || c == '+' || c == ',' || c == ';' || c == '=';
    }

    /** An absolute-form request target split into its parts. */
    public record AbsoluteForm(String authority, String path, String query) {}

    /**
     * Parses an HTTP/1.1 absolute-form target (RFC 9112 §3.2.2): an http
     * or https URI with a valid authority and no userinfo. An empty path
     * becomes "/". Returns null when {@code target} isn't one. Rare on an
     * origin server, so it allocates freely.
     */
    public static AbsoluteForm parseAbsoluteForm(String target) {
        int n = target.length();
        int colon = target.indexOf(':');
        if (colon < 0 || colon + 2 >= n || target.charAt(colon + 1) != '/'
            || target.charAt(colon + 2) != '/') {
            return null;
        }
        boolean http = colon == 4 && target.regionMatches(true, 0, "http", 0, 4);
        boolean https = colon == 5 && target.regionMatches(true, 0, "https", 0, 5);
        if (!http && !https) return null;
        int authStart = colon + 3;
        int authEnd = authStart;
        while (authEnd < n && target.charAt(authEnd) != '/' && target.charAt(authEnd) != '?') {
            authEnd++;
        }
        if (!isValidAuthority(target, authStart, authEnd)) return null;
        String authority = target.substring(authStart, authEnd);
        int q = target.indexOf('?', authEnd);
        String path;
        if (authEnd == n || target.charAt(authEnd) == '?') {
            path = "/";
        } else {
            path = target.substring(authEnd, q < 0 ? n : q);
        }
        String query = q < 0 ? null : target.substring(q + 1);
        return new AbsoluteForm(authority, path, query);
    }
}

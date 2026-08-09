package com.s_exp.enso.http3.qpack;

import java.util.HashMap;
import java.util.Map;

/**
 * QPACK Static Table per RFC 9204 Appendix A. 99 entries, indexed 0..98.
 * Some entries share a name with different values (e.g. {@code :status} has
 * many); the name-only lookup returns the lowest index in that group so
 * encoders emit the shortest indexed-name reference.
 *
 * <p>Data transcribed from RFC 9204 Appendix A. Non-code (spec) content.
 */
public final class QpackStaticTable {

    private QpackStaticTable() {}

    public static final String[][] TABLE;

    /** Name → lowest static-table index for that name. */
    public static final Map<String, Integer> NAME_INDEX = new HashMap<>();
    /** name+"\0"+value → static-table index for that exact pair. */
    public static final Map<String, Integer> NAME_VALUE_INDEX = new HashMap<>();

    static {
        TABLE = new String[][] {
            {":authority", ""},
            {":path", "/"},
            {"age", "0"},
            {"content-disposition", ""},
            {"content-length", "0"},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"if-modified-since", ""},
            {"if-none-match", ""},
            {"last-modified", ""},
            {"link", ""},
            {"location", ""},
            {"referer", ""},
            {"set-cookie", ""},
            {":method", "CONNECT"},
            {":method", "DELETE"},
            {":method", "GET"},
            {":method", "HEAD"},
            {":method", "OPTIONS"},
            {":method", "POST"},
            {":method", "PUT"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "103"},
            {":status", "200"},
            {":status", "304"},
            {":status", "404"},
            {":status", "503"},
            {"accept", "*/*"},
            {"accept", "application/dns-message"},
            {"accept-encoding", "gzip, deflate, br"},
            {"accept-ranges", "bytes"},
            {"access-control-allow-headers", "cache-control"},
            {"access-control-allow-headers", "content-type"},
            {"access-control-allow-origin", "*"},
            {"cache-control", "max-age=0"},
            {"cache-control", "max-age=2592000"},
            {"cache-control", "max-age=604800"},
            {"cache-control", "no-cache"},
            {"cache-control", "no-store"},
            {"cache-control", "public, max-age=31536000"},
            {"content-encoding", "br"},
            {"content-encoding", "gzip"},
            {"content-type", "application/dns-message"},
            {"content-type", "application/javascript"},
            {"content-type", "application/json"},
            {"content-type", "application/x-www-form-urlencoded"},
            {"content-type", "image/gif"},
            {"content-type", "image/jpeg"},
            {"content-type", "image/png"},
            {"content-type", "text/css"},
            {"content-type", "text/html; charset=utf-8"},
            {"content-type", "text/plain"},
            {"content-type", "text/plain;charset=utf-8"},
            {"range", "bytes=0-"},
            {"strict-transport-security", "max-age=31536000"},
            {"strict-transport-security", "max-age=31536000; includesubdomains"},
            {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
            {"vary", "accept-encoding"},
            {"vary", "origin"},
            {"x-content-type-options", "nosniff"},
            {"x-xss-protection", "1; mode=block"},
            {":status", "100"},
            {":status", "204"},
            {":status", "206"},
            {":status", "302"},
            {":status", "400"},
            {":status", "403"},
            {":status", "421"},
            {":status", "425"},
            {":status", "500"},
            {"accept-language", ""},
            {"access-control-allow-credentials", "FALSE"},
            {"access-control-allow-credentials", "TRUE"},
            {"access-control-allow-headers", "*"},
            {"access-control-allow-methods", "get"},
            {"access-control-allow-methods", "get, post, options"},
            {"access-control-allow-methods", "options"},
            {"access-control-expose-headers", "content-length"},
            {"access-control-request-headers", "content-type"},
            {"access-control-request-method", "get"},
            {"access-control-request-method", "post"},
            {"alt-svc", "clear"},
            {"authorization", ""},
            {"content-security-policy",
                "script-src 'none'; object-src 'none'; base-uri 'none'"},
            {"early-data", "1"},
            {"expect-ct", ""},
            {"forwarded", ""},
            {"if-range", ""},
            {"origin", ""},
            {"purpose", "prefetch"},
            {"server", ""},
            {"timing-allow-origin", "*"},
            {"upgrade-insecure-requests", "1"},
            {"user-agent", ""},
            {"x-forwarded-for", ""},
            {"x-frame-options", "deny"},
            {"x-frame-options", "sameorigin"},
        };
        if (TABLE.length != 99) {
            throw new AssertionError("static table length: " + TABLE.length);
        }
        for (int i = 0; i < TABLE.length; i++) {
            String name = TABLE[i][0];
            String value = TABLE[i][1];
            NAME_INDEX.putIfAbsent(name, i);
            NAME_VALUE_INDEX.put(name + '\0' + value, i);
        }
    }

    /** Static-table entry count. */
    public static int size() { return TABLE.length; }

    /** @return the (name, value) pair at index {@code i}. */
    public static String[] get(int i) { return TABLE[i]; }

    /** @return index of exact name+value match, or -1. */
    public static int findExact(String name, String value) {
        Integer i = NAME_VALUE_INDEX.get(name + '\0' + value);
        return i == null ? -1 : i;
    }

    /** @return index of first entry with matching name, or -1. */
    public static int findName(String name) {
        Integer i = NAME_INDEX.get(name);
        return i == null ? -1 : i;
    }
}

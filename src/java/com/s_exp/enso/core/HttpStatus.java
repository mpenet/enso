// ABOUTME: HTTP status reason phrases, and the plain-text error responses every protocol sends
// ABOUTME: for the statuses the server decides itself (400, 408, 413, 431, 500, 503, ...).
package com.s_exp.enso.core;

import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.api.Response;
import java.nio.charset.StandardCharsets;

/**
 * One table for reason phrases and server-generated error responses, so
 * an error looks the same on HTTP/1.1, HTTP/2 and HTTP/3: status, a
 * {@code text/plain; charset=utf-8} body holding the reason phrase.
 */
public final class HttpStatus {

    public static final String TEXT_PLAIN = "text/plain; charset=utf-8";

    private static final PersistentArrayMap TEXT_HEADERS =
        new PersistentArrayMap(new Object[] {"content-type", TEXT_PLAIN});
    // Prebuilt, shared and never mutated: index = status - 400.
    private static final Response[] ERRORS = new Response[200];

    static {
        for (int status = 400; status < 600; status++) {
            String reason = reason(status);
            if (!reason.isEmpty()) {
                ERRORS[status - 400] = new Response(status, TEXT_HEADERS,
                                                    reason.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private HttpStatus() {}

    /** The reason phrase for {@code status}, empty when it has none here. */
    public static String reason(int status) {
        return switch (status) {
            case 100 -> "Continue";
            case 101 -> "Switching Protocols";
            case 200 -> "OK";
            case 201 -> "Created";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 303 -> "See Other";
            case 304 -> "Not Modified";
            case 307 -> "Temporary Redirect";
            case 308 -> "Permanent Redirect";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 408 -> "Request Timeout";
            case 411 -> "Length Required";
            case 413 -> "Content Too Large";
            case 417 -> "Expectation Failed";
            case 426 -> "Upgrade Required";
            case 431 -> "Request Header Fields Too Large";
            case 500 -> "Internal Server Error";
            case 501 -> "Not Implemented";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 505 -> "HTTP Version Not Supported";
            default -> "";
        };
    }

    /**
     * The server's own response for error {@code status} (4xx / 5xx with a
     * reason phrase here): shared, allocation-free. Other statuses get a
     * fresh bodiless response.
     */
    public static Response error(int status) {
        if (status >= 400 && status < 600) {
            Response r = ERRORS[status - 400];
            if (r != null) return r;
        }
        return new Response(status, PersistentArrayMap.EMPTY, null);
    }
}

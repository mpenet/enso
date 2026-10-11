// ABOUTME: Server-side checks of a WebSocket opening handshake that don't depend on the HTTP
// ABOUTME: driver: the Origin policy (cross-site WebSocket hijacking) and owned response headers.
package com.s_exp.enso.websocket;

import java.util.function.Predicate;

/**
 * Handshake policy shared by the HTTP drivers that upgrade to WebSocket.
 *
 * <p>Origin: browsers attach cookies to a cross-site WebSocket handshake,
 * and WebSockets are not subject to CORS, so a page on another site could
 * open an authenticated socket (cross-site WebSocket hijacking). A browser
 * always sends {@code Origin} on a WebSocket handshake; without a policy
 * the server accepts only its own origin, whose scheme and host must match
 * the connection's and the {@code Host} header (as gorilla/websocket and
 * Spring do). A handshake without {@code Origin} doesn't come from a
 * browser; with no policy it is accepted, but a configured allowlist is a
 * hard gate that refuses it.
 */
public final class WebSocketHandshake {

    private WebSocketHandshake() {}

    /**
     * Whether {@code origin} (the {@code Origin} header, null when absent)
     * may open a WebSocket on a request whose {@code Host} is {@code host}
     * over a {@code secure} (TLS) connection or not. {@code allowed} is the
     * configured policy, null for same origin. A configured allowlist is a
     * hard gate: a missing or opaque Origin is refused.
     */
    public static boolean originAllowed(String origin, String host, boolean secure,
                                        Predicate<String> allowed) {
        if (allowed != null) {
            // An allowlist (even match-anything "*") gates on an attributable
            // origin: a missing or opaque / non-serialised Origin (the string
            // "null" from a sandboxed iframe or a privacy-stripped request)
            // is refused regardless, as CORS's Access-Control-Allow-Origin: *
            // deliberately does not match the null origin.
            return origin != null && isSerializedOrigin(origin) && allowed.test(origin);
        }
        if (origin == null) {
            return true;
        }
        return sameOrigin(origin, host, secure);
    }

    /**
     * Whether {@code origin} is a single serialised origin
     * ({@code scheme://host[:port]}): a non-empty scheme, a non-empty
     * authority and no path. False for an opaque origin ("null") or anything
     * else that isn't a serialised origin.
     */
    static boolean isSerializedOrigin(String origin) {
        int sep = origin.indexOf("://");
        if (sep <= 0) {
            return false;
        }
        String authority = origin.substring(sep + 3);
        return !authority.isEmpty() && authority.indexOf('/') < 0;
    }

    /**
     * Whether a serialised origin ({@code scheme://host[:port]}) is the
     * connection's own: its scheme matches the transport (https when
     * {@code secure}, else http) and its host[:port] equals {@code host}.
     * Compared as sent: browsers omit default ports, as clients do in
     * {@code Host}. False for an opaque origin ("null") or anything else.
     */
    static boolean sameOrigin(String origin, String host, boolean secure) {
        if (!isSerializedOrigin(origin)) {
            return false;
        }
        int sep = origin.indexOf("://");
        String scheme = origin.substring(0, sep);
        if (!scheme.equalsIgnoreCase(secure ? "https" : "http")) {
            return false;
        }
        String authority = origin.substring(sep + 3);
        return host != null && host.equalsIgnoreCase(authority);
    }

    /**
     * Response headers the server sets itself on a 101, or that make no
     * sense on it; a handler's value for one of them is dropped.
     * Sec-WebSocket-Extensions belongs to the server: only it knows which
     * extensions the connection speaks.
     */
    public static boolean isServerOwnedHeader(String name) {
        return name.equalsIgnoreCase("upgrade")
            || name.equalsIgnoreCase("connection")
            || name.equalsIgnoreCase("sec-websocket-accept")
            || name.equalsIgnoreCase("sec-websocket-protocol")
            || name.equalsIgnoreCase("sec-websocket-extensions");
    }
}

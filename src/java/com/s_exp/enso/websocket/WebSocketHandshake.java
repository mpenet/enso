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
 * the server accepts only its own origin, whose host must equal the
 * {@code Host} header (as gorilla/websocket and Spring do). A handshake
 * without {@code Origin} doesn't come from a browser and is accepted.
 */
public final class WebSocketHandshake {

    private WebSocketHandshake() {}

    /**
     * Whether {@code origin} (the {@code Origin} header, null when absent)
     * may open a WebSocket on a request whose {@code Host} is {@code host}.
     * {@code allowed} is the configured policy, null for same origin.
     */
    public static boolean originAllowed(String origin, String host, Predicate<String> allowed) {
        if (origin == null) {
            return true;
        }
        if (allowed != null) {
            return allowed.test(origin);
        }
        return host != null && host.equalsIgnoreCase(originAuthority(origin));
    }

    /**
     * The host[:port] of a serialised origin ({@code scheme://host[:port]}),
     * or null for an opaque origin ("null") or anything else. Compared as
     * sent: browsers omit default ports, as clients do in {@code Host}.
     */
    static String originAuthority(String origin) {
        int sep = origin.indexOf("://");
        if (sep <= 0) {
            return null;
        }
        String authority = origin.substring(sep + 3);
        return authority.isEmpty() || authority.indexOf('/') >= 0 ? null : authority;
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

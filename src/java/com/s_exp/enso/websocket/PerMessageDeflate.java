// ABOUTME: permessage-deflate (RFC 7692): negotiation of a client's offers and the per-connection
// ABOUTME: Deflater / Inflater pair, created on first use and released when the connection ends.
package com.s_exp.enso.websocket;

import java.util.Locale;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * The permessage-deflate extension as negotiated for one connection, and
 * its compression state.
 *
 * <p>Negotiation (RFC 7692 §7): the first acceptable offer wins. An offer
 * with an unknown parameter, a repeated one or an invalid value is declined
 * (§7, §7.1). {@code client_max_window_bits} and
 * {@code client_no_context_takeover} need nothing from the server: the
 * inflater handles any window size and any reset pattern.
 * {@code server_max_window_bits=N} below 15 is honoured even though
 * {@code java.util.zip} always compresses with a 32 KiB window: only
 * messages of at most 2^N bytes are compressed, each with a fresh window,
 * so no back-reference reaches further than the message itself; larger
 * messages are sent uncompressed, which §6 allows.
 *
 * <p>Memory: the Deflater (about 256 KiB of native memory at the default
 * settings) and the Inflater (about 40 KiB) are allocated on first use and
 * released by {@link #releaseDeflater} / {@link #releaseInflater} when the
 * connection ends. Without the server's context takeover the Deflater
 * keeps nothing between messages, so it is borrowed from {@link ZlibPool}
 * for each message instead. The Inflater stays: a client's
 * {@code client_no_context_takeover} offer isn't binding unless echoed, and
 * clients keep their context when it isn't (Autobahn's does), while
 * echoing it makes some clients build a compressor per message.
 */
public final class PerMessageDeflate {

    private static final String NAME = "permessage-deflate";

    /** The client asked the server to compress every message on its own. */
    final boolean serverNoContextTakeover;
    /** The window the client allows the server, in bits (8-15). */
    final int serverWindowBits;
    private final String responseHeader;
    // Used by the thread holding the connection's write lock.
    private Deflater deflater;
    // Used by the read loop only.
    private Inflater inflater;

    /** {@code serverMaxWindowBits}: the offered value, 0 when not offered. */
    private PerMessageDeflate(boolean serverNoContextTakeover, int serverMaxWindowBits) {
        this.serverNoContextTakeover = serverNoContextTakeover;
        this.serverWindowBits = serverMaxWindowBits == 0 ? 15 : serverMaxWindowBits;
        StringBuilder sb = new StringBuilder(NAME);
        if (serverNoContextTakeover) {
            sb.append("; server_no_context_takeover");
        }
        if (serverMaxWindowBits != 0) {
            // §7.1.2.1: accepting the parameter means echoing it, with a
            // value no larger than offered.
            sb.append("; server_max_window_bits=").append(serverMaxWindowBits);
        }
        this.responseHeader = sb.toString();
    }

    /**
     * Whether a data message of {@code length} bytes is sent compressed:
     * long enough to gain, and within a window smaller than 15 bits.
     */
    boolean compresses(int length, int threshold) {
        return length >= threshold && (serverWindowBits == 15 || length <= 1 << serverWindowBits);
    }

    /** Whether the Deflater starts over after every message. */
    boolean resetsAfterEachMessage() {
        return serverNoContextTakeover || serverWindowBits < 15;
    }

    /**
     * Picks the first acceptable permessage-deflate offer in a
     * {@code Sec-WebSocket-Extensions} request header value; null when there
     * is none (the connection then runs uncompressed).
     */
    public static PerMessageDeflate negotiate(String offers) {
        if (offers == null) {
            return null;
        }
        int n = offers.length();
        int i = 0;
        while (i < n) {
            int end = elementEnd(offers, i, n, ',');
            PerMessageDeflate accepted = accept(offers, i, end);
            if (accepted != null) {
                return accepted;
            }
            i = end + 1;
        }
        return null;
    }

    /** The {@code Sec-WebSocket-Extensions} response header value. */
    public String responseHeader() {
        return responseHeader;
    }

    /** The Deflater for the message being compressed. */
    Deflater deflater() {
        Deflater d = deflater;
        if (d == null) {
            d = resetsAfterEachMessage() ? ZlibPool.deflater() : new Deflater(ZlibPool.LEVEL, true);
            deflater = d;
        }
        return d;
    }

    /**
     * A message was compressed: without context takeover the Deflater
     * starts over, given back to the pool.
     */
    void deflated() {
        if (resetsAfterEachMessage() && deflater != null) {
            ZlibPool.give(deflater);
            deflater = null;
        }
    }

    /** The Inflater, kept for the connection's lifetime. */
    Inflater inflater() {
        Inflater i = inflater;
        if (i == null) {
            i = new Inflater(true);
            inflater = i;
        }
        return i;
    }

    /** The connection ended: frees the Deflater, or gives a borrowed one back. */
    void releaseDeflater() {
        if (deflater != null) {
            if (resetsAfterEachMessage()) {
                ZlibPool.give(deflater);
            } else {
                deflater.end();
            }
            deflater = null;
        }
    }

    /** The connection ended: frees the Inflater. */
    void releaseInflater() {
        if (inflater != null) {
            inflater.end();
            inflater = null;
        }
    }

    /**
     * Parses one offer, {@code s[from..to)}: the extension name, then
     * {@code ;}-separated parameters. Null when it isn't permessage-deflate
     * or can't be accepted.
     */
    private static PerMessageDeflate accept(String s, int from, int to) {
        int nameEnd = elementEnd(s, from, to, ';');
        if (!trimmedEqualsIgnoreCase(s, from, nameEnd, NAME)) {
            return null;
        }
        boolean serverNoContextTakeover = false;
        boolean clientNoContextTakeover = false;
        int serverMaxWindowBits = 0;
        boolean clientMaxWindowBits = false;
        // s[i] is the ';' before the next parameter, or i == to.
        int i = nameEnd;
        while (i < to) {
            int start = i + 1;
            int end = elementEnd(s, start, to, ';');
            int eq = indexOf(s, start, end, '=');
            String name = s.substring(start, eq < 0 ? end : eq).trim().toLowerCase(Locale.ROOT);
            String value = eq < 0 ? null : unquote(s.substring(eq + 1, end).trim());
            if (eq >= 0 && value == null) {
                return null;
            }
            switch (name) {
                case "server_no_context_takeover" -> {
                    if (serverNoContextTakeover || value != null) return null;
                    serverNoContextTakeover = true;
                }
                case "client_no_context_takeover" -> {
                    if (clientNoContextTakeover || value != null) return null;
                    clientNoContextTakeover = true;
                }
                case "server_max_window_bits" -> {
                    // A value is required.
                    if (serverMaxWindowBits != 0 || value == null) return null;
                    serverMaxWindowBits = windowBits(value);
                    if (serverMaxWindowBits < 0) return null;
                }
                case "client_max_window_bits" -> {
                    if (clientMaxWindowBits || (value != null && windowBits(value) < 0)) return null;
                    clientMaxWindowBits = true;
                }
                default -> {
                    return null;
                }
            }
            i = end;
        }
        return new PerMessageDeflate(serverNoContextTakeover, serverMaxWindowBits);
    }

    /** 8-15 written without leading zeros (§7.1.2.1), else -1. */
    private static int windowBits(String v) {
        if (v.length() == 1 && v.charAt(0) >= '8' && v.charAt(0) <= '9') {
            return v.charAt(0) - '0';
        }
        if (v.length() == 2 && v.charAt(0) == '1' && v.charAt(1) >= '0' && v.charAt(1) <= '5') {
            return 10 + v.charAt(1) - '0';
        }
        return -1;
    }

    /** A token, or the content of a quoted-string; null when malformed. */
    private static String unquote(String v) {
        if (v.isEmpty()) {
            return null;
        }
        if (v.charAt(0) != '"') {
            return v.indexOf('"') < 0 ? v : null;
        }
        if (v.length() < 2 || v.charAt(v.length() - 1) != '"') {
            return null;
        }
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 1; i < v.length() - 1; i++) {
            char c = v.charAt(i);
            if (c == '\\') {
                if (++i == v.length() - 1) {
                    return null;
                }
                c = v.charAt(i);
            } else if (c == '"') {
                return null;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** Index of the next {@code sep} in s[from..to) outside quoted strings, or {@code to}. */
    private static int elementEnd(String s, int from, int to, char sep) {
        boolean quoted = false;
        for (int i = from; i < to; i++) {
            char c = s.charAt(i);
            if (quoted) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    quoted = false;
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == sep) {
                return i;
            }
        }
        return to;
    }

    private static int indexOf(String s, int from, int to, char c) {
        for (int i = from; i < to; i++) {
            if (s.charAt(i) == c) {
                return i;
            }
        }
        return -1;
    }

    private static boolean trimmedEqualsIgnoreCase(String s, int from, int to, String expected) {
        while (from < to && isSpace(s.charAt(from))) from++;
        while (to > from && isSpace(s.charAt(to - 1))) to--;
        return to - from == expected.length() && s.regionMatches(true, from, expected, 0, expected.length());
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t';
    }
}

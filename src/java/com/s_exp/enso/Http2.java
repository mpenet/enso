package com.s_exp.enso;

/**
 * RFC 9113 constants: frame types, flags, error codes, SETTINGS identifiers,
 * and the connection preface. Grouped here so the codec and connection driver
 * share a single vocabulary.
 */
final class Http2 {

    private Http2() {
    }

    // ---- Frame types (RFC 9113 §6) ----
    static final int TYPE_DATA          = 0x0;
    static final int TYPE_HEADERS       = 0x1;
    static final int TYPE_PRIORITY      = 0x2;
    static final int TYPE_RST_STREAM    = 0x3;
    static final int TYPE_SETTINGS      = 0x4;
    static final int TYPE_PUSH_PROMISE  = 0x5;
    static final int TYPE_PING          = 0x6;
    static final int TYPE_GOAWAY        = 0x7;
    static final int TYPE_WINDOW_UPDATE = 0x8;
    static final int TYPE_CONTINUATION  = 0x9;

    // ---- Frame flags (RFC 9113 §6) ----
    static final int FLAG_ACK         = 0x1;   // SETTINGS, PING
    static final int FLAG_END_STREAM  = 0x1;   // DATA, HEADERS
    static final int FLAG_END_HEADERS = 0x4;   // HEADERS, CONTINUATION, PUSH_PROMISE
    static final int FLAG_PADDED      = 0x8;   // DATA, HEADERS, PUSH_PROMISE
    static final int FLAG_PRIORITY    = 0x20;  // HEADERS

    // ---- Error codes (RFC 9113 §7) ----
    static final int ERROR_NO_ERROR            = 0x0;
    static final int ERROR_PROTOCOL_ERROR      = 0x1;
    static final int ERROR_INTERNAL_ERROR      = 0x2;
    static final int ERROR_FLOW_CONTROL_ERROR  = 0x3;
    static final int ERROR_SETTINGS_TIMEOUT    = 0x4;
    static final int ERROR_STREAM_CLOSED       = 0x5;
    static final int ERROR_FRAME_SIZE_ERROR    = 0x6;
    static final int ERROR_REFUSED_STREAM      = 0x7;
    static final int ERROR_CANCEL              = 0x8;
    static final int ERROR_COMPRESSION_ERROR   = 0x9;
    static final int ERROR_CONNECT_ERROR       = 0xa;
    static final int ERROR_ENHANCE_YOUR_CALM   = 0xb;
    static final int ERROR_INADEQUATE_SECURITY = 0xc;
    static final int ERROR_HTTP_1_1_REQUIRED   = 0xd;

    // ---- SETTINGS identifiers (RFC 9113 §6.5.2) ----
    static final int SETTINGS_HEADER_TABLE_SIZE      = 0x1;
    static final int SETTINGS_ENABLE_PUSH            = 0x2;
    static final int SETTINGS_MAX_CONCURRENT_STREAMS = 0x3;
    static final int SETTINGS_INITIAL_WINDOW_SIZE    = 0x4;
    static final int SETTINGS_MAX_FRAME_SIZE         = 0x5;
    static final int SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6;

    // ---- Spec-mandated defaults ----
    static final int DEFAULT_HEADER_TABLE_SIZE      = 4096;
    static final int DEFAULT_INITIAL_WINDOW_SIZE    = 65_535;
    static final int DEFAULT_MAX_FRAME_SIZE         = 16_384;
    static final int MAX_ALLOWED_FRAME_SIZE         = 16_777_215; // 2^24-1
    static final int MAX_ALLOWED_WINDOW_SIZE        = 0x7FFF_FFFF; // 2^31-1

    static final int FRAME_HEADER_SIZE = 9;

    static final byte[] PREFACE =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

    /** Thrown to signal a connection-level protocol error carrying a code from {@code ERROR_*}. */
    static final class ConnectionError extends java.io.IOException {
        final int code;
        ConnectionError(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}

// ABOUTME: HTTP/3 frame type constants (RFC 9114 section 7.2) and the check for reserved
// ABOUTME: HTTP/2-only frame types.
package com.s_exp.enso.http3;

/**
 * HTTP/3 frame types (RFC 9114 §7.2). Only server-relevant types have
 * dedicated constants; unknown and grease types are ignored (§9), while
 * HTTP/2-only types are errors ({@link #isReservedHttp2}).
 */
public final class Http3FrameType {

    /** {@code DATA} — request or response body. */
    public static final long DATA = 0x00;
    /** {@code HEADERS} — QPACK-encoded field section. */
    public static final long HEADERS = 0x01;
    /** {@code CANCEL_PUSH} — client-only; server MAY treat as protocol error. */
    public static final long CANCEL_PUSH = 0x03;
    /** {@code SETTINGS} — connection-level settings, control stream only. */
    public static final long SETTINGS = 0x04;
    /** {@code PUSH_PROMISE} — server push; unused by us. */
    public static final long PUSH_PROMISE = 0x05;
    /** {@code GOAWAY} — graceful shutdown, control stream only. */
    public static final long GOAWAY = 0x07;
    /** {@code MAX_PUSH_ID} — server push limit; unused by us. */
    public static final long MAX_PUSH_ID = 0x0D;

    private Http3FrameType() {}

    /**
     * HTTP/2 frame types with no HTTP/3 equivalent (PRIORITY, PING,
     * WINDOW_UPDATE, CONTINUATION). RFC 9114 §7.2.8: receiving one is a
     * connection error of type H3_FRAME_UNEXPECTED.
     */
    public static boolean isReservedHttp2(long type) {
        return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
    }
}

package com.s_exp.enso.quiche.h3;

/**
 * HTTP/3 frame types (RFC 9114 §7.2). Only server-relevant types have
 * dedicated constants; unknown/reserved types are silently ignored per
 * §9 when they are not one of the mandatory control-stream types.
 */
public final class H3FrameType {

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

    private H3FrameType() {}
}

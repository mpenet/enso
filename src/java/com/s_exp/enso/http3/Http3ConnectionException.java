package com.s_exp.enso.http3;

/**
 * Thrown by peer-frame validation when the h3 spec (RFC 9114 §8) says
 * the whole QUIC connection MUST be closed with an application error.
 * The session catches this at the top of stream-data dispatch and
 * translates it into a {@code quiche_conn_close(app=true, errorCode)}.
 *
 * <p>Codes are the numeric H3 error space (RFC 9114 §8.1) + QPACK
 * codes from RFC 9204 §8.3.
 */
public final class Http3ConnectionException extends RuntimeException {

    // RFC 9114 §8.1
    public static final long H3_NO_ERROR = 0x100L;
    public static final long H3_GENERAL_PROTOCOL_ERROR = 0x101L;
    public static final long H3_INTERNAL_ERROR = 0x102L;
    public static final long H3_STREAM_CREATION_ERROR = 0x103L;
    public static final long H3_CLOSED_CRITICAL_STREAM = 0x104L;
    public static final long H3_FRAME_UNEXPECTED = 0x105L;
    public static final long H3_FRAME_ERROR = 0x106L;
    public static final long H3_EXCESSIVE_LOAD = 0x107L;
    public static final long H3_ID_ERROR = 0x108L;
    public static final long H3_SETTINGS_ERROR = 0x109L;
    public static final long H3_MISSING_SETTINGS = 0x10aL;
    public static final long H3_REQUEST_REJECTED = 0x10bL;
    public static final long H3_REQUEST_CANCELLED = 0x10cL;
    public static final long H3_REQUEST_INCOMPLETE = 0x10dL;
    public static final long H3_MESSAGE_ERROR = 0x10eL;
    public static final long H3_CONNECT_ERROR = 0x10fL;
    public static final long H3_VERSION_FALLBACK = 0x110L;

    // RFC 9204 §8.3 — QPACK error codes.
    public static final long QPACK_DECOMPRESSION_FAILED = 0x200L;
    public static final long QPACK_ENCODER_STREAM_ERROR = 0x201L;
    public static final long QPACK_DECODER_STREAM_ERROR = 0x202L;

    private final long errorCode;

    public Http3ConnectionException(long errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public long errorCode() { return errorCode; }
}

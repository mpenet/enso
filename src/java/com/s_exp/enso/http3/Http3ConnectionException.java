package com.s_exp.enso.http3;

/**
 * Thrown by peer-frame validation when the h3 spec (RFC 9114 §8) says
 * the whole QUIC connection MUST be closed with an application error.
 * The session catches this at the top of stream-data dispatch and
 * translates it into a {@code quiche_conn_close(app=true, errorCode)}.
 *
 * <p>Codes are the numeric H3 error space (RFC 9114 §8.1):
 * <ul>
 *   <li>0x100 H3_NO_ERROR
 *   <li>0x101 H3_GENERAL_PROTOCOL_ERROR
 *   <li>0x105 H3_FRAME_UNEXPECTED
 *   <li>0x106 H3_FRAME_ERROR
 *   <li>0x108 H3_ID_ERROR
 *   <li>0x10a H3_MISSING_SETTINGS
 *   <li>0x10c H3_CLOSED_CRITICAL_STREAM
 * </ul>
 */
public final class Http3ConnectionException extends RuntimeException {

    public static final long H3_NO_ERROR = 0x100L;
    public static final long H3_GENERAL_PROTOCOL_ERROR = 0x101L;
    public static final long H3_STREAM_CREATION_ERROR = 0x103L;
    public static final long H3_FRAME_UNEXPECTED = 0x105L;
    public static final long H3_FRAME_ERROR = 0x106L;
    public static final long H3_ID_ERROR = 0x108L;
    public static final long H3_MISSING_SETTINGS = 0x10aL;
    public static final long H3_CLOSED_CRITICAL_STREAM = 0x10cL;

    private final long errorCode;

    public Http3ConnectionException(long errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public long errorCode() { return errorCode; }
}

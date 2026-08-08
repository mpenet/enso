package com.s_exp.enso.http3.qpack;

/**
 * QPACK-level failure signalled from a decoder/encoder. Carries an H3
 * error code so the caller can either reset the offending stream
 * (per-stream errors like QPACK_DECOMPRESSION_FAILED) or close the whole
 * connection (session-level errors like QPACK_ENCODER_STREAM_ERROR).
 *
 * <p>H3 error codes from RFC 9204 §8.3 / RFC 9114 §8.1. Stored as raw
 * varint values because the H3 wire format encodes them that way.
 */
public class QpackException extends RuntimeException {

    // RFC 9204 §8.3 QPACK error codes.
    public static final long QPACK_DECOMPRESSION_FAILED = 0x200;
    public static final long QPACK_ENCODER_STREAM_ERROR = 0x201;
    public static final long QPACK_DECODER_STREAM_ERROR = 0x202;

    // Truthy convenience — RFC 9114 §8.1.
    public static final long H3_FRAME_ERROR = 0x106;
    public static final long H3_EXCESSIVE_LOAD = 0x107;

    private final long errorCode;
    private final boolean streamLevel;

    public QpackException(long errorCode, boolean streamLevel, String message) {
        super(message);
        this.errorCode = errorCode;
        this.streamLevel = streamLevel;
    }

    public QpackException(long errorCode, boolean streamLevel, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.streamLevel = streamLevel;
    }

    public long errorCode() { return errorCode; }
    /** True → reset the offending stream. False → close the connection. */
    public boolean isStreamLevel() { return streamLevel; }
}

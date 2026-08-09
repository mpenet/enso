package com.s_exp.enso.http3;

/**
 * HTTP/3 unidirectional stream types (RFC 9114 §6.2). The first varint
 * on a peer-opened uni stream selects one of these; unknown types are
 * per §6.2 valid — the receiver MUST cancel the stream via
 * {@code STOP_SENDING(H3_STREAM_CREATION_ERROR)}.
 */
public final class Http3StreamType {

    /** Control stream (bearing SETTINGS/GOAWAY etc.). */
    public static final long CONTROL = 0x00;
    /** Push stream — server-initiated, unused here. */
    public static final long PUSH = 0x01;
    /** QPACK encoder stream (peer→us instructions to update our decoder). */
    public static final long QPACK_ENCODER = 0x02;
    /** QPACK decoder stream (peer→us acks/insert-count feedback). */
    public static final long QPACK_DECODER = 0x03;

    private Http3StreamType() {}
}

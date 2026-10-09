// ABOUTME: Encodes the connection-level HTTP/3 frames the server sends on its control stream
// ABOUTME: (SETTINGS, GOAWAY); responses are framed in place by Http3ResponseWriter.
package com.s_exp.enso.http3;

import java.nio.ByteBuffer;

/**
 * Fresh-buffer encoders for the frames of the server's control stream,
 * sent once or twice per connection. Response HEADERS and DATA frames are
 * written straight into the event loop's frame buffer by
 * {@link Http3ResponseWriter}.
 */
public final class Http3FrameWriter {

    private Http3FrameWriter() {}

    /** Encode a SETTINGS frame from a flat {id1, val1, id2, val2, ...} array. */
    public static ByteBuffer settings(long[] idValuePairs) {
        if ((idValuePairs.length & 1) != 0) {
            throw new IllegalArgumentException("settings must be id/value pairs");
        }
        int payloadSize = 0;
        for (long v : idValuePairs) payloadSize += Http3Varint.size(v);
        int total = Http3Varint.size(Http3FrameType.SETTINGS) + Http3Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Http3Varint.encode(out, Http3FrameType.SETTINGS);
        Http3Varint.encode(out, payloadSize);
        for (long v : idValuePairs) Http3Varint.encode(out, v);
        out.flip();
        return out;
    }


    /** Encode a GOAWAY frame carrying the given stream/push ID. */
    public static ByteBuffer goaway(long id) {
        int payloadSize = Http3Varint.size(id);
        int total = Http3Varint.size(Http3FrameType.GOAWAY) + Http3Varint.size(payloadSize) + payloadSize;
        ByteBuffer out = ByteBuffer.allocate(total);
        Http3Varint.encode(out, Http3FrameType.GOAWAY);
        Http3Varint.encode(out, payloadSize);
        Http3Varint.encode(out, id);
        out.flip();
        return out;
    }
}

// ABOUTME: HTTP/3 unidirectional streams of a connection: opens ours (control with SETTINGS, QPACK
// ABOUTME: encoder/decoder), sends GOAWAY, and parses and validates every stream the peer opens.
package com.s_exp.enso.http3;

import com.s_exp.enso.http3.qpack.NBitInteger;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

/**
 * The connection-level half of HTTP/3 (RFC 9114 §6.2, §7.2; RFC 9204 §4.2),
 * event loop only.
 *
 * <ul>
 *   <li>Ours: control stream (SETTINGS advertising a QPACK table capacity
 *       of 0, so peers never insert into a dynamic table we don't keep,
 *       and the field-section limit), QPACK encoder and decoder streams.
 *       Opening is retried until the peer grants uni-stream credit.
 *   <li>Peer's: the type varint identifies each; the control stream is
 *       parsed (SETTINGS first and once, GOAWAY ids non-increasing,
 *       request-only frames rejected), encoder / decoder instructions are
 *       validated against capacity 0, grease and unknown types discarded
 *       (unknown ones also get STOP_SENDING).
 * </ul>
 *
 * Violations raise {@link Http3ConnectionException}; the connection closes
 * with its code.
 */
final class Http3ControlStreams {

    private static final Logger LOG = Logger.getLogger(Http3ControlStreams.class.getName());

    // The QPACK decoder supports the static table only: a non-zero
    // capacity would invite encoder instructions it rejects.
    private static final long QPACK_MAX_TABLE_CAPACITY = 0;
    private static final long QPACK_BLOCKED_STREAMS = 0;
    private static final int STREAM_TYPE_PUSH = 0x01;

    /** Writes to our uni streams; null in unit tests that only feed peer streams. */
    interface Output {
        /** False when the stream can't be written (not opened yet: no credit). */
        boolean write(Http3Stream s, byte[] b, int off, int len, boolean fin);

        void stopSending(long streamId, long errorCode);
    }

    private final Output out;
    private final long localMaxFieldSectionSize;

    // Server uni streams: control 3, QPACK encoder 7, decoder 11.
    final Http3Stream control = new Http3Stream.Control(0x03);
    final Http3Stream qpackEncoder = new Http3Stream.Control(0x07);
    final Http3Stream qpackDecoder = new Http3Stream.Control(0x0B);
    private int openStep;

    // First-seen peer stream ids of the singleton types (RFC 9114
    // §6.2.1 / RFC 9204 §4.2: a second one is H3_STREAM_CREATION_ERROR).
    private long peerControlStreamId = -1;
    private long peerQpackEncStreamId = -1;
    private long peerQpackDecStreamId = -1;
    // Peer uni streams of other types (grease / unknown) until they end,
    // so their later bytes are never read as a type; the critical ones are
    // the ids above. Made on first need.
    private Long2ObjectHashMap<Long> peerUniTypes;
    // Peer uni streams whose type varint is only partly known; made on first need.
    private Long2ObjectHashMap<ByteBuffer> peerUniHeaderBuf;
    // Partial QPACK instructions straddling two reads.
    private ByteBuffer peerQpackEncAccum;
    private ByteBuffer peerQpackDecAccum;
    private Http3FrameReader peerControlReader;
    private boolean sawPeerSettings;
    private boolean sawPeerGoaway;
    private long lastPeerGoawayId;
    // Largest push id the peer allowed (MAX_PUSH_ID), -1 before any.
    private long peerMaxPushId = -1;
    /** Peer's SETTINGS_MAX_FIELD_SECTION_SIZE, -1 when not advertised. */
    long peerMaxFieldSectionSize = -1;

    Http3ControlStreams(Output out, long localMaxFieldSectionSize) {
        this.out = out;
        this.localMaxFieldSectionSize = localMaxFieldSectionSize;
    }

    /**
     * Opens our three uni streams and sends SETTINGS. Resumable: a step the
     * peer's uni-stream limit refuses is retried on the next call.
     */
    boolean open() {
        while (openStep < 4) {
            boolean ok = switch (openStep) {
                case 0 -> write(control, typeBytes(Http3StreamType.CONTROL));
                case 1 -> write(control, settingsBytes());
                case 2 -> write(qpackEncoder, typeBytes(Http3StreamType.QPACK_ENCODER));
                default -> write(qpackDecoder, typeBytes(Http3StreamType.QPACK_DECODER));
            };
            if (!ok) return false;
            openStep++;
        }
        return true;
    }

    boolean isOpen() {
        return openStep == 4;
    }

    /** Sends GOAWAY (RFC 9114 §5.2) naming the first request stream id that won't be processed. */
    void sendGoaway(long streamId) {
        ByteBuffer b = Http3FrameWriter.goaway(streamId);
        byte[] bytes = new byte[b.remaining()];
        b.get(bytes);
        write(control, bytes);
    }

    private boolean write(Http3Stream s, byte[] bytes) {
        return out.write(s, bytes, 0, bytes.length, false);
    }

    private static byte[] typeBytes(long type) {
        byte[] b = new byte[Http3Varint.size(type)];
        Http3Varint.encode(b, 0, type);
        return b;
    }

    private byte[] settingsBytes() {
        // A configured 0 means "no limit": the setting is omitted (an
        // advertised 0 would forbid any field).
        ByteBuffer settings = Http3FrameWriter.settings(localMaxFieldSectionSize > 0
            ? new long[]{
                Http3SettingId.QPACK_MAX_TABLE_CAPACITY, QPACK_MAX_TABLE_CAPACITY,
                Http3SettingId.QPACK_BLOCKED_STREAMS, QPACK_BLOCKED_STREAMS,
                Http3SettingId.MAX_FIELD_SECTION_SIZE, localMaxFieldSectionSize}
            : new long[]{
                Http3SettingId.QPACK_MAX_TABLE_CAPACITY, QPACK_MAX_TABLE_CAPACITY,
                Http3SettingId.QPACK_BLOCKED_STREAMS, QPACK_BLOCKED_STREAMS});
        byte[] b = new byte[settings.remaining()];
        settings.get(b);
        return b;
    }

    /** True for the peer's control and QPACK streams, whose loss closes the connection. */
    boolean isCritical(long streamId) {
        return streamId == peerControlStreamId || streamId == peerQpackEncStreamId
            || streamId == peerQpackDecStreamId;
    }

    /** The peer reset uni stream {@code streamId}. */
    void onPeerReset(long streamId) {
        if (isCritical(streamId)) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_CLOSED_CRITICAL_STREAM,
                "peer reset critical stream " + streamId);
        }
        if (peerUniTypes != null) peerUniTypes.remove(streamId);
        if (peerUniHeaderBuf != null) peerUniHeaderBuf.remove(streamId);
    }

    /** The type of an identified peer uni stream, or null. */
    private Long knownType(long streamId) {
        if (streamId == peerControlStreamId) return Http3StreamType.CONTROL;
        if (streamId == peerQpackEncStreamId) return Http3StreamType.QPACK_ENCODER;
        if (streamId == peerQpackDecStreamId) return Http3StreamType.QPACK_DECODER;
        return peerUniTypes == null ? null : peerUniTypes.get(streamId);
    }

    /** Bytes the peer sent on uni stream {@code streamId}. */
    void onPeerData(long streamId, byte[] data, int off, int len, boolean fin) {
        Long knownType = knownType(streamId);
        ByteBuffer buf;
        if (knownType == null) {
            // Type varint not fully known yet — accumulate.
            if (peerUniHeaderBuf == null) peerUniHeaderBuf = new Long2ObjectHashMap<>();
            ByteBuffer accum = peerUniHeaderBuf.get(streamId);
            if (accum == null) {
                accum = ByteBuffer.allocate(Math.max(8, len));
                peerUniHeaderBuf.put(streamId, accum);
            }
            if (accum.remaining() < len) {
                ByteBuffer bigger = ByteBuffer.allocate(accum.position() + len);
                accum.flip();
                bigger.put(accum);
                accum = bigger;
                peerUniHeaderBuf.put(streamId, accum);
            }
            accum.put(data, off, len);
            ByteBuffer readView = accum.duplicate();
            readView.flip();
            int peekLen = Http3Varint.peekLength(readView);
            if (peekLen < 0 || readView.remaining() < peekLen) {
                // Still incomplete; with FIN nothing more will arrive.
                if (fin) peerUniHeaderBuf.remove(streamId);
                return;
            }
            long type = Http3Varint.decode(readView);
            peerUniHeaderBuf.remove(streamId);
            if (type == Http3StreamType.CONTROL) {
                if (peerControlStreamId >= 0) throw duplicateStream("control", streamId);
                peerControlStreamId = streamId;
            } else if (type == Http3StreamType.QPACK_ENCODER) {
                if (peerQpackEncStreamId >= 0) throw duplicateStream("QPACK encoder", streamId);
                peerQpackEncStreamId = streamId;
            } else if (type == Http3StreamType.QPACK_DECODER) {
                if (peerQpackDecStreamId >= 0) throw duplicateStream("QPACK decoder", streamId);
                peerQpackDecStreamId = streamId;
            } else if (type == STREAM_TYPE_PUSH) {
                // RFC 9114 §6.2.2: only servers push.
                throw new Http3ConnectionException(Http3ConnectionException.H3_STREAM_CREATION_ERROR,
                    "client-initiated push stream " + streamId);
            } else {
                // Grease (RFC 9114 §7.2.8) or unknown type (§6.2): recorded
                // until the stream ends so the rest is discarded. Unknown
                // types get STOP_SENDING (H3_STREAM_CREATION_ERROR).
                if (!fin) {
                    if (peerUniTypes == null) peerUniTypes = new Long2ObjectHashMap<>();
                    peerUniTypes.put(streamId, type);
                }
                if (!isGreaseType(type)) {
                    LOG.fine(() -> "h3 unknown peer uni stream type=0x" + Long.toHexString(type)
                        + " id=" + streamId);
                    if (out != null) out.stopSending(streamId, Http3ConnectionException.H3_STREAM_CREATION_ERROR);
                }
                return;
            }
            buf = readView;
            knownType = type;
        } else {
            buf = ByteBuffer.wrap(data, off, len);
        }
        long t = knownType;
        // RFC 9114 §6.2.1: closing a critical stream is H3_CLOSED_CRITICAL_STREAM.
        if (fin && (t == Http3StreamType.CONTROL || t == Http3StreamType.QPACK_ENCODER
                || t == Http3StreamType.QPACK_DECODER)) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_CLOSED_CRITICAL_STREAM,
                "peer closed critical stream type=0x" + Long.toHexString(t) + " id=" + streamId);
        }
        if (t == Http3StreamType.CONTROL) {
            onControlBytes(buf);
        } else if (t == Http3StreamType.QPACK_ENCODER) {
            validateEncoderStream(buf);
        } else if (t == Http3StreamType.QPACK_DECODER) {
            validateDecoderStream(buf);
        } else if (fin && peerUniTypes != null) {
            peerUniTypes.remove(streamId);
        }
    }

    /** Peer uni streams being tracked (diagnostics, tests). */
    int trackedPeerStreams() {
        return peerUniTypes == null ? 0 : peerUniTypes.size();
    }

    // ---- QPACK instruction streams -------------------------------------

    /** Appends {@code more} to {@code accum}; returns a read-mode buffer at the first unread byte. */
    private static ByteBuffer appendToAccum(ByteBuffer accum, ByteBuffer more) {
        int incoming = more.remaining();
        if (accum == null) {
            ByteBuffer nb = ByteBuffer.allocate(Math.max(32, incoming));
            nb.put(more);
            nb.flip();
            return nb;
        }
        int total = accum.remaining() + incoming;
        ByteBuffer dst;
        if (accum.capacity() >= total) {
            accum.compact();
            dst = accum;
        } else {
            dst = ByteBuffer.allocate(Math.max(total, accum.capacity() * 2));
            dst.put(accum);
        }
        dst.put(more);
        dst.flip();
        return dst;
    }

    private static ByteBuffer compactRemaining(ByteBuffer work) {
        int rem = work.remaining();
        if (rem == 0) return null;
        ByteBuffer tail = ByteBuffer.allocate(Math.max(32, rem));
        tail.put(work);
        tail.flip();
        return tail;
    }

    /**
     * RFC 9204 §4.3: under capacity 0 the only valid encoder instruction is
     * Set Dynamic Table Capacity 0; anything else is QPACK_ENCODER_STREAM_ERROR.
     */
    private void validateEncoderStream(ByteBuffer buf) {
        ByteBuffer work = appendToAccum(peerQpackEncAccum, buf);
        while (work.hasRemaining()) {
            int startPos = work.position();
            int b = work.get(startPos) & 0xFF;
            if ((b & 0xE0) == 0x20) {
                long cap;
                try {
                    work.get();
                    cap = NBitInteger.decode(work, 5, b);
                } catch (java.nio.BufferUnderflowException ex) {
                    work.position(startPos);
                    peerQpackEncAccum = compactRemaining(work);
                    return;
                } catch (RuntimeException ex) {
                    throw new Http3ConnectionException(Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                        "malformed Set Dynamic Table Capacity: " + ex.getMessage());
                }
                if (cap != 0) {
                    throw new Http3ConnectionException(Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                        "peer Set Dynamic Table Capacity=" + cap + " exceeds advertised limit 0");
                }
                continue;
            }
            throw new Http3ConnectionException(Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                "peer QPACK encoder instruction 0x" + Integer.toHexString(b) + " not allowed under capacity=0");
        }
        peerQpackEncAccum = null;
    }

    /**
     * RFC 9204 §4.4: our encoder never references the dynamic table, so
     * Section Acknowledgment and Insert Count Increment are always
     * QPACK_DECODER_STREAM_ERROR; Stream Cancellation is ignored.
     */
    private void validateDecoderStream(ByteBuffer buf) {
        ByteBuffer work = appendToAccum(peerQpackDecAccum, buf);
        while (work.hasRemaining()) {
            int startPos = work.position();
            int b = work.get(startPos) & 0xFF;
            try {
                if ((b & 0xC0) == 0x00) {
                    work.get();
                    long inc = NBitInteger.decode(work, 6, b);
                    throw new Http3ConnectionException(Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                        "peer Insert Count Increment=" + inc + " but no dynamic table entries");
                }
                if ((b & 0x80) != 0) {
                    work.get();
                    long sid = NBitInteger.decode(work, 7, b);
                    throw new Http3ConnectionException(Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                        "peer Section Acknowledgment for stream " + sid
                            + " but no field section used the dynamic table");
                }
                work.get();
                NBitInteger.decode(work, 6, b);
            } catch (java.nio.BufferUnderflowException ex) {
                work.position(startPos);
                peerQpackDecAccum = compactRemaining(work);
                return;
            } catch (Http3ConnectionException hce) {
                throw hce;
            } catch (RuntimeException ex) {
                throw new Http3ConnectionException(Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                    "malformed QPACK decoder instruction: " + ex.getMessage());
            }
        }
        peerQpackDecAccum = null;
    }

    // ---- peer control stream --------------------------------------------

    private void onControlBytes(ByteBuffer buf) {
        if (peerControlReader == null) peerControlReader = new Http3FrameReader();
        try {
            peerControlReader.feed(buf);
        } catch (IllegalStateException e) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                "peer control-stream feed: " + e.getMessage());
        }
        // RFC 9114 §6.2.1: SETTINGS MUST be the first frame, whatever the
        // first one is (a reserved type the reader skips included).
        long first = peerControlReader.firstFrameType();
        if (first >= 0 && first != Http3FrameType.SETTINGS) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_MISSING_SETTINGS,
                "first frame on peer control stream must be SETTINGS, got 0x" + Long.toHexString(first));
        }
        while (true) {
            Http3FrameReader.Frame f;
            try {
                f = peerControlReader.poll();
            } catch (IllegalStateException e) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                    "peer control-stream frame reader: " + e.getMessage());
            }
            if (f == null) break;
            if (f.type == Http3FrameType.SETTINGS) {
                if (sawPeerSettings) {
                    throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_UNEXPECTED,
                        "duplicate SETTINGS on peer control stream");
                }
                sawPeerSettings = true;
                validatePeerSettings(f.payload);
            } else if (f.type == Http3FrameType.HEADERS || f.type == Http3FrameType.DATA
                    || f.type == Http3FrameType.PUSH_PROMISE || Http3FrameType.isReservedHttp2(f.type)) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(f.type) + " forbidden on control stream");
            } else if (f.type == Http3FrameType.GOAWAY) {
                // RFC 9114 §5.2: the id may only decrease (H3_ID_ERROR).
                long goawayId = singleVarint(f.payload, "GOAWAY");
                if (sawPeerGoaway && goawayId > lastPeerGoawayId) {
                    throw new Http3ConnectionException(Http3ConnectionException.H3_ID_ERROR,
                        "GOAWAY ID increased: prev=" + lastPeerGoawayId + " new=" + goawayId);
                }
                sawPeerGoaway = true;
                lastPeerGoawayId = goawayId;
            } else if (f.type == Http3FrameType.MAX_PUSH_ID) {
                // RFC 9114 §7.2.7: never decreases. We don't push, so the
                // value is only checked.
                long id = singleVarint(f.payload, "MAX_PUSH_ID");
                if (id < peerMaxPushId) {
                    throw new Http3ConnectionException(Http3ConnectionException.H3_ID_ERROR,
                        "MAX_PUSH_ID decreased: prev=" + peerMaxPushId + " new=" + id);
                }
                peerMaxPushId = id;
            } else if (f.type == Http3FrameType.CANCEL_PUSH) {
                // RFC 9114 §7.2.3: we never promised a push, so every push
                // id it names is unknown.
                long id = singleVarint(f.payload, "CANCEL_PUSH");
                throw new Http3ConnectionException(Http3ConnectionException.H3_ID_ERROR,
                    "CANCEL_PUSH for push " + id + ", which was never promised");
            }
            // Unknown and reserved frame types were skipped by the reader.
        }
    }

    /** A payload that must be exactly one varint (RFC 9114 §7.1: anything else is H3_FRAME_ERROR). */
    private static long singleVarint(byte[] payload, String frame) {
        ByteBuffer b = ByteBuffer.wrap(payload);
        int len = Http3Varint.peekLength(b);
        if (len < 0 || len != payload.length) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                "malformed " + frame + " payload (" + payload.length + " bytes)");
        }
        return Http3Varint.decode(b);
    }

    /** RFC 9114 §7.2.4.1: (id, value) varint pairs, ids unique, no HTTP/2-only ids. */
    private void validatePeerSettings(byte[] payload) {
        ByteBuffer b = ByteBuffer.wrap(payload);
        long[] seen = new long[payload.length / 2];
        int seenCount = 0;
        while (b.hasRemaining()) {
            long id;
            long value;
            try {
                id = Http3Varint.decode(b);
                if (!b.hasRemaining()) {
                    throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                        "truncated SETTINGS (missing value for id 0x" + Long.toHexString(id) + ")");
                }
                value = Http3Varint.decode(b);
            } catch (Http3ConnectionException hce) {
                throw hce;
            } catch (RuntimeException ex) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                    "malformed SETTINGS payload: " + ex.getMessage());
            }
            for (int i = 0; i < seenCount; i++) {
                if (seen[i] == id) {
                    throw new Http3ConnectionException(Http3ConnectionException.H3_SETTINGS_ERROR,
                        "duplicate SETTINGS id 0x" + Long.toHexString(id));
                }
            }
            seen[seenCount++] = id;
            // HTTP/2's ENABLE_PUSH, MAX_CONCURRENT_STREAMS,
            // INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE (0x02-0x05) are banned.
            if (id >= 0x02 && id <= 0x05) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_SETTINGS_ERROR,
                    "h2-reserved SETTINGS id 0x" + Long.toHexString(id) + " not allowed in h3");
            }
            if (id == Http3SettingId.MAX_FIELD_SECTION_SIZE) {
                peerMaxFieldSectionSize = value;
            }
        }
    }

    private static Http3ConnectionException duplicateStream(String kind, long streamId) {
        return new Http3ConnectionException(Http3ConnectionException.H3_STREAM_CREATION_ERROR,
            "second peer " + kind + " stream " + streamId);
    }

    /** RFC 9114 §7.2.8: reserved stream types are {@code 0x1f * N + 0x21}. */
    private static boolean isGreaseType(long t) {
        return t >= 0x21L && (t - 0x21L) % 0x1fL == 0L;
    }
}

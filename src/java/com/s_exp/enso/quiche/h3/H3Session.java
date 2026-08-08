package com.s_exp.enso.quiche.h3;

import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.qpack.QpackException;
import com.s_exp.enso.quiche.qpack.QpackFieldSection;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Pure-Java HTTP/3 session state on top of the QUIC transport primitives
 * exposed by the {@link Quiche} JNI shim. Replaces the {@code quiche_h3_*}
 * FFM calls that triggered libmalloc freelist corruption crashes on
 * macOS ARM64 + JDK 25 (see task #79/#86; the JNI migration in #111 also
 * moved us off FFM entirely).
 *
 * <p>Scope is v1-server:
 * <ul>
 *   <li>Open our three server-side unidirectional streams (control,
 *       QPACK encoder, QPACK decoder) at construction.
 *   <li>Send a minimal SETTINGS frame on the control stream advertising
 *       {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0} so peers do not
 *       insert into our dynamic table (see
 *       {@link QpackFieldSection} for why).
 *   <li>Route incoming stream bytes by stream type: request stream
 *       (bidi client-initiated) → per-stream {@link H3FrameReader}.
 *       Peer uni streams: read the first varint to identify type; we
 *       currently only bother parsing the peer's control stream.
 *   <li>Write HEADERS + DATA + FIN back on request streams via
 *       {@link #writeResponse}.
 * </ul>
 *
 * <p>Not v1: server push, priority updates, connection close via GOAWAY,
 * dynamic-table QPACK, blocked streams. All can be added incrementally.
 */
public final class H3Session {

    private static final Logger LOG = Logger.getLogger(H3Session.class.getName());

    // RFC 9000 §2.1: stream ID low 2 bits encode initiator + directionality.
    // 0b00 = client bidi (request streams), 0b01 = server bidi (unused
    // in H3 flow), 0b10 = client uni, 0b11 = server uni.
    static final long DIR_CLIENT_BIDI = 0x0;
    static final long DIR_SERVER_BIDI = 0x1;
    static final long DIR_CLIENT_UNI = 0x2;
    static final long DIR_SERVER_UNI = 0x3;

    private final long conn;
    // Our outbound uni stream IDs — assigned in order.
    private long ctrlStreamId = -1;
    private long qpackEncStreamId = -1;
    private long qpackDecStreamId = -1;
    private long nextServerUniId = 0x03; // server uni starts at 3.
    // Per-request state; keyed by client-bidi stream id.
    private final Map<Long, RequestStream> requestStreams = new HashMap<>();
    // First-seen peer stream IDs for the three singleton uni-stream types.
    // RFC 9114 §6.2.1: duplicates MUST close the connection with
    // H3_STREAM_CREATION_ERROR (task #100 wires the connection close;
    // for now we log + drop the duplicate stream).
    private long peerControlStreamId = -1;
    private long peerQpackEncStreamId = -1;
    private long peerQpackDecStreamId = -1;
    // Peer uni streams that we've identified. Value = stream type varint.
    // Streams whose type hasn't arrived yet aren't in this map.
    private final Map<Long, Long> peerUniTypes = new HashMap<>();
    // Peer uni streams whose type varint is only partially known.
    private final Map<Long, ByteBuffer> peerUniHeaderBuf = new HashMap<>();
    private boolean initialised = false;

    public H3Session(long conn) {
        this.conn = conn;
    }

    /**
     * Open control + QPACK encoder + QPACK decoder uni streams and send
     * our initial SETTINGS. Idempotent — safe to call every time the
     * transport becomes writable in case earlier stream opens deferred.
     */
    /**
     * Open our three server-uni streams + emit SETTINGS. Idempotent and
     * retry-safe: if any sub-step short-writes (peer hasn't extended
     * enough uni-stream credit yet), the completion flags stay unset and
     * the next call resumes from the first still-pending step. Task #114.
     */
    public void ensureInitialised() {
        if (initialised) return;
        // Assign stream IDs on first entry so retries reuse them. Server
        // uni IDs advance by 4 (RFC 9000 §2.1).
        if (ctrlStreamId < 0) {
            ctrlStreamId = nextServerUniId; nextServerUniId += 4;
            qpackEncStreamId = nextServerUniId; nextServerUniId += 4;
            qpackDecStreamId = nextServerUniId; nextServerUniId += 4;
        }
        if (!ctrlTypeSent) {
            if (!writeStreamTypePrefix(ctrlStreamId, H3StreamType.CONTROL)) return;
            ctrlTypeSent = true;
        }
        if (!settingsSent) {
            ByteBuffer settings = H3FrameWriter.settings(new long[]{
                H3SettingId.QPACK_MAX_TABLE_CAPACITY, 0,
                H3SettingId.QPACK_BLOCKED_STREAMS, 0,
            });
            if (!writeAll(ctrlStreamId, settings, false)) return;
            settingsSent = true;
        }
        if (!qpackEncTypeSent) {
            if (!writeStreamTypePrefix(qpackEncStreamId, H3StreamType.QPACK_ENCODER)) return;
            qpackEncTypeSent = true;
        }
        if (!qpackDecTypeSent) {
            if (!writeStreamTypePrefix(qpackDecStreamId, H3StreamType.QPACK_DECODER)) return;
            qpackDecTypeSent = true;
        }
        initialised = true;
    }

    // Init sub-step completion flags — sticky once true.
    private boolean ctrlTypeSent;
    private boolean settingsSent;
    private boolean qpackEncTypeSent;
    private boolean qpackDecTypeSent;

    /**
     * Feed inbound stream data. Router dispatches by stream type — bidi
     * request streams accumulate in a per-stream frame reader; peer uni
     * streams get their type identified from the first varint and then
     * either parsed (control) or ignored (QPACK enc/dec under cap 0).
     */
    public void onStreamData(long streamId, byte[] data, boolean fin,
                              RequestSink sink) {
        long dir = streamId & 0x3;
        if (dir == DIR_CLIENT_BIDI) {
            handleRequestStream(streamId, data, fin, sink);
        } else if (dir == DIR_CLIENT_UNI) {
            handlePeerUniStream(streamId, data, fin);
        }
        // Server-uni: ignored (that's our own outbound). Server-bidi:
        // unused in H3.
    }

    /**
     * Encode and send a full HTTP/3 response back on a request stream.
     * FIN is applied to the DATA frame when {@code body} is present, else
     * on the HEADERS frame.
     */
    public void writeResponse(long streamId, List<String[]> headers,
                               byte[] body) {
        byte[] hdrs = QpackFieldSection.encode(headers, qpackScratch);
        boolean hasBody = body != null && body.length > 0;
        // Reuse a single per-session scratch ByteBuffer for the frame
        // envelope. Grow if a response's headers or body exceed current
        // capacity. Owner-thread only; no sync.
        int needHdrs = 16 + hdrs.length; // frame overhead + payload
        frameBuf = ensureFrameCap(frameBuf, needHdrs);
        writeAll(streamId,
            H3FrameWriter.writeHeaders(frameBuf, hdrs), !hasBody);
        if (hasBody) {
            int needBody = 16 + body.length;
            frameBuf = ensureFrameCap(frameBuf, needBody);
            writeAll(streamId,
                H3FrameWriter.writeData(frameBuf, body), true);
        }
        releaseReader(requestStreams.remove(streamId));
    }

    // Response frame scratch — grows to largest response seen on this
    // conn. Bounded implicitly by the connection's overall payload sizes.
    private ByteBuffer frameBuf = ByteBuffer.allocate(4096);
    // QPACK encoder scratch. QpackFieldSection.encode(headers, scratch)
    // writes here then returns a freshly-allocated byte[] copy for the
    // frame body; scratch itself is reused across responses.
    private final ByteBuffer qpackScratch = ByteBuffer.allocate(1024);

    private static ByteBuffer ensureFrameCap(ByteBuffer buf, int need) {
        if (buf.capacity() >= need) return buf;
        int newCap = Math.max(buf.capacity() * 2, need);
        return ByteBuffer.allocate(newCap);
    }

    // -----------------------------------------------------------------

    private void handleRequestStream(long streamId, byte[] data, boolean fin,
                                      RequestSink sink) {
        RequestStream rs = requestStreams.get(streamId);
        if (rs == null) {
            rs = new RequestStream(acquireReader());
            requestStreams.put(streamId, rs);
        }
        rs.reader.feed(ByteBuffer.wrap(data));
        while (true) {
            H3FrameReader.Frame f = rs.reader.poll();
            if (f == null) break;
            // RFC 9114 §7.2: frames that only make sense on the control
            // stream MUST be treated as H3_FRAME_UNEXPECTED on a request
            // stream. Reset the stream; a follow-up (task #100) will
            // escalate control-stream-only frames to connection close.
            if (f.type == H3FrameType.SETTINGS
                || f.type == H3FrameType.GOAWAY
                || f.type == H3FrameType.MAX_PUSH_ID
                || f.type == H3FrameType.CANCEL_PUSH
                || f.type == H3FrameType.PUSH_PROMISE) {
                LOG.warning("h3 unexpected frame type=0x" + Long.toHexString(f.type)
                    + " on request stream=" + streamId);
                resetStream(streamId, 0x105); // H3_FRAME_UNEXPECTED
                releaseReader(requestStreams.remove(streamId));
                return;
            }
            if (f.type == H3FrameType.HEADERS) {
                List<String[]> headers;
                try {
                    headers = QpackFieldSection.decode(f.payload);
                } catch (QpackException qe) {
                    // Per RFC 9204 §2.2: QPACK decoding errors that are
                    // stream-level (e.g. dynamic-table refs under cap 0)
                    // reset the affected stream; connection-level errors
                    // close the whole connection. Under cap=0 all our
                    // errors are stream-level.
                    LOG.info("h3 QPACK error stream=" + streamId
                        + " code=0x" + Long.toHexString(qe.errorCode())
                        + " msg=" + qe.getMessage());
                    resetStream(streamId, qe.errorCode());
                    releaseReader(requestStreams.remove(streamId));
                    return;
                }
                sink.onHeaders(streamId, headers);
            } else if (f.isDataChunk()) {
                sink.onData(streamId, f.dataChunk, f.dataFinalChunk);
            }
            // Unknown/other frame types silently ignored per RFC 9114 §9
            // (proper streaming skip is task #103).
        }
        if (fin) {
            sink.onFin(streamId);
            releaseReader(requestStreams.remove(streamId));
        }
    }

    private void resetStream(long streamId, long errorCode) {
        // Shutdown both directions so peer stops sending and we don't try
        // to respond.
        try {
            Quiche.connStreamShutdown(conn, streamId,
                Quiche.QUICHE_SHUTDOWN_READ, errorCode);
        } catch (Throwable ignored) {}
        try {
            Quiche.connStreamShutdown(conn, streamId,
                Quiche.QUICHE_SHUTDOWN_WRITE, errorCode);
        } catch (Throwable ignored) {}
    }

    private void handlePeerUniStream(long streamId, byte[] data, boolean fin) {
        Long knownType = peerUniTypes.get(streamId);
        ByteBuffer buf;
        if (knownType == null) {
            // Type varint not fully known yet — accumulate.
            ByteBuffer accum = peerUniHeaderBuf.get(streamId);
            if (accum == null) {
                accum = ByteBuffer.allocate(Math.max(8, data.length));
                peerUniHeaderBuf.put(streamId, accum);
            }
            if (accum.remaining() < data.length) {
                ByteBuffer bigger = ByteBuffer.allocate(accum.position() + data.length);
                accum.flip();
                bigger.put(accum);
                accum = bigger;
                peerUniHeaderBuf.put(streamId, accum);
            }
            accum.put(data);
            ByteBuffer readView = accum.duplicate();
            readView.flip();
            int peekLen = Varint.peekLength(readView);
            if (peekLen < 0 || readView.remaining() < peekLen) {
                // Type varint still incomplete. If peer sent FIN we can
                // drop the accumulator — no more bytes will arrive.
                if (fin) peerUniHeaderBuf.remove(streamId);
                return;
            }
            long type = Varint.decode(readView);
            peerUniHeaderBuf.remove(streamId);
            // Reject a second CONTROL / QPACK-ENCODER / QPACK-DECODER
            // stream (RFC 9114 §6.2.1). Drop the offending stream; a
            // future task will escalate to a connection-level close.
            if (type == H3StreamType.CONTROL) {
                if (peerControlStreamId >= 0 && peerControlStreamId != streamId) {
                    LOG.warning("h3 duplicate peer CONTROL stream id="
                        + streamId + " first=" + peerControlStreamId);
                    return;
                }
                peerControlStreamId = streamId;
            } else if (type == H3StreamType.QPACK_ENCODER) {
                if (peerQpackEncStreamId >= 0 && peerQpackEncStreamId != streamId) {
                    LOG.warning("h3 duplicate peer QPACK ENCODER stream id="
                        + streamId + " first=" + peerQpackEncStreamId);
                    return;
                }
                peerQpackEncStreamId = streamId;
            } else if (type == H3StreamType.QPACK_DECODER) {
                if (peerQpackDecStreamId >= 0 && peerQpackDecStreamId != streamId) {
                    LOG.warning("h3 duplicate peer QPACK DECODER stream id="
                        + streamId + " first=" + peerQpackDecStreamId);
                    return;
                }
                peerQpackDecStreamId = streamId;
            } else if (type == 0x01L /* PUSH */) {
                // RFC 9114 §6.2.2: server-initiated push MUST NOT arrive on
                // a client uni stream. Treat as H3_STREAM_CREATION_ERROR.
                LOG.warning("h3 client-initiated PUSH stream id=" + streamId);
                resetStream(streamId, 0x103); // H3_STREAM_CREATION_ERROR
                return;
            } else if (isGreaseType(type)) {
                // RFC 9114 §7.2.8: grease types (0x1f * N + 0x21) MUST be
                // ignored — read + discard silently.
                peerUniTypes.put(streamId, type);
                return;
            } else {
                // RFC 9114 §6.2.3: any other type = MUST STOP_SENDING with
                // H3_STREAM_CREATION_ERROR. We only shut the read side so
                // peer stops sending; write side is theirs to close.
                LOG.info("h3 unknown peer uni stream type=0x"
                    + Long.toHexString(type) + " id=" + streamId);
                try {
                    com.s_exp.enso.quiche.Quiche.connStreamShutdown(
                        conn, streamId,
                        com.s_exp.enso.quiche.Quiche.QUICHE_SHUTDOWN_READ,
                        0x103);
                } catch (Throwable ignored) {}
                return;
            }
            peerUniTypes.put(streamId, type);
            // Any leftover bytes after the type varint fall through to
            // the type-specific handler.
            byte[] leftover = new byte[readView.remaining()];
            readView.get(leftover);
            buf = ByteBuffer.wrap(leftover);
            knownType = type;
        } else {
            buf = ByteBuffer.wrap(data);
        }
        // For v1 we only need to parse the peer control stream (SETTINGS,
        // GOAWAY). QPACK enc/dec streams under our cap=0 contract carry
        // no meaningful data.
        if (knownType == H3StreamType.CONTROL) {
            // TODO: parse peer SETTINGS/GOAWAY. Not required for basic
            // request/response — leave for follow-up (task #100).
        }
    }

    /**
     * RFC 9114 §7.2.8 grease-type check. Reserved unassigned stream types
     * follow the pattern {@code 0x1f * N + 0x21} for non-negative N.
     */
    private static boolean isGreaseType(long t) {
        if (t < 0x21L) return false;
        return ((t - 0x21L) % 0x1fL) == 0L;
    }

    private boolean writeStreamTypePrefix(long streamId, long type) {
        int sz = Varint.size(type);
        ByteBuffer bb = ByteBuffer.allocate(sz);
        Varint.encode(bb, type);
        bb.flip();
        return writeAll(streamId, bb, false);
    }

    /**
     * Blocking send of an entire ByteBuffer over a stream. In v1 we assume
     * quiche_conn_stream_send accepts the full buffer in one call for our
     * small header/frame sizes; if quiche returns a short write we retry
     * once. Larger streaming payloads (big response bodies) get chunked at
     * the caller.
     */
    /**
     * @return true iff quiche accepted all {@code remaining} bytes.
     *         Short writes leave the ByteBuffer's position advanced past
     *         the unwritten bytes (the caller does not retry — see
     *         task #104 for the fin-split fix).
     */
    private boolean writeAll(long streamId, ByteBuffer buf, boolean fin) {
        int remaining = buf.remaining();
        byte[] bytes;
        int off;
        if (buf.hasArray()) {
            // Zero-copy: hand quiche the backing array directly with the
            // ByteBuffer's current view offsets. H3FrameWriter always
            // returns heap-backed buffers so we hit this path in practice.
            bytes = buf.array();
            off = buf.arrayOffset() + buf.position();
            buf.position(buf.limit());
        } else {
            bytes = new byte[remaining];
            buf.get(bytes);
            off = 0;
        }
        long rc = Quiche.connStreamSend(conn, streamId, bytes, off, remaining, fin);
        if (rc < 0) {
            LOG.info("h3 stream_send stream=" + streamId + " rc=" + rc);
            return false;
        }
        if (rc < remaining) {
            LOG.info("h3 short stream_send stream=" + streamId
                + " wrote=" + rc + " of=" + remaining);
            return false;
        }
        return true;
    }

    /**
     * Per-request state held on the owner thread. Not thread-safe;
     * owner-only access.
     */
    private static final class RequestStream {
        final H3FrameReader reader;
        RequestStream(H3FrameReader reader) { this.reader = reader; }
    }

    // Reader pool — task #93. Under load a single connection may see
    // many transient request streams; keeping a small deque of reset
    // readers amortises the ~4 KB rolling buffer allocation across
    // successive streams. Cap keeps the pool from growing unboundedly
    // under bursty concurrency.
    private static final int READER_POOL_CAP = 32;
    private final java.util.ArrayDeque<H3FrameReader> readerPool =
        new java.util.ArrayDeque<>();

    private H3FrameReader acquireReader() {
        H3FrameReader r = readerPool.pollFirst();
        return r != null ? r : new H3FrameReader();
    }

    private void releaseReader(RequestStream rs) {
        if (rs == null) return;
        if (readerPool.size() < READER_POOL_CAP) {
            rs.reader.reset();
            readerPool.offerFirst(rs.reader);
        }
    }

    /**
     * Callback surface for the Ring bridge. Called on the owner thread
     * while draining a request stream's ingress bytes.
     */
    public interface RequestSink {
        void onHeaders(long streamId, List<String[]> headers);
        void onData(long streamId, byte[] chunk, boolean finalChunk);
        void onFin(long streamId);
    }
}

package com.s_exp.enso.quiche.h3;

import com.s_exp.enso.quiche.QuicheStreams;
import com.s_exp.enso.quiche.qpack.QpackFieldSection;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Pure-Java HTTP/3 session state on top of the QUIC transport primitives
 * exposed by {@link QuicheStreams}. Replaces the {@code quiche_h3_*} FFM
 * calls that triggered the libmalloc freelist corruption crashes on
 * macOS ARM64 + JDK 25 (see task #79).
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

    private final MemorySegment conn;
    private final Arena arena;
    // Our outbound uni stream IDs — assigned in order.
    private long ctrlStreamId = -1;
    private long qpackEncStreamId = -1;
    private long qpackDecStreamId = -1;
    private long nextServerUniId = 0x03; // server uni starts at 3.
    // Per-request state; keyed by client-bidi stream id.
    private final Map<Long, RequestStream> requestStreams = new HashMap<>();
    // Peer uni streams that we've identified. Value = stream type varint.
    // Streams whose type hasn't arrived yet aren't in this map.
    private final Map<Long, Long> peerUniTypes = new HashMap<>();
    // Peer uni streams whose type varint is only partially known.
    private final Map<Long, ByteBuffer> peerUniHeaderBuf = new HashMap<>();
    private boolean initialised = false;

    public H3Session(MemorySegment conn, Arena arena) {
        this.conn = conn;
        this.arena = arena;
    }

    /**
     * Open control + QPACK encoder + QPACK decoder uni streams and send
     * our initial SETTINGS. Idempotent — safe to call every time the
     * transport becomes writable in case earlier stream opens deferred.
     */
    public void ensureInitialised() {
        if (initialised) return;
        // Open the three server-uni streams by sending their type varint
        // as the first byte(s). quiche assigns a fresh ID on first
        // stream_send if we pick unused ones.
        ctrlStreamId = nextServerUniId; nextServerUniId += 4;
        qpackEncStreamId = nextServerUniId; nextServerUniId += 4;
        qpackDecStreamId = nextServerUniId; nextServerUniId += 4;

        writeStreamTypePrefix(ctrlStreamId, H3StreamType.CONTROL);
        // Emit our SETTINGS immediately after the type prefix so peers
        // that gate other traffic on our SETTINGS make progress.
        ByteBuffer settings = H3FrameWriter.settings(new long[]{
            H3SettingId.QPACK_MAX_TABLE_CAPACITY, 0,
            H3SettingId.QPACK_BLOCKED_STREAMS, 0,
        });
        writeAll(ctrlStreamId, settings, false);

        writeStreamTypePrefix(qpackEncStreamId, H3StreamType.QPACK_ENCODER);
        writeStreamTypePrefix(qpackDecStreamId, H3StreamType.QPACK_DECODER);
        initialised = true;
    }

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
        byte[] hdrs = QpackFieldSection.encode(headers);
        ByteBuffer headersFrame = H3FrameWriter.headers(hdrs);
        boolean hasBody = body != null && body.length > 0;
        writeAll(streamId, headersFrame, !hasBody);
        if (hasBody) {
            writeAll(streamId, H3FrameWriter.data(body), true);
        }
        requestStreams.remove(streamId);
    }

    // -----------------------------------------------------------------

    private void handleRequestStream(long streamId, byte[] data, boolean fin,
                                      RequestSink sink) {
        RequestStream rs = requestStreams.computeIfAbsent(streamId,
            k -> new RequestStream());
        rs.reader.feed(ByteBuffer.wrap(data));
        while (true) {
            H3FrameReader.Frame f = rs.reader.poll();
            if (f == null) break;
            if (f.type == H3FrameType.HEADERS) {
                List<String[]> headers = QpackFieldSection.decode(f.payload);
                rs.headers = headers;
                sink.onHeaders(streamId, headers);
            } else if (f.isDataChunk()) {
                sink.onData(streamId, f.dataChunk, f.dataFinalChunk);
            }
            // Unknown/other frame types silently ignored per RFC 9114 §9.
        }
        if (fin) {
            sink.onFin(streamId);
        }
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
            if (peekLen < 0 || readView.remaining() < peekLen) return;
            long type = Varint.decode(readView);
            peerUniTypes.put(streamId, type);
            peerUniHeaderBuf.remove(streamId);
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
            // request/response — leave for follow-up.
        }
        // fin on a peer uni stream is fine to ignore for v1.
    }

    private void writeStreamTypePrefix(long streamId, long type) {
        int sz = Varint.size(type);
        ByteBuffer bb = ByteBuffer.allocate(sz);
        Varint.encode(bb, type);
        bb.flip();
        writeAll(streamId, bb, false);
    }

    /**
     * Blocking send of an entire ByteBuffer over a stream. In v1 we assume
     * quiche_conn_stream_send accepts the full buffer in one call for our
     * small header/frame sizes; if quiche returns a short write we retry
     * once. Larger streaming payloads (big response bodies) get chunked at
     * the caller.
     */
    private void writeAll(long streamId, ByteBuffer buf, boolean fin) {
        int remaining = buf.remaining();
        byte[] bytes = new byte[remaining];
        buf.get(bytes);
        MemorySegment src = arena.allocate(remaining);
        MemorySegment.copy(bytes, 0, src, ValueLayout.JAVA_BYTE, 0, remaining);
        long written = 0;
        while (written < remaining) {
            long rc = QuicheStreams.streamSend(
                conn, streamId,
                src.asSlice(written), remaining - written,
                fin && (written + (remaining - written) == remaining),
                MemorySegment.NULL);
            if (rc < 0) {
                LOG.info("h3 stream_send stream=" + streamId + " rc=" + rc);
                return;
            }
            written += rc;
        }
    }

    /**
     * Per-request state held on the owner thread. Not thread-safe;
     * owner-only access.
     */
    private static final class RequestStream {
        final H3FrameReader reader = new H3FrameReader();
        List<String[]> headers;
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

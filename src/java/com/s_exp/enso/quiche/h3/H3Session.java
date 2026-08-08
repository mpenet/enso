package com.s_exp.enso.quiche.h3;

import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.qpack.QpackException;
import com.s_exp.enso.quiche.qpack.QpackFieldSection;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.nio.ByteBuffer;
import java.util.List;
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
    private final Long2ObjectHashMap<RequestStream> requestStreams = new Long2ObjectHashMap<>();
    // First-seen peer stream IDs for the three singleton uni-stream types.
    // RFC 9114 §6.2.1: duplicates MUST close the connection with
    // H3_STREAM_CREATION_ERROR (task #100 wires the connection close;
    // for now we log + drop the duplicate stream).
    private long peerControlStreamId = -1;
    private long peerQpackEncStreamId = -1;
    private long peerQpackDecStreamId = -1;
    // Peer uni streams that we've identified. Value = stream type varint.
    // Streams whose type hasn't arrived yet aren't in this map.
    private final Long2ObjectHashMap<Long> peerUniTypes = new Long2ObjectHashMap<>();
    // Peer uni streams whose type varint is only partially known.
    private final Long2ObjectHashMap<ByteBuffer> peerUniHeaderBuf = new Long2ObjectHashMap<>();
    private boolean initialised = false;

    public H3Session(long conn) {
        this.conn = conn;
    }

    /**
     * Open our three server-uni streams (control + QPACK enc/dec) and
     * emit our initial SETTINGS. Idempotent and retry-safe: if any
     * sub-step short-writes (peer hasn't extended enough uni-stream
     * credit yet), the completion flags stay unset and the next call
     * resumes from the first still-pending step. Task #114.
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
        onStreamData(streamId, data, 0, data.length, fin, sink);
    }

    /**
     * byte[]+off+len variant: lets the driver pass its owner-thread
     * recvBuf directly without a fresh per-chunk allocation (task
     * #147-adjacent). H3FrameReader.feed copies into its rolling buf
     * immediately, so the caller's byte[] is free to be overwritten
     * after this call returns.
     */
    public void onStreamData(long streamId, byte[] data, int off, int len,
                              boolean fin, RequestSink sink) {
        try {
            long dir = streamId & 0x3;
            if (dir == DIR_CLIENT_BIDI) {
                handleRequestStream(streamId, data, off, len, fin, sink);
            } else if (dir == DIR_CLIENT_UNI) {
                handlePeerUniStream(streamId, data, off, len, fin);
            }
            // Server-uni: ignored (that's our own outbound). Server-bidi:
            // unused in H3.
        } catch (H3ConnectionException hce) {
            // Protocol-level violation → close the whole connection with
            // the H3 error code. Owner-thread driver observes
            // connIsClosed on next iteration and exits cleanly.
            LOG.info("h3 closing connection code=0x"
                + Long.toHexString(hce.errorCode()) + " reason="
                + hce.getMessage());
            byte[] reason = hce.getMessage() == null
                ? new byte[0]
                : hce.getMessage().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                Quiche.connClose(conn, true, hce.errorCode(), reason);
            } catch (Throwable ignored) {}
        }
    }

    /**
     * Encode and send a full HTTP/3 response back on a request stream.
     * FIN is applied to the DATA frame when {@code body} is present, else
     * on the HEADERS frame.
     */
    public void writeResponse(long streamId, List<String[]> headers,
                               byte[] body) {
        boolean hasBody = body != null && body.length > 0;
        // Encode HEADERS + DATA into a single frame buffer + single
        // writeAll. Fixes ordering hazard where a deferred HEADERS could
        // reach quiche AFTER a fin=true DATA frame (task #131), and
        // halves JNI hops per response (task #143).
        int hdrsBudget = 32;
        int hn = headers.size();
        for (int i = 0; i < hn; i++) {
            String[] hf = headers.get(i);
            hdrsBudget += 24 + (hf[0] == null ? 0 : hf[0].length())
                             + (hf[1] == null ? 0 : hf[1].length());
        }
        int total = hdrsBudget + (hasBody ? (16 + body.length) : 0);
        frameBuf = ensureFrameCap(frameBuf, total);
        frameBuf.clear();
        H3FrameWriter.appendHeadersFrom(frameBuf, headers);
        if (hasBody) {
            H3FrameWriter.appendData(frameBuf, body);
        }
        frameBuf.flip();
        // Single stream_send with fin=true — HEADERS + DATA travel
        // together, FIN can't outrun HEADERS.
        writeAll(streamId, frameBuf, true);
        releaseReader(requestStreams.remove(streamId));
    }

    // Response frame scratch — grows to largest response seen on this
    // conn. Bounded implicitly by the connection's overall payload sizes.
    // QPACK now encodes directly into this buffer (task #123), so a
    // separate qpackScratch is no longer needed.
    private ByteBuffer frameBuf = ByteBuffer.allocate(4096);

    private static ByteBuffer ensureFrameCap(ByteBuffer buf, int need) {
        if (buf.capacity() >= need) return buf;
        int newCap = Math.max(buf.capacity() * 2, need);
        return ByteBuffer.allocate(newCap);
    }

    // -----------------------------------------------------------------

    private void handleRequestStream(long streamId, byte[] data, int off, int len,
                                      boolean fin, RequestSink sink) {
        RequestStream rs = requestStreams.get(streamId);
        if (rs == null) {
            rs = new RequestStream(acquireReader());
            requestStreams.put(streamId, rs);
        }
        try {
            rs.reader.feed(data, off, len);
        } catch (IllegalStateException e) {
            releaseReader(requestStreams.remove(streamId));
            throw new H3ConnectionException(
                H3ConnectionException.H3_FRAME_ERROR,
                "request-stream reader: " + e.getMessage());
        }
        while (true) {
            H3FrameReader.Frame f;
            try {
                f = rs.reader.poll();
            } catch (IllegalStateException e) {
                releaseReader(requestStreams.remove(streamId));
                throw new H3ConnectionException(
                    H3ConnectionException.H3_FRAME_ERROR,
                    "request-stream reader: " + e.getMessage());
            }
            if (f == null) break;
            // RFC 9114 §7.2: control-only frames on a request stream MUST
            // be treated as H3_FRAME_UNEXPECTED at the connection level.
            if (f.type == H3FrameType.SETTINGS
                || f.type == H3FrameType.GOAWAY
                || f.type == H3FrameType.MAX_PUSH_ID
                || f.type == H3FrameType.CANCEL_PUSH
                || f.type == H3FrameType.PUSH_PROMISE) {
                releaseReader(requestStreams.remove(streamId));
                throw new H3ConnectionException(
                    H3ConnectionException.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(f.type)
                        + " forbidden on request stream " + streamId);
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

    private void handlePeerUniStream(long streamId, byte[] data, int off, int len,
                                      boolean fin) {
        Long knownType = peerUniTypes.get(streamId);
        ByteBuffer buf;
        if (knownType == null) {
            // Type varint not fully known yet — accumulate.
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
                resetStream(streamId, H3ConnectionException.H3_STREAM_CREATION_ERROR);
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
                    Quiche.connStreamShutdown(
                        conn, streamId,
                        Quiche.QUICHE_SHUTDOWN_READ,
                        H3ConnectionException.H3_STREAM_CREATION_ERROR);
                } catch (Throwable ignored) {}
                return;
            }
            peerUniTypes.put(streamId, type);
            // Any leftover bytes after the type varint fall through to
            // the type-specific handler. readView still holds a slice
            // over `accum` — safe to pass on directly since we're done
            // with the type varint.
            buf = readView;
            knownType = type;
        } else {
            buf = ByteBuffer.wrap(data, off, len);
        }
        // Peer control stream: parse SETTINGS / GOAWAY / MAX_PUSH_ID.
        // Any protocol-level violation raises H3ConnectionException which
        // onStreamData catches + translates into a quiche_conn_close.
        if (knownType == H3StreamType.CONTROL) {
            handlePeerControlBytes(buf);
        }
        // QPACK enc/dec streams under our cap=0 contract carry no
        // meaningful data — drop.
    }

    /**
     * Feed the peer's control-stream bytes to a per-connection reader
     * and enforce RFC 9114 §7.2 ordering rules. Protocol violations here
     * MUST close the whole connection, not just the stream.
     */
    private void handlePeerControlBytes(ByteBuffer buf) {
        if (peerControlReader == null) peerControlReader = new H3FrameReader();
        try {
            peerControlReader.feed(buf);
        } catch (IllegalStateException e) {
            throw new H3ConnectionException(
                H3ConnectionException.H3_FRAME_ERROR,
                "peer control-stream feed: " + e.getMessage());
        }
        while (true) {
            H3FrameReader.Frame f;
            try {
                f = peerControlReader.poll();
            } catch (IllegalStateException e) {
                // Reader detected an over-sized frame → treat as
                // H3_EXCESSIVE_LOAD / FRAME_ERROR at the connection layer.
                throw new H3ConnectionException(
                    H3ConnectionException.H3_FRAME_ERROR,
                    "peer control-stream frame reader: " + e.getMessage());
            }
            if (f == null) break;
            // RFC 9114 §7.2.4: SETTINGS MUST be the first frame.
            if (!sawPeerSettings && f.type != H3FrameType.SETTINGS) {
                throw new H3ConnectionException(
                    H3ConnectionException.H3_MISSING_SETTINGS,
                    "first frame on peer control stream must be SETTINGS, got 0x"
                        + Long.toHexString(f.type));
            }
            if (f.type == H3FrameType.SETTINGS) {
                if (sawPeerSettings) {
                    throw new H3ConnectionException(
                        H3ConnectionException.H3_FRAME_UNEXPECTED,
                        "duplicate SETTINGS on peer control stream");
                }
                sawPeerSettings = true;
                // We accept + ignore peer settings values. Under our
                // advertised MAX_TABLE_CAPACITY=0 nothing they choose
                // affects our encoding.
            } else if (f.type == H3FrameType.HEADERS
                    || f.type == H3FrameType.DATA
                    || f.type == H3FrameType.PUSH_PROMISE) {
                throw new H3ConnectionException(
                    H3ConnectionException.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(f.type)
                        + " forbidden on control stream");
            } else if (f.type == H3FrameType.GOAWAY) {
                // RFC 9114 §5.2: peer's GOAWAY IDs must be non-increasing
                // across repeated frames. Increasing = H3_ID_ERROR at
                // connection level (task #138).
                long goawayId;
                try {
                    goawayId = Varint.decode(java.nio.ByteBuffer.wrap(f.payload));
                } catch (Throwable ex) {
                    throw new H3ConnectionException(
                        H3ConnectionException.H3_FRAME_ERROR,
                        "malformed GOAWAY payload: " + ex.getMessage());
                }
                if (sawPeerGoaway && goawayId > lastPeerGoawayId) {
                    throw new H3ConnectionException(
                        H3ConnectionException.H3_ID_ERROR,
                        "GOAWAY ID increased: prev=" + lastPeerGoawayId
                            + " new=" + goawayId);
                }
                sawPeerGoaway = true;
                lastPeerGoawayId = goawayId;
            } else if (f.type == H3FrameType.MAX_PUSH_ID
                    || f.type == H3FrameType.CANCEL_PUSH) {
                // We never enable push (SETTINGS_ENABLE_CONNECT_PROTOCOL
                // == 0, MAX_PUSH_ID unset). Accept + ignore.
            }
            // Unknown / reserved frame types: reader stream-skipped them.
        }
    }

    private H3FrameReader peerControlReader;
    private boolean sawPeerSettings;
    private boolean sawPeerGoaway;
    private long lastPeerGoawayId;

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
     * Try to send the buffer's bytes on {@code streamId}. Checks stream
     * capacity first to avoid the busy-spin path when peer flow control
     * is closed. On partial or capacity=0, copies the un-sent remainder
     * into an owned byte[] and enqueues it in {@link #pendingByStream}
     * for later resumption by {@link #drainPendingWrites}. FIN is only
     * applied on the terminal call that consumes the last byte — matches
     * RFC 9000 §4.5 semantics; earlier partials must use fin=false so a
     * short-write doesn't strand the FIN signal.
     *
     * @return true iff every byte was sent in this call (FIN, if
     *   requested, was applied).
     */
    private boolean writeAll(long streamId, ByteBuffer buf, boolean fin) {
        int remaining = buf.remaining();
        byte[] bytes;
        int off;
        if (buf.hasArray()) {
            bytes = buf.array();
            off = buf.arrayOffset() + buf.position();
            buf.position(buf.limit());
        } else {
            bytes = new byte[remaining];
            buf.get(bytes);
            off = 0;
        }
        long cap = Quiche.connStreamCapacity(conn, streamId);
        if (cap < 0) {
            LOG.info("h3 stream_capacity stream=" + streamId + " rc=" + cap);
            return false;
        }
        if (cap == 0) {
            // No credit right now — copy the payload out of caller's
            // reused scratch and defer.
            enqueuePending(streamId, copyOwned(bytes, off, remaining), fin);
            return false;
        }
        int chunk = (int) Math.min((long) remaining, cap);
        boolean applyFin = fin && (chunk == remaining);
        long rc = Quiche.connStreamSend(conn, streamId, bytes, off, chunk, applyFin);
        if (rc < 0) {
            LOG.info("h3 stream_send stream=" + streamId + " rc=" + rc);
            return false;
        }
        if (rc == remaining) return true;
        // Partial: enqueue what wasn't sent (may be entire chunk on rc==0,
        // or leftover past what capacity accepted).
        int written = (int) rc;
        enqueuePending(streamId,
            copyOwned(bytes, off + written, remaining - written), fin);
        return false;
    }

    private static byte[] copyOwned(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    private void enqueuePending(long streamId, byte[] bytes, boolean fin) {
        // Init cap 2 — most streams only defer 1-2 items when flow
        // control blocks. ArrayDeque default is 16 which allocates a
        // ~128-byte Object[] per new stream (task #144).
        java.util.Deque<Pending> q = pendingByStream.get(streamId);
        if (q == null) {
            q = new java.util.ArrayDeque<>(2);
            pendingByStream.put(streamId, q);
        }
        q.addLast(new Pending(bytes, fin));
    }

    /**
     * Retry any deferred stream writes. Called by the owner-thread driver
     * loop after regular drainOutbound so newly-opened flow-control
     * windows get picked up promptly.
     */
    public void drainPendingWrites() {
        if (pendingByStream.isEmpty()) return;
        // Two-pass: forEach mutates queue values in place, then we walk
        // pendingRemovals to drop empty entries. Long2ObjectHashMap
        // doesn't support removal during iteration.
        pendingRemovalsSize = 0;
        pendingByStream.forEach((streamId, q) -> {
            while (!q.isEmpty()) {
                Pending p = q.peekFirst();
                long cap = Quiche.connStreamCapacity(conn, streamId);
                if (cap < 0) { q.clear(); break; }
                if (cap == 0) break;
                int chunk = (int) Math.min((long) p.len, cap);
                boolean applyFin = p.fin && (chunk == p.len);
                long rc = Quiche.connStreamSend(
                    conn, streamId, p.buf, p.off, chunk, applyFin);
                if (rc < 0) { q.clear(); break; }
                if (rc == 0) break;
                p.off += (int) rc;
                p.len -= (int) rc;
                if (p.len == 0) q.pollFirst();
            }
            if (q.isEmpty()) {
                if (pendingRemovalsSize == pendingRemovals.length) {
                    pendingRemovals = java.util.Arrays.copyOf(
                        pendingRemovals, pendingRemovals.length * 2);
                }
                pendingRemovals[pendingRemovalsSize++] = streamId;
            }
        });
        for (int i = 0; i < pendingRemovalsSize; i++) {
            pendingByStream.remove(pendingRemovals[i]);
        }
    }

    private long[] pendingRemovals = new long[8];
    private int pendingRemovalsSize;

    /** Per-stream deferred write: what quiche's flow control blocked. */
    private static final class Pending {
        byte[] buf;
        int off;
        int len;
        final boolean fin;
        Pending(byte[] buf, boolean fin) {
            this.buf = buf;
            this.off = 0;
            this.len = buf.length;
            this.fin = fin;
        }
    }

    private final Long2ObjectHashMap<java.util.Deque<Pending>> pendingByStream =
        new Long2ObjectHashMap<>();

    /** Exposed so the driver loop can skip parking when writes await capacity. */
    public boolean hasPendingWrites() {
        return !pendingByStream.isEmpty();
    }

    /**
     * Drop all session-level state for a stream. Called by the transport
     * driver when quiche_conn_stream_recv reports a terminal error
     * (STOP_SENDING / RESET_STREAM); without this, per-stream maps
     * accumulate under peer reset-flood (task #140).
     */
    public void forgetStream(long streamId) {
        releaseReader(requestStreams.remove(streamId));
        pendingByStream.remove(streamId);
        peerUniTypes.remove(streamId);
        peerUniHeaderBuf.remove(streamId);
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

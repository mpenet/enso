package com.s_exp.enso.http3;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.http3.qpack.QpackException;
import com.s_exp.enso.http3.qpack.QpackFieldSection;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Pure-Java HTTP/3 session state (framing, QPACK, stream rules) on top of
 * the QUIC transport primitives exposed by the {@link Quiche} JNI shim;
 * quiche's own {@code quiche_h3_*} layer is not used.
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
 *       (bidi client-initiated) → per-stream {@link Http3FrameReader}.
 *       Peer uni streams: read the first varint to identify type, then
 *       parse the control stream, validate QPACK encoder/decoder
 *       instructions against our capacity of 0, and discard unknown /
 *       grease streams.
 *   <li>Write HEADERS + DATA + FIN back on request streams via
 *       {@link #writeResponse}.
 * </ul>
 *
 * <p>Not v1: server push, priority updates, connection close via GOAWAY,
 * dynamic-table QPACK, blocked streams. All can be added incrementally.
 */
public final class Http3Session {

    private static final Logger LOG = Logger.getLogger(Http3Session.class.getName());

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
    // RFC 9114 §6.2.1 / RFC 9204 §4.2: duplicates close the connection
    // with H3_STREAM_CREATION_ERROR.
    private long peerControlStreamId = -1;
    private long peerQpackEncStreamId = -1;
    private long peerQpackDecStreamId = -1;
    // Peer uni streams that we've identified. Value = stream type varint
    // (unknown / grease types included until they end, so their later
    // bytes are discarded, never re-read as a type). Streams whose type
    // hasn't arrived yet aren't in this map.
    private final Long2ObjectHashMap<Long> peerUniTypes = new Long2ObjectHashMap<>();
    // Peer uni streams whose type varint is only partially known.
    private final Long2ObjectHashMap<ByteBuffer> peerUniHeaderBuf = new Long2ObjectHashMap<>();
    // Rolling accumulators for QPACK encoder/decoder streams — a single
    // instruction (varint + optional payload) can straddle two stream_recv
    // chunks, so we buffer partial trailing bytes and prepend them next call.
    // Small cap since we expect only short instructions under capacity=0.
    private ByteBuffer peerQpackEncAccum;
    private ByteBuffer peerQpackDecAccum;
    private boolean initialised = false;

    // SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1). Local value
    // is what we advertise (0 = not advertised; see fieldSectionCap).
    // Peer's advertised value is checked against our outbound HEADERS
    // uncompressed size (name+value+32 per pair, RFC 9204 §4.5.1) — an
    // advisory check that only logs; -1 means peer did not advertise.
    private final long localMaxFieldSectionSize;
    // What we actually accept: the advertised limit, or when none is
    // advertised (0 = no limit) UNADVERTISED_FIELD_SECTION_CAP. Bounds
    // both the HEADERS frames we buffer and their decoded size.
    private final int fieldSectionCap;
    private final long qpackMaxTableCapacity;
    private final long qpackBlockedStreams;
    private long peerMaxFieldSectionSize = -1;

    public Http3Session(long conn, Config cfg) {
        this.conn = conn;
        this.localMaxFieldSectionSize = cfg.http3MaxFieldSectionSize;
        this.fieldSectionCap = cfg.http3MaxFieldSectionSize > 0
            ? cfg.http3MaxFieldSectionSize : UNADVERTISED_FIELD_SECTION_CAP;
        this.qpackMaxTableCapacity = cfg.http3QpackMaxTableCapacity;
        this.qpackBlockedStreams = cfg.http3QpackBlockedStreams;
    }

    /**
     * Open our three server-uni streams (control + QPACK enc/dec) and
     * emit our initial SETTINGS. Idempotent and retry-safe: short writes
     * are queued in {@link #pendingByStream}; if a stream can't be
     * opened at all (peer's uni-stream limit), the completion flags stay
     * unset and the next call resumes from the first still-pending step.
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
            if (!writeStreamTypePrefix(ctrlStreamId, Http3StreamType.CONTROL)) return;
            ctrlTypeSent = true;
        }
        if (!settingsSent) {
            // MAX_FIELD_SECTION_SIZE = 0 in config means "no limit": the
            // setting is omitted (an advertised 0 would forbid any field).
            ByteBuffer settings = Http3FrameWriter.settings(localMaxFieldSectionSize > 0
                ? new long[]{
                    Http3SettingId.QPACK_MAX_TABLE_CAPACITY, qpackMaxTableCapacity,
                    Http3SettingId.QPACK_BLOCKED_STREAMS, qpackBlockedStreams,
                    Http3SettingId.MAX_FIELD_SECTION_SIZE, localMaxFieldSectionSize}
                : new long[]{
                    Http3SettingId.QPACK_MAX_TABLE_CAPACITY, qpackMaxTableCapacity,
                    Http3SettingId.QPACK_BLOCKED_STREAMS, qpackBlockedStreams});
            if (!writeAll(ctrlStreamId, settings, false)) return;
            settingsSent = true;
        }
        if (!qpackEncTypeSent) {
            if (!writeStreamTypePrefix(qpackEncStreamId, Http3StreamType.QPACK_ENCODER)) return;
            qpackEncTypeSent = true;
        }
        if (!qpackDecTypeSent) {
            if (!writeStreamTypePrefix(qpackDecStreamId, Http3StreamType.QPACK_DECODER)) return;
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
     * are parsed (control), validated (QPACK encoder/decoder instructions
     * under capacity 0) or discarded (unknown / grease types).
     */
    public void onStreamData(long streamId, byte[] data, boolean fin,
                              RequestSink sink) {
        onStreamData(streamId, data, 0, data.length, fin, sink);
    }

    /**
     * byte[]+off+len variant: lets the driver pass its owner-thread
     * recvBuf directly without a fresh per-chunk allocation (task
     * #147-adjacent). Http3FrameReader.feed copies into its rolling buf
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
        } catch (Http3ConnectionException hce) {
            closeConnection(hce);
        }
    }

    /**
     * Protocol-level violation → close the whole connection with the H3
     * error code. Owner-thread driver observes connIsClosed on next
     * iteration and exits cleanly.
     *
     * <p>Reason string sent as empty byte[] — some peer stacks
     * (h3spec/haskell-quic) do strict predicate checks that reject
     * non-empty reasons even when the app error code is correct (task
     * #162). The full message is still logged server-side for our
     * debugging.
     */
    private void closeConnection(Http3ConnectionException hce) {
        LOG.info("h3 closing connection code=0x"
            + Long.toHexString(hce.errorCode()) + " reason="
            + hce.getMessage());
        try {
            Quiche.connClose(conn, true, hce.errorCode(), EMPTY_REASON);
        } catch (Throwable ignored) {}
    }

    /**
     * The peer reset {@code streamId} (stream_recv reported
     * STREAM_RESET). Resetting a control or QPACK stream closes the
     * connection with H3_CLOSED_CRITICAL_STREAM (RFC 9114 §6.2.1, RFC
     * 9204 §4.2). For any other stream only the read-side state is
     * dropped: RESET_STREAM ends just the peer's sending side (RFC 9000
     * §3.2), so response bytes still queued for it are sent.
     */
    public void onStreamReset(long streamId) {
        if (streamId == peerControlStreamId || streamId == peerQpackEncStreamId
                || streamId == peerQpackDecStreamId) {
            closeConnection(new Http3ConnectionException(
                Http3ConnectionException.H3_CLOSED_CRITICAL_STREAM,
                "peer reset critical stream " + streamId));
            return;
        }
        forgetReadSide(streamId);
    }

    private static final byte[] EMPTY_REASON = new byte[0];

    // Field-section ceiling when no SETTINGS_MAX_FIELD_SECTION_SIZE is
    // advertised. RFC 9114 §4.2.2 lets a server reject any request whose
    // headers it won't process; without a ceiling a peer could make us
    // buffer and decode arbitrarily large HEADERS on every stream. 1 MiB
    // matches Go net/http's default header limit (DefaultMaxHeaderBytes).
    static final int UNADVERTISED_FIELD_SECTION_CAP = 1 << 20;

    /**
     * Encode and send a full HTTP/3 response back on a request stream.
     * FIN is applied to the DATA frame when {@code body} is present, else
     * on the HEADERS frame.
     */
    public void writeResponse(long streamId, List<String[]> headers,
                               byte[] body) {
        boolean hasBody = body != null && body.length > 0;
        // Small bodies: HEADERS + DATA encoded into the frame buffer and
        // handed over in one stream_send (task #143). Large bodies: HEADERS
        // + the DATA frame header from the frame buffer, then the payload
        // straight from the body array — deferred by reference, never
        // copied (the response owns it). writeBytes keeps per-stream
        // order, so FIN can't outrun HEADERS (task #131).
        boolean inline = hasBody && body.length <= INLINE_BODY_MAX;
        int hdrsBudget = computeHeadersBudget(streamId, headers);
        ByteBuffer buf = ensureFrameCap(hdrsBudget + (hasBody ? 16 : 0) + (inline ? body.length : 0));
        buf.clear();
        Http3FrameWriter.appendHeadersFrom(buf, headers);
        if (inline) {
            Http3FrameWriter.appendData(buf, body);
        } else if (hasBody) {
            Http3Varint.encode(buf, Http3FrameType.DATA);
            Http3Varint.encode(buf, body.length);
        }
        buf.flip();
        if (hasBody && !inline) {
            if (writeAll(streamId, buf, false)) {
                writeBytes(streamId, body, 0, body.length, true, false);
            }
        } else {
            writeAll(streamId, buf, true);
        }
        stopReadingRequest(streamId);
    }

    // Bodies up to this size are copied into the frame buffer (one JNI
    // call); larger ones are sent from their own array.
    private static final int INLINE_BODY_MAX = 16 * 1024;

    /**
     * Emit HEADERS only (no FIN) — first half of a streaming response.
     * Body bytes follow via {@link #sendStreamBytes} once
     * {@link #hasPendingWrites(long)} reports the HEADERS flushed.
     */
    public void writeHeadersOnly(long streamId, List<String[]> headers) {
        int hdrsBudget = computeHeadersBudget(streamId, headers);
        ByteBuffer buf = ensureFrameCap(hdrsBudget);
        buf.clear();
        Http3FrameWriter.appendHeadersFrom(buf, headers);
        buf.flip();
        writeAll(streamId, buf, false);
    }

    /**
     * Hand up to {@code len} bytes to quiche right now, bounded by flow
     * control, bypassing the deferred-write queue. Used by streamed
     * response bodies, which keep their own position and only call this
     * once {@link #hasPendingWrites(long)} is false. FIN is applied only
     * if every byte is accepted. When {@code fin} is set the response is
     * complete (see {@link #stopReadingRequest}).
     *
     * @return bytes accepted (possibly 0), or -1 once the stream can no
     *   longer take data (peer STOP_SENDING / reset).
     */
    public int sendStreamBytes(long streamId, byte[] b, int off, int len, boolean fin) {
        long rc = Quiche.connStreamSend(conn, streamId, b, off, len, fin);
        if (rc == Quiche.QUICHE_ERR_DONE) return 0;
        if (rc < 0) {
            LOG.log(rc == Quiche.QUICHE_ERR_STREAM_STOPPED
                        || rc == Quiche.QUICHE_ERR_STREAM_RESET ? Level.FINE : Level.WARNING,
                "h3 stream_send stream=" + streamId + " rc=" + rc);
            return -1;
        }
        if (fin && rc == len) stopReadingRequest(streamId);
        return (int) rc;
    }

    /**
     * True once nobody can receive what we send on {@code streamId}: the
     * peer stopped our sending side (STOP_SENDING) or the stream is gone.
     */
    public boolean sendStopped(long streamId) {
        return Quiche.connStreamCapacity(conn, streamId) < 0;
    }

    /**
     * The response on {@code streamId} is complete. If the request is
     * still arriving (no FIN yet), we no longer need it: RFC 9114 §4.1.2
     * says to abort reading with STOP_SENDING(H3_NO_ERROR); quiche then
     * discards further stream data. Without this, the dropped reader
     * state would make later body bytes parse as frame headers.
     * Reader reuse is safe because {@link Http3FrameReader#reset} clears
     * state on release and QUIC stream IDs are never reused.
     */
    private void stopReadingRequest(long streamId) {
        RequestStream rs = requestStreams.remove(streamId);
        if (rs == null) return;
        Quiche.connStreamShutdown(conn, streamId, Quiche.QUICHE_SHUTDOWN_READ,
            Http3ConnectionException.H3_NO_ERROR);
        releaseReader(rs);
    }

    /**
     * Compute frame-buffer budget for HEADERS + log advisory when the
     * uncompressed size exceeds peer's SETTINGS_MAX_FIELD_SECTION_SIZE.
     * Shared between {@link #writeResponse} and {@link #writeHeadersOnly}.
     */
    private int computeHeadersBudget(long streamId, List<String[]> headers) {
        // Frame type + fixed 8-byte length + QPACK prefix, then an upper
        // bound per field on the bytes the encoder actually writes.
        int hdrsBudget = 16;
        int hn = headers.size();
        long uncompressedSize = 0;
        for (int i = 0; i < hn; i++) {
            String[] hf = headers.get(i);
            hdrsBudget += QpackFieldSection.maxEncodedLength(hf[0], hf[1]);
            // RFC 9204 §4.5.1: field-line size = name + value octets + 32.
            uncompressedSize += hf[0].length()
                + (hf[1] == null ? 0 : hf[1].length())
                + 32L;
        }
        // Advisory check against peer's SETTINGS_MAX_FIELD_SECTION_SIZE.
        // We proceed anyway (spec: peer MAY react with H3_EXCESSIVE_LOAD;
        // rejecting here would drop a response the peer's stack might still
        // handle), but log so oversize responses are diagnosable.
        if (peerMaxFieldSectionSize >= 0
                && uncompressedSize > peerMaxFieldSectionSize) {
            LOG.warning("h3 response field-section size " + uncompressedSize
                + " exceeds peer's SETTINGS_MAX_FIELD_SECTION_SIZE "
                + peerMaxFieldSectionSize + " (stream=" + streamId + ")");
        }
        return hdrsBudget;
    }

    // Response frame scratch — grows to largest response seen on this
    // conn. Bounded implicitly by the connection's overall payload sizes.
    // QPACK now encodes directly into this buffer (task #123), so a
    // separate qpackScratch is no longer needed.
    private ByteBuffer frameBuf = ByteBuffer.allocate(4096);
    // Ceiling on the retained frameBuf. A one-off monster response
    // would otherwise pin the largest buffer for the connection's whole
    // lifetime. Above the cap: allocate a throwaway buffer for this
    // response, keep the small one for the common case, let GC reclaim.
    private static final int FRAME_BUF_MAX_KEEP = 256 * 1024;

    private ByteBuffer ensureFrameCap(int need) {
        if (frameBuf.capacity() >= need) return frameBuf;
        int newCap = Math.max(frameBuf.capacity() * 2, need);
        ByteBuffer next = ByteBuffer.allocate(newCap);
        if (newCap <= FRAME_BUF_MAX_KEEP) {
            frameBuf = next;
        }
        return next;
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
            discardReader(requestStreams.remove(streamId));
            throw new Http3ConnectionException(
                Http3ConnectionException.H3_FRAME_ERROR,
                "request-stream reader: " + e.getMessage());
        }
        while (true) {
            Http3FrameReader.Frame f;
            try {
                f = rs.reader.poll();
            } catch (IllegalStateException e) {
                discardReader(requestStreams.remove(streamId));
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_ERROR,
                    "request-stream reader: " + e.getMessage());
            }
            if (f == null) break;
            // RFC 9114 §7.2: control-only frames on a request stream MUST
            // be treated as H3_FRAME_UNEXPECTED at the connection level.
            if (f.type == Http3FrameType.SETTINGS
                || f.type == Http3FrameType.GOAWAY
                || f.type == Http3FrameType.MAX_PUSH_ID
                || f.type == Http3FrameType.CANCEL_PUSH
                || f.type == Http3FrameType.PUSH_PROMISE
                || Http3FrameType.isReservedHttp2(f.type)) {
                discardReader(requestStreams.remove(streamId));
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(f.type)
                        + " forbidden on request stream " + streamId);
            }
            if (f.oversized) {
                LOG.fine("h3 stream " + streamId + " reset: HEADERS exceeds "
                    + "field section limit " + fieldSectionCap);
                rejectRequest(streamId, Http3ConnectionException.H3_EXCESSIVE_LOAD, sink);
                return;
            }
            if (f.type == Http3FrameType.HEADERS) {
                // RFC 9114 §4.1: HEADERS, DATA*, optional trailing
                // HEADERS; anything after the trailers is an invalid
                // frame sequence.
                if (rs.phase == RequestStream.TRAILERS) {
                    discardReader(requestStreams.remove(streamId));
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_FRAME_UNEXPECTED,
                        "HEADERS after trailers on request stream " + streamId);
                }
                List<String[]> headers;
                try {
                    headers = QpackFieldSection.decode(f.payload, fieldSectionCap);
                } catch (QpackException qe) {
                    if (qe.isStreamLevel()) {
                        LOG.fine("h3 stream " + streamId + " reset: " + qe.getMessage());
                        rejectRequest(streamId, qe.errorCode(), sink);
                        return;
                    }
                    // RFC 9204 §2.2: any decode failure on a request
                    // stream (bad static index, dynamic-ref-under-cap-0,
                    // malformed literal) = connection-level error with
                    // the QPACK code the decoder produced. h3spec 16 /
                    // task #155 — we were resetting the stream instead
                    // of closing the connection, so the error code never
                    // reached the peer.
                    discardReader(requestStreams.remove(streamId));
                    throw new Http3ConnectionException(
                        qe.errorCode(),
                        "QPACK decode failed on stream " + streamId
                            + ": " + qe.getMessage());
                }
                try {
                    if (rs.phase == RequestStream.HEADERS) {
                        rs.phase = RequestStream.BODY;
                        sink.onHeaders(streamId, headers);
                    } else {
                        // Trailers: validated, then dropped (Ring has no
                        // trailer surface).
                        rs.phase = RequestStream.TRAILERS;
                        validateTrailers(streamId, headers);
                    }
                } catch (Http3StreamException se) {
                    streamError(streamId, se, sink);
                    return;
                }
            } else if (f.isDataChunk()) {
                if (rs.phase != RequestStream.BODY) {
                    discardReader(requestStreams.remove(streamId));
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_FRAME_UNEXPECTED,
                        (rs.phase == RequestStream.HEADERS ? "DATA before HEADERS"
                            : "DATA after trailers") + " on request stream " + streamId);
                }
                try {
                    sink.onData(streamId, f.dataChunk);
                } catch (Http3StreamException se) {
                    streamError(streamId, se, sink);
                    return;
                }
            }
            // Unknown/other frame types silently ignored per RFC 9114 §9
            // (proper streaming skip is task #103).
        }
        if (fin) {
            // RFC 9114 §7.1: stream MUST NOT terminate mid-frame. If the
            // reader still holds partial bytes, the peer truncated the
            // last frame — connection-level H3_FRAME_ERROR.
            if (rs.reader.hasPartial()) {
                discardReader(requestStreams.remove(streamId));
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_ERROR,
                    "stream " + streamId + " terminated mid-frame");
            }
            try {
                sink.onFin(streamId);
            } catch (Http3StreamException se) {
                streamError(streamId, se, sink);
                return;
            }
            releaseReader(requestStreams.remove(streamId));
        }
    }

    /** RFC 9114 §4.1.2 / §4.3: no pseudo-headers, valid names and values. */
    private static void validateTrailers(long streamId, List<String[]> fields) {
        for (int i = 0, n = fields.size(); i < n; i++) {
            String[] f = fields.get(i);
            if (!validFieldName(f[0]) || !validFieldValue(f[1])) {
                throw new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
                    "invalid trailer field '" + f[0] + "' on stream " + streamId);
            }
        }
    }

    /** RFC 9114 §4.2: a non-empty lowercase token (so never a pseudo-header). */
    static boolean validFieldName(String s) {
        return HttpFields.isLowercaseToken(s, 0);
    }

    /** RFC 9114 §10.3: CR, LF and NUL are never valid in a field value. */
    static boolean validFieldValue(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') return false;
        }
        return true;
    }

    private void streamError(long streamId, Http3StreamException se, RequestSink sink) {
        LOG.fine("h3 stream " + streamId + " reset 0x"
            + Long.toHexString(se.errorCode()) + ": " + se.getMessage());
        rejectRequest(streamId, se.errorCode(), sink);
    }

    /**
     * Stream error on a request stream (RFC 9114 §8): reset it in both
     * directions and tell the sink, which abandons whatever the request
     * had started (body pipe, handler, response).
     */
    private void rejectRequest(long streamId, long errorCode, RequestSink sink) {
        resetRequestStream(streamId, errorCode);
        sink.onReset(streamId);
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
            int peekLen = Http3Varint.peekLength(readView);
            if (peekLen < 0 || readView.remaining() < peekLen) {
                // Type varint still incomplete. If peer sent FIN we can
                // drop the accumulator — no more bytes will arrive.
                if (fin) peerUniHeaderBuf.remove(streamId);
                return;
            }
            long type = Http3Varint.decode(readView);
            peerUniHeaderBuf.remove(streamId);
            // Reject a second CONTROL / QPACK-ENCODER / QPACK-DECODER
            // stream (RFC 9114 §6.2.1, RFC 9204 §4.2).
            if (type == Http3StreamType.CONTROL) {
                if (peerControlStreamId >= 0) throw duplicateStream("control", streamId);
                peerControlStreamId = streamId;
            } else if (type == Http3StreamType.QPACK_ENCODER) {
                if (peerQpackEncStreamId >= 0) throw duplicateStream("QPACK encoder", streamId);
                peerQpackEncStreamId = streamId;
            } else if (type == Http3StreamType.QPACK_DECODER) {
                if (peerQpackDecStreamId >= 0) throw duplicateStream("QPACK decoder", streamId);
                peerQpackDecStreamId = streamId;
            } else if (type == 0x01L /* PUSH */) {
                // RFC 9114 §6.2.2: only servers push; a client-initiated
                // push stream is a connection error.
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_STREAM_CREATION_ERROR,
                    "client-initiated push stream " + streamId);
            } else {
                // Grease (RFC 9114 §7.2.8) or unknown type (§6.2): recorded
                // until the stream ends so the rest of it is discarded
                // without being re-read as a type. Unknown types also get
                // STOP_SENDING with H3_STREAM_CREATION_ERROR so the peer
                // stops sending.
                if (!fin) peerUniTypes.put(streamId, type);
                if (!isGreaseType(type)) {
                    LOG.fine("h3 unknown peer uni stream type=0x"
                        + Long.toHexString(type) + " id=" + streamId);
                    try {
                        Quiche.connStreamShutdown(
                            conn, streamId,
                            Quiche.QUICHE_SHUTDOWN_READ,
                            Http3ConnectionException.H3_STREAM_CREATION_ERROR);
                    } catch (Throwable ignored) {}
                }
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
        // RFC 9114 §6.2.1 — control + QPACK enc/dec streams are
        // "critical". Peer FIN on any of them = H3_CLOSED_CRITICAL_STREAM
        // (h3spec 18 / task #157).
        if (fin && knownType != null
                && (knownType == Http3StreamType.CONTROL
                    || knownType == Http3StreamType.QPACK_ENCODER
                    || knownType == Http3StreamType.QPACK_DECODER)) {
            throw new Http3ConnectionException(
                Http3ConnectionException.H3_CLOSED_CRITICAL_STREAM,
                "peer closed critical stream type=0x"
                    + Long.toHexString(knownType) + " id=" + streamId);
        }
        // Peer control stream: parse SETTINGS / GOAWAY / MAX_PUSH_ID.
        // Any protocol-level violation raises Http3ConnectionException which
        // onStreamData catches + translates into a quiche_conn_close.
        if (knownType == Http3StreamType.CONTROL) {
            handlePeerControlBytes(buf);
        } else if (knownType == Http3StreamType.QPACK_ENCODER) {
            // Under our advertised MAX_TABLE_CAPACITY=0, the ONLY
            // encoder instruction we accept from the peer is Set Dynamic
            // Table Capacity with value 0 (which is a no-op). Anything
            // else = QPACK_ENCODER_STREAM_ERROR (h3spec 17 / task #156).
            validatePeerQpackEncoderStream(buf);
        } else if (knownType == Http3StreamType.QPACK_DECODER) {
            // Peer decoder stream instructions must have non-zero
            // arguments where required. Insert Count Increment = 0 is
            // QPACK_DECODER_STREAM_ERROR (h3spec 19 / task #158).
            validatePeerQpackDecoderStream(buf);
        } else if (fin) {
            // A grease / unknown stream ended (critical ones can't reach
            // here): nothing more will arrive on it.
            peerUniTypes.remove(streamId);
        }
    }

    /**
     * Append {@code more} onto the running accumulator {@code accum},
     * returning a read-mode buffer positioned at the first unread byte.
     * Grows if capacity is insufficient. Small init size (32) since QPACK
     * instructions under capacity=0 are typically 1-9 bytes.
     */
    private static ByteBuffer appendToAccum(ByteBuffer accum, ByteBuffer more) {
        int incoming = more.remaining();
        // Only null check — remaining==0 with non-null accum is legitimate
        // state that must NOT overwrite. compactRemaining returns null for
        // rem==0, but conservative guard avoids future foot-guns.
        if (accum == null) {
            int cap = Math.max(32, incoming);
            ByteBuffer nb = ByteBuffer.allocate(cap);
            nb.put(more);
            nb.flip();
            return nb;
        }
        int total = accum.remaining() + incoming;
        ByteBuffer dst;
        if (accum.capacity() >= total) {
            accum.compact();     // read-mode → write-mode with unread at 0
            dst = accum;
        } else {
            int cap = Math.max(total, accum.capacity() * 2);
            dst = ByteBuffer.allocate(cap);
            dst.put(accum);      // copy unread bytes
        }
        dst.put(more);
        dst.flip();
        return dst;
    }

    /**
     * RFC 9204 §4.1 — QPACK encoder-stream instructions. Under our
     * advertised capacity=0 we reject any Set Dynamic Table Capacity
     * with a non-zero value (only value=0 is a valid no-op) and any
     * Insert With Name Reference / Insert With Literal Name / Duplicate
     * (all of which imply peer wants a dynamic table).
     *
     * <p>Accepts a rolling accumulator: an instruction can span two
     * stream_recv chunks (varint continuation bytes especially). On
     * partial parse, the incomplete tail is buffered in
     * {@link #peerQpackEncAccum} and prepended on the next call.
     */
    private void validatePeerQpackEncoderStream(ByteBuffer buf) {
        ByteBuffer work = appendToAccum(peerQpackEncAccum, buf);
        while (work.hasRemaining()) {
            int startPos = work.position();
            int b = work.get(startPos) & 0xFF;
            // Set Dynamic Table Capacity: 001xxxxx (5-bit prefix int).
            if ((b & 0xE0) == 0x20) {
                long cap;
                try {
                    work.get(); // consume first byte
                    cap = com.s_exp.enso.http3.qpack.NBitInteger.decode(
                        work, 5, b);
                } catch (java.nio.BufferUnderflowException ex) {
                    // Incomplete instruction — rewind and buffer.
                    work.position(startPos);
                    peerQpackEncAccum = compactRemaining(work);
                    return;
                } catch (Throwable ex) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                        "malformed Set Dynamic Table Capacity: " + ex.getMessage());
                }
                if (cap != 0) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                        "peer Set Dynamic Table Capacity=" + cap
                            + " exceeds advertised limit 0");
                }
                continue;
            }
            // Any Insert With Name Reference (1xxxxxxx), Insert With
            // Literal Name (01xxxxxx), or Duplicate (000xxxxx) implies
            // peer wants a dynamic table — reject.
            throw new Http3ConnectionException(
                Http3ConnectionException.QPACK_ENCODER_STREAM_ERROR,
                "peer QPACK encoder instruction 0x" + Integer.toHexString(b)
                    + " not allowed under capacity=0");
        }
        peerQpackEncAccum = null;
    }

    /**
     * RFC 9204 §4.4 — QPACK decoder-stream instructions. Our encoder never
     * uses the dynamic table (every field section has Required Insert
     * Count 0), so Section Acknowledgment (§4.4.1: no section left to
     * acknowledge) and Insert Count Increment (§4.4.3: zero, or beyond
     * the zero entries we inserted) are always QPACK_DECODER_STREAM_ERROR.
     * Stream Cancellation is fine to ignore. Same partial-instruction
     * handling as the encoder stream.
     */
    private void validatePeerQpackDecoderStream(ByteBuffer buf) {
        ByteBuffer work = appendToAccum(peerQpackDecAccum, buf);
        while (work.hasRemaining()) {
            int startPos = work.position();
            int b = work.get(startPos) & 0xFF;
            try {
                if ((b & 0xC0) == 0x00) {
                    // Insert Count Increment: 00xxxxxx (6-bit prefix int).
                    work.get();
                    long inc = com.s_exp.enso.http3.qpack.NBitInteger.decode(
                        work, 6, b);
                    throw new Http3ConnectionException(
                        Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                        "peer Insert Count Increment=" + inc + " but no dynamic table entries");
                }
                if ((b & 0x80) != 0) {
                    // Section Acknowledgment: 1xxxxxxx (7-bit prefix int).
                    work.get();
                    long sid = com.s_exp.enso.http3.qpack.NBitInteger.decode(work, 7, b);
                    throw new Http3ConnectionException(
                        Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                        "peer Section Acknowledgment for stream " + sid
                            + " but no field section used the dynamic table");
                }
                if ((b & 0xC0) == 0x40) {
                    // Stream Cancellation: 01xxxxxx (6-bit prefix int).
                    work.get();
                    com.s_exp.enso.http3.qpack.NBitInteger.decode(work, 6, b);
                    continue;
                }
            } catch (java.nio.BufferUnderflowException ex) {
                work.position(startPos);
                peerQpackDecAccum = compactRemaining(work);
                return;
            } catch (Http3ConnectionException hce) {
                throw hce;
            } catch (Throwable ex) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                    "malformed QPACK decoder instruction: " + ex.getMessage());
            }
            throw new Http3ConnectionException(
                Http3ConnectionException.QPACK_DECODER_STREAM_ERROR,
                "unknown QPACK decoder instruction 0x" + Integer.toHexString(b));
        }
        peerQpackDecAccum = null;
    }

    /**
     * Return {@code work} as a fresh accumulator retaining only the
     * unread bytes at [position, limit). Callers use this to persist
     * incomplete-instruction tails across recv calls.
     */
    private static ByteBuffer compactRemaining(ByteBuffer work) {
        int rem = work.remaining();
        if (rem == 0) return null;
        ByteBuffer tail = ByteBuffer.allocate(Math.max(32, rem));
        tail.put(work);
        tail.flip();
        return tail;
    }

    /**
     * Feed the peer's control-stream bytes to a per-connection reader
     * and enforce RFC 9114 §7.2 ordering rules. Protocol violations here
     * MUST close the whole connection, not just the stream.
     */
    private void handlePeerControlBytes(ByteBuffer buf) {
        if (peerControlReader == null) peerControlReader = new Http3FrameReader();
        try {
            peerControlReader.feed(buf);
        } catch (IllegalStateException e) {
            throw new Http3ConnectionException(
                Http3ConnectionException.H3_FRAME_ERROR,
                "peer control-stream feed: " + e.getMessage());
        }
        while (true) {
            Http3FrameReader.Frame f;
            try {
                f = peerControlReader.poll();
            } catch (IllegalStateException e) {
                // Reader detected an over-sized frame → treat as
                // H3_EXCESSIVE_LOAD / FRAME_ERROR at the connection layer.
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_ERROR,
                    "peer control-stream frame reader: " + e.getMessage());
            }
            if (f == null) break;
            // RFC 9114 §7.2.4: SETTINGS MUST be the first frame.
            if (!sawPeerSettings && f.type != Http3FrameType.SETTINGS) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_MISSING_SETTINGS,
                    "first frame on peer control stream must be SETTINGS, got 0x"
                        + Long.toHexString(f.type));
            }
            if (f.type == Http3FrameType.SETTINGS) {
                if (sawPeerSettings) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_FRAME_UNEXPECTED,
                        "duplicate SETTINGS on peer control stream");
                }
                sawPeerSettings = true;
                // RFC 9114 §7.2.4.1: any h2-reserved setting ID in an h3
                // SETTINGS = H3_SETTINGS_ERROR (h3spec 15 / task #154).
                // h2 IDs 0x02, 0x03, 0x04, 0x05 (RFC 7540 §6.5.2) are
                // banned on the h3 wire.
                validatePeerSettings(f.payload);
            } else if (f.type == Http3FrameType.HEADERS
                    || f.type == Http3FrameType.DATA
                    || f.type == Http3FrameType.PUSH_PROMISE
                    || Http3FrameType.isReservedHttp2(f.type)) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(f.type)
                        + " forbidden on control stream");
            } else if (f.type == Http3FrameType.GOAWAY) {
                // RFC 9114 §5.2: peer's GOAWAY IDs must be non-increasing
                // across repeated frames. Increasing = H3_ID_ERROR at
                // connection level (task #138).
                long goawayId;
                try {
                    goawayId = Http3Varint.decode(java.nio.ByteBuffer.wrap(f.payload));
                } catch (Throwable ex) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_FRAME_ERROR,
                        "malformed GOAWAY payload: " + ex.getMessage());
                }
                if (sawPeerGoaway && goawayId > lastPeerGoawayId) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_ID_ERROR,
                        "GOAWAY ID increased: prev=" + lastPeerGoawayId
                            + " new=" + goawayId);
                }
                sawPeerGoaway = true;
                lastPeerGoawayId = goawayId;
            } else if (f.type == Http3FrameType.MAX_PUSH_ID
                    || f.type == Http3FrameType.CANCEL_PUSH) {
                // We never enable push (SETTINGS_ENABLE_CONNECT_PROTOCOL
                // == 0, MAX_PUSH_ID unset). Accept + ignore.
            }
            // Unknown / reserved frame types: reader stream-skipped them.
        }
    }

    private Http3FrameReader peerControlReader;
    private boolean sawPeerSettings;
    private boolean sawPeerGoaway;
    private long lastPeerGoawayId;

    /** RFC 9114 §7.2.4.1 — h3 SETTINGS body is a sequence of (id, value) varint pairs. */
    private void validatePeerSettings(byte[] payload) {
        ByteBuffer b = ByteBuffer.wrap(payload);
        // Ids seen so far (each pair is ≥ 2 bytes).
        long[] seen = new long[payload.length / 2];
        int seenCount = 0;
        while (b.hasRemaining()) {
            long id, value;
            try {
                id = Http3Varint.decode(b);
                if (!b.hasRemaining()) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_FRAME_ERROR,
                        "truncated SETTINGS (missing value for id 0x"
                            + Long.toHexString(id) + ")");
                }
                value = Http3Varint.decode(b);
            } catch (Http3ConnectionException hce) {
                throw hce;
            } catch (Throwable ex) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_ERROR,
                    "malformed SETTINGS payload: " + ex.getMessage());
            }
            // RFC 9114 §7.2.4: an identifier MUST NOT occur twice.
            for (int i = 0; i < seenCount; i++) {
                if (seen[i] == id) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_SETTINGS_ERROR,
                        "duplicate SETTINGS id 0x" + Long.toHexString(id));
                }
            }
            seen[seenCount++] = id;
            // h2-reserved IDs (RFC 7540 §6.5.2): SETTINGS_ENABLE_PUSH,
            // SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
            // SETTINGS_MAX_FRAME_SIZE — MUST NOT appear in h3 SETTINGS.
            if (id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05
                    || id == 0x06 /* SETTINGS_MAX_HEADER_LIST_SIZE — same ID both, ok */) {
                if (id != 0x06) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_SETTINGS_ERROR,
                        "h2-reserved SETTINGS id 0x" + Long.toHexString(id)
                            + " not allowed in h3");
                }
            }
            // Known IDs we consume:
            //   MAX_FIELD_SECTION_SIZE (0x06) — peer's limit on our outbound
            //     HEADERS uncompressed size (name+value+32 per pair, RFC 9204
            //     §4.5.1). Checked, advisory only (logged), in
            //     computeHeadersBudget.
            // Others (QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS) are
            // silently ignored under our advertised MAX_TABLE_CAPACITY=0.
            if (id == Http3SettingId.MAX_FIELD_SECTION_SIZE) {
                peerMaxFieldSectionSize = value;
            }
        }
    }

    private static Http3ConnectionException duplicateStream(String kind, long streamId) {
        return new Http3ConnectionException(
            Http3ConnectionException.H3_STREAM_CREATION_ERROR,
            "second peer " + kind + " stream " + streamId);
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
        int sz = Http3Varint.size(type);
        ByteBuffer bb = ByteBuffer.allocate(sz);
        Http3Varint.encode(bb, type);
        bb.flip();
        return writeAll(streamId, bb, false);
    }

    /**
     * Try to send the buffer's bytes on {@code streamId}. Whatever flow
     * control doesn't accept now is copied out of the (reused) buffer and
     * enqueued in {@link #pendingByStream} for later resumption by
     * {@link #drainPendingWrites}. FIN is only
     * applied on the terminal call that consumes the last byte — matches
     * RFC 9000 §4.5 semantics; earlier partials must use fin=false so a
     * short-write doesn't strand the FIN signal.
     *
     * @return true when every byte was either sent or queued behind
     *   earlier deferred bytes; false when the stream can't take them
     *   (reset, stopped, stream limit).
     */
    private boolean writeAll(long streamId, ByteBuffer buf, boolean fin) {
        int remaining = buf.remaining();
        if (buf.hasArray()) {
            byte[] bytes = buf.array();
            int off = buf.arrayOffset() + buf.position();
            buf.position(buf.limit());
            return writeBytes(streamId, bytes, off, remaining, fin, true);
        }
        byte[] bytes = new byte[remaining];
        buf.get(bytes);
        return writeBytes(streamId, bytes, 0, remaining, fin, false);
    }

    /**
     * {@link #writeAll} over {@code bytes[off, off+len)}. {@code scratch}
     * says the caller reuses the array: deferred bytes are then copied;
     * otherwise (an owned response body) the deferral references it.
     * quiche's stream_send clamps to flow-control credit (DONE when none)
     * and creates our own uni streams on first use, so no separate
     * capacity check is needed.
     */
    private boolean writeBytes(long streamId, byte[] bytes, int off, int len,
                               boolean fin, boolean scratch) {
        // If a prior write to this stream already deferred bytes into
        // pendingByStream, we MUST enqueue behind them — a fresh
        // stream_send here would reach the peer BEFORE the earlier
        // deferred bytes, reordering HEADERS vs DATA (task #131's shape
        // extended to multi-frame streaming responses).
        java.util.Deque<Pending> q = pendingByStream.get(streamId);
        if (q != null && !q.isEmpty()) {
            defer(streamId, bytes, off, len, fin, scratch);
            return true;
        }
        long rc = Quiche.connStreamSend(conn, streamId, bytes, off, len, fin);
        // DONE = no flow-control credit; defer the whole payload.
        if (rc == Quiche.QUICHE_ERR_DONE) rc = 0;
        if (rc < 0) {
            // Peer reset (STREAM_STOPPED/RESET) is benign; other codes
            // (FINAL_SIZE, INVALID_STREAM_STATE) indicate a bug on our
            // side and must surface. Drop deferred state either way.
            Level lvl = (rc == Quiche.QUICHE_ERR_STREAM_STOPPED
                         || rc == Quiche.QUICHE_ERR_STREAM_RESET)
                        ? Level.FINE : Level.WARNING;
            LOG.log(lvl, "h3 stream_send stream=" + streamId + " rc=" + rc);
            pendingByStream.remove(streamId);
            return false;
        }
        // quiche applies FIN only when it took every byte.
        if (rc == len) return true;
        // Partial: enqueue what wasn't sent (may be entire chunk on rc==0,
        // or leftover past what capacity accepted).
        int written = (int) rc;
        defer(streamId, bytes, off + written, len - written, fin, scratch);
        return true;
    }

    private void defer(long streamId, byte[] bytes, int off, int len,
                       boolean fin, boolean scratch) {
        if (scratch) {
            byte[] own = new byte[len];
            System.arraycopy(bytes, off, own, 0, len);
            enqueuePending(streamId, new Pending(own, 0, len, fin));
        } else {
            enqueuePending(streamId, new Pending(bytes, off, len, fin));
        }
    }

    private void enqueuePending(long streamId, Pending p) {
        // Init cap 2 — most streams only defer 1-2 items when flow
        // control blocks. ArrayDeque default is 16 which allocates a
        // ~128-byte Object[] per new stream (task #144).
        java.util.Deque<Pending> q = pendingByStream.get(streamId);
        if (q == null) {
            q = new java.util.ArrayDeque<>(2);
            pendingByStream.put(streamId, q);
        }
        q.addLast(p);
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
        pendingByStream.forEach(drainPendingStream);
        for (int i = 0; i < pendingRemovalsSize; i++) {
            pendingByStream.remove(pendingRemovals[i]);
        }
    }

    private long[] pendingRemovals = new long[8];
    private int pendingRemovalsSize;

    // Allocated once rather than as a capturing lambda on every
    // drainPendingWrites call.
    private final Long2ObjectHashMap.EntryConsumer<java.util.Deque<Pending>> drainPendingStream =
        this::drainPending;

    /** Retry one stream's deferred writes, recording it once drained. */
    private void drainPending(long streamId, java.util.Deque<Pending> q) {
        while (!q.isEmpty()) {
            Pending p = q.peekFirst();
            // quiche clamps to credit and applies FIN only when every
            // byte is taken.
            long rc = Quiche.connStreamSend(
                conn, streamId, p.buf, p.off, p.len, p.fin);
            if (rc == Quiche.QUICHE_ERR_DONE) break;
            if (rc < 0) {
                if (rc != Quiche.QUICHE_ERR_STREAM_STOPPED
                    && rc != Quiche.QUICHE_ERR_STREAM_RESET) {
                    LOG.warning("h3 pending stream_send stream="
                        + streamId + " rc=" + rc);
                }
                q.clear();
                break;
            }
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
    }

    /** Per-stream deferred write: what quiche's flow control blocked. */
    private static final class Pending {
        byte[] buf;
        int off;
        int len;
        final boolean fin;
        Pending(byte[] buf, int off, int len, boolean fin) {
            this.buf = buf;
            this.off = off;
            this.len = len;
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
     * True iff {@code streamId} has outbound bytes still queued in
     * {@link #pendingByStream}. Used by the streaming response pump to
     * pause reading until the peer's flow-control window opens.
     */
    public boolean hasPendingWrites(long streamId) {
        java.util.Deque<Pending> q = pendingByStream.get(streamId);
        return q != null && !q.isEmpty();
    }

    /**
     * Drop all session-level state for a stream once both its directions
     * are terminated; without this, per-stream maps accumulate under
     * reset floods (task #140).
     */
    private void forgetStream(long streamId) {
        forgetReadSide(streamId);
        pendingByStream.remove(streamId);
    }

    private void forgetReadSide(long streamId) {
        releaseReader(requestStreams.remove(streamId));
        peerUniTypes.remove(streamId);
        peerUniHeaderBuf.remove(streamId);
    }

    /**
     * Terminate a request stream with {@code errorCode} on both directions
     * (STOP_SENDING + RESET_STREAM), then drop any per-stream state. Used
     * for stream errors (e.g. a body over {@link Config#maxRequestBodyBytes})
     * and by the connection when a streamed response aborts — without the
     * shutdown the peer keeps sending DATA against a stream we already
     * stopped consuming, next of which lands in the "DATA before HEADERS"
     * branch and kills the whole connection.
     */
    public void resetRequestStream(long streamId, long errorCode) {
        resetStream(streamId, errorCode);
        forgetStream(streamId);
    }

    /**
     * Per-request state held on the owner thread. Not thread-safe;
     * owner-only access.
     */
    private static final class RequestStream {
        // Frame-sequence position (RFC 9114 §4.1).
        static final int HEADERS = 0, BODY = 1, TRAILERS = 2;
        final Http3FrameReader reader;
        int phase = HEADERS;
        RequestStream(Http3FrameReader reader) { this.reader = reader; }
    }

    // Reader pool — task #93. Under load a single connection may see
    // many transient request streams; keeping a small deque of reset
    // readers amortises the ~4 KB rolling buffer allocation across
    // successive streams. Cap keeps the pool from growing unboundedly
    // under bursty concurrency.
    private static final int READER_POOL_CAP = 32;
    private final java.util.ArrayDeque<Http3FrameReader> readerPool =
        new java.util.ArrayDeque<>();

    private Http3FrameReader acquireReader() {
        Http3FrameReader r = readerPool.pollFirst();
        if (r != null) return r;
        // The limit counts decoded bytes (name + value + 32 per field). A
        // field line's encoding is shorter than that unless the encoder
        // picks a Huffman code longer than the raw literal (up to 30 bits
        // per octet), which no sensible encoder does; so the same limit
        // bounds the HEADERS frames we buffer, and a longer frame is
        // rejected as oversized.
        return new Http3FrameReader(fieldSectionCap);
    }

    private void releaseReader(RequestStream rs) {
        if (rs == null) return;
        if (readerPool.size() < READER_POOL_CAP) {
            rs.reader.reset();
            readerPool.offerFirst(rs.reader);
        }
    }

    /**
     * Drop a reader without returning it to the pool. Used on error
     * paths that raise {@link Http3ConnectionException}: the reader may
     * hold a partial frame with corrupt pending-length state; pooling
     * risks handing bad state to a future stream. The whole session
     * closes on the exception, so no future request will hit the pool
     * on the SAME connection — but if a stream reset somehow surfaces
     * without connection close, discarding is the safe default.
     */
    private void discardReader(RequestStream rs) {
        // No-op; rs falls out of scope + GC. Named site for future
        // observability. Reader is NOT reset (state may be poisoned).
    }

    /**
     * Callback surface for the Ring bridge. Called on the owner thread
     * while draining a request stream's ingress bytes. A callback may
     * throw {@link Http3StreamException}: the session then resets the
     * stream and calls {@link #onReset}.
     */
    public interface RequestSink {
        void onHeaders(long streamId, List<String[]> headers);
        /** Body bytes from a DATA frame; the body ends at {@link #onFin}. */
        void onData(long streamId, byte[] chunk);
        void onFin(long streamId);
        /** The session reset {@code streamId} with a stream error. */
        void onReset(long streamId);
    }
}

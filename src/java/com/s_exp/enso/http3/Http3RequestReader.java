// ABOUTME: Reads HTTP/3 request streams on the event loop: frames parsed straight from the receive
// ABOUTME: buffer, headers decoded and validated into the Ring request, body bytes into the pipe.
package com.s_exp.enso.http3;

import clojure.lang.IPersistentMap;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.RequestHead;
import com.s_exp.enso.http3.qpack.QpackDecoder;
import com.s_exp.enso.http3.qpack.QpackException;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.util.RingHeaders;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Request-stream input of one connection (RFC 9114 §4.1: HEADERS, DATA*,
 * optional trailing HEADERS), event loop only.
 *
 * <p>Each {@code quiche_conn_stream_recv} lands in the loop's receive
 * buffer and frames are parsed in place: a HEADERS frame that arrived
 * whole is decoded right there; one split across reads is gathered in a
 * buffer counted against the connection's header budget (a peer opening
 * many streams with partial header sections gets H3_REQUEST_REJECTED once
 * the budget is spent, and {@code :header-timeout} bounds how long one may
 * linger); DATA payload is copied once, into the request's body pipe. A
 * request whose HEADERS frame ends the stream gets an empty body and no
 * pipe.
 *
 * <p>Limits, as on the other protocols: a decoded field section over
 * {@code :max-header-bytes} (SETTINGS_MAX_FIELD_SECTION_SIZE) or with more
 * than {@code :max-header-fields} fields is answered 431; one over the
 * hard ceiling (4x, at least 64 KiB) is a stream error, never buffered. A
 * declared body over {@code :max-request-body-bytes} gets 413 without the
 * handler; a body that grows past it fails the handler's reads with a 413.
 *
 * <p>Errors: {@link Http3StreamException} resets just the stream,
 * {@link Http3ConnectionException} closes the connection.
 */
final class Http3RequestReader implements QpackDecoder.FieldSink {

    private static final Logger LOG = Logger.getLogger(Http3RequestReader.class.getName());
    private static final LogLimiter MALFORMED = new LogLimiter(LOG, Level.FINE);
    private static final LogLimiter START_FAILURES = new LogLimiter(LOG, Level.WARNING);

    // Floor of the hard field-section ceiling (4x :max-header-bytes): a
    // section over it is never buffered or decoded (RFC 9114 §4.2.2).
    private static final int HARD_CAP_MIN = 64 * 1024;

    private final Http3Connection conn;
    // :max-header-bytes (431 over it) and the hard ceiling (stream error).
    private final int fieldCap;
    private final int hardCap;
    private final int maxFields;

    // Request being decoded (sink state). kv is the loop's field scratch,
    // borrowed for the decode.
    private RequestHead head;
    private Object[] kv;
    private int kvLen;
    private boolean trailers;
    private long decodedSize;
    private int fieldCount;
    private boolean tooLarge;
    private String expect;

    Http3RequestReader(Http3Connection conn, int fieldCap, int maxFields) {
        this.conn = conn;
        this.fieldCap = fieldCap;
        this.hardCap = hardCap(fieldCap);
        this.maxFields = maxFields;
    }

    /** The hard field-section ceiling for {@code fieldCap}. */
    static int hardCap(int fieldCap) {
        return (int) Math.min(Integer.MAX_VALUE, Math.max(4L * fieldCap, HARD_CAP_MIN));
    }

    // ---- stream reads ----------------------------------------------------------

    /** Reads every stream quiche reports readable since the last call. */
    void readStreams(long now) {
        long sid;
        while (!conn.closing() && (sid = conn.quiche.readableNext()) >= 0) {
            try {
                if ((sid & 0x3) == 0) {
                    readRequest(sid, now);
                } else if ((sid & 0x3) == 0x2) {
                    readPeerUni(sid);
                }
            } catch (Http3ConnectionException e) {
                conn.closeWithError(e);
            }
        }
    }

    private void readPeerUni(long sid) {
        byte[] buf = conn.loop.recvBuf;
        Http3ControlStreams control = conn.control();
        while (true) {
            long rc = conn.quiche.streamRecv(sid, buf, 0, buf.length);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                control.onPeerReset(sid);
                return;
            }
            int n = (int) (rc >>> 1);
            boolean fin = (rc & 1) != 0;
            control.onPeerData(sid, buf, 0, n, fin);
            if (fin || n < buf.length) return;
        }
    }

    private void readRequest(long sid, long now) {
        Http3Exchange ex = conn.exchanges.get(sid);
        if (ex == null) {
            // A new request stream (they may arrive out of order). Streams
            // already finished are never reported readable again: quiche
            // drops data on a stream whose reading was stopped or reset.
            if (sid > conn.highestRequestStream) conn.highestRequestStream = sid;
            conn.requestStreams++;
            if (conn.draining() && sid >= conn.goawayId) {
                // RFC 9114 §5.2: past our GOAWAY, never processed; the
                // client may retry elsewhere.
                conn.quiche.streamShutdown(sid, Quiche.QUICHE_SHUTDOWN_READ,
                    Http3ConnectionException.H3_REQUEST_REJECTED);
                conn.quiche.streamShutdown(sid, Quiche.QUICHE_SHUTDOWN_WRITE,
                    Http3ConnectionException.H3_REQUEST_REJECTED);
                return;
            }
            ex = new Http3Exchange(conn, sid);
            ex.firstByteNanos = now;
            conn.addExchange(ex);
            conn.headerPhaseStarted(ex);
        }
        read(ex, now);
    }

    /** The handler drained the body pipe: reads resume. */
    void resume(Http3Exchange ex, long now) {
        if (!ex.readPaused) return;
        ex.readPaused = false;
        if (ex.readPhase == Http3Exchange.READ_HEADERS) {
            // :header-timeout ignores the time we didn't read it.
            ex.firstByteNanos = now;
            conn.headerPhaseStarted(ex);
        }
        try {
            read(ex, now);
        } catch (Http3ConnectionException e) {
            conn.closeWithError(e);
        }
    }

    private void read(Http3Exchange ex, long now) {
        byte[] buf = conn.loop.recvBuf;
        while (!ex.finished && !conn.closing() && ex.readPhase != Http3Exchange.READ_DONE) {
            Http3BodyPipe pipe = ex.pipe;
            int len = buf.length;
            if (pipe != null) {
                if (pipe.rejected()) {
                    // Over :max-request-body-bytes: the rest stays in quiche
                    // (flow control stalls the peer) until the 413 is sent,
                    // which stops the stream's input.
                    return;
                }
                int room = pipe.room();
                if (room == 0) {
                    // Body backpressure: leave the bytes in quiche (flow
                    // control stalls the peer) until the handler reads (or
                    // the connection's other bodies do); that wakes us.
                    ex.readPaused = true;
                    pipe.resumeWhenDrained(ex.resumeTask());
                    return;
                }
                // Never more than the pipes may hold: the bound is exact.
                len = Math.min(len, room);
            } else if (ex.readPhase == Http3Exchange.READ_HEADERS && conn.bodyBudgetUsed()) {
                // Body bytes may follow the HEADERS frame in this read and
                // land in the pipe it creates: never more than the
                // connection's pipes may still take.
                long connRoom = conn.bodyBudget().limit() - conn.bodyBudget().used();
                if (connRoom <= 0) {
                    ex.readPaused = true;
                    if (conn.bodyBudget().await(ex.budgetWaiter())) return;
                    // Below the low-water mark already: read on.
                    ex.readPaused = false;
                    continue;
                }
                len = (int) Math.min(len, connRoom);
            }
            long rc = conn.quiche.streamRecv(ex.id, buf, 0, len);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                peerReset(ex, now);
                return;
            }
            int n = (int) (rc >>> 1);
            boolean fin = (rc & 1) != 0;
            try {
                consume(ex, buf, 0, n, fin, now);
            } catch (Http3StreamException e) {
                MALFORMED.log("h3 stream " + ex.id + " reset 0x" + Long.toHexString(e.errorCode()) + ": "
                    + e.getMessage());
                if (e.errorCode() == Http3ConnectionException.H3_MESSAGE_ERROR) {
                    conn.listener.protocolError("bad-request");
                }
                conn.resetStream(ex, e.errorCode(), now);
                return;
            }
            if (fin || n < len) return;
        }
    }

    /**
     * The peer reset its sending side. Before the request was complete
     * nothing more can come: our side is reset with H3_REQUEST_INCOMPLETE
     * so the stream (and the peer's stream credit) is released. After,
     * the body is truncated but the response is still sent (RFC 9000
     * §3.2), unless the peer also stopped it.
     */
    private void peerReset(Http3Exchange ex, long now) {
        if (!conn.peerReset()) return;
        if (ex.request == null && ex.fixedStatus == 0) {
            conn.quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_WRITE,
                Http3ConnectionException.H3_REQUEST_INCOMPLETE);
            ex.sendClosed = true;
            conn.readDone(ex);
            conn.finish(ex, now);
            return;
        }
        conn.readDone(ex);
        if (ex.pipe != null) ex.pipe.signalTruncated();
        if (conn.quiche.streamCapacity(ex.id) < 0) {
            // STOP_SENDING too: the request is cancelled (RFC 9114 §4.1.1).
            ex.sendClosed = true;
            conn.discardPending(ex);
            ex.abandon();
            conn.finish(ex, now);
            return;
        }
        conn.maybeFinish(ex, now);
    }

    // ---- frame parsing -------------------------------------------------------------

    /** Parses {@code b[off, off + len)} of {@code ex}'s stream; {@code fin}: the stream ends after it. */
    private void consume(Http3Exchange ex, byte[] b, int off, int len, boolean fin, long now) {
        int pos = off;
        int end = off + len;
        while (pos < end && !ex.finished && ex.readPhase != Http3Exchange.READ_DONE) {
            if (ex.frameType < 0) {
                pos = readFrameHeader(ex, b, pos, end);
                if (ex.frameType < 0) break;
                startFrame(ex);
                if (ex.frameRemaining == 0) {
                    if (ex.frameType == Http3FrameType.HEADERS) {
                        endFrame(ex, b, pos, 0, fin && pos == end, now);
                    } else {
                        ex.frameType = -1;
                        ex.skipping = false;
                    }
                    continue;
                }
            }
            int avail = (int) Math.min(ex.frameRemaining, end - pos);
            boolean last = avail == ex.frameRemaining;
            if (ex.frameType == Http3FrameType.DATA) {
                body(ex, b, pos, avail);
                ex.frameRemaining -= avail;
                pos += avail;
                if (last) ex.frameType = -1;
            } else if (ex.skipping) {
                ex.frameRemaining -= avail;
                pos += avail;
                if (last) {
                    ex.frameType = -1;
                    ex.skipping = false;
                }
            } else if (ex.fieldLen == 0 && last) {
                // HEADERS arrived whole: decode in place.
                ex.frameRemaining = 0;
                pos += avail;
                endFrame(ex, b, pos - avail, avail, fin && pos == end, now);
            } else {
                gather(ex, b, pos, avail);
                ex.frameRemaining -= avail;
                pos += avail;
                if (last) endFrame(ex, ex.fieldBuf, 0, ex.fieldLen, fin && pos == end, now);
            }
        }
        if (fin && !ex.finished && ex.readPhase != Http3Exchange.READ_DONE) onFin(ex, now);
    }

    /** Reads a frame header (type and length varints), possibly across reads; returns the new position. */
    private static int readFrameHeader(Http3Exchange ex, byte[] b, int pos, int end) {
        if (ex.frameHeadLen == 0) {
            // Whole header in this read: parsed in place.
            int typeLen = Http3Varint.length(b[pos]);
            if (pos + typeLen < end) {
                int lenLen = Http3Varint.length(b[pos + typeLen]);
                if (pos + typeLen + lenLen <= end) {
                    ex.frameType = Http3Varint.decode(b, pos);
                    ex.frameRemaining = Http3Varint.decode(b, pos + typeLen);
                    return pos + typeLen + lenLen;
                }
            }
        }
        byte[] h = ex.frameHead;
        if (h == null) {
            h = new byte[16];
            ex.frameHead = h;
        }
        while (pos < end) {
            h[ex.frameHeadLen++] = b[pos++];
            int typeLen = Http3Varint.length(h[0]);
            if (ex.frameHeadLen < typeLen + 1) continue;
            int lenLen = Http3Varint.length(h[typeLen]);
            if (ex.frameHeadLen < typeLen + lenLen) continue;
            ex.frameType = Http3Varint.decode(h, 0);
            ex.frameRemaining = Http3Varint.decode(h, typeLen);
            ex.frameHeadLen = 0;
            return pos;
        }
        return pos;
    }

    /** Checks a new frame against the stream's phase (RFC 9114 §4.1, §7.2). */
    private void startFrame(Http3Exchange ex) {
        long type = ex.frameType;
        if (type == Http3FrameType.SETTINGS || type == Http3FrameType.GOAWAY
                || type == Http3FrameType.MAX_PUSH_ID || type == Http3FrameType.CANCEL_PUSH
                || type == Http3FrameType.PUSH_PROMISE || Http3FrameType.isReservedHttp2(type)) {
            // §7.2: control-only (and HTTP/2-only) frames on a request
            // stream are a connection error.
            throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_UNEXPECTED,
                "frame type 0x" + Long.toHexString(type) + " forbidden on request stream " + ex.id);
        }
        if (type == Http3FrameType.DATA) {
            if (ex.readPhase != Http3Exchange.READ_BODY) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    (ex.readPhase == Http3Exchange.READ_HEADERS ? "DATA before HEADERS" : "DATA after trailers")
                        + " on request stream " + ex.id);
            }
            return;
        }
        if (type == Http3FrameType.HEADERS) {
            if (ex.readPhase == Http3Exchange.READ_TRAILERS) {
                throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "HEADERS after trailers on request stream " + ex.id);
            }
            // The limit counts decoded bytes (name + value + 32 per field);
            // an encoding is shorter unless Huffman is misused, so it also
            // bounds the frames we gather (RFC 9114 §4.2.2: a stream error).
            if (ex.frameRemaining > hardCap) {
                throw new Http3StreamException(Http3ConnectionException.H3_EXCESSIVE_LOAD,
                    "HEADERS exceeds field section ceiling " + hardCap);
            }
            return;
        }
        // Unknown and reserved types are skipped (§7.2.8, §9).
        ex.skipping = true;
    }

    private void gather(Http3Exchange ex, byte[] b, int off, int len) {
        if (conn.bufferedHeaderBytes + len > conn.headerBudget) {
            throw new Http3StreamException(Http3ConnectionException.H3_REQUEST_REJECTED,
                "connection header budget " + conn.headerBudget + " exhausted");
        }
        int need = ex.fieldLen + len;
        byte[] fb = ex.fieldBuf;
        if (fb == null || fb.length < need) {
            byte[] bigger = need <= Http3Loop.POOLED_FIELD_BUF ? conn.loop.takeFieldBuf() : null;
            if (bigger == null || bigger.length < need) {
                bigger = new byte[Math.max(need, Math.min(hardCap, Math.max(1024, 2 * need)))];
            }
            if (fb != null) {
                System.arraycopy(fb, 0, bigger, 0, ex.fieldLen);
                conn.loop.giveFieldBuf(fb);
            }
            ex.fieldBuf = bigger;
        }
        System.arraycopy(b, off, ex.fieldBuf, ex.fieldLen, len);
        ex.fieldLen += len;
        conn.bufferedHeaderBytes += len;
    }

    /** Releases an exchange's header gathering state (on finish). */
    void release(Http3Exchange ex) {
        conn.bufferedHeaderBytes -= ex.fieldLen;
        ex.fieldLen = 0;
        if (ex.fieldBuf != null) {
            conn.loop.giveFieldBuf(ex.fieldBuf);
            ex.fieldBuf = null;
        }
    }

    /** A HEADERS frame completed: {@code b[off, off + len)} is its field section. */
    private void endFrame(Http3Exchange ex, byte[] b, int off, int len, boolean endsStream, long now) {
        ex.frameType = -1;
        ex.skipping = false;
        try {
            if (ex.readPhase == Http3Exchange.READ_HEADERS) {
                ex.readPhase = Http3Exchange.READ_BODY;
                dispatch(ex, b, off, len, endsStream, now);
            } else {
                ex.readPhase = Http3Exchange.READ_TRAILERS;
                trailers(ex, b, off, len);
            }
        } finally {
            if (b == ex.fieldBuf) release(ex);
        }
    }

    private void body(Http3Exchange ex, byte[] b, int off, int len) {
        Http3BodyPipe pipe = ex.pipe;
        // No pipe: the request's body isn't consumed (a 501 answered without
        // a handler, or the response already went out).
        if (pipe == null || len == 0) return;
        conn.bodyBytesRead += len;
        int r = pipe.offer(b, off, len);
        if (r == Http3BodyPipe.OVER_DECLARED_LENGTH) {
            throw malformed(ex, "body longer than content-length");
        }
        // OVER_CAP: the pipe now fails the handler's reads with a 413 (the
        // exchange answers it) and reading this stream stops.
    }

    private void onFin(Http3Exchange ex, long now) {
        // RFC 9114 §7.1: a stream must not end mid-frame.
        if (ex.frameType >= 0 || ex.frameHeadLen > 0) {
            throw new Http3ConnectionException(Http3ConnectionException.H3_FRAME_ERROR,
                "stream " + ex.id + " terminated mid-frame");
        }
        if (ex.readPhase == Http3Exchange.READ_HEADERS) {
            // RFC 9114 §4.1.2: the stream ended without a request. Our side
            // is reset so the stream (and the peer's credit) is released.
            conn.quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_WRITE,
                Http3ConnectionException.H3_REQUEST_INCOMPLETE);
            ex.sendClosed = true;
            conn.readDone(ex);
            conn.finish(ex, now);
            return;
        }
        Http3BodyPipe pipe = ex.pipe;
        if (pipe != null) {
            if (!pipe.matchesDeclaredLength()) throw malformed(ex, "body shorter than content-length");
            pipe.signalEnd();
        }
        conn.readDone(ex);
        conn.maybeFinish(ex, now);
    }

    // ---- header sections ----------------------------------------------------------------

    @Override
    public void field(String name, String value) {
        if (trailers) {
            // RFC 9114 §4.1.2 / §4.3: no pseudo-headers, valid names and values.
            if (!Http3RequestReader.validName(name) || !RequestHead.isFieldValue(value)) {
                throw new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
                    "invalid trailer field '" + name + "'");
            }
            return;
        }
        if (tooLarge) return;
        decodedSize += name.length() + value.length() + 32L;
        if (decodedSize > fieldCap
                || ((name.isEmpty() || name.charAt(0) != ':') && ++fieldCount > maxFields)) {
            // Answered 431 once the section is decoded.
            tooLarge = true;
            return;
        }
        int kind = head.add(name, value);
        if (kind == RequestHead.MALFORMED) {
            throw new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
                "malformed request: " + head.failure());
        }
        if (kind == RequestHead.FIELD) {
            if (name.length() == 6 && name.equals("expect")) expect = value;
            // Room for "host" and one spare slot: the merged array must
            // never be this scratch itself.
            if (kvLen + 4 >= kv.length) {
                kv = java.util.Arrays.copyOf(kv, kv.length * 2);
                conn.loop.fields = kv;
            }
            kv[kvLen++] = name;
            kv[kvLen++] = value;
        }
    }

    static boolean validName(String s) {
        return com.s_exp.enso.core.HttpFields.isLowercaseToken(s, 0);
    }

    private void decode(Http3Exchange ex, byte[] b, int off, int len) {
        try {
            conn.loop.qpack.decode(b, off, len, hardCap, this);
        } catch (QpackException qe) {
            if (qe.isStreamLevel()) {
                throw new Http3StreamException(qe.errorCode(), qe.getMessage());
            }
            // RFC 9204 §2.2: a decoding failure on a request stream is a
            // connection error with the QPACK code (h3spec 16).
            throw new Http3ConnectionException(qe.errorCode(),
                "QPACK decode failed on stream " + ex.id + ": " + qe.getMessage());
        }
    }

    private void trailers(Http3Exchange ex, byte[] b, int off, int len) {
        trailers = true;
        try {
            decode(ex, b, off, len);
        } finally {
            trailers = false;
        }
        // Validated, then dropped: Ring has no trailer surface.
    }

    /**
     * Decodes and validates a request head and starts its handler
     * ({@code endsStream}: the stream ended with it, so no body).
     */
    private void dispatch(Http3Exchange ex, byte[] b, int off, int len, boolean endsStream, long now) {
        if (conn.liveHandlers.get() >= conn.maxLiveHandlers) {
            // Abandoned handlers that ignore interrupts must not pile up.
            throw new Http3StreamException(Http3ConnectionException.H3_REQUEST_REJECTED,
                "too many running handlers on stream " + ex.id);
        }
        RequestHead rh = conn.loop.requestHead;
        rh.reset();
        head = rh;
        kv = conn.loop.fields;
        kvLen = 0;
        try {
            decodeAndStart(ex, rh, b, off, len, endsStream, now);
        } finally {
            java.util.Arrays.fill(kv, 0, kvLen, null);
            kv = null;
        }
    }

    private void decodeAndStart(Http3Exchange ex, RequestHead rh, byte[] b, int off, int len,
                                boolean endsStream, long now) {
        decodedSize = 0;
        fieldCount = 0;
        tooLarge = false;
        expect = null;
        decode(ex, b, off, len);
        if (tooLarge) {
            conn.listener.protocolError("header-too-large");
            respondEarly(ex, 431, now);
            return;
        }
        int verdict = rh.finish();
        if (verdict == RequestHead.MALFORMED) throw malformed(ex, rh.failure());
        if (verdict == RequestHead.NOT_IMPLEMENTED) {
            // A well-formed CONNECT: tunnels aren't served.
            respondEarly(ex, 501, now);
            return;
        }
        String path = rh.path();
        // RFC 3986: a request target is ASCII.
        for (int i = 0, n = path.length(); i < n; i++) {
            if (path.charAt(i) > 0x7E) throw malformed(ex, "non-ASCII :path");
        }
        long contentLength = rh.contentLength();
        if (endsStream && contentLength > 0) throw malformed(ex, "body shorter than content-length");
        long maxBody = conn.config.maxRequestBodyBytes;
        if (maxBody > 0 && contentLength > maxBody) {
            // Answered without running the handler, as on HTTP/1.1 and h2.
            conn.listener.protocolError("body-too-large");
            respondEarly(ex, 413, now);
            return;
        }
        boolean continuePending = false;
        if (expect != null) {
            // RFC 9110 §10.1.1, as on HTTP/1.1: 100-continue is answered on
            // the body's first read, anything else gets 417.
            if (!expect.equalsIgnoreCase("100-continue")) {
                conn.listener.protocolError("bad-request");
                respondEarly(ex, 417, now);
                return;
            }
            continuePending = !endsStream;
        }
        kv[kvLen++] = "host";
        kv[kvLen++] = rh.authority();
        // Repeated fields combine per RFC 9110 §5.3 ("; " for cookie).
        Object[] fields = RingHeaders.mergeDuplicates(kv, kvLen);
        IPersistentMap headers = RingHeaders.toMap(fields);
        // Ring: :body is present only when the request has one.
        java.io.InputStream body = null;
        if (!endsStream) {
            ex.pipe = new Http3BodyPipe(maxBody, contentLength, conn.config.readTimeoutMillis,
                conn.config.minDataRateBytes, conn.config.minDataRateGraceMillis,
                conn.account(), conn.bodyBudget());
            conn.bodyStarted(ex);
            body = continuePending ? new ContinueOnRead(ex, ex.pipe.inputStream()) : ex.pipe.inputStream();
            ex.continuePending = continuePending;
        }
        String method = rh.method();
        ex.headRequest = "HEAD".equals(method);
        ex.request = new Request(method, rh.uri(), rh.query(), "HTTP/3.0", headers, body, conn.remote,
            conn.listener.port(), Request.K_HTTPS);
        ex.begin();
        if (conn.config.handlerTimeoutMillis > 0) {
            ex.timed = true;
            conn.listener.timer.schedule(ex, conn.config.handlerTimeoutMillis);
        }
        Thread t = conn.listener.handlerThreads.newThread(ex);
        // Published before start, so an abandon right after can interrupt it.
        ex.handlerThread = t;
        conn.liveHandlers.incrementAndGet();
        try {
            t.start();
        } catch (Throwable e) {
            // Never started, so never finishing: uncounted here, else the
            // connection's slot would wait for it forever.
            conn.handlerFinished(ex);
            if (e instanceof VirtualMachineError vme) throw vme;
            START_FAILURES.log("h3 handler thread failed to start, sending 503", e);
            respondEarly(ex, 503, now);
            return;
        }
        conn.handlerDispatched(now);
    }

    /** Answers {@code status} without a handler (413, 417, 431, 501). */
    private void respondEarly(Http3Exchange ex, int status, long now) {
        ex.claim(Exchange.HANDLER);
        ex.fixedStatus = status;
        conn.writer.respond(ex, now);
    }

    /**
     * The body of an Expect: 100-continue request: the first read asks the
     * loop for the 100 (Continue) before waiting for bytes (RFC 9114 §4.1).
     */
    private static final class ContinueOnRead extends java.io.InputStream {
        private final Http3Exchange ex;
        private final java.io.InputStream in;

        ContinueOnRead(Http3Exchange ex, java.io.InputStream in) {
            this.ex = ex;
            this.in = in;
        }

        @Override
        public int read() throws java.io.IOException {
            ex.bodyReadStarted();
            return in.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws java.io.IOException {
            if (len > 0) ex.bodyReadStarted();
            return in.read(b, off, len);
        }

        @Override
        public int available() throws java.io.IOException {
            return in.available();
        }

        @Override
        public void close() throws java.io.IOException {
            in.close();
        }
    }

    private static Http3StreamException malformed(Http3Exchange ex, String why) {
        return new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
            "malformed request on stream " + ex.id + ": " + why);
    }
}

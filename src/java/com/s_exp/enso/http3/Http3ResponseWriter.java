// ABOUTME: Sends HTTP/3 responses on the event loop: QPACK-encodes the prepared ResponseHead into a
// ABOUTME: minimal HEADERS frame, writes bodies inline or by reference, pumps streamed bodies.
package com.s_exp.enso.http3;

import com.s_exp.enso.core.HttpStatus;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.http3.qpack.QpackFieldSection;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Response output of one connection, event loop only.
 *
 * <p>A response's HEADERS frame (minimal-length varints), and for bodies
 * up to {@link #INLINE_BODY_MAX} the DATA frame too, are encoded into the
 * loop's frame buffer and handed to quiche in one {@code stream_send}
 * carrying the FIN. Larger byte bodies follow from the handler's own
 * array, never copied unless flow control defers them. Streamed bodies
 * (File, InputStream, StreamingBody) are pumped slice by slice from the
 * handler's thread ({@link Http3ResponseBody}).
 *
 * <p>Fields come from the handler thread's {@link ResponseHead} (validated
 * there; status 200-599, names lowercase, framing fields dropped); Date
 * is added from a per-second cache, Server from the listener, and
 * content-length whenever the body length is known. Responses the server
 * decides itself (500, 501, 503, 413, 417, 431) are the shared
 * {@link HttpStatus#error} ones, the same on every protocol.
 */
final class Http3ResponseWriter implements Http3ResponseBody.Sender {

    private static final Logger LOG = Logger.getLogger(Http3ResponseWriter.class.getName());
    private static final LogLimiter OVERSIZED = new LogLimiter(LOG, Level.FINE);

    /** Bodies up to this size share the HEADERS frame's stream_send. */
    static final int INLINE_BODY_MAX = 16 * 1024;
    // Room before the field section for the HEADERS type and length varints.
    private static final int HEAD_ROOM = 9;

    // The interim 100 (Continue): a HEADERS frame whose field section
    // holds only :status 100.
    private static final byte[] CONTINUE_100 = continueFrame();

    private final Http3Connection conn;
    // Exchange whose body is being pumped (Sender target).
    private Http3Exchange current;
    private long currentNow;
    private int streaming;

    Http3ResponseWriter(Http3Connection conn) {
        this.conn = conn;
    }

    // ---- responses ------------------------------------------------------------------

    /** The exchange's response is ready (handler, timeout, or a 501 decided here). */
    void respond(Http3Exchange ex, long now) {
        ResponseHead h = ex.head;
        ex.head = null;
        if (ex.responseState != Http3Exchange.RESP_NONE || ex.sendClosed) {
            if (h != null) recycle(h);
            return;
        }
        if (ex.fixedStatus != 0) {
            if (h != null) recycle(h);
            h = conn.heads().acquire();
            h.prepare(HttpStatus.error(ex.fixedStatus), ex.headRequest, ResponseHead.MULTIPLEXED);
        }
        sendHead(ex, h, now);
    }

    /**
     * Sends the 100 (Continue) the handler's first body read asked for
     * (Expect: 100-continue), unless the response already started.
     */
    void sendContinue(Http3Exchange ex, long now) {
        if (ex.responseState != Http3Exchange.RESP_NONE || ex.sendClosed) return;
        conn.responseWritten();
        conn.write(ex, CONTINUE_100, 0, CONTINUE_100.length, false, true, now);
    }

    private static byte[] continueFrame() {
        ByteBuffer f = ByteBuffer.allocate(16);
        f.position(HEAD_ROOM);
        f.put((byte) 0).put((byte) 0);
        QpackFieldSection.encodeStatus(f, 100);
        int start = closeHeadersFrame(f);
        return java.util.Arrays.copyOfRange(f.array(), start, f.position());
    }

    private void sendHead(Http3Exchange ex, ResponseHead h, long now) {
        conn.responseWritten();
        long peerMax = conn.control().peerMaxFieldSectionSize;
        if (peerMax >= 0 && decodedSize(h) > peerMax) {
            // RFC 9114 §4.2.2: a section over the peer's
            // SETTINGS_MAX_FIELD_SECTION_SIZE isn't sent. A 500 instead,
            // or a reset when even that is too large.
            OVERSIZED.log("h3 response field section exceeds the peer's SETTINGS_MAX_FIELD_SECTION_SIZE "
                + peerMax + ", sending 500 stream=" + ex.id);
            Http3ResponseBody body = ex.body;
            if (body != null) {
                ex.body = null;
                body.cancel();
            }
            recycle(h);
            h = conn.heads().acquire();
            h.prepare(HttpStatus.error(500), ex.headRequest, ResponseHead.MULTIPLEXED);
            if (decodedSize(h) > peerMax) {
                recycle(h);
                conn.resetStream(ex, Http3ConnectionException.H3_INTERNAL_ERROR, now);
                return;
            }
        }
        int status = h.status();
        ex.status = status;
        boolean allowed = h.bodyAllowed();
        int kind = h.bodyKind();
        byte[] bytes = null;
        String text = null;
        int length = 0;
        if (allowed && kind == ResponseHead.BODY_BYTES) {
            bytes = h.bytes();
            length = bytes.length;
        } else if (allowed && kind == ResponseHead.BODY_ASCII) {
            text = h.text();
            length = text.length();
        }
        boolean inline = length <= INLINE_BODY_MAX;
        Http3Loop loop = conn.loop;
        // The shared policy decides (Service); the loop and the listener
        // hold the encoded field lines. No Alt-Svc on HTTP/3 itself.
        byte[] date = Service.addsDate(h) ? loop.dateField() : null;
        byte[] server = conn.listener.service.serverField(h) != null ? conn.listener.serverField : null;
        int n = h.fieldCount();
        int need = HEAD_ROOM + 2 + 5 + 32 + 16 + (date == null ? 0 : date.length)
            + (server == null ? 0 : server.length) + (inline ? length : 0);
        for (int i = 0; i < n; i++) {
            Object v = h.value(i);
            need += 12 + h.name(i).length() + (v instanceof String s ? s.length() : 20);
        }
        ByteBuffer f = loop.frame(need);
        f.position(HEAD_ROOM);
        f.put((byte) 0).put((byte) 0);
        QpackFieldSection.encodeStatus(f, status);
        for (int i = 0; i < n; i++) {
            Object v = h.value(i);
            if (v instanceof String s) {
                QpackFieldSection.encodeField(f, h.name(i), s);
            } else if (((Number) v).longValue() >= 0) {
                QpackFieldSection.encodeDecimal(f, h.name(i), ((Number) v).longValue());
            } else {
                QpackFieldSection.encodeField(f, h.name(i), h.valueString(i));
            }
        }
        if (date != null) f.put(date);
        if (server != null) f.put(server);
        long contentLength = h.contentLength();
        if (contentLength >= 0) QpackFieldSection.encodeDecimal(f, "content-length", contentLength);
        int start = closeHeadersFrame(f);
        Http3ResponseBody body = ex.body;
        if (body != null) {
            recycle(h);
            ex.responseState = Http3Exchange.RESP_STREAMING;
            streaming++;
            if (!conn.write(ex, f.array(), start, f.position() - start, false, true, now)) {
                aborted(ex, now);
                return;
            }
            pumpBody(ex, now);
            return;
        }
        if (length == 0) {
            recycle(h);
            finishResponse(ex, f, start, 0, now);
            return;
        }
        if (inline) {
            if (bytes != null) {
                appendData(f, bytes, 0, length);
            } else {
                appendAscii(f, text);
            }
            recycle(h);
            finishResponse(ex, f, start, length, now);
            return;
        }
        // Large body: HEADERS + DATA header from the frame buffer, payload
        // straight from the body array (FIN with it); ASCII text in slices
        // through the frame buffer (copied only where quiche defers them).
        recycle(h);
        int at = f.position();
        at = Http3Varint.encode(f.array(), at, Http3FrameType.DATA);
        at = Http3Varint.encode(f.array(), at, length);
        f.position(at);
        ex.responseState = Http3Exchange.RESP_SENT;
        ex.responseBytes = length;
        if (conn.write(ex, f.array(), start, at - start, false, true, now)) {
            if (bytes != null) {
                conn.write(ex, bytes, 0, length, true, false, now);
            } else {
                writeAscii(ex, text, f.array(), now);
            }
        }
        afterResponse(ex, now);
    }

    /** Writes {@code text} (one byte per char) through {@code scratch}, the last slice with the FIN. */
    private void writeAscii(Http3Exchange ex, String text, byte[] scratch, long now) {
        int len = text.length();
        for (int pos = 0; pos < len; ) {
            int n = Math.min(scratch.length, len - pos);
            for (int i = 0; i < n; i++) scratch[i] = (byte) text.charAt(pos + i);
            pos += n;
            if (!conn.write(ex, scratch, 0, n, pos == len, true, now)) return;
        }
    }

    /**
     * The decoded size of the field section {@link #sendHead} sends for
     * {@code h}, as RFC 9114 §4.2.2 counts it (name + value + 32 per field).
     */
    private long decodedSize(ResponseHead h) {
        long size = 7 + 3 + 32; // :status
        if (Service.addsDate(h)) size += 4 + 29 + 32;
        String server = conn.listener.service.serverField(h);
        if (server != null && conn.listener.serverField != null) size += 6 + server.length() + 32;
        for (int i = 0, n = h.fieldCount(); i < n; i++) {
            Object v = h.value(i);
            int vlen = v instanceof String s ? s.length() : decimalLength(((Number) v).longValue());
            size += h.name(i).length() + vlen + 32;
        }
        long contentLength = h.contentLength();
        if (contentLength >= 0) size += 14 + decimalLength(contentLength) + 32;
        return size;
    }

    private static int decimalLength(long v) {
        int n = v < 0 ? 2 : 1;
        for (long a = Math.abs(v / 10); a > 0; a /= 10) n++;
        return n;
    }

    /**
     * Writes the HEADERS type and the minimal length varint right before the
     * field section encoded at {@link #HEAD_ROOM}; returns the frame start.
     */
    private static int closeHeadersFrame(ByteBuffer f) {
        int payload = f.position() - HEAD_ROOM;
        int start = HEAD_ROOM - 1 - Http3Varint.size(payload);
        byte[] a = f.array();
        a[start] = (byte) Http3FrameType.HEADERS;
        Http3Varint.encode(a, start + 1, payload);
        return start;
    }

    private static void appendData(ByteBuffer f, byte[] b, int off, int len) {
        int at = Http3Varint.encode(f.array(), f.position(), Http3FrameType.DATA);
        at = Http3Varint.encode(f.array(), at, len);
        f.position(at);
        f.put(b, off, len);
    }

    private static void appendAscii(ByteBuffer f, String text) {
        int len = text.length();
        byte[] a = f.array();
        int at = Http3Varint.encode(a, f.position(), Http3FrameType.DATA);
        at = Http3Varint.encode(a, at, len);
        for (int i = 0; i < len; i++) a[at + i] = (byte) text.charAt(i);
        f.position(at + len);
    }

    /** One stream_send for the whole response (HEADERS and inline DATA) with FIN. */
    private void finishResponse(Http3Exchange ex, ByteBuffer f, int start, int bodyLength, long now) {
        ex.responseState = Http3Exchange.RESP_SENT;
        ex.responseBytes = bodyLength;
        conn.write(ex, f.array(), start, f.position() - start, true, true, now);
        afterResponse(ex, now);
    }

    /**
     * The whole response was handed over. A request still arriving isn't
     * needed any more: RFC 9114 §4.1.2 says to stop reading it with
     * STOP_SENDING(H3_NO_ERROR); its handler (if still reading) sees a
     * truncated body.
     */
    private void afterResponse(Http3Exchange ex, long now) {
        if (ex.readPhase != Http3Exchange.READ_DONE) {
            conn.quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_READ, Http3ConnectionException.H3_NO_ERROR);
            ex.readPhase = Http3Exchange.READ_DONE;
            if (ex.pipe != null) ex.pipe.signalTruncated();
        }
        conn.maybeFinish(ex, now);
    }

    private void recycle(ResponseHead h) {
        h.release();
        conn.heads().release(h);
    }

    // ---- streamed bodies ---------------------------------------------------------------

    /** The producer offered a slice, finished or failed. */
    void pumpBody(Http3Exchange ex, long now) {
        Http3ResponseBody body = ex.body;
        if (body == null || ex.responseState != Http3Exchange.RESP_STREAMING || ex.finished) return;
        // HEADERS (or an earlier frame header) still waiting: stream order.
        if (ex.hasPending()) return;
        current = ex;
        currentNow = now;
        int st;
        try {
            st = body.pump(this);
        } finally {
            current = null;
        }
        conn.bodyHeld(body, body.held());
        switch (st) {
            case Http3ResponseBody.SENDING -> conn.markBlocked(ex, now);
            case Http3ResponseBody.COMPLETE -> {
                conn.unmarkBlocked(ex);
                ex.sendClosed = true;
                ex.responseState = Http3Exchange.RESP_SENT;
                streaming--;
                afterResponse(ex, now);
            }
            case Http3ResponseBody.ABORTED -> aborted(ex, now);
            default -> conn.unmarkBlocked(ex);
        }
    }

    /** A streamed body failed or its stream died: a reset, never a clean FIN. */
    private void aborted(Http3Exchange ex, long now) {
        if (ex.responseState == Http3Exchange.RESP_STREAMING) streaming--;
        ex.responseState = Http3Exchange.RESP_SENT;
        conn.resetStream(ex, Http3ConnectionException.H3_INTERNAL_ERROR, now);
    }

    @Override
    public int send(byte[] b, int off, int len, boolean fin) {
        Http3Exchange ex = current;
        long rc = conn.quiche.streamSend(ex.id, b, off, len, fin);
        if (rc == Quiche.QUICHE_ERR_DONE) return 0;
        if (rc < 0) return -1;
        if (rc > 0) {
            long before = ex.responseBytes;
            ex.responseBytes += rc;
            ex.sent(before, ex.responseBytes, currentNow);
        }
        return (int) rc;
    }

    /** The stream's send capacity grew: deferred bytes first, then the body. */
    void resume(Http3Exchange ex, long now) {
        if (ex.hasPending()) {
            if (!conn.drainPending(ex, now)) {
                // The peer stopped or reset the stream.
                if (ex.responseState == Http3Exchange.RESP_STREAMING) streaming--;
                ex.responseState = Http3Exchange.RESP_SENT;
                ex.abandon();
                conn.finish(ex, now);
                return;
            }
            if (ex.hasPending()) return;
        }
        if (ex.responseState == Http3Exchange.RESP_STREAMING) {
            pumpBody(ex, now);
        } else {
            conn.unmarkBlocked(ex);
            conn.maybeFinish(ex, now);
        }
    }

    /** Streamed responses in progress (for the idle STOP_SENDING check). */
    int idleBodies() {
        return streaming;
    }

    private long stopNow;
    private int stoppedCount;
    private final Long2ObjectHashMap.EntryConsumer<Http3Exchange> stopScan = this::stopScanOne;

    private void stopScanOne(long id, Http3Exchange ex) {
        if (ex.responseState != Http3Exchange.RESP_STREAMING || ex.blocked || ex.hasPending()) return;
        Http3ResponseBody b = ex.body;
        if (b == null || b.hasOffer()) return;
        long[] stopped = conn.loop.scanIds;
        if (stoppedCount < stopped.length && conn.quiche.streamCapacity(id) < 0) stopped[stoppedCount++] = id;
    }

    /**
     * A body whose producer is idle (an event stream waiting for its next
     * event) would only learn of the peer's STOP_SENDING from its next
     * write: ask quiche, at most every few tens of milliseconds.
     */
    void checkStoppedBodies(long now) {
        if (streaming == 0) return;
        stopNow = now;
        stoppedCount = 0;
        conn.exchanges.forEach(stopScan);
        long[] stopped = conn.loop.scanIds;
        for (int i = 0; i < stoppedCount; i++) {
            Http3Exchange ex = conn.exchanges.get(stopped[i]);
            if (ex == null) continue;
            streaming--;
            ex.responseState = Http3Exchange.RESP_SENT;
            ex.sendClosed = true;
            ex.abandon();
            conn.finish(ex, stopNow);
        }
    }

    // ---- teardown -----------------------------------------------------------------------

    /** Events for an exchange that is already done: release what its handler left. */
    void discard(Http3Exchange ex) {
        ResponseHead h = ex.head;
        ex.head = null;
        if (h != null) recycle(h);
        Http3ResponseBody b = ex.body;
        if (b != null) b.cancel();
    }

    private final Long2ObjectHashMap.EntryConsumer<Http3Exchange> abandon = this::abandonOne;

    private void abandonOne(long id, Http3Exchange ex) {
        ex.finished = true;
        conn.discardPending(ex);
        conn.bodyHeld(ex.body, 0);
        ex.abandon();
        if (ex.pipe != null) {
            // Nobody will read what is buffered: its budget goes back now.
            ex.pipe.signalTruncated();
            ex.pipe.discard();
        }
        discard(ex);
    }

    /** The connection is closing: every request is abandoned. */
    void abandonAll(long now) {
        conn.exchanges.forEach(abandon);
        conn.exchanges.clear();
        streaming = 0;
    }

    /** An exchange finished: report it. */
    void completed(Http3Exchange ex) {
        if (ex.responseState == Http3Exchange.RESP_STREAMING) {
            streaming--;
            ex.responseState = Http3Exchange.RESP_SENT;
        }
        if (ex.status == 0) return;
        ex.complete();
    }
}

// ABOUTME: Maps HTTP/2 exchanges to Ring: builds the request from decoded header fields on the
// ABOUTME: framer, serves the stream's Exchange on its thread and frames the response via ResponseHead.
package com.s_exp.enso.http2;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.core.ChunkedWriters;
import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.core.HttpStatus;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.RequestHead;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.util.RingHeaders;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One per connection. The request side runs on the framer thread only
 * (it is the HPACK decoder's {@link Hpack.FieldSink}); the response side
 * on each stream's handler thread. A response with a fixed body (none,
 * bytes, ASCII text) is handed over whole to the writer, which finishes
 * the exchange; streamed bodies are produced by the handler thread.
 */
final class Http2Exchange implements Hpack.FieldSink {

    private static final Logger LOG = Logger.getLogger(Http2Exchange.class.getName());
    private static final LogLimiter INVALID_RESPONSES = new LogLimiter(LOG, Level.WARNING);
    private static final LogLimiter BODY_FAILURES = new LogLimiter(LOG, Level.WARNING);


    private static final int FIELDS_INITIAL = 16;
    private static final int STREAMING_GATHER_BYTES = 512;

    // ResponseHeads shared by every connection: one is in use from a
    // response's preparation until its header block is encoded. A borrow
    // or give-back probes HEAD_POOL_PROBES slots spread over the whole
    // array from a start hashed from the stream (its id and connection):
    // every response runs on a fresh thread, so a start derived from the
    // thread would send heads back to slots the next borrowers never look
    // at, and seeding ThreadLocalRandom costs each fresh thread a shared
    // atomic. A head grown past HEAD_POOL_MAX_FIELDS isn't kept.
    private static final int HEAD_POOL_SLOTS = 256;
    private static final int HEAD_POOL_PROBES = 16;
    private static final int HEAD_POOL_STRIDE = HEAD_POOL_SLOTS / HEAD_POOL_PROBES + 1;
    private static final int HEAD_POOL_MAX_FIELDS = 64;
    private static final AtomicReferenceArray<ResponseHead> HEADS = new AtomicReferenceArray<>(HEAD_POOL_SLOTS);

    private final Http2Connection conn;
    private final RingHandler handler;
    private final Config config;
    private final InetAddress remoteAddress;
    private final int localPort;
    // Ring :scheme of the connection: :https over TLS, :http in cleartext.
    private final clojure.lang.Keyword scheme;

    // ---- Framer side ----
    private final RequestHead requestHead = new RequestHead();
    // Ring header name/value pairs of the request being decoded, plus room
    // for "host". Handed to the request map when it fits exactly.
    private Object[] fields = new Object[FIELDS_INITIAL];
    private int fieldLen;
    private boolean malformed;
    private boolean trailers;
    private boolean malformedTrailers;
    private boolean pseudoInTrailers;
    // Regular fields of the head being decoded, against :max-header-fields.
    private int fieldCount;
    private boolean tooManyFields;
    // The head's Expect value, or null.
    private String expect;

    Http2Exchange(Http2Connection conn, RingHandler handler, Config config, InetAddress remoteAddress,
                  int localPort, clojure.lang.Keyword scheme) {
        this.conn = conn;
        this.scheme = scheme;
        this.handler = handler;
        this.config = config;
        this.remoteAddress = remoteAddress;
        this.localPort = localPort;
    }

    // ---- Request (framer) ------------------------------------------------------------

    /** Framer, connection idle: gives back a field array grown by a large head. */
    void releaseIdle() {
        if (fieldLen == 0 && fields.length > FIELDS_INITIAL) {
            fields = new Object[FIELDS_INITIAL];
        }
    }

    /** The next decoded block is a request head. */
    void beginRequest() {
        requestHead.reset();
        if (fieldLen > 0) {
            // A previous block that didn't become a request.
            java.util.Arrays.fill(fields, 0, fieldLen, null);
        }
        fieldLen = 0;
        malformed = false;
        trailers = false;
        fieldCount = 0;
        tooManyFields = false;
        expect = null;
    }

    /** The Expect field of the head just decoded, or null. */
    String expectation() {
        return expect;
    }

    /** The head just decoded had more fields than :max-header-fields (answered 431). */
    boolean tooManyFields() {
        return tooManyFields;
    }

    /** The next decoded block is a trailer section: only checked, Ring has no trailers. */
    void beginTrailers() {
        trailers = true;
        malformedTrailers = false;
        pseudoInTrailers = false;
    }

    /** The block decoded as trailers carried a pseudo-header: a request head, not trailers. */
    boolean pseudoInTrailers() {
        return pseudoInTrailers;
    }

    /**
     * The trailer section just decoded broke the field rules: a
     * pseudo-header (§8.1), a name that isn't a lowercase token, a value
     * with CTL or surrounding whitespace (§8.2.1), or a connection-specific
     * field (§8.2.2). The request is malformed.
     */
    boolean malformedTrailers() {
        return malformedTrailers;
    }

    @Override
    public void field(String name, String value) {
        field(name, value, false);
    }

    @Override
    public void field(String name, String value, boolean validChars) {
        if (trailers) {
            if (!name.isEmpty() && name.charAt(0) == ':') {
                pseudoInTrailers = true;
                malformedTrailers = true;
            } else if (!malformedTrailers && !isTrailerField(name, value)) {
                malformedTrailers = true;
            }
            return;
        }
        if (malformed || tooManyFields) return;
        if ((name.isEmpty() || name.charAt(0) != ':') && ++fieldCount > config.maxHeaderFields) {
            tooManyFields = true;
            return;
        }
        int kind = requestHead.add(name, value, validChars);
        if (kind == RequestHead.MALFORMED) {
            malformed = true;
        } else if (kind == RequestHead.FIELD) {
            if (name.length() == 6 && name.equals("expect")) {
                expect = value;
            }
            if (fieldLen + 4 > fields.length) {
                fields = java.util.Arrays.copyOf(fields, fields.length * 2);
            }
            fields[fieldLen++] = name;
            fields[fieldLen++] = value;
        }
    }

    private static boolean isTrailerField(String name, String value) {
        if (!HttpFields.isLowercaseToken(name, 0) || !RequestHead.isFieldValue(value)) return false;
        return switch (name) {
            case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" -> false;
            case "te" -> value.equalsIgnoreCase("trailers");
            default -> true;
        };
    }

    /** The request's Content-Length, -1 if none (valid once {@link #buildRequest} succeeded). */
    long contentLength() {
        return requestHead.contentLength();
    }

    /**
     * Validates the decoded head with the shared {@link RequestHead} rules
     * and builds the Ring request, or returns null for a malformed one (a
     * stream error). A well-formed CONNECT comes back with method CONNECT
     * and is answered 501.
     */
    Request buildRequest(InputStream body) {
        if (malformed) return null;
        RequestHead rh = requestHead;
        int verdict = rh.finish();
        if (verdict == RequestHead.MALFORMED) {
            return null;
        }
        // :authority stands in for Host (§8.3.1); without it the Host
        // header, as sent.
        String authority = rh.authority();
        if (authority != null) {
            fields[fieldLen++] = "host";
            fields[fieldLen++] = authority;
        }
        IPersistentMap headers;
        if (fieldLen == 0) {
            headers = PersistentArrayMap.EMPTY;
        } else {
            // Duplicates joined ("cookie" per RFC 9113 §8.2.3, others per
            // RFC 9110 §5.3) into an exact-fit array the map takes over.
            Object[] merged = RingHeaders.mergeDuplicates(fields, fieldLen);
            if (merged == fields) {
                fields = new Object[fields.length];
            } else {
                java.util.Arrays.fill(fields, 0, fieldLen, null);
            }
            headers = RingHeaders.toMap(merged);
        }
        fieldLen = 0;
        return new Request(rh.method(), rh.uri(), rh.query(), "HTTP/2.0", headers, body,
                           remoteAddress, localPort, scheme, conn.socket());
    }

    // ---- Response (handler threads) ----------------------------------------------------

    /**
     * Serves {@code s} on its own thread (the shared {@link Exchange}:
     * handler, client errors, error handler, claim against the timeout)
     * and writes the response. Returns true when the exchange was handed
     * over whole: the writer finishes it ({@link Http2Connection#exchangeFinished}).
     */
    boolean serve(Http2Stream s) {
        if (s.claimed() != Exchange.OPEN) {
            // Reset (or timed out) before the handler could start.
            return false;
        }
        // Null only for a 431 whose truncated head didn't form a request.
        Request request = s.request;
        Response response;
        if (s.earlyStatus != 0 || request.method.equals("CONNECT")) {
            // Answered without the handler: 413 / 417 / 431 decided by the
            // framer, or a CONNECT (buildRequest only lets a well-formed one
            // through; tunnels aren't served).
            response = HttpStatus.error(s.earlyStatus != 0 ? s.earlyStatus : 501);
            if (!s.claim(Exchange.HANDLER)) return false;
        } else {
            response = s.serve(handler);
            // Null: the timeout (503) or a reset claimed the stream first.
            if (response == null) return false;
        }
        return respond(s, response, request != null && request.method.equals("HEAD"));
    }

    /**
     * {@code :handler-timeout} claimed the response before the handler
     * answered: 503 instead. Returns true when the exchange was handed over.
     */
    boolean respondTimeout(Http2Stream s) {
        s.interruptHandler();
        return respond(s, HttpStatus.error(503), s.request != null && "HEAD".equals(s.request.method));
    }

    private boolean respond(Http2Stream s, Response response, boolean headRequest) {
        Http2Writer writer = conn.writer();
        ResponseHead rh = borrowHead(s);
        int status = 0;
        boolean handedOver = false;
        try {
            if (response.webSocketListener != null) {
                // RFC 9113 §8.6: no 101 / Upgrade over HTTP/2, and Extended
                // CONNECT (RFC 8441) isn't offered.
                Exchange.closeBody(response.body);
                response = HttpStatus.error(501);
            }
            try {
                rh.prepare(response, headRequest, ResponseHead.MULTIPLEXED);
            } catch (RuntimeException e) {
                INVALID_RESPONSES.log("invalid HTTP/2 response from handler, sending 500", e);
                Exchange.closeBody(response.body);
                rh.prepare(HttpStatus.error(500), headRequest, ResponseHead.MULTIPLEXED);
            }
            status = rh.status();
            s.status = status;
            int kind = rh.bodyKind();
            if (kind == ResponseHead.BODY_NONE || kind == ResponseHead.BODY_BYTES
                || kind == ResponseHead.BODY_ASCII) {
                // Nothing left to produce or close: the writer takes it all.
                byte[] bytes = null;
                String text = null;
                int len = 0;
                if (rh.bodyAllowed() && kind == ResponseHead.BODY_BYTES) {
                    bytes = rh.bytes();
                    len = bytes.length;
                } else if (rh.bodyAllowed() && kind == ResponseHead.BODY_ASCII) {
                    text = rh.text();
                    len = text.length();
                }
                handedOver = true;
                writer.handOver(s, rh, bytes, text, len);
                return true;
            }
            byte[] small = rh.bodyAllowed() && kind == ResponseHead.BODY_STREAM ? smallInMemoryBody(rh) : null;
            if (small != null) {
                handedOver = true;
                writer.handOver(s, rh, small, null, small.length);
                return true;
            }
            writeStreamed(writer, s, rh);
            if (!s.remoteEnded()) {
                // Complete response sent while the request body is still
                // arriving: ask the client to stop sending (§8.1).
                conn.resetStream(s, Http2.ERROR_NO_ERROR, true);
            }
        } catch (Throwable t) {
            // Socket died, the stream was reset mid-write, or the body
            // failed. Never answer a peer's RST_STREAM with another one
            // (§5.4.2): resetStream only sends one if the stream is open.
            if (!(t instanceof IOException)) {
                BODY_FAILURES.log("HTTP/2 response body failed", t);
            }
            conn.resetStream(s, Http2.ERROR_INTERNAL_ERROR, true);
        } finally {
            if (!handedOver) {
                rh.release();
                giveBack(s, rh);
                conn.requestCompleted(s, status);
            }
        }
        return false;
    }

    /**
     * The bytes of a stream body that is a {@link ByteArrayInputStream}
     * (Ring's string-input-stream) holding the whole body, up to one frame,
     * read out and the stream closed; null for any other body. Handed over
     * like a byte array, it costs that array and nothing else: no ring, no
     * handler thread waiting for its END_STREAM.
     */
    private static byte[] smallInMemoryBody(ResponseHead rh) throws IOException {
        InputStream in = rh.stream();
        if (in.getClass() != ByteArrayInputStream.class) return null;
        long declared = rh.declaredLength();
        int available = in.available();
        long len = declared >= 0 ? declared : available;
        if (len > available || len > Http2Writer.DATA_FRAME_MAX) return null;
        byte[] body = in.readNBytes((int) len);
        rh.disownBody();
        in.close();
        return body;
    }

    /** File, stream and streaming bodies, produced on the handler thread. */
    private void writeStreamed(Http2Writer writer, Http2Stream s, ResponseHead rh) throws IOException {
        int kind = rh.bodyKind();
        long length = rh.contentLength();
        if (!rh.bodyAllowed()
            || (length == 0 && kind != ResponseHead.BODY_STREAMING && kind != ResponseHead.BODY_STREAM)) {
            // HEAD, 204, 304 or an empty file: the source is never read
            // (ResponseHead.release closes it).
            writer.begin(s, rh, true, false);
            writer.finish(s);
            return;
        }
        switch (kind) {
            case ResponseHead.BODY_FILE -> {
                FileChannel ch = rh.fileChannel();
                rh.disownBody();
                try (ch) {
                    writer.begin(s, rh, false, false);
                    long left = length;
                    while (left > 0) {
                        int r = writer.readInto(s, ch, left);
                        if (r < 0) break;
                        left -= r;
                    }
                    if (left > 0) {
                        // The file shrank since its length was sent.
                        throw new IOException("response body file shorter than its Content-Length");
                    }
                    writer.finish(s);
                }
            }
            case ResponseHead.BODY_STREAM -> {
                InputStream in = rh.stream();
                rh.disownBody();
                try (in) {
                    // A ByteArrayInputStream (Ring's string-input-stream)
                    // holds the whole body: its length is exact and reading
                    // never blocks, so head, bytes and END_STREAM share a
                    // batch (unless it is shorter than a declared length:
                    // that fails as any stream does). Any other stream may
                    // be slow: its head leaves at once.
                    long declared = rh.declaredLength();
                    boolean inMemory = in.getClass() == ByteArrayInputStream.class
                        && (declared < 0 || in.available() >= declared);
                    writer.begin(s, rh, false, !inMemory);
                    long left = declared >= 0 ? declared : inMemory ? in.available() : Long.MAX_VALUE;
                    while (left > 0) {
                        int r = writer.readInto(s, in, left);
                        if (r < 0) break;
                        left -= r;
                    }
                    if (declared >= 0 && left > 0) {
                        throw new IOException("response body shorter than its Content-Length");
                    }
                    writer.finish(s);
                }
            }
            case ResponseHead.BODY_STREAMING -> {
                writer.begin(s, rh, false, true);
                long declared = rh.declaredLength();
                DataOutputStream out = new DataOutputStream(writer, s, declared);
                // The stream's ring is the buffer: the writer's own only
                // gathers small writes (its minimum size), larger ones go
                // straight to the ring.
                ChunkedWriter chunked = new ChunkedWriter(out, STREAMING_GATHER_BYTES, false);
                // No finally: a failed body must not end with END_STREAM,
                // which would make the truncated response look complete.
                rh.streaming().write(chunked);
                ChunkedWriters.finish(chunked);
                if (declared >= 0 && out.written < declared) {
                    throw new IOException("response body shorter than its Content-Length");
                }
                writer.finish(s);
            }
            default -> throw new IllegalStateException("body kind " + kind);
        }
    }

    /**
     * {@link com.s_exp.enso.api.StreamingBody} output: copies into the
     * stream's bounded ring; flush waits for this stream's bytes only.
     */
    private static final class DataOutputStream extends OutputStream {
        private final Http2Writer writer;
        private final Http2Stream stream;
        private final long declared;
        private final byte[] one = new byte[1];
        long written;

        DataOutputStream(Http2Writer writer, Http2Stream stream, long declared) {
            this.writer = writer;
            this.stream = stream;
            this.declared = declared;
        }

        @Override
        public void write(int b) throws IOException {
            one[0] = (byte) b;
            write(one, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len <= 0) return;
            if (declared >= 0 && written + len > declared) {
                throw new IOException("response body longer than its Content-Length");
            }
            writer.write(stream, b, off, len);
            written += len;
        }

        @Override
        public void flush() throws IOException {
            // User flush! pushes this stream's bytes to the wire (SSE etc.).
            writer.flush(stream);
        }
    }

    private static int poolStart(Http2Stream s) {
        int h = (s.id ^ s.conn.poolSeed) * 0x9E3779B9;
        return h ^ (h >>> 16);
    }

    static ResponseHead borrowHead(Http2Stream s) {
        int start = poolStart(s);
        for (int i = 0; i < HEAD_POOL_PROBES; i++) {
            int idx = (start + i * HEAD_POOL_STRIDE) & (HEAD_POOL_SLOTS - 1);
            ResponseHead h = HEADS.get(idx);
            if (h != null && HEADS.compareAndSet(idx, h, null)) {
                return h;
            }
        }
        return new ResponseHead();
    }

    /** Returns a released head to the shared pool (dropped when the pool is full or it grew large). */
    static void giveBack(Http2Stream s, ResponseHead h) {
        if (h.capacity() > HEAD_POOL_MAX_FIELDS) return;
        int start = poolStart(s);
        for (int i = 0; i < HEAD_POOL_PROBES; i++) {
            int idx = (start + i * HEAD_POOL_STRIDE) & (HEAD_POOL_SLOTS - 1);
            if (HEADS.get(idx) == null && HEADS.compareAndSet(idx, null, h)) {
                return;
            }
        }
    }

}

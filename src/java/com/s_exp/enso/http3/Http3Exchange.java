// ABOUTME: One HTTP/3 request stream end to end: frame-parse state, the shared Exchange (handler,
// ABOUTME: response claim against the timeout and cancels), and the streamed-body producer.
package com.s_exp.enso.http3;

import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.StreamingBody;
import com.s_exp.enso.core.ChunkedWriters;
import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.core.Service;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A request stream. Read side and response sending belong to the
 * connection's event loop; {@link #run} is the handler's virtual thread;
 * {@link #onTimeout} the shared timer's thread. They meet at:
 *
 * <ul>
 *   <li>the response claim ({@link Exchange}): the handler, the handler
 *       timeout or an abandon (stream reset, connection gone), whichever
 *       comes first, decides the response or that there is none;
 *   <li>{@link #signal}: event bits plus a lock-free push onto the
 *       connection's queue, which wakes the loop.
 * </ul>
 */
final class Http3Exchange extends Http3Stream implements Runnable, SignalStack.Node<Http3Exchange> {

    private static final Logger LOG = Logger.getLogger(Http3Exchange.class.getName());
    private static final LogLimiter BODY_FAILURES = new LogLimiter(LOG, Level.FINE);
    private static final LogLimiter INVALID_RESPONSES = new LogLimiter(LOG, Level.WARNING);

    private static final VarHandle EVENTS;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            EVENTS = l.findVarHandle(Http3Exchange.class, "events", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** A response (handler, timeout or fallback) is ready to send. */
    static final int EV_RESPONSE = 1;
    /** The streamed body offered a slice, finished or failed. */
    static final int EV_BODY = 2;
    /** The handler drained the request body below the high-water mark. */
    static final int EV_RESUME_READ = 4;
    /** The handler's first body read on an Expect: 100-continue request: send the 100. */
    static final int EV_CONTINUE = 8;

    // Read-side phases (RFC 9114 §4.1: HEADERS, DATA*, optional trailers).
    static final int READ_HEADERS = 0;
    static final int READ_BODY = 1;
    static final int READ_TRAILERS = 2;
    static final int READ_DONE = 3;

    // Response progress (event loop only).
    static final int RESP_NONE = 0;
    static final int RESP_STREAMING = 1;
    static final int RESP_SENT = 2;

    private static final int STREAM_CHUNK_BYTES = 64 * 1024;

    final Http3Connection conn;

    // ---- read side (event loop) ------------------------------------
    int readPhase = READ_HEADERS;
    /** Type of the frame being read, -1 between frames. */
    long frameType = -1;
    /** Payload bytes of the current frame still to come. */
    long frameRemaining;
    /** A frame header split across reads (at most two 8-byte varints); allocated when one is. */
    byte[] frameHead;
    int frameHeadLen;
    /** HEADERS payload split across reads; counted against the connection's budget. */
    byte[] fieldBuf;
    int fieldLen;
    /** Discarding the payload of the current frame (unknown type). */
    boolean skipping;
    /** System.nanoTime the header section clock started (first request byte, or reading resumed), for :header-timeout. */
    long firstByteNanos;
    Http3BodyPipe pipe;
    boolean readPaused;

    // ---- dispatch ----------------------------------------------------
    boolean headRequest;
    /** Handler timeout armed on the shared timer. */
    boolean timed;
    /** Expect: 100-continue on a request with a body, until the handler first reads it (signals once). */
    volatile boolean continuePending;

    // ---- handler → event loop ----------------------------------------
    @SuppressWarnings("unused") // accessed through EVENTS
    private volatile int events;
    private Http3Exchange pushNext;
    private Http3Exchange takeNext;
    /** Prepared response; the loop encodes it and returns it to the pool. */
    ResponseHead head;
    /** A response the loop builds itself (500, 501, 503), or 0. */
    int fixedStatus;
    /** Streamed body (File, InputStream, StreamingBody), or null; read by abandon on the loop. */
    volatile Http3ResponseBody body;

    // ---- response progress (event loop) ------------------------------
    /** Forgotten by the connection: stream done or reset. */
    boolean finished;
    int responseState = RESP_NONE;

    private Runnable resume;
    private com.s_exp.enso.core.MemoryBudget.Waiter budgetWaiter;

    Http3Exchange(Http3Connection conn, long id) {
        super(id);
        this.conn = conn;
    }

    /** Wake-up the body pipe runs once the handler drained it. */
    Runnable resumeTask() {
        Runnable r = resume;
        if (r == null) {
            r = () -> signal(EV_RESUME_READ);
            resume = r;
        }
        return r;
    }

    /** Wake-up for a read paused on the connection's body budget before this request had a pipe. */
    com.s_exp.enso.core.MemoryBudget.Waiter budgetWaiter() {
        com.s_exp.enso.core.MemoryBudget.Waiter w = budgetWaiter;
        if (w == null) {
            w = new com.s_exp.enso.core.MemoryBudget.Waiter() {
                @Override
                protected void budgetAvailable() {
                    signal(EV_RESUME_READ);
                }
            };
            budgetWaiter = w;
        }
        return w;
    }

    /** The exchange is over: a read paused on the connection's body budget no longer waits. */
    void cancelBudgetWait(com.s_exp.enso.core.MemoryBudget b) {
        com.s_exp.enso.core.MemoryBudget.Waiter w = budgetWaiter;
        if (w != null) b.cancel(w);
    }

    @Override public Http3Exchange pushNext() { return pushNext; }
    @Override public void pushNext(Http3Exchange n) { pushNext = n; }
    @Override public Http3Exchange takeNext() { return takeNext; }
    @Override public void takeNext(Http3Exchange n) { takeNext = n; }

    /** Any thread: records {@code bits} and queues this exchange on its loop if it wasn't. */
    void signal(int bits) {
        int old = (int) EVENTS.getAndBitwiseOr(this, bits);
        if (old == 0) conn.signalled(this);
    }

    /** Event loop: takes the pending event bits. */
    int takeEvents() {
        return (int) EVENTS.getAndSet(this, 0);
    }

    /** No response will be sent; the handler is interrupted and its body producer fails. */
    void abandon() {
        cancel();
        Http3ResponseBody b = body;
        if (b != null) b.cancel();
    }

    /** {@code :handler-timeout} claimed the response (timer thread; never blocks). */
    @Override
    protected void handlerTimedOut() {
        fixedStatus = 503;
        interruptHandler();
        signal(EV_RESPONSE);
    }

    @Override
    protected Service service() {
        return conn.listener.service;
    }

    @Override
    protected String protocol() {
        return Http3Listener.PROTOCOL;
    }

    @Override
    protected Throwable bodyFailure() {
        Http3BodyPipe p = pipe;
        return p != null ? p.failure() : null;
    }

    @Override
    protected long requestBytes() {
        Http3BodyPipe p = pipe;
        return p != null ? p.received() : 0;
    }

    /** Handler thread, first body read: asks the loop for the 100 (Continue). */
    void bodyReadStarted() {
        if (continuePending) {
            continuePending = false;
            signal(EV_CONTINUE);
        }
    }

    // ---- handler thread ------------------------------------------------

    @Override
    public void run() {
        try {
            respond();
        } finally {
            conn.handlerFinished(this);
        }
    }

    private void respond() {
        if (claimed() != OPEN) {
            // Abandoned (or timed out) before the handler could start.
            return;
        }
        // The shared exchange: handler, client errors, error handler, and
        // the claim against the timeout and abandons (null: lost).
        Response response = serve(conn.handler());
        if (response == null) return;
        ResponseHead h = null;
        int fixed = 0;
        if (response.webSocketListener != null) {
            // HTTP/3 has no 101 / Upgrade (RFC 9114 §4.5).
            closeBody(response.body);
            fixed = 501;
        } else {
            h = conn.heads().acquire();
            try {
                h.prepare(response, headRequest, ResponseHead.MULTIPLEXED);
            } catch (RuntimeException e) {
                INVALID_RESPONSES.log("invalid response from handler, sending 500: " + e.getMessage());
                closeBody(response.body);
                conn.heads().release(h);
                h = null;
                fixed = 500;
            }
        }
        FileChannel file = null;
        InputStream in = null;
        StreamingBody streaming = null;
        long length = -1;
        long declared = -1;
        if (h != null && h.bodyAllowed()) {
            switch (h.bodyKind()) {
                case ResponseHead.BODY_FILE -> {
                    file = h.fileChannel();
                    length = h.contentLength();
                }
                case ResponseHead.BODY_STREAM -> in = h.stream();
                case ResponseHead.BODY_STREAMING -> streaming = h.streaming();
                default -> {
                }
            }
            declared = h.declaredLength();
        }
        boolean streamed = file != null || in != null || streaming != null;
        Http3ResponseBody b = null;
        if (streamed) {
            h.disownBody();
            b = new Http3ResponseBody(this, declared);
            body = b;
        }
        head = h;
        fixedStatus = fixed;
        signal(EV_RESPONSE);
        if (!streamed) return;
        // The connection may have gone since the claim: then nothing sends
        // this body and the producer must fail fast.
        if (conn.isGone()) b.cancel();
        produce(b, file, length, in, streaming);
    }

    /** Reads / generates the body and hands it to the loop slice by slice; any failure resets the stream. */
    private void produce(Http3ResponseBody out, FileChannel file, long length, InputStream in,
                         StreamingBody streaming) {
        try {
            if (streaming != null) {
                ChunkedWriter writer = new ChunkedWriter(out.outputStream(),
                    ChunkedWriter.DEFAULT_BUFFER_BYTES, false);
                try {
                    streaming.write(writer);
                } finally {
                    ChunkedWriters.finish(writer);
                }
                out.finish();
            } else if (file != null) {
                try (FileChannel fc = file) {
                    produceFile(out, fc, length);
                }
            } else {
                try (InputStream is = in) {
                    produceStream(out, is, out.declaredLength());
                }
            }
        } catch (Throwable t) {
            BODY_FAILURES.log("h3 response body failed stream=" + id, t);
            out.fail();
            if (t instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    /** A file of known length: the last slice carries the FIN. */
    private static void produceFile(Http3ResponseBody out, FileChannel fc, long length) throws IOException {
        byte[] buf = new byte[(int) Math.min(STREAM_CHUNK_BYTES, Math.max(1, length))];
        ByteBuffer bb = ByteBuffer.wrap(buf);
        long left = length;
        while (left > 0) {
            bb.clear();
            if (left < buf.length) bb.limit((int) left);
            int n = fc.read(bb);
            if (n < 0) throw new IOException("file shorter than its length");
            left -= n;
            out.write(buf, 0, n, left == 0);
        }
        if (length == 0) out.finish();
    }

    /**
     * An InputStream. Each slice is what one blocking read returns plus
     * whatever is already available. The last slice carries the FIN when
     * the end is known without blocking: the handler's Content-Length was
     * reached, or the stream reports its exact remainder
     * (ByteArrayInputStream, FileInputStream) and none is left.
     */
    private static void produceStream(Http3ResponseBody out, InputStream in, long declared)
            throws IOException {
        boolean exact = in instanceof java.io.ByteArrayInputStream
            || in instanceof java.io.FileInputStream;
        // Sized to what the body can need when that is known (its
        // Content-Length, or the exact remainder), a slice otherwise.
        long need = declared >= 0 ? declared : exact ? in.available() : STREAM_CHUNK_BYTES;
        byte[] buf = new byte[(int) Math.max(1, Math.min(STREAM_CHUNK_BYTES, need))];
        long sent = 0;
        while (true) {
            int n = in.read(buf, 0, buf.length);
            if (n < 0) {
                out.finish();
                return;
            }
            int r;
            while (n < buf.length && in.available() > 0 && (r = in.read(buf, n, buf.length - n)) > 0) {
                n += r;
            }
            // A declared Content-Length bounds the body, as on HTTP/1.1 and
            // HTTP/2: bytes past it are dropped, not sent.
            if (declared >= 0 && sent + n > declared) {
                n = (int) (declared - sent);
            }
            sent += n;
            boolean last = (declared >= 0 && sent >= declared) || (exact && in.available() <= 0);
            out.write(buf, 0, n, last);
            if (last) return;
        }
    }
}

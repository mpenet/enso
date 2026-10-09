// ABOUTME: HTTP/1.1 response side of a connection: the output buffer, status lines and heads,
// ABOUTME: bodies (inline, chunked, fixed-length, file), error responses and pipelined coalescing.
package com.s_exp.enso.http1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.Socket;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.core.ChunkedWriters;
import com.s_exp.enso.core.HttpDates;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.core.HttpStatus;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.WatchedOutputStream;
import com.s_exp.enso.core.WriteWatchdog;
import com.s_exp.enso.websocket.PerMessageDeflate;
import com.s_exp.enso.websocket.WebSocketConnection;
import com.s_exp.enso.websocket.WebSocketHandshake;

/**
 * Writes one connection's responses. Everything goes through one buffer
 * (hbuf): the response head is built in it and small writes join it (see
 * {@link Output}), so a head and a small body leave in one write, and
 * responses to pipelined requests share writes (see {@link #holdOutput}).
 * Used by the connection thread only, but for the held-output flusher.
 */
final class ResponseWriter {

    private static final byte[] CONTINUE_100 =
        "HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CHUNK_END = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CONTENT_LENGTH = "Content-Length: ".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CONNECTION_CLOSE = "Connection: close\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] TE_CHUNKED = "Transfer-Encoding: chunked\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CONTENT_TYPE_TEXT =
        "Content-Type: text/plain; charset=utf-8\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] SWITCHING_PROTOCOLS =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            .getBytes(StandardCharsets.ISO_8859_1);
    // Filled for 100..599 in the static initializer below, so connection
    // threads only ever read fully built, safely published lines.
    private static final byte[][] STATUS_LINES = new byte[600][];
    // Initial response head / output buffer; grows as needed.
    private static final int OUTPUT_BUFFER_BYTES = 1024;
    // Response bodies up to this size are copied behind the head for a
    // one-syscall response.
    private static final int MAX_INLINE_BODY = 16_384;
    // Pending output bytes (pipelined responses, small writes) that force
    // a flush.
    private static final int COALESCE_HIGH_WATER = 32_768;
    // Writes at least this large skip hbuf: copying them costs more than
    // the extra write saves.
    private static final int DIRECT_WRITE_BYTES = 8192;

    // Pipelined output held in hbuf while a handler runs (see holdOutput).
    private static final int HELD_NONE = 0;
    private static final int HELD_ARMED = 1;
    private static final int HELD_FLUSHING = 2;
    private static final int HELD_FLUSHED = 3;
    private static final VarHandle HELD_STATE;
    // How long a pipelined response may wait in hbuf for the next
    // handler's response to share its write: one timer tick.
    private static final int HELD_FLUSH_DELAY_MILLIS = 10;

    static {
        for (int status = 100; status < 600; status++) {
            STATUS_LINES[status] = buildStatusLine(status);
        }
        try {
            HELD_STATE = MethodHandles.lookup()
                .findVarHandle(ResponseWriter.class, "heldState", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final Socket socket;
    private final Service service;
    private final Timer timer;
    // :write-timeout, null when disabled.
    private final WriteWatchdog watchdog;
    final ResponseHead head = new ResponseHead();

    // The socket's stream (through the write watchdog when enabled).
    private OutputStream transport;
    // What everything writes through: small writes gather in hbuf, so a
    // response head and its body share one write (see Output).
    private final OutputStream out = new Output();
    private byte[] hbuf = new byte[OUTPUT_BUFFER_BYTES];
    private int hlen;
    private byte[] chunkBuf;
    @SuppressWarnings("unused") // accessed through HELD_STATE
    private volatile int heldState;
    // Allocated on first use: only pipelining holds output.
    private HeldFlush heldFlush;
    private Thread connectionThread;
    // Body bytes of the response being written, for events and JFR.
    long bodyBytesWritten;

    ResponseWriter(Socket socket, Service service, WriteWatchdog watchdog) {
        this.socket = socket;
        this.service = service;
        this.timer = service.timer;
        this.watchdog = watchdog;
    }

    /** Starts writing to {@code transport}; {@code connectionThread} owns hbuf. */
    void start(OutputStream transport, Thread connectionThread) {
        this.transport = transport;
        this.connectionThread = connectionThread;
    }

    /** What everything on this connection writes through (see {@link Output}). */
    OutputStream output() {
        return out;
    }

    /** Whether bytes are waiting in hbuf. */
    boolean hasPending() {
        return hlen > 0;
    }

    void flush() throws IOException {
        out.flush();
    }

    /** At connection close: unlinks the held-output timer node from the wheel. */
    void retireTimers() {
        if (heldFlush != null) timer.retire(heldFlush);
    }

    /** Gives back the grown output buffer and the body copy buffer of an idle connection. */
    void shrinkIdle() {
        if (hbuf.length > OUTPUT_BUFFER_BYTES) {
            hbuf = new byte[OUTPUT_BUFFER_BYTES];
        }
        chunkBuf = null;
    }

    private void flushHbuf() throws IOException {
        if (hlen > 0) {
            transport.write(hbuf, 0, hlen);
            hlen = 0;
        }
    }

    /**
     * The connection's output stream over hbuf, so nothing is copied twice:
     * the response head is built in hbuf and small writes (100 Continue,
     * chunk framing, small chunks, error responses, WebSocket frames) join
     * it there, going out in one write on {@link #flush} or once
     * {@link #COALESCE_HIGH_WATER} bytes are pending. A write of
     * {@link #DIRECT_WRITE_BYTES} or more goes straight to the transport
     * after what is pending. One writer at a time.
     */
    private final class Output extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            hEnsure(1);
            hbuf[hlen++] = (byte) b;
            if (hlen >= COALESCE_HIGH_WATER) {
                flushHbuf();
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len >= DIRECT_WRITE_BYTES) {
                flushHbuf();
                transport.write(b, off, len);
            } else {
                hAppend(b, off, len);
                if (hlen >= COALESCE_HIGH_WATER) {
                    flushHbuf();
                }
            }
        }

        /**
         * Writes what is pending. The transport keeps no buffer of its own
         * (a direct write is on its way when it returns), so with nothing
         * pending there is nothing to do.
         */
        @Override
        public void flush() throws IOException {
            if (hlen > 0) {
                flushHbuf();
                transport.flush();
            }
        }
    }

    // ---- Pipelined output held across a handler --------------------------

    /**
     * Pipelined responses wait in hbuf so several share one write, but a
     * handler may take any time: a response already complete must not
     * wait for it. So while the next handler runs, the held bytes are on a
     * one-tick timer: a handler that returns first takes them back and
     * the coalescing goes on; otherwise a virtual thread writes them out.
     * Only the connection thread touches hbuf otherwise, and it takes the
     * bytes back ({@link #reclaimOutput}) before any write or socket read.
     */
    void holdOutput() {
        if (heldFlush == null) {
            heldFlush = new HeldFlush();
        }
        HELD_STATE.setVolatile(this, HELD_ARMED);
        timer.schedule(heldFlush, HELD_FLUSH_DELAY_MILLIS);
    }

    /**
     * Back to the connection thread owning hbuf: the held bytes are still
     * there (timer cancelled in time) or were written by the flusher
     * (waited for, then dropped).
     */
    void reclaimOutput() {
        if ((int) HELD_STATE.getVolatile(this) == HELD_NONE) {
            return;
        }
        timer.cancel(heldFlush);
        if (HELD_STATE.compareAndSet(this, HELD_ARMED, HELD_NONE)) {
            return;
        }
        // An interrupt status would make park return at once: set aside
        // while waiting, so this doesn't spin.
        boolean interrupted = Thread.interrupted();
        while ((int) HELD_STATE.getVolatile(this) != HELD_FLUSHED) {
            java.util.concurrent.locks.LockSupport.park(this);
            interrupted |= Thread.interrupted();
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        hlen = 0;
        HELD_STATE.setVolatile(this, HELD_NONE);
    }

    private final class HeldFlush extends Timer.Task {
        @Override
        protected void onTimeout() {
            if (HELD_STATE.compareAndSet(ResponseWriter.this, HELD_ARMED, HELD_FLUSHING)) {
                Thread.ofVirtual().name("enso-h1-flush").start(ResponseWriter.this::flushHeld);
            }
        }
    }

    private void flushHeld() {
        try {
            transport.write(hbuf, 0, hlen);
            transport.flush();
        } catch (IOException ignored) {
            // the connection is broken: its own next write fails too
        } finally {
            HELD_STATE.setVolatile(this, HELD_FLUSHED);
            java.util.concurrent.locks.LockSupport.unpark(connectionThread);
        }
    }

    /** Writes the 100 Continue for a body whose request said Expect: 100-continue. */
    void writeContinue() throws IOException {
        reclaimOutput();
        out.write(CONTINUE_100);
        out.flush();
    }

    /**
     * The 503 answering a handler that outlived :handler-timeout, built
     * whole so another thread can write it in one piece.
     */
    static byte[] handlerTimeoutResponse() throws IOException {
        byte[] body = HttpStatus.reason(503).getBytes(StandardCharsets.ISO_8859_1);
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(256);
        bytes.write(STATUS_LINES[503]);
        bytes.write(CONTENT_TYPE_TEXT);
        bytes.write(CONTENT_LENGTH);
        bytes.write(Integer.toString(body.length).getBytes(StandardCharsets.ISO_8859_1));
        bytes.write(CRLF);
        bytes.write(CONNECTION_CLOSE);
        bytes.write(HttpDates.dateLine());
        bytes.write(CRLF);
        bytes.write(body);
        return bytes.toByteArray();
    }

    /** Writes {@code bytes} straight to the transport, past hbuf, and flushes. */
    void writeDirect(byte[] bytes) throws IOException {
        transport.write(bytes);
        transport.flush();
    }

    // ---- Response writing ---------------------------------------------------

    /**
     * Prepares {@link #head} from the handler's response; false (logged,
     * nothing written) when the response is invalid.
     */
    boolean prepare(Response response, boolean headRequest) {
        // hbuf may already hold earlier pipelined responses; only bytes past
        // this mark belong to the response being written.
        int responseStart = hlen;
        try {
            head.prepare(response, headRequest, ResponseHead.HTTP1);
            return true;
        } catch (RuntimeException e) {
            HttpConnection.INVALID_RESPONSES.log("invalid response from handler", e);
            hlen = responseStart;
            return false;
        }
    }

    /**
     * Serialises {@link #head}, prepared from the handler's response, and
     * its body. Returns whether the connection stays open: {@code keepAlive}
     * unless the body's framing or a failure ends it. The head is released
     * (body source closed) however this ends. {@code nextRequestBuffered}:
     * the next pipelined request is already buffered, only consulted for a
     * response written whole into hbuf (nothing is read meanwhile).
     */
    boolean writeResponse(boolean http11, boolean keepAlive, boolean nextRequestBuffered) throws IOException {
        ResponseHead h = head;
        try {
            int status = h.status();
            hAppend(statusLine(status));
            for (int i = 0, n = h.fieldCount(); i < n; i++) {
                appendField(h.name(i), h.value(i));
            }
            if (Service.addsDate(h)) {
                hAppend(HttpDates.dateLine());
            }
            String altSvc = service.altSvcField(h);
            if (altSvc != null) {
                appendField("alt-svc", altSvc);
            }
            String server = service.serverField(h);
            if (server != null) {
                appendField("server", server);
            }

            int kind = h.bodyKind();
            boolean streamed = kind == ResponseHead.BODY_STREAM || kind == ResponseHead.BODY_STREAMING;
            long contentLength = h.contentLength();
            boolean chunked = false;
            if (contentLength >= 0) {
                hAppend(CONTENT_LENGTH);
                hAppendLong(contentLength);
                hCrlf();
            } else if (streamed && status >= 200 && status != 204 && status != 304) {
                // Unknown length: chunked framing, or the end of the
                // connection where HTTP/1.0 has nothing else.
                if (http11 && keepAlive) {
                    chunked = true;
                    hAppend(TE_CHUNKED);
                } else {
                    keepAlive = false;
                }
            }
            // A handler-supplied Connection without "close" (e.g. keep-alive)
            // must not hide that the server is closing.
            if (!keepAlive && !h.closeRequested()) {
                hAppend(CONNECTION_CLOSE);
            }
            hCrlf();

            boolean inlineOnly = true;
            if (h.bodyAllowed()) {
                // Headers may already be on the wire past this point, so a
                // failing body can't become a 500: abort the connection so
                // the client sees the truncation.
                try {
                    switch (kind) {
                        case ResponseHead.BODY_ASCII -> {
                            String text = h.text();
                            int len = text.length();
                            if (len <= MAX_INLINE_BODY) {
                                hAppendAscii(text, len);
                            } else {
                                inlineOnly = false;
                                flushHbuf();
                                writeAsciiDirect(text, len);
                            }
                            bodyBytesWritten = len;
                        }
                        case ResponseHead.BODY_BYTES -> {
                            byte[] bytes = h.bytes();
                            if (bytes.length <= MAX_INLINE_BODY) {
                                hAppend(bytes);
                            } else {
                                inlineOnly = false;
                                flushHbuf();
                                out.write(bytes);
                            }
                            bodyBytesWritten = bytes.length;
                        }
                        case ResponseHead.BODY_FILE -> {
                            inlineOnly = false;
                            flushHbuf();
                            // A file that shrank since size() leaves the body
                            // short: close so the client detects it.
                            long sent = sendFile(h.fileChannel(), contentLength);
                            bodyBytesWritten = sent;
                            if (sent < contentLength) {
                                keepAlive = false;
                            }
                        }
                        case ResponseHead.BODY_STREAM -> {
                            // The head stays in hbuf: a small body joins it
                            // in one write.
                            inlineOnly = false;
                            long declared = h.declaredLength();
                            if (chunked) {
                                writeChunked(h.stream());
                            } else if (declared >= 0) {
                                // fixed-length response: ship exactly the
                                // declared bytes; a short stream forces close
                                // so the client detects truncation.
                                long written = boundedTransfer(h.stream(), out, declared);
                                bodyBytesWritten = written;
                                if (written < declared) {
                                    keepAlive = false;
                                }
                            } else {
                                bodyBytesWritten = h.stream().transferTo(out);
                            }
                        }
                        case ResponseHead.BODY_STREAMING -> {
                            // The head goes out before the handler's writer
                            // runs, which may wait (SSE, long polling).
                            inlineOnly = false;
                            flushHbuf();
                            long declared = h.declaredLength();
                            FixedLengthOutputStream fixed = declared >= 0
                                ? new FixedLengthOutputStream(out, declared) : null;
                            ChunkedWriter writer = new ChunkedWriter(fixed != null ? fixed : out,
                                                                     chunkScratch(), chunked);
                            // No finally: a failed body must not end with the
                            // terminating chunk, which would make the truncated
                            // response look complete.
                            h.streaming().write(writer);
                            ChunkedWriters.finish(writer);
                            bodyBytesWritten = writer.bytesWritten();
                            if (fixed != null && fixed.remaining > 0) {
                                keepAlive = false;
                            }
                        }
                        default -> {
                        }
                    }
                } catch (RuntimeException e) {
                    HttpConnection.BODY_FAILURES.log("response body failed, closing connection", e);
                    return false;
                }
            }

            // Held back only while the next pipelined request is already
            // buffered: its response can share the write.
            if (!inlineOnly || !keepAlive || !nextRequestBuffered || hlen >= COALESCE_HIGH_WATER) {
                out.flush();
            }
            return keepAlive;
        } finally {
            h.release();
        }
    }

    /**
     * Writes the 101 Switching Protocols head accepting a WebSocket
     * upgrade: the server-owned Sec-WebSocket-* fields, then the
     * handler's other fields. False (logged, nothing written) when the
     * handler's response is invalid. The head is released either way.
     */
    boolean writeSwitchingProtocols(Response response, String key, String protocol, PerMessageDeflate deflate) {
        int responseStart = hlen;
        try {
            head.prepare(response, false, ResponseHead.HTTP1);
            hAppend(SWITCHING_PROTOCOLS);
            hHeader("Sec-WebSocket-Accept", WebSocketConnection.computeAccept(key));
            if (protocol != null) {
                hHeader("Sec-WebSocket-Protocol", protocol);
            }
            if (deflate != null) {
                hHeader("Sec-WebSocket-Extensions", deflate.responseHeader());
            }
            for (int i = 0, n = head.fieldCount(); i < n; i++) {
                String name = head.name(i);
                if (!WebSocketHandshake.isServerOwnedHeader(name)) {
                    hHeader(name, head.value(i));
                }
            }
            hCrlf();
            return true;
        } catch (RuntimeException e) {
            HttpConnection.INVALID_RESPONSES.log("invalid WebSocket upgrade response from handler", e);
            hlen = responseStart;
            return false;
        } finally {
            head.release();
        }
    }

    /**
     * Copies up to {@code limit} bytes from {@code is} to {@code out}. Returns
     * the number of bytes actually written (may be less than {@code limit} if
     * the stream ended early). Excess bytes on the stream are not read; the
     * stream is closed by the caller.
     */
    private long boundedTransfer(InputStream is, OutputStream out, long limit) throws IOException {
        byte[] scratch = chunkScratch();
        long remaining = limit;
        while (remaining > 0) {
            int max = (int) Math.min(remaining, scratch.length);
            int n = is.read(scratch, 0, max);
            if (n < 0) {
                break;
            }
            out.write(scratch, 0, n);
            remaining -= n;
        }
        return limit - remaining;
    }

    /**
     * Zero-copy file transfer via {@link FileChannel#transferTo} when the socket
     * exposes a {@link SocketChannel} (plain HTTP path). Falls back to a
     * user-space copy for socket types without a channel — TLS via
     * {@link com.s_exp.enso.core.TlsSocket.AdapterSocket} takes this path because
     * the ciphertext has to pass through {@link javax.net.ssl.SSLEngine} first.
     * Sends at most {@code length} bytes and returns how many were sent; the
     * channel is closed by the caller. Each transferTo is bounded to one
     * write-watchdog slice so a slow reader still shows progress. A
     * transferTo that moves nothing before the end of the file (the JDK
     * may return 0 instead of blocking) hands the rest to a user-space
     * copy rather than ending the body early or spinning.
     */
    private long sendFile(FileChannel fc, long length) throws IOException {
        SocketChannel sc = socket.getChannel();
        if (sc == null) {
            return boundedTransfer(Channels.newInputStream(fc), out, length);
        }
        // transferTo(sc) writes directly to the socket underneath, so any
        // headers still sitting in the buffer would arrive after the body.
        out.flush();
        WriteWatchdog wd = watchdog;
        long position = 0;
        while (position < length) {
            long n;
            if (wd != null) wd.enter();
            try {
                n = fc.transferTo(position, Math.min(length - position, WatchedOutputStream.SLICE_BYTES), sc);
            } finally {
                if (wd != null) wd.exit();
            }
            if (n <= 0) {
                if (position < fc.size()) {
                    fc.position(position);
                    position += boundedTransfer(Channels.newInputStream(fc), out, length - position);
                }
                break;
            }
            position += n;
        }
        return position;
    }

    /**
     * Per-connection body copy buffer, allocated on first use and reused
     * for every later response / request-body drain on this connection.
     */
    byte[] chunkScratch() {
        byte[] scratch = chunkBuf;
        if (scratch == null) {
            scratch = new byte[ChunkedWriter.DEFAULT_BUFFER_BYTES];
            chunkBuf = scratch;
        }
        return scratch;
    }

    private void writeChunked(InputStream body) throws IOException {
        // Data is read behind room for the size line and framed in place,
        // so each chunk is one contiguous write: [size CRLF][data][CRLF].
        byte[] chunk = chunkScratch();
        int room = ChunkedWriter.SIZE_LINE_ROOM;
        long total = 0;
        while (true) {
            int n = body.read(chunk, room, chunk.length - room - 2);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                continue;
            }
            int start = ChunkedWriter.frame(chunk, room, n);
            out.write(chunk, start, room + n + 2 - start);
            total += n;
        }
        out.write(CHUNK_END);
        bodyBytesWritten = total;
    }

    /**
     * A whole error response with Connection: close, written now after
     * what is pending. {@code extraHeaders}: preformatted field lines
     * (each ending CRLF), or null.
     */
    void writeError(int status, String message, byte[] extraHeaders) {
        try {
            flushHbuf();
            byte[] body = message.getBytes(StandardCharsets.UTF_8);
            bodyBytesWritten = body.length;
            hAppend(statusLine(status));
            if (extraHeaders != null) {
                hAppend(extraHeaders);
            }
            hAppend(CONTENT_TYPE_TEXT);
            hAppend(CONTENT_LENGTH);
            hAppendLong(body.length);
            hCrlf();
            hAppend(CONNECTION_CLOSE);
            hAppend(HttpDates.dateLine());
            hCrlf();
            hAppend(body);
            flushHbuf();
        } catch (IOException ignored) {
            // best effort
        }
    }

    private void hEnsure(int extra) {
        if (hlen + extra > hbuf.length) {
            hbuf = Arrays.copyOf(hbuf, Math.max(hbuf.length * 2, hlen + extra));
        }
    }

    private void hAppend(byte[] bytes) {
        hAppend(bytes, 0, bytes.length);
    }

    private void hAppend(byte[] bytes, int off, int len) {
        hEnsure(len);
        System.arraycopy(bytes, off, hbuf, hlen, len);
        hlen += len;
    }

    private void hAppend(String s) {
        int len = s.length();
        hEnsure(len);
        for (int i = 0; i < len; i++) {
            hbuf[hlen++] = (byte) s.charAt(i);
        }
    }

    private void hAppendAscii(String s, int len) {
        hEnsure(len);
        for (int i = 0; i < len; i++) {
            hbuf[hlen++] = (byte) s.charAt(i);
        }
    }

    private void writeAsciiDirect(String s, int len) throws IOException {
        byte[] scratch = chunkScratch();
        int chunk = scratch.length;
        int i = 0;
        while (i < len) {
            int n = Math.min(chunk, len - i);
            for (int j = 0; j < n; j++) {
                scratch[j] = (byte) s.charAt(i + j);
            }
            out.write(scratch, 0, n);
            i += n;
        }
    }

    private void hAppendLong(long v) {
        // Digits are produced from the non-positive magnitude so that
        // Long.MIN_VALUE, which has no positive counterpart, needs no
        // special case.
        boolean negative = v < 0;
        long n = negative ? v : -v;
        int digits = 1;
        for (long t = n; t <= -10; t /= 10) {
            digits++;
        }
        int len = negative ? digits + 1 : digits;
        hEnsure(len);
        int end = hlen + len;
        for (int i = end - 1; i >= end - digits; i--) {
            hbuf[i] = (byte) ('0' - (n % 10));
            n /= 10;
        }
        if (negative) {
            hbuf[hlen] = '-';
        }
        hlen = end;
    }

    private void hCrlf() {
        hEnsure(2);
        hbuf[hlen++] = '\r';
        hbuf[hlen++] = '\n';
    }

    /** A field already validated by {@link ResponseHead}: String, Long or Integer value. */
    private void appendField(String name, Object value) {
        hAppend(name);
        hEnsure(2);
        hbuf[hlen++] = ':';
        hbuf[hlen++] = ' ';
        if (value instanceof Long l) {
            hAppendLong(l);
        } else if (value instanceof Integer i) {
            hAppendLong(i);
        } else {
            hAppend((String) value);
        }
        hCrlf();
    }

    /** A server-built field: validated here, before any byte reaches hbuf. */
    private void hHeader(String name, Object value) {
        HttpFields.checkResponseName(name);
        if (!(value instanceof Long) && !(value instanceof Integer)) {
            HttpFields.checkResponseValue((String) value);
        }
        appendField(name, value);
    }

    private static byte[] statusLine(int status) {
        return STATUS_LINES[status];
    }

    private static byte[] buildStatusLine(int status) {
        return ("HTTP/1.1 " + status + " " + HttpStatus.reason(status) + "\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    }


    /**
     * Holds a {@link com.s_exp.enso.api.StreamingBody} to the Content-Length
     * its handler declared: writing past it fails before any excess byte
     * reaches the wire, and {@link #remaining} tells the caller whether it
     * fell short.
     */
    private static final class FixedLengthOutputStream extends OutputStream {

        private final OutputStream out;
        long remaining;

        FixedLengthOutputStream(OutputStream out, long length) {
            this.out = out;
            this.remaining = length;
        }

        @Override
        public void write(int b) throws IOException {
            checkFits(1);
            out.write(b);
            remaining--;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            checkFits(len);
            out.write(b, off, len);
            remaining -= len;
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        private void checkFits(int len) {
            if (len > remaining) {
                throw new IllegalStateException("response body exceeds its declared Content-Length");
            }
        }
    }
}

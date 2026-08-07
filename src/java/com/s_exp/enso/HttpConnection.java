package com.s_exp.enso;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;

final class HttpConnection implements Runnable {

    private static final Logger LOG = Logger.getLogger(HttpConnection.class.getName());

    private static final byte[] CONTINUE_100 =
        "HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CHUNK_END = "0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CONTENT_LENGTH = "Content-Length: ".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CONNECTION_CLOSE = "Connection: close\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] TE_CHUNKED = "Transfer-Encoding: chunked\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] CONTENT_TYPE_TEXT =
        "Content-Type: text/plain; charset=utf-8\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[][] STATUS_LINES = new byte[600][];

    private final Socket socket;
    private final RingHandler handler;
    private final EnsoServer server;
    private final Config config;

    private InputStream in;
    private OutputStream out;
    private byte[] buf;
    private int pos;
    private int limit;
    private RequestBody currentBody;
    private Object[] headerScratch = new Object[32];
    private int headerScratchLen;
    private byte[] hbuf = new byte[1024];
    private int hlen;
    private byte[] chunkBuf;
    /**
     * True while this connection is between requests: keep-alive completed the
     * previous response, no bytes for the next request have been buffered or
     * observed on the socket yet. Read by the acceptor thread during
     * {@link EnsoServer#close} to distinguish sockets that can be torn down
     * without dropping an in-flight request from those still handling one.
     * Cleared by {@link #socketRead} on the first byte received of a new
     * request, closing the shutdown race to the kernel-read latency window.
     */
    volatile boolean idle;
    private long requestDeadlineNanos;
    private int currentSoTimeout = -1;

    HttpConnection(Socket socket, RingHandler handler, EnsoServer server) {
        this.socket = socket;
        this.handler = handler;
        this.server = server;
        this.config = server.config();
        this.buf = new byte[Math.min(config.requestBufferSize, config.maxHeaderBytes)];
    }

    Socket socketRef() {
        return socket;
    }

    @Override
    public void run() {
        server.register(this);
        try (Socket s = socket) {
            in = s.getInputStream();
            out = s.getOutputStream();
            while (server.isRunning() && handleOne()) {
                // keep-alive loop
            }
            flushHbuf();
        } catch (IOException e) {
            // client went away or timed out
        } finally {
            server.unregister(this);
        }
    }

    private void flushHbuf() throws IOException {
        if (hlen > 0) {
            out.write(hbuf, 0, hlen);
            hlen = 0;
        }
    }

    /**
     * Blocking read from the socket, honouring the per-request deadline.
     * On first byte received of a new request, starts the deadline clock.
     * Adjusts SO_TIMEOUT so a single stalled read cannot exceed the budget.
     */
    private int socketRead(byte[] dst, int off, int len) throws IOException {
        int requestTimeoutMs = config.requestTimeoutMillis;
        int idleTimeoutMs = config.idleTimeoutMillis;
        int deadlineMs = 0;
        if (requestDeadlineNanos != 0 && requestTimeoutMs > 0) {
            long remainingNs = requestDeadlineNanos - System.nanoTime();
            if (remainingNs <= 0) {
                throw new HttpError(408, "Request Timeout");
            }
            long remainingMs = (remainingNs + 999_999L) / 1_000_000L;
            deadlineMs = (int) Math.min(remainingMs, idleTimeoutMs > 0 ? idleTimeoutMs : Integer.MAX_VALUE);
            if (deadlineMs <= 0) {
                deadlineMs = 1;
            }
        } else {
            deadlineMs = idleTimeoutMs;
        }
        if (deadlineMs != currentSoTimeout) {
            socket.setSoTimeout(deadlineMs);
            currentSoTimeout = deadlineMs;
        }
        int n;
        try {
            n = in.read(dst, off, len);
        } catch (java.net.SocketTimeoutException e) {
            if (requestDeadlineNanos != 0 && System.nanoTime() >= requestDeadlineNanos) {
                throw new HttpError(408, "Request Timeout");
            }
            throw e;
        }
        if (n > 0) {
            // Once any byte for a new request lands, the connection is no
            // longer idle. Clearing this here closes the shutdown race: the
            // acceptor thread can only close a socket while idle is still
            // true, i.e. before any request byte has been observed.
            if (idle) {
                idle = false;
            }
            if (requestDeadlineNanos == 0 && requestTimeoutMs > 0) {
                requestDeadlineNanos = System.nanoTime() + (long) requestTimeoutMs * 1_000_000L;
            }
        }
        return n;
    }

    private boolean handleOne() throws IOException {
        compact();
        idle = pos == limit;
        requestDeadlineNanos = 0;
        Request request;
        try {
            request = parseRequest();
        } catch (HttpError e) {
            idle = false;
            writeError(e.status, e.getMessage());
            return false;
        } catch (IOException e) {
            if (!server.isRunning() && idle) {
                return false;
            }
            throw e;
        }
        idle = false;
        if (request == null) {
            return false;
        }

        Response response;
        try {
            response = handler.handle(request);
            if (response == null) {
                throw new NullPointerException("handler returned null response");
            }
        } catch (HttpError e) {
            writeError(e.status, e.getMessage());
            return false;
        } catch (Throwable t) {
            response = invokeErrorHandler(request, t);
            if (response == null) {
                writeError(500, "Internal Server Error");
                return false;
            }
        }

        if (response.webSocketListener != null) {
            handleWebSocketUpgrade(request, response);
            return false;
        }

        boolean keepAlive;
        try {
            keepAlive = writeResponse(request, response);
        } catch (IllegalArgumentException e) {
            LOG.log(Level.WARNING, "invalid response from handler", e);
            writeError(500, "Internal Server Error");
            return false;
        }
        return drainBody() && keepAlive;
    }

    /**
     * Validates the WebSocket handshake, writes the 101 Switching Protocols
     * response, then runs the WebSocket read loop on the current virtual
     * thread. On return the underlying socket is closed.
     */
    private void handleWebSocketUpgrade(Request request, Response response) throws IOException {
        String upgrade = request.header("upgrade");
        String connection = request.header("connection");
        String key = request.header("sec-websocket-key");
        String version = request.header("sec-websocket-version");
        if (upgrade == null || !upgrade.equalsIgnoreCase("websocket")
            || connection == null || !containsToken(connection, "upgrade")
            || key == null || key.isEmpty()
            || version == null || !version.equals("13")) {
            writeError(400, "Invalid WebSocket handshake");
            return;
        }
        flushHbuf();
        String accept = WebSocketConnection.computeAccept(key.trim());
        StringBuilder sb = new StringBuilder(256);
        sb.append("HTTP/1.1 101 Switching Protocols\r\n")
          .append("Upgrade: websocket\r\n")
          .append("Connection: Upgrade\r\n")
          .append("Sec-WebSocket-Accept: ").append(accept).append("\r\n");
        if (response.webSocketProtocol != null) {
            sb.append("Sec-WebSocket-Protocol: ").append(response.webSocketProtocol).append("\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        int maxMessage = (int) Math.min(Integer.MAX_VALUE, config.maxRequestBodyBytes > 0
                                        ? config.maxRequestBodyBytes
                                        : 10L * 1024 * 1024);
        WebSocketConnection ws = new WebSocketConnection(socket, in, out,
                                                         response.webSocketListener, maxMessage);
        ws.run();
    }

    private static boolean containsToken(String header, String token) {
        int i = 0;
        int len = header.length();
        while (i < len) {
            while (i < len && (header.charAt(i) == ' ' || header.charAt(i) == ',')) {
                i++;
            }
            int start = i;
            while (i < len && header.charAt(i) != ',') {
                i++;
            }
            int end = i;
            while (end > start && header.charAt(end - 1) == ' ') {
                end--;
            }
            if (end - start == token.length()
                && header.regionMatches(true, start, token, 0, token.length())) {
                return true;
            }
        }
        return false;
    }

    private Response invokeErrorHandler(Request request, Throwable t) {
        RingErrorHandler eh = server.errorHandler();
        if (eh == null) {
            LOG.log(Level.WARNING, "unhandled handler exception", t);
            return null;
        }
        try {
            Response r = eh.handle(request, t);
            if (r == null) {
                LOG.log(Level.WARNING, "error handler returned nil", t);
            }
            return r;
        } catch (Throwable inner) {
            LOG.log(Level.WARNING, "original handler exception", t);
            LOG.log(Level.WARNING, "error handler itself threw", inner);
            return null;
        }
    }

    private Request parseRequest() throws IOException {
        int lineEnd = scanLine();
        while (lineEnd == pos) {
            pos += 2;
            lineEnd = scanLine();
        }
        if (lineEnd < 0) {
            if (pos == limit) {
                return null;
            }
            throw new HttpError(400, "Bad Request");
        }

        int sp1 = indexOf(pos, lineEnd, (byte) ' ');
        int sp2 = sp1 < 0 ? -1 : indexOf(sp1 + 1, lineEnd, (byte) ' ');
        if (sp1 < 0 || sp2 < 0) {
            throw new HttpError(400, "Bad Request");
        }
        String method = method(pos, sp1);
        int q = indexOf(sp1 + 1, sp2, (byte) '?');
        String uri;
        String queryString;
        if (q < 0) {
            uri = str(sp1 + 1, sp2);
            queryString = null;
        } else {
            uri = str(sp1 + 1, q);
            queryString = str(q + 1, sp2);
        }
        String protocol;
        if (lineEnd - sp2 - 1 == 8 && matches(sp2 + 1, "HTTP/1.")) {
            byte minor = buf[lineEnd - 1];
            if (minor == '1') {
                protocol = "HTTP/1.1";
            } else if (minor == '0') {
                protocol = "HTTP/1.0";
            } else {
                throw new HttpError(505, "HTTP Version Not Supported");
            }
        } else {
            throw new HttpError(505, "HTTP Version Not Supported");
        }
        pos = lineEnd + 2;

        IPersistentMap headers = parseHeaders();

        String transferEncoding = (String) headers.valAt("transfer-encoding");
        String contentLengthHeader = (String) headers.valAt("content-length");
        RequestBody body = null;
        if (transferEncoding != null) {
            if (!isChunkedTerminal(transferEncoding)) {
                throw new HttpError(501, "Not Implemented");
            }
            if (contentLengthHeader != null) {
                // per RFC 7230 §3.3.3: if both present, must be treated as error
                throw new HttpError(400, "Bad Request");
            }
            body = new ChunkedBody();
        } else if (contentLengthHeader != null) {
            long contentLength;
            try {
                contentLength = Long.parseLong(contentLengthHeader);
            } catch (NumberFormatException e) {
                throw new HttpError(400, "Bad Request");
            }
            if (contentLength < 0) {
                throw new HttpError(400, "Bad Request");
            }
            if (config.maxRequestBodyBytes > 0 && contentLength > config.maxRequestBodyBytes) {
                throw new HttpError(413, "Content Too Large");
            }
            if (contentLength > 0) {
                body = new FixedLengthBody(contentLength);
            }
        }
        if ("100-continue".equalsIgnoreCase((String) headers.valAt("expect"))) {
            flushHbuf();
            out.write(CONTINUE_100);
            out.flush();
        }
        currentBody = body;
        return new Request(method, uri, queryString, protocol, headers, body,
                           socket.getInetAddress(), socket.getLocalPort());
    }

    private static boolean isChunkedTerminal(String te) {
        int i = te.lastIndexOf(',');
        String last = (i < 0 ? te : te.substring(i + 1)).trim();
        return last.equalsIgnoreCase("chunked");
    }

    private IPersistentMap parseHeaders() throws IOException {
        // Reused Object[] scratch: [k0, v0, k1, v1, ...]. Linear scan for
        // duplicate names — for typical <15 header requests it's faster than
        // HashMap probing and skips the HashMap + Node[] + N Node allocations.
        headerScratchLen = 0;
        while (true) {
            int start = pos;
            int i = start;
            int colon = -1;
            while (true) {
                while (i + 1 < limit) {
                    byte b = buf[i];
                    if (b == ':' && colon < 0) {
                        colon = i;
                    } else if (b == '\r' && buf[i + 1] == '\n') {
                        break;
                    }
                    i++;
                }
                if (i + 1 < limit) {
                    break;
                }
                if (limit == buf.length) {
                    if (buf.length >= config.maxHeaderBytes) {
                        throw new HttpError(431, "Request Header Fields Too Large");
                    }
                    buf = Arrays.copyOf(buf, Math.min(buf.length * 2, config.maxHeaderBytes));
                }
                flushHbuf();
                int n = socketRead(buf, limit, buf.length - limit);
                if (n < 0) {
                    throw new HttpError(400, "Bad Request");
                }
                limit += n;
            }
            int lineEnd = i;
            if (lineEnd == start) {
                pos = lineEnd + 2;
                if (headerScratchLen == 0) {
                    return PersistentArrayMap.EMPTY;
                }
                Object[] copy = new Object[headerScratchLen];
                System.arraycopy(headerScratch, 0, copy, 0, headerScratchLen);
                return (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(copy);
            }
            // RFC 7230 §3.2.4: obs-fold (a header line starting with SP or HTAB
            // is a continuation of the previous one) is deprecated and must be
            // rejected. Divergent proxy interpretations enable request smuggling.
            byte first = buf[start];
            if (first == ' ' || first == '\t') {
                throw new HttpError(400, "Bad Request");
            }
            if (colon <= start) {
                throw new HttpError(400, "Bad Request");
            }
            String name = HeaderNames.lookup(buf, start, colon);
            if (name == null) {
                name = lowerAscii(start, colon);
            }
            int vs = colon + 1;
            while (vs < lineEnd && (buf[vs] == ' ' || buf[vs] == '\t')) {
                vs++;
            }
            int ve = lineEnd;
            while (ve > vs && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t')) {
                ve--;
            }
            String value = str(vs, ve);
            // Linear duplicate scan across scratch. Fast for typical N < 15.
            int dupIdx = -1;
            for (int j = 0; j < headerScratchLen; j += 2) {
                Object k = headerScratch[j];
                if (k == name || name.equals(k)) {
                    dupIdx = j;
                    break;
                }
            }
            if (dupIdx >= 0) {
                if (name.equals("content-length")) {
                    // Request-smuggling vector; reject.
                    throw new HttpError(400, "Bad Request");
                }
                headerScratch[dupIdx + 1] = ((String) headerScratch[dupIdx + 1]) + "," + value;
            } else {
                if (headerScratchLen + 2 > headerScratch.length) {
                    headerScratch = Arrays.copyOf(headerScratch, headerScratch.length * 2);
                }
                headerScratch[headerScratchLen++] = name;
                headerScratch[headerScratchLen++] = value;
            }
            pos = lineEnd + 2;
        }
    }

    private boolean writeResponse(Request request, Response response) throws IOException {
        // Validate response headers before any byte hits hbuf; a bad header now
        // surfaces as IllegalArgumentException with hbuf untouched, so the
        // catch in handleOne can send a clean 500 without splicing garbage.
        validateHeaders(response.headers);

        boolean keepAlive = request.protocol.equals("HTTP/1.1")
            && !"close".equalsIgnoreCase(request.header("connection"));

        int status = response.status;
        Object body = response.body;
        byte[] bodyBytes = null;
        String asciiBody = null;
        int asciiBodyLen = 0;
        InputStream bodyStream = null;
        File bodyFile = null;
        StreamingBody streamingBody = null;
        if (body instanceof String s) {
            int len = s.length();
            boolean ascii = true;
            for (int i = 0; i < len; i++) {
                if (s.charAt(i) > 127) {
                    ascii = false;
                    break;
                }
            }
            if (ascii) {
                asciiBody = s;
                asciiBodyLen = len;
            } else {
                bodyBytes = s.getBytes(StandardCharsets.UTF_8);
            }
        } else if (body instanceof byte[] b) {
            bodyBytes = b;
        } else if (body instanceof InputStream is) {
            bodyStream = is;
        } else if (body instanceof File f) {
            bodyFile = f;
        } else if (body instanceof StreamingBody sb) {
            streamingBody = sb;
        } else if (body != null) {
            throw new IllegalArgumentException("unsupported response body type: " + body.getClass().getName());
        }

        boolean noBody = status < 200 || status == 204 || status == 304;
        boolean head = request.method.equals("HEAD");

        hAppend(statusLine(status));

        boolean hasContentLength = false;
        long declaredLength = -1;
        boolean hasDate = false;
        boolean hasTransferEncoding = false;
        String connectionHeader = null;
        if (response.headers != null) {
            for (Map.Entry<?, ?> e : response.headers.entrySet()) {
                Object key = e.getKey();
                String name = key instanceof String s ? s : String.valueOf(key);
                Object value = e.getValue();
                switch (name.length()) {
                    case 14 -> {
                        if (name.equalsIgnoreCase("content-length")) {
                            hasContentLength = true;
                            declaredLength = parseContentLength(value);
                        }
                    }
                    case 4 -> hasDate = hasDate || name.equalsIgnoreCase("date");
                    case 10 -> {
                        if (name.equalsIgnoreCase("connection")) {
                            connectionHeader = String.valueOf(value);
                        }
                    }
                    case 17 -> hasTransferEncoding = hasTransferEncoding || name.equalsIgnoreCase("transfer-encoding");
                    default -> {
                    }
                }
                if (value instanceof List<?> values) {
                    for (Object v : values) {
                        hHeader(name, v);
                    }
                } else {
                    hHeader(name, value);
                }
            }
        }
        if ("close".equalsIgnoreCase(connectionHeader)) {
            keepAlive = false;
        }
        if (!hasDate) {
            hAppend(HttpDates.dateLine());
        }

        boolean useChunked = false;
        boolean useStreaming = false;
        if (!noBody && !hasContentLength && !hasTransferEncoding) {
            if (streamingBody != null) {
                if (request.protocol.equals("HTTP/1.1") && keepAlive) {
                    useStreaming = true;
                    hAppend(TE_CHUNKED);
                } else {
                    // no framing available on HTTP/1.0; must close
                    useStreaming = true;
                    keepAlive = false;
                }
            } else if (bodyStream != null) {
                if (request.protocol.equals("HTTP/1.1") && keepAlive) {
                    useChunked = true;
                    hAppend(TE_CHUNKED);
                } else {
                    keepAlive = false;
                }
            } else {
                long len = bodyBytes != null ? bodyBytes.length
                    : asciiBody != null ? asciiBodyLen
                    : bodyFile != null ? bodyFile.length() : 0;
                hAppend(CONTENT_LENGTH);
                hAppendLong(len);
                hCrlf();
            }
        }
        if (!keepAlive && connectionHeader == null) {
            hAppend(CONNECTION_CLOSE);
        }
        hCrlf();

        boolean inlineOnly = (noBody || head)
            || (bodyBytes != null && bodyBytes.length <= config.maxInlineBody)
            || (asciiBody != null && asciiBodyLen <= config.maxInlineBody)
            || (bodyBytes == null && asciiBody == null && bodyStream == null
                && bodyFile == null && streamingBody == null);

        if (!noBody && !head) {
            if (streamingBody != null) {
                flushHbuf();
                boolean framed = useStreaming && request.protocol.equals("HTTP/1.1") && keepAlive;
                ChunkedWriter writer = new ChunkedWriter(out, config.chunkBufferSize, framed);
                try {
                    streamingBody.write(writer);
                } finally {
                    writer.closeInternal();
                }
            } else if (asciiBody != null) {
                if (asciiBodyLen <= config.maxInlineBody) {
                    hAppendAscii(asciiBody, asciiBodyLen);
                } else {
                    flushHbuf();
                    writeAsciiDirect(asciiBody, asciiBodyLen);
                }
            } else if (bodyBytes != null) {
                if (bodyBytes.length <= config.maxInlineBody) {
                    hAppend(bodyBytes);
                } else {
                    flushHbuf();
                    out.write(bodyBytes);
                }
            } else if (bodyStream != null) {
                flushHbuf();
                try (InputStream is = bodyStream) {
                    if (useChunked) {
                        writeChunked(is);
                    } else if (declaredLength >= 0) {
                        // fixed-length response: guarantee we ship exactly
                        // declaredLength bytes; short stream forces close so
                        // the client detects truncation.
                        long written = boundedTransfer(is, out, declaredLength);
                        if (written < declaredLength) {
                            keepAlive = false;
                        }
                    } else {
                        is.transferTo(out);
                    }
                }
            } else if (bodyFile != null) {
                flushHbuf();
                sendFile(bodyFile);
            }
        } else if (bodyStream != null) {
            bodyStream.close();
        }

        if (!inlineOnly || !keepAlive || pos >= limit || hlen >= config.coalesceHighWater) {
            flushHbuf();
        }
        return keepAlive;
    }

    private static final byte[] HEX = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

    private static long parseContentLength(Object value) {
        String s;
        if (value instanceof Number n) {
            return n.longValue();
        } else if (value instanceof String str) {
            s = str;
        } else {
            s = String.valueOf(value);
        }
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Copies up to {@code limit} bytes from {@code is} to {@code out}. Returns
     * the number of bytes actually written (may be less than {@code limit} if
     * the stream ended early). Excess bytes on the stream are not read; the
     * stream is closed by the caller.
     */
    private long boundedTransfer(InputStream is, OutputStream out, long limit) throws IOException {
        byte[] scratch = chunkBuf;
        if (scratch == null) {
            scratch = new byte[config.chunkBufferSize];
            chunkBuf = scratch;
        }
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
     * {@link com.s_exp.enso.TlsSocket.AdapterSocket} takes this path because
     * the ciphertext has to pass through {@link javax.net.ssl.SSLEngine} first.
     */
    private void sendFile(File file) throws IOException {
        SocketChannel sc = socket.getChannel();
        if (sc == null) {
            try (var fis = new FileInputStream(file)) {
                fis.transferTo(out);
            }
            return;
        }
        try (FileChannel fc = FileChannel.open(file.toPath(), StandardOpenOption.READ)) {
            long remaining = fc.size();
            long position = 0;
            while (remaining > 0) {
                long n = fc.transferTo(position, remaining, sc);
                if (n <= 0) {
                    break;
                }
                position += n;
                remaining -= n;
            }
        }
    }

    private void writeChunked(InputStream body) throws IOException {
        byte[] chunk = chunkBuf;
        if (chunk == null) {
            chunk = new byte[config.chunkBufferSize];
            chunkBuf = chunk;
        }
        int chunkLen = chunk.length;
        while (true) {
            int n = body.read(chunk);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                continue;
            }
            hAppendHex(n);
            hCrlf();
            hAppend(chunk, 0, n);
            hCrlf();
            flushHbuf();
        }
        out.write(CHUNK_END);
    }

    private void hAppendHex(int v) {
        int digits = 1;
        int t = v;
        while ((t >>>= 4) != 0) {
            digits++;
        }
        hEnsure(digits);
        for (int i = digits - 1; i >= 0; i--) {
            hbuf[hlen + i] = HEX[v & 0xF];
            v >>>= 4;
        }
        hlen += digits;
    }

    private boolean drainBody() throws IOException {
        RequestBody body = currentBody;
        currentBody = null;
        if (body == null || body.isFinished()) {
            return true;
        }
        return body.drain(config.maxDrainBytes);
    }

    private void writeError(int status, String message) {
        try {
            flushHbuf();
            byte[] body = message.getBytes(StandardCharsets.UTF_8);
            hAppend(statusLine(status));
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

    private void compact() {
        if (pos > 0) {
            if (pos < limit) {
                System.arraycopy(buf, pos, buf, 0, limit - pos);
            }
            limit -= pos;
            pos = 0;
        }
    }

    /** Returns the index of the CR of the next CRLF, or -1 on EOF. */
    private int scanLine() throws IOException {
        int i = pos;
        while (true) {
            while (i + 1 < limit) {
                if (buf[i] == '\r' && buf[i + 1] == '\n') {
                    return i;
                }
                i++;
            }
            if (limit == buf.length) {
                if (buf.length >= config.maxHeaderBytes) {
                    throw new HttpError(431, "Request Header Fields Too Large");
                }
                buf = Arrays.copyOf(buf, Math.min(buf.length * 2, config.maxHeaderBytes));
            }
            flushHbuf();
            int n = socketRead(buf, limit, buf.length - limit);
            if (n < 0) {
                return -1;
            }
            limit += n;
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
        int chunk = Math.min(len, 8192);
        byte[] scratch = new byte[chunk];
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
        int digits = 1;
        for (long t = v; t >= 10; t /= 10) {
            digits++;
        }
        hEnsure(digits);
        int end = hlen + digits;
        for (int i = end - 1; i >= hlen; i--) {
            hbuf[i] = (byte) ('0' + (v % 10));
            v /= 10;
        }
        hlen = end;
    }

    private void hCrlf() {
        hEnsure(2);
        hbuf[hlen++] = '\r';
        hbuf[hlen++] = '\n';
    }

    private void hHeader(String name, Object value) {
        hAppend(name);
        hEnsure(2);
        hbuf[hlen++] = ':';
        hbuf[hlen++] = ' ';
        if (value instanceof String s) {
            hAppend(s);
        } else if (value instanceof Long l) {
            hAppendLong(l);
        } else if (value instanceof Integer i) {
            hAppendLong(i);
        } else {
            hAppend(String.valueOf(value));
        }
        hCrlf();
    }

    /**
     * Guards against response header injection: a handler-supplied header name
     * or value containing CR or LF would split the response and let an attacker
     * inject arbitrary headers or a fake response body. Validated upfront so
     * the throw happens before any byte is written to {@code hbuf}.
     */
    private static void rejectCrlf(String s) {
        int len = s.length();
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == 0) {
                throw new IllegalArgumentException(
                    "response header name/value contains illegal control character");
            }
        }
    }

    private static void validateHeaders(Map<?, ?> headers) {
        if (headers == null) {
            return;
        }
        for (Map.Entry<?, ?> e : headers.entrySet()) {
            Object key = e.getKey();
            String name = key instanceof String s ? s : String.valueOf(key);
            rejectCrlf(name);
            Object value = e.getValue();
            if (value instanceof List<?> values) {
                for (Object v : values) {
                    if (v instanceof String s) {
                        rejectCrlf(s);
                    } else if (!(v instanceof Number)) {
                        rejectCrlf(String.valueOf(v));
                    }
                }
            } else if (value instanceof String s) {
                rejectCrlf(s);
            } else if (!(value instanceof Number)) {
                rejectCrlf(String.valueOf(value));
            }
        }
    }

    private static byte[] statusLine(int status) {
        if (status >= 100 && status < 600) {
            byte[] line = STATUS_LINES[status];
            if (line == null) {
                line = buildStatusLine(status);
                STATUS_LINES[status] = line;
            }
            return line;
        }
        return buildStatusLine(status);
    }

    private static byte[] buildStatusLine(int status) {
        return ("HTTP/1.1 " + status + " " + reason(status) + "\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    }

    private boolean matches(int from, String s) {
        for (int i = 0; i < s.length(); i++) {
            if (buf[from + i] != s.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private String method(int from, int to) {
        int len = to - from;
        switch (buf[from]) {
            case 'G' -> {
                if (len == 3 && buf[from + 1] == 'E' && buf[from + 2] == 'T') return "GET";
            }
            case 'P' -> {
                if (len == 4 && buf[from + 1] == 'O' && buf[from + 2] == 'S' && buf[from + 3] == 'T') return "POST";
                if (len == 3 && buf[from + 1] == 'U' && buf[from + 2] == 'T') return "PUT";
                if (len == 5 && matches(from, "PATCH")) return "PATCH";
            }
            case 'H' -> {
                if (len == 4 && matches(from, "HEAD")) return "HEAD";
            }
            case 'D' -> {
                if (len == 6 && matches(from, "DELETE")) return "DELETE";
            }
            case 'O' -> {
                if (len == 7 && matches(from, "OPTIONS")) return "OPTIONS";
            }
            case 'C' -> {
                if (len == 7 && matches(from, "CONNECT")) return "CONNECT";
            }
            case 'T' -> {
                if (len == 5 && matches(from, "TRACE")) return "TRACE";
            }
            default -> {
            }
        }
        return str(from, to);
    }

    private int indexOf(int from, int to, byte b) {
        for (int i = from; i < to; i++) {
            if (buf[i] == b) {
                return i;
            }
        }
        return -1;
    }

    private String str(int from, int to) {
        return new String(buf, from, to - from, StandardCharsets.ISO_8859_1);
    }

    private String lowerAscii(int from, int to) {
        int len = to - from;
        char[] chars = new char[len];
        for (int i = 0; i < len; i++) {
            char c = (char) (buf[from + i] & 0xFF);
            if (c >= 'A' && c <= 'Z') {
                c += 32;
            }
            chars[i] = c;
        }
        return new String(chars);
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 303 -> "See Other";
            case 304 -> "Not Modified";
            case 307 -> "Temporary Redirect";
            case 308 -> "Permanent Redirect";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 408 -> "Request Timeout";
            case 411 -> "Length Required";
            case 413 -> "Content Too Large";
            case 431 -> "Request Header Fields Too Large";
            case 500 -> "Internal Server Error";
            case 501 -> "Not Implemented";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 505 -> "HTTP Version Not Supported";
            default -> "";
        };
    }

    private abstract class RequestBody extends InputStream {

        @Override
        public final int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xFF;
        }

        abstract boolean isFinished();

        boolean drain(long maxBytes) throws IOException {
            // response fully written at this point, hbuf is free scratch
            if (hbuf.length < 4096) {
                hbuf = new byte[4096];
            }
            long total = 0;
            while (!isFinished()) {
                int n = read(hbuf, 0, hbuf.length);
                if (n < 0) {
                    break;
                }
                total += n;
                if (total > maxBytes) {
                    return false;
                }
            }
            return true;
        }
    }

    private final class FixedLengthBody extends RequestBody {

        private long remaining;

        FixedLengthBody(long remaining) {
            this.remaining = remaining;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            len = (int) Math.min(len, remaining);
            int n;
            if (pos < limit) {
                n = Math.min(len, limit - pos);
                System.arraycopy(buf, pos, b, off, n);
                pos += n;
            } else {
                flushHbuf();
                n = socketRead(b, off, len);
                if (n < 0) {
                    throw new EOFException("unexpected EOF reading request body");
                }
            }
            remaining -= n;
            return n;
        }

        @Override
        public int available() {
            return pos < limit ? (int) Math.min(remaining, limit - pos) : 0;
        }

        @Override
        boolean isFinished() {
            return remaining == 0;
        }
    }

    private final class ChunkedBody extends RequestBody {

        private long chunkRemaining;
        private long totalRead;
        private boolean finished;
        private boolean started;

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (finished) {
                return -1;
            }
            if (chunkRemaining == 0) {
                if (started) {
                    consumeCrlf();
                }
                started = true;
                chunkRemaining = readChunkSize();
                if (chunkRemaining == 0) {
                    readTrailerAndTerminator();
                    finished = true;
                    return -1;
                }
                long cap = config.maxRequestBodyBytes;
                if (cap > 0 && totalRead + chunkRemaining > cap) {
                    throw new HttpError(413, "Content Too Large");
                }
            }
            len = (int) Math.min(len, chunkRemaining);
            int n;
            if (pos < limit) {
                n = Math.min(len, limit - pos);
                System.arraycopy(buf, pos, b, off, n);
                pos += n;
            } else {
                flushHbuf();
                n = socketRead(b, off, len);
                if (n < 0) {
                    throw new EOFException("unexpected EOF in chunk data");
                }
            }
            chunkRemaining -= n;
            totalRead += n;
            return n;
        }

        @Override
        public int available() {
            return pos < limit ? (int) Math.min(chunkRemaining, limit - pos) : 0;
        }

        @Override
        boolean isFinished() {
            return finished;
        }

        private long readChunkSize() throws IOException {
            int lineEnd = scanLine();
            if (lineEnd < 0) {
                throw new EOFException("unexpected EOF in chunk size");
            }
            int end = lineEnd;
            int semi = indexOf(pos, lineEnd, (byte) ';');
            if (semi >= 0) {
                end = semi;
            }
            long size = 0;
            int start = pos;
            if (start == end) {
                throw new IOException("empty chunk size");
            }
            for (int i = start; i < end; i++) {
                int digit = hexDigit(buf[i]);
                if (digit < 0) {
                    throw new IOException("invalid chunk size");
                }
                // Reject before the shift so any additional digit past 16 hex
                // digits fails cleanly instead of wrapping into a negative long.
                if ((size & 0xF000_0000_0000_0000L) != 0) {
                    throw new IOException("chunk size overflow");
                }
                size = (size << 4) | digit;
            }
            pos = lineEnd + 2;
            return size;
        }

        private void consumeCrlf() throws IOException {
            ensureBuffered(2);
            if (buf[pos] != '\r' || buf[pos + 1] != '\n') {
                throw new IOException("missing CRLF after chunk");
            }
            pos += 2;
        }

        private void readTrailerAndTerminator() throws IOException {
            while (true) {
                int lineEnd = scanLine();
                if (lineEnd < 0) {
                    throw new EOFException("unexpected EOF in trailer");
                }
                boolean empty = lineEnd == pos;
                pos = lineEnd + 2;
                if (empty) {
                    return;
                }
            }
        }

        private void ensureBuffered(int need) throws IOException {
            while (limit - pos < need) {
                if (limit == buf.length) {
                    compact();
                }
                flushHbuf();
                int n = socketRead(buf, limit, buf.length - limit);
                if (n < 0) {
                    throw new EOFException("unexpected EOF");
                }
                limit += n;
            }
        }

        private int hexDigit(byte b) {
            if (b >= '0' && b <= '9') return b - '0';
            if (b >= 'a' && b <= 'f') return b - 'a' + 10;
            if (b >= 'A' && b <= 'F') return b - 'A' + 10;
            return -1;
        }
    }
}

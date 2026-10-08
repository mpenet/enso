package com.s_exp.enso.http1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.StreamingBody;
import com.s_exp.enso.core.HeaderNames;
import com.s_exp.enso.core.HttpDates;
import com.s_exp.enso.core.HttpError;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.util.RingHeaders;
import com.s_exp.enso.websocket.WebSocketConnection;
import com.s_exp.enso.websocket.WebSocketListener;
import com.s_exp.enso.websocket.WebSocketSocket;

public final class HttpConnection implements Runnable {

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
    private static final byte[] SWITCHING_PROTOCOLS =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            .getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] SEC_WEBSOCKET_VERSION_13 =
        "Sec-WebSocket-Version: 13\r\n".getBytes(StandardCharsets.ISO_8859_1);
    // Filled for 100..599 in the static initializer below, so connection
    // threads only ever read fully built, safely published lines.
    private static final byte[][] STATUS_LINES = new byte[600][];
    /**
     * Request header field lines accepted per request before a 431 (same
     * default as Apache LimitRequestFields and Tomcat maxHeaderCount).
     */
    private static final int MAX_HEADER_FIELDS = 100;
    static {
        for (int status = 100; status < 600; status++) {
            STATUS_LINES[status] = buildStatusLine(status);
        }
    }

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
    public volatile boolean idle;
    /**
     * The WebSocket this connection was upgraded to, once its handshake is
     * written. Read by {@link EnsoServer#close} to close it gracefully.
     */
    private volatile WebSocketConnection webSocket;
    private long requestDeadlineNanos;
    private int currentSoTimeout = -1;
    private int servedRequests;

    public HttpConnection(Socket socket, RingHandler handler, EnsoServer server) {
        this.socket = socket;
        this.handler = handler;
        this.server = server;
        this.config = server.config();
        this.buf = new byte[Math.min(config.requestBufferSize, config.maxHeaderBytes)];
    }

    public Socket socketRef() {
        return socket;
    }

    public WebSocketConnection webSocket() {
        return webSocket;
    }

    @Override
    public void run() {
        server.register(this);
        try (Socket s = socket) {
            in = s.getInputStream();
            // BufferedOutputStream coalesces the small direct emissions
            // (100-Continue, CHUNK_END trailer, error responses) with
            // the following body write into a single syscall. Big writes
            // that exceed the buffer size pass through directly per
            // BufferedOutputStream's contract, so the streaming path
            // isn't split. Over TLS each flush becomes one record per
            // buffer's worth, so the buffer matches the 16 KiB record limit.
            int outBufferSize = s instanceof TlsSocket.AdapterSocket ? 16384 : 8192;
            out = new java.io.BufferedOutputStream(s.getOutputStream(), outBufferSize);
            while (server.isRunning() && handleOne()) {
                servedRequests++;
            }
            flushHbuf();
            out.flush();
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
     * Coalesced responses (pipelining) are pushed to the wire first: the peer
     * may be waiting on them before it sends the bytes this read waits for.
     */
    private int socketRead(byte[] dst, int off, int len) throws IOException {
        flushHbuf();
        out.flush();
        int requestTimeoutMs = config.requestTimeoutMillis;
        // Between requests, honor keepAliveTimeoutMillis if set (falls
        // back to idleTimeoutMillis). A fresh connection's first request
        // and mid-request reads use idleTimeoutMillis / the per-request
        // budget.
        int idleTimeoutMs = (idle && servedRequests > 0 && config.keepAliveTimeoutMillis > 0)
            ? config.keepAliveTimeoutMillis
            : config.idleTimeoutMillis;
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
            response = RingErrorHandler.respond(server.errorHandler(), request, t);
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
        // hbuf may already hold earlier pipelined responses; only bytes past
        // this mark belong to the response being written.
        int responseStart = hlen;
        try {
            keepAlive = writeResponse(request, response);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "invalid response from handler", e);
            // Discard any partial header bytes accumulated in hbuf before
            // the throw so the 500 is emitted cleanly. writeResponse only
            // lets exceptions escape before the headers leave hbuf.
            hlen = responseStart;
            writeError(500, "Internal Server Error");
            return false;
        }
        try {
            return drainBody() && keepAlive;
        } catch (HttpError e) {
            // The response is already written; an unreadable leftover body
            // only means the connection can't be reused.
            return false;
        }
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
        // RFC 6455 §4.1 / §4.2.1: a GET over HTTP/1.1 whose key is the
        // base64 of 16 bytes.
        if (!request.method.equals("GET") || !request.protocol.equals("HTTP/1.1")
            || upgrade == null || !upgrade.equalsIgnoreCase("websocket")
            || connection == null || !containsToken(connection, "upgrade")
            || !isWebSocketKey(key)
            || version == null) {
            writeError(400, "Invalid WebSocket handshake");
            return;
        }
        // §4.4: an unsupported version gets 426 naming the one we speak.
        if (!version.equals("13")) {
            writeError(426, "Unsupported WebSocket version", SEC_WEBSOCKET_VERSION_13);
            return;
        }
        // Reject upgrade requests carrying a body — RFC 6455 §4.1
        // doesn't forbid it, but any bytes past the request headers
        // would be misinterpreted as the first WebSocket frame after
        // upgrade → framing error / disconnect.
        if (currentBody != null) {
            writeError(400, "WebSocket upgrade cannot carry a request body");
            return;
        }
        // §4.1: the client fails the connection if the server selects a
        // subprotocol it didn't offer, so that's a handler error.
        String protocol = response.webSocketProtocol;
        String offered = request.header("sec-websocket-protocol");
        if (protocol != null && (offered == null || !containsToken(offered, protocol))) {
            LOG.log(Level.WARNING, "WebSocket subprotocol not offered by the client: {0}", protocol);
            writeError(500, "Internal Server Error");
            return;
        }
        int responseStart = hlen;
        try {
            hAppend(SWITCHING_PROTOCOLS);
            hHeader("Sec-WebSocket-Accept", WebSocketConnection.computeAccept(key));
            if (protocol != null) {
                hHeader("Sec-WebSocket-Protocol", protocol);
            }
            if (response.headers != null) {
                for (Map.Entry<?, ?> e : response.headers.entrySet()) {
                    Object k = e.getKey();
                    String name = k instanceof String s ? s : String.valueOf(k);
                    if (!isUpgradeOwnedHeader(name)) {
                        hHeaderValues(name, e.getValue());
                    }
                }
            }
            hCrlf();
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "invalid WebSocket upgrade response from handler", e);
            hlen = responseStart;
            writeError(500, "Internal Server Error");
            return;
        }
        flushHbuf();
        out.flush();

        // The request-read budget doesn't apply to the WebSocket; reads are
        // bound by the idle timeout alone (0 = none).
        socket.setSoTimeout(config.idleTimeoutMillis);
        // Frames the client sent right behind the handshake already sit in
        // buf; they are read before the socket.
        InputStream wsIn = pos < limit
            ? new SequenceInputStream(new ByteArrayInputStream(buf, pos, limit - pos), in)
            : in;
        pos = limit;
        // :max-request-body-bytes caps WebSocket messages too. Messages are
        // buffered whole, so a disabled body cap (0) falls back to 10 MiB.
        int maxMessage = (int) Math.min(Integer.MAX_VALUE, config.maxRequestBodyBytes > 0
                                        ? config.maxRequestBodyBytes
                                        : 10L * 1024 * 1024);
        WebSocketConnection ws = new WebSocketConnection(socket, wsIn, out,
                                                         response.webSocketListener, maxMessage);
        webSocket = ws;
        // A shutdown that began before the field was set didn't see this
        // WebSocket, so it closes itself.
        if (!server.isRunning()) {
            ws.shutdown();
        }
        ws.run();
    }

    private static boolean isWebSocketKey(String key) {
        if (key == null) {
            return false;
        }
        try {
            return Base64.getDecoder().decode(key).length == 16;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Headers the 101 response sets itself or that make no sense on it. */
    private static boolean isUpgradeOwnedHeader(String name) {
        return name.equalsIgnoreCase("upgrade")
            || name.equalsIgnoreCase("connection")
            || name.equalsIgnoreCase("sec-websocket-accept")
            || name.equalsIgnoreCase("sec-websocket-protocol")
            || name.equalsIgnoreCase("content-length")
            || name.equalsIgnoreCase("transfer-encoding");
    }

    /** {@link #containsToken} over a response header value, one field line per list element. */
    private static boolean valueContainsToken(Object value, String token) {
        if (value instanceof List<?> values) {
            for (Object v : values) {
                if (v != null && containsToken(String.valueOf(v), token)) {
                    return true;
                }
            }
            return false;
        }
        return value != null && containsToken(String.valueOf(value), token);
    }

    private static boolean containsToken(String header, String token) {
        int i = 0;
        int len = header.length();
        while (i < len) {
            while (i < len && (isOws(header.charAt(i)) || header.charAt(i) == ',')) {
                i++;
            }
            int start = i;
            while (i < len && header.charAt(i) != ',') {
                i++;
            }
            int end = i;
            while (end > start && isOws(header.charAt(end - 1))) {
                end--;
            }
            if (end - start == token.length()
                && header.regionMatches(true, start, token, 0, token.length())) {
                return true;
            }
        }
        return false;
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
        // Empty method or empty request-target is malformed (RFC 9112 §3).
        if (sp1 <= pos || sp2 <= sp1 + 1) {
            throw new HttpError(400, "Bad Request");
        }
        String method = method(pos, sp1);
        int q = scanTarget(sp1 + 1, sp2);
        String uri;
        String queryString;
        if (q < 0) {
            uri = str(sp1 + 1, sp2);
            queryString = null;
        } else {
            uri = str(sp1 + 1, q);
            queryString = str(q + 1, sp2);
        }
        // HTTP-version = "HTTP/" DIGIT "." DIGIT. Anything else (including a
        // target with a stray SP pushing junk here) is a syntax error → 400;
        // only a well-formed but unsupported version earns 505.
        if (lineEnd - sp2 - 1 != 8 || !matches(sp2 + 1, "HTTP/")
            || !isDigit(buf[sp2 + 6]) || buf[sp2 + 7] != '.' || !isDigit(buf[lineEnd - 1])) {
            throw new HttpError(400, "Bad Request");
        }
        String protocol;
        byte minor = buf[lineEnd - 1];
        if (buf[sp2 + 6] == '1' && minor == '1') {
            protocol = "HTTP/1.1";
        } else if (buf[sp2 + 6] == '1' && minor == '0') {
            protocol = "HTTP/1.0";
        } else {
            throw new HttpError(505, "HTTP Version Not Supported");
        }
        pos = lineEnd + 2;

        IPersistentMap headers = parseHeaders();

        // RFC 9112 §3.2: an HTTP/1.1 request lacking Host gets a 400.
        if (protocol.equals("HTTP/1.1") && headers.valAt("host") == null) {
            throw new HttpError(400, "Bad Request");
        }

        String transferEncoding = (String) headers.valAt("transfer-encoding");
        String contentLengthHeader = (String) headers.valAt("content-length");
        RequestBody body = null;
        if (transferEncoding != null) {
            validateTransferEncoding(transferEncoding, protocol);
            if (contentLengthHeader != null) {
                // per RFC 7230 §3.3.3: if both present, must be treated as error
                throw new HttpError(400, "Bad Request");
            }
            body = new ChunkedBody();
        } else if (contentLengthHeader != null) {
            long contentLength = parseDecimal(contentLengthHeader);
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
        // RFC 9110 §10.1.1: HTTP/1.0 expectations are ignored, 100 is only
        // useful when a body follows, and unknown expectations get 417.
        String expect = (String) headers.valAt("expect");
        if (expect != null && protocol.equals("HTTP/1.1")) {
            if (!expect.equalsIgnoreCase("100-continue")) {
                throw new HttpError(417, "Expectation Failed");
            }
            if (body != null) {
                flushHbuf();
                out.write(CONTINUE_100);
                out.flush();
            }
        }
        currentBody = body;
        return new Request(method, uri, queryString, protocol, headers, body,
                           socket.getInetAddress(), socket.getLocalPort(),
                           socket instanceof SSLSocket || socket instanceof TlsSocket.AdapterSocket
                               ? Request.K_HTTPS : Request.K_HTTP);
    }

    /**
     * Parses RFC 9110 §8.6 {@code Content-Length = 1*DIGIT}. Returns -1 for
     * anything else (sign, whitespace, list form, empty) or on long overflow,
     * where {@link Long#parseLong} would accept a leading '+' or '-'.
     */
    private static long parseDecimal(String s) {
        int len = s.length();
        if (len == 0) {
            return -1;
        }
        long v = 0;
        for (int i = 0; i < len; i++) {
            int d = s.charAt(i) - '0';
            if (d < 0 || d > 9 || v > (Long.MAX_VALUE - d) / 10) {
                return -1;
            }
            v = v * 10 + d;
        }
        return v;
    }

    /**
     * RFC 9112 §6.3: a request whose final transfer coding isn't chunked has
     * no determinable length → 400. chunked is the only coding decoded here,
     * so any coding before it → 501 (§6.1), except a repeated chunked, which
     * is malformed → 400. Transfer-Encoding on HTTP/1.0 is faulty framing
     * (§6.1) → 400.
     */
    private static void validateTransferEncoding(String te, String protocol) {
        int end = te.length();
        while (end > 0 && isOws(te.charAt(end - 1))) {
            end--;
        }
        int start = end;
        while (start > 0 && te.charAt(start - 1) != ',') {
            start--;
        }
        int s = start;
        while (s < end && isOws(te.charAt(s))) {
            s++;
        }
        boolean chunkedLast = end - s == 7 && te.regionMatches(true, s, "chunked", 0, 7);
        if (!chunkedLast || !protocol.equals("HTTP/1.1")) {
            throw new HttpError(400, "Bad Request");
        }
        for (int i = 0; i < start; i++) {
            char c = te.charAt(i);
            if (c != ',' && !isOws(c)) {
                String earlier = te.substring(0, start - 1);
                if (containsToken(earlier, "chunked")) {
                    throw new HttpError(400, "Bad Request");
                }
                throw new HttpError(501, "Not Implemented");
            }
        }
    }

    private static boolean isOws(char c) {
        return c == ' ' || c == '\t';
    }

    private IPersistentMap parseHeaders() throws IOException {
        // Reused Object[] scratch: [k0, v0, k1, v1, ...]. Duplicate names are
        // merged once at the end by a linear scan — for typical <15 header
        // requests it's faster than HashMap probing and skips the HashMap +
        // Node[] + N Node allocations. The field count cap keeps that scan
        // bounded.
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
                    // Compact before growing. Request line + prior header
                    // lines sit at [0..start); reclaim them so a request
                    // near maxHeaderBytes doesn't spuriously 431.
                    if (start > 0) {
                        int shift = start;
                        System.arraycopy(buf, start, buf, 0, limit - start);
                        limit -= shift;
                        pos -= shift;
                        start = 0;
                        i -= shift;
                        if (colon >= 0) colon -= shift;
                    }
                    if (limit == buf.length) {
                        if (buf.length >= config.maxHeaderBytes) {
                            throw new HttpError(431, "Request Header Fields Too Large");
                        }
                        buf = Arrays.copyOf(buf, Math.min(buf.length * 2, config.maxHeaderBytes));
                    }
                }
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
                // Copy first: mergeDuplicates hands back its input when it
                // has nothing to merge, and the scratch is reused. Its output
                // has unique keys, so the map skips a second dedupe pass.
                Object[] copy = Arrays.copyOf(headerScratch, headerScratchLen);
                return new PersistentArrayMap(RingHeaders.mergeDuplicates(copy, headerScratchLen));
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
            // RFC 7230 §3.2 field-name = token (tchar only). Whitespace or
            // CTL between name and ':' is a smuggling vector when a fronting
            // proxy tokenises differently.
            validateTokenBytes(start, colon);
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
            // NUL in a field value is a §3.2.6 protocol violation. CR/LF
            // are already excluded by the CRLF terminator scan.
            validateFieldValueBytes(vs, ve);
            String value = str(vs, ve);
            if (name.equals("content-length")
                || name.equals("transfer-encoding")
                || name.equals("host")) {
                // Request-smuggling vectors — duplicate framing headers
                // (RFC 9112 §6.1) or duplicate Host (§3.2.2) get rejected
                // rather than concatenated.
                for (int j = 0; j < headerScratchLen; j += 2) {
                    if (name.equals(headerScratch[j])) {
                        throw new HttpError(400, "Bad Request");
                    }
                }
            }
            if (headerScratchLen == 2 * MAX_HEADER_FIELDS) {
                throw new HttpError(431, "Request Header Fields Too Large");
            }
            if (headerScratchLen + 2 > headerScratch.length) {
                headerScratch = Arrays.copyOf(headerScratch, headerScratch.length * 2);
            }
            headerScratch[headerScratchLen++] = name;
            headerScratch[headerScratchLen++] = value;
            pos = lineEnd + 2;
        }
    }

    private boolean writeResponse(Request request, Response response) throws IOException {
        // Response header validation runs inline in hHeader — a single
        // snapshot of the Object value gets validated + written, closing
        // the TOCTOU where a racing toString could bypass a separate
        // pre-scan. On throw, handleOne resets hlen to discard any
        // partial hbuf state (nothing has flushed to the socket yet since
        // header emit doesn't call flushHbuf).
        String requestConnection = request.header("connection");
        // The last response this connection will carry (keep-alive cap
        // reached, server stopping) must say so: RFC 9112 §9.6. The cap on
        // keep-alive reuse per connection bounds resource hold time
        // (RFC-agnostic mitigation; nginx defaults to 1000).
        boolean keepAlive = request.protocol.equals("HTTP/1.1")
            && (requestConnection == null || !containsToken(requestConnection, "close"))
            && server.isRunning()
            && (config.maxKeepAliveRequests <= 0 || servedRequests + 1 < config.maxKeepAliveRequests);

        int status = response.status;
        Object body = response.body;
        byte[] bodyBytes = null;
        String asciiBody = null;
        int asciiBodyLen = 0;
        InputStream bodyStream = null;
        File bodyFile = null;
        StreamingBody streamingBody = null;
        if (body instanceof String s) {
            // Encoded with the Content-Type charset, as Ring does. ASCII text
            // is written char-by-char only where that charset encodes ASCII
            // as itself.
            Charset charset = HttpFields.responseCharset(response.headers);
            boolean ascii = charset.equals(StandardCharsets.UTF_8)
                || charset.equals(StandardCharsets.ISO_8859_1)
                || charset.equals(StandardCharsets.US_ASCII);
            int len = s.length();
            for (int i = 0; ascii && i < len; i++) {
                if (s.charAt(i) > 127) {
                    ascii = false;
                }
            }
            if (ascii) {
                asciiBody = s;
                asciiBodyLen = len;
            } else {
                bodyBytes = s.getBytes(charset);
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
        // The server frames bodies whose length it knows itself; a stale or
        // wrong handler Content-Length would desync keep-alive framing.
        boolean knownLength = !noBody && !head && bodyStream == null && streamingBody == null;

        // The body stream / file is closed however emission ends, including
        // a header validation failure before any body byte is read.
        FileChannel fileChannel = null;
        try {
            long fileLength = 0;
            if (bodyFile != null) {
                if (knownLength) {
                    // One open + size() serves both Content-Length and the
                    // transfer, so the two can't disagree.
                    try {
                        fileChannel = FileChannel.open(bodyFile.toPath(), StandardOpenOption.READ);
                        fileLength = fileChannel.size();
                    } catch (IOException e) {
                        throw new UncheckedIOException("unreadable response body file", e);
                    }
                } else {
                    fileLength = bodyFile.length();
                }
            }

            hAppend(statusLine(status));

            boolean hasContentLength = false;
            long declaredLength = -1;
            boolean hasDate = false;
            boolean hasAltSvc = false;
            boolean hasServer = false;
            boolean handlerSentClose = false;
            if (response.headers != null) {
                for (Map.Entry<?, ?> e : response.headers.entrySet()) {
                    Object key = e.getKey();
                    String name = key instanceof String s ? s : String.valueOf(key);
                    Object value = e.getValue();
                    switch (name.length()) {
                        case 14 -> {
                            if (name.equalsIgnoreCase("content-length")) {
                                // RFC 9110 §8.6: never sent on 1xx or 204.
                                if (knownLength || status < 200 || status == 204) {
                                    continue;
                                }
                                hasContentLength = true;
                                declaredLength = parseContentLength(value);
                            }
                        }
                        case 4 -> hasDate = hasDate || name.equalsIgnoreCase("date");
                        case 10 -> {
                            if (name.equalsIgnoreCase("connection")) {
                                handlerSentClose = handlerSentClose || valueContainsToken(value, "close");
                            }
                        }
                        case 7 -> hasAltSvc = hasAltSvc || name.equalsIgnoreCase("alt-svc");
                        case 6 -> hasServer = hasServer || name.equalsIgnoreCase("server");
                        case 17 -> {
                            // Framing is the server's: the body below is
                            // written by its own chunked / length logic.
                            if (name.equalsIgnoreCase("transfer-encoding")) {
                                continue;
                            }
                        }
                        default -> {
                        }
                    }
                    hHeaderValues(name, value);
                }
            }
            if (handlerSentClose) {
                keepAlive = false;
            }
            if (!hasDate) {
                hAppend(HttpDates.dateLine());
            }
            // Advertise the h3 endpoint via Alt-Svc so ALPN-aware clients can
            // upgrade on their next request. Handler-supplied Alt-Svc wins.
            if (!hasAltSvc && config.altSvcValue != null) {
                hHeader("alt-svc", config.altSvcValue);
            }
            if (!hasServer && config.serverHeader != null && !config.serverHeader.isEmpty()) {
                hHeader("server", config.serverHeader);
            }

            boolean useChunked = false;
            boolean useStreaming = false;
            if (!noBody && !hasContentLength) {
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
                        : bodyFile != null ? fileLength : 0;
                    hAppend(CONTENT_LENGTH);
                    hAppendLong(len);
                    hCrlf();
                }
            }
            // A handler-supplied Connection without "close" (e.g. keep-alive)
            // must not hide that the server is closing.
            if (!keepAlive && !handlerSentClose) {
                hAppend(CONNECTION_CLOSE);
            }
            hCrlf();

            boolean inlineOnly = (noBody || head)
                || (bodyBytes != null && bodyBytes.length <= config.maxInlineBody)
                || (asciiBody != null && asciiBodyLen <= config.maxInlineBody)
                || (bodyBytes == null && asciiBody == null && bodyStream == null
                    && bodyFile == null && streamingBody == null);

            if (!noBody && !head) {
                // Headers may already be on the wire past this point, so a
                // failing body can't become a 500: abort the connection so
                // the client sees the truncation.
                try {
                    if (streamingBody != null) {
                        flushHbuf();
                        boolean framed = useStreaming && request.protocol.equals("HTTP/1.1") && keepAlive;
                        FixedLengthOutputStream fixed = declaredLength >= 0
                            ? new FixedLengthOutputStream(out, declaredLength) : null;
                        ChunkedWriter writer = new ChunkedWriter(fixed != null ? fixed : out,
                                                                 config.chunkBufferSize, framed);
                        // No finally: a failed body must not end with the
                        // terminating chunk, which would make the truncated
                        // response look complete.
                        streamingBody.write(writer);
                        writer.closeInternal();
                        if (fixed != null && fixed.remaining > 0) {
                            keepAlive = false;
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
                        if (useChunked) {
                            writeChunked(bodyStream);
                        } else if (declaredLength >= 0) {
                            // fixed-length response: guarantee we ship exactly
                            // declaredLength bytes; short stream forces close so
                            // the client detects truncation.
                            long written = boundedTransfer(bodyStream, out, declaredLength);
                            if (written < declaredLength) {
                                keepAlive = false;
                            }
                        } else {
                            bodyStream.transferTo(out);
                        }
                    } else if (bodyFile != null) {
                        flushHbuf();
                        // A file that shrank since size() leaves the body
                        // short: close so the client detects it.
                        if (sendFile(fileChannel, fileLength) < fileLength) {
                            keepAlive = false;
                        }
                    }
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "response body failed, closing connection", e);
                    return false;
                }
            }

            if (!inlineOnly || !keepAlive || pos >= limit || hlen >= config.coalesceHighWater) {
                flushHbuf();
                // Push through the BufferedOutputStream layer so the response
                // hits the wire at end of request, not when the buffer fills.
                out.flush();
            }
            return keepAlive;
        } finally {
            if (bodyStream != null) {
                bodyStream.close();
            }
            if (fileChannel != null) {
                fileChannel.close();
            }
        }
    }

    private static final byte[] HEX = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * Parses a handler-declared Content-Length the way hHeader will emit it,
     * so the enforced length and the wire value agree. Anything that isn't
     * 1*DIGIT on the wire (sign, "5.0", a list) is a handler error.
     */
    private static long parseContentLength(Object value) {
        long n;
        if (value instanceof Long || value instanceof Integer) {
            n = ((Number) value).longValue();
        } else {
            String s = value instanceof String str ? str : String.valueOf(value);
            n = parseDecimal(s.trim());
        }
        if (n < 0) {
            throw new IllegalArgumentException("invalid Content-Length response header: " + value);
        }
        return n;
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
     * channel is closed by the caller.
     */
    private long sendFile(FileChannel fc, long length) throws IOException {
        SocketChannel sc = socket.getChannel();
        if (sc == null) {
            return boundedTransfer(Channels.newInputStream(fc), out, length);
        }
        // out is now a BufferedOutputStream (task #225). transferTo(sc)
        // writes directly to the socket underneath, so any headers still
        // sitting in the buffer would arrive AFTER the body. Flush first.
        out.flush();
        long position = 0;
        while (position < length) {
            long n = fc.transferTo(position, length - position, sc);
            if (n <= 0) {
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
    private byte[] chunkScratch() {
        byte[] scratch = chunkBuf;
        if (scratch == null) {
            scratch = new byte[config.chunkBufferSize];
            chunkBuf = scratch;
        }
        return scratch;
    }

    private void writeChunked(InputStream body) throws IOException {
        byte[] chunk = chunkScratch();
        while (true) {
            int n = body.read(chunk);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                continue;
            }
            // Only the size line goes through hbuf; the chunk itself is
            // written straight out so hbuf never grows to chunk size.
            hAppendHex(n);
            hCrlf();
            flushHbuf();
            out.write(chunk, 0, n);
            out.write(CRLF);
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
        writeError(status, message, null);
    }

    /** {@code extraHeaders}: preformatted field lines (each ending CRLF), or null. */
    private void writeError(int status, String message, byte[] extraHeaders) {
        try {
            flushHbuf();
            byte[] body = message.getBytes(StandardCharsets.UTF_8);
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
                // Compact stale front bytes (already consumed by earlier
                // parseRequestLine call) before growing. Avoids a 431
                // when the raw line would fit in maxHeaderBytes.
                if (pos > 0) {
                    int shift = pos;
                    System.arraycopy(buf, pos, buf, 0, limit - pos);
                    limit -= shift;
                    pos = 0;
                    i -= shift;
                }
                if (limit == buf.length) {
                    if (buf.length >= config.maxHeaderBytes) {
                        throw new HttpError(431, "Request Header Fields Too Large");
                    }
                    buf = Arrays.copyOf(buf, Math.min(buf.length * 2, config.maxHeaderBytes));
                }
            }
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

    /** One field line per element for a List value (e.g. Set-Cookie). */
    private void hHeaderValues(String name, Object value) {
        if (value instanceof List<?> values) {
            for (Object v : values) {
                hHeader(name, v);
            }
        } else {
            hHeader(name, value);
        }
    }

    private void hHeader(String name, Object value) {
        // Guards against response header injection: a handler-supplied
        // name or value containing CR or LF would split the response. Header
        // bytes are the low 8 bits of each char, so anything above U+00FF is
        // rejected too (U+010D would otherwise reach the wire as CR).
        // Validated before any byte is written to hbuf.
        // Snapshot Object → String once so validation matches emit exactly.
        // A separate pre-scan would let a racing toString() bypass the check
        // (TOCTOU); inline validation of the exact snapshot closes that gap.
        // Numbers can't contain CR/LF/NUL, skip snapshot on the hot path.
        HttpFields.checkResponseName(name);
        if (value instanceof Long || value instanceof Integer) {
            hAppend(name);
            hEnsure(2);
            hbuf[hlen++] = ':';
            hbuf[hlen++] = ' ';
            if (value instanceof Long l) hAppendLong(l);
            else hAppendLong((Integer) value);
            hCrlf();
            return;
        }
        String vs = value instanceof String s ? s : String.valueOf(value);
        HttpFields.checkResponseValue(vs);
        hAppend(name);
        hEnsure(2);
        hbuf[hlen++] = ':';
        hbuf[hlen++] = ' ';
        hAppend(vs);
        hCrlf();
    }

    private static byte[] statusLine(int status) {
        if (status >= 100 && status < 600) {
            return STATUS_LINES[status];
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
        // Uncommon or custom method: validate tchar-only per RFC 7230 §3.1.1.
        validateTokenBytes(from, to);
        return str(from, to);
    }

    private static boolean isDigit(byte b) {
        return b >= '0' && b <= '9';
    }

    /**
     * Rejects CTL / SP / DEL in the request-target (RFC 9112 §3.2) and
     * returns the index of the first '?', or -1, in the same pass.
     */
    private int scanTarget(int from, int to) {
        int q = -1;
        for (int i = from; i < to; i++) {
            int c = buf[i] & 0xFF;
            if (c <= 0x20 || c == 0x7F) {
                throw new HttpError(400, "Bad Request");
            }
            if (c == '?' && q < 0) {
                q = i;
            }
        }
        return q;
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

    /**
     * RFC 7230 §3.2.6 tchar validation. Rejects any byte outside the
     * token character set — protects against method/header-name smuggling
     * where a fronting proxy tokenises differently from us on SP/CTL/
     * control chars. Called on the header-name byte range in the request
     * buffer (must precede lowercasing so uppercase alpha is accepted).
     */
    private void validateTokenBytes(int from, int to) {
        for (int i = from; i < to; i++) {
            if (!HttpFields.isTchar(buf[i] & 0xFF)) {
                throw new HttpError(400, "Bad Request");
            }
        }
    }

    /** Reject NUL / CR / LF anywhere in the value bytes. */
    private void validateFieldValueBytes(int from, int to) {
        for (int i = from; i < to; i++) {
            int c = buf[i] & 0xFF;
            if (c == 0 || c == '\r' || c == '\n') {
                throw new HttpError(400, "Bad Request");
            }
        }
    }

    /**
     * Lowercased header name from validated tchar bytes. Names already in
     * lowercase (what HTTP/2-era clients send) become a String directly;
     * only mixed-case ones pay for a lowered copy first.
     */
    private String lowerAscii(int from, int to) {
        int firstUpper = from;
        while (firstUpper < to && (buf[firstUpper] < 'A' || buf[firstUpper] > 'Z')) {
            firstUpper++;
        }
        if (firstUpper == to) {
            return str(from, to);
        }
        byte[] lowered = Arrays.copyOfRange(buf, from, to);
        for (int i = firstUpper - from; i < lowered.length; i++) {
            byte b = lowered[i];
            if (b >= 'A' && b <= 'Z') {
                lowered[i] = (byte) (b + 32);
            }
        }
        return new String(lowered, StandardCharsets.ISO_8859_1);
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
            case 417 -> "Expectation Failed";
            case 426 -> "Upgrade Required";
            case 431 -> "Request Header Fields Too Large";
            case 500 -> "Internal Server Error";
            case 501 -> "Not Implemented";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 505 -> "HTTP Version Not Supported";
            default -> "";
        };
    }

    /**
     * Holds a {@link StreamingBody} to the Content-Length its handler
     * declared: writing past it fails before any excess byte reaches the
     * wire, and {@link #remaining} tells the caller whether it fell short.
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

    private abstract class RequestBody extends InputStream {

        // Reused single-byte scratch for read() so a client using
        // Reader.read()-style byte-at-a-time consumption doesn't allocate
        // per call. Thread-confined — one RequestBody per stream, and the
        // Ring handler runs on a single vthread.
        private final byte[] oneByte = new byte[1];

        @Override
        public final int read() throws IOException {
            return read(oneByte, 0, 1) < 0 ? -1 : oneByte[0] & 0xFF;
        }

        abstract boolean isFinished();

        boolean drain(long maxBytes) throws IOException {
            // hbuf may still hold a coalesced response, so drain into the
            // body copy buffer instead.
            byte[] scratch = chunkScratch();
            long total = 0;
            while (!isFinished()) {
                int n = read(scratch, 0, scratch.length);
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
                // Extensions are ignored but must not smuggle a bare LF/CR
                // or other CTL that a different parser would treat as a
                // line break ("funky chunks").
                for (int i = semi + 1; i < lineEnd; i++) {
                    int c = buf[i] & 0xFF;
                    if ((c < 0x20 && c != '\t') || c == 0x7F) {
                        throw new HttpError(400, "Bad Request");
                    }
                }
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
            // Cap total trailer bytes at maxHeaderBytes across all lines.
            // scanLine bounds each individual line; without this a peer
            // could stream unlimited short trailer lines and stall a
            // connection open (slowloris-adjacent).
            int totalBytes = 0;
            int cap = config.maxHeaderBytes;
            while (true) {
                int lineEnd = scanLine();
                if (lineEnd < 0) {
                    throw new EOFException("unexpected EOF in trailer");
                }
                // pos is read after scanLine, which may have compacted the
                // buffer and moved the line start.
                totalBytes += (lineEnd - pos) + 2; // include CRLF
                if (totalBytes > cap) {
                    throw new HttpError(431, "Request Header Fields Too Large");
                }
                if (lineEnd == pos) {
                    pos = lineEnd + 2;
                    return;
                }
                validateTrailerLine(pos, lineEnd);
                pos = lineEnd + 2;
            }
        }

        /** Trailer lines are field lines (RFC 9112 §7.1.2): token ":" value. */
        private void validateTrailerLine(int from, int to) {
            int colon = indexOf(from, to, (byte) ':');
            if (colon <= from) {
                throw new HttpError(400, "Bad Request");
            }
            validateTokenBytes(from, colon);
            validateFieldValueBytes(colon + 1, to);
        }

        private void ensureBuffered(int need) throws IOException {
            while (limit - pos < need) {
                if (limit == buf.length) {
                    compact();
                }
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

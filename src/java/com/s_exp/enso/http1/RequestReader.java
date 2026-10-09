// ABOUTME: HTTP/1.1 request side of a connection: the parse buffer, socket reads under the phase's
// ABOUTME: timeout, request line and header parsing, and request bodies (fixed-length, chunked).
package com.s_exp.enso.http1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.core.HeaderNames;
import com.s_exp.enso.core.HttpError;
import com.s_exp.enso.core.HttpStatus;
import com.s_exp.enso.core.RequestBodyException;
import com.s_exp.enso.core.RequestBodyTimeoutException;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.core.RequestHead;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.util.RingHeaders;

/**
 * Reads requests off one connection's socket, on the connection thread.
 *
 * <p>Each socket read is bounded by the current phase's timeout (see
 * {@link HttpConnection}): {@code :idle-timeout} while waiting for the
 * first byte of a request, the remaining {@code :header-timeout} budget
 * while the head is incomplete, {@code :read-timeout} for body reads.
 * The parse buffer and its cursors live here, so the parsing loops touch
 * only this object's fields.
 */
final class RequestReader {

    // Initial request parse buffer, enough for most request heads; grows
    // up to :max-header-bytes.
    private static final int REQUEST_BUFFER_BYTES = 4096;
    // Parse buffer kept by an idle connection, enough to start reading the
    // next request.
    private static final int IDLE_REQUEST_BUFFER_BYTES = 1024;
    // A keep-alive connection idle this long gives back what its last
    // requests grew (buffers, cached values, TLS buffers) and waits out the
    // rest of :idle-timeout holding only the initial buffers.
    private static final int IDLE_SHRINK_MILLIS = 1000;
    // Lingering close (nginx lingering_time): how long input is read and
    // discarded after the output is shut down.
    private static final int LINGER_MILLIS = 2000;
    // Longest chunk-size line, extensions included (nginx and Netty cap it
    // far below the header limit too): framing, not payload.
    private static final int MAX_CHUNK_LINE_BYTES = 4096;

    // Which timeout bounds the next socket read.
    private static final int PHASE_IDLE = 0;
    private static final int PHASE_HEAD = 1;
    private static final int PHASE_BODY = 2;

    private final HttpConnection connection;
    private final ResponseWriter writer;
    private final Socket socket;
    private final Config config;
    // Fixed for the connection's life: looked up once, not per request.
    private final java.net.InetAddress remoteAddress;
    private final int localPort;
    private final clojure.lang.Keyword scheme;

    private InputStream in;
    private byte[] buf;
    private int pos;
    private int limit;
    private RequestBody currentBody;
    private Object[] headerScratch = new Object[32];
    private int headerScratchLen;
    // Per known header name (HeaderNames index), the last value String
    // parsed on this connection, reused when the next request repeats it;
    // likewise the last target path and query.
    private final String[] lastValues = new String[HeaderNames.COUNT];
    private String lastUri;
    private String lastQuery;
    private int phase;
    // This idle period already gave its buffers back (see IDLE_SHRINK_MILLIS).
    private boolean idleShrunk;
    // Bytes of the request head consumed so far (request line, field
    // lines, their CRLFs): :max-header-bytes bounds their sum.
    private int headBytes;
    private long headerDeadlineNanos;
    private int currentSoTimeout = -1;
    // Set while a body may only consume what is already buffered.
    private boolean bufferedOnly;

    RequestReader(HttpConnection connection, ResponseWriter writer, Socket socket, Config config) {
        this.connection = connection;
        this.writer = writer;
        this.socket = socket;
        this.config = config;
        this.buf = new byte[Math.min(REQUEST_BUFFER_BYTES, config.maxHeaderBytes)];
        this.remoteAddress = socket.getInetAddress();
        this.localPort = socket.getLocalPort();
        this.scheme = socket instanceof TlsSocket.AdapterSocket ? Request.K_HTTPS : Request.K_HTTP;
    }

    /** {@code prefix[0, prefixLen)}: bytes already read from {@code in}, parsed first (none when null). */
    void start(InputStream in, byte[] prefix, int prefixLen) {
        this.in = in;
        if (prefix != null && prefixLen > 0) {
            if (prefixLen > buf.length) {
                buf = new byte[prefixLen];
            }
            System.arraycopy(prefix, 0, buf, 0, prefixLen);
            pos = 0;
            limit = prefixLen;
        }
    }

    /** The current request's body, null when it has none. */
    RequestBody body() {
        return currentBody;
    }

    /** The current request's body, handed over: the reader forgets it. */
    RequestBody takeBody() {
        RequestBody body = currentBody;
        currentBody = null;
        return body;
    }

    /** Whether bytes of a next request (pipelining) are already buffered. */
    boolean hasBuffered() {
        return pos < limit;
    }

    /** Whether reads are bounded by :read-timeout, i.e. a request body is being read. */
    boolean inBody() {
        return phase == PHASE_BODY;
    }

    /** Reads from here on are request body reads, bounded by :read-timeout. */
    void startBody() {
        phase = PHASE_BODY;
    }

    /** The next read waits for a request under :idle-timeout. */
    void startIdle() {
        phase = PHASE_IDLE;
    }

    /**
     * Whether input may be waiting unread: bytes already buffered, or bytes
     * the socket has received. A close now would make the kernel reset the
     * connection.
     */
    boolean inputPending() {
        if (pos < limit) {
            return true;
        }
        try {
            return in != null && in.available() > 0;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * The peer may still be sending (an upload the server refused, an
     * unread body): closing with unread input makes the kernel send a
     * reset, which can destroy the response before the client reads it.
     * So the output is shut down first (FIN, or close_notify then FIN over
     * TLS) and input is read and discarded until the peer closes or
     * {@link #LINGER_MILLIS} pass.
     */
    void lingeringClose() {
        try {
            socket.shutdownOutput();
            long deadline = System.nanoTime() + LINGER_MILLIS * 1_000_000L;
            byte[] discard = buf;
            while (true) {
                long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
                if (remainingMs <= 0) {
                    return;
                }
                socket.setSoTimeout((int) remainingMs);
                if (in.read(discard, 0, discard.length) < 0) {
                    return;
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // timed out, reset, or a socket without half-close: just close
        }
    }

    /**
     * The input of a connection upgraded to WebSocket. Frames the client
     * sent right behind the handshake already sit in buf; they are read
     * before the socket.
     */
    InputStream upgradeInput() {
        InputStream wsIn = pos < limit
            ? new SequenceInputStream(new ByteArrayInputStream(buf, pos, limit - pos), in)
            : in;
        pos = limit;
        return wsIn;
    }

    /**
     * Blocking read from the socket under the current phase's timeout
     * (class doc). The first byte of a new request ends the idle phase and
     * starts the header clock. Coalesced responses (pipelining) are pushed
     * to the wire first: the peer may be waiting on them before it sends
     * the bytes this read waits for.
     */
    private int socketRead(byte[] dst, int off, int len) throws IOException {
        if (bufferedOnly) {
            throw WouldBlock.INSTANCE;
        }
        writer.reclaimOutput();
        writer.flush();
        int timeout;
        if (phase == PHASE_IDLE) {
            timeout = idleReadTimeout();
        } else if (phase == PHASE_HEAD && headerDeadlineNanos != 0) {
            long remainingNs = headerDeadlineNanos - System.nanoTime();
            if (remainingNs <= 0) {
                throw new HttpError(408, "Request Timeout");
            }
            timeout = (int) Math.max(1, Math.min(Integer.MAX_VALUE, (remainingNs + 999_999L) / 1_000_000L));
        } else {
            timeout = config.readTimeoutMillis;
        }
        if (timeout != currentSoTimeout) {
            socket.setSoTimeout(timeout);
            currentSoTimeout = timeout;
        }
        int n;
        try {
            n = in.read(dst, off, len);
        } catch (SocketTimeoutException e) {
            if (phase == PHASE_IDLE) {
                throw e;
            }
            throw new HttpError(408, "Request Timeout");
        }
        if (n > 0 && phase == PHASE_IDLE) {
            startHead();
        }
        return n;
    }

    /**
     * Waits for the first bytes of the next request; false on EOF. The
     * wait is split: after {@link #IDLE_SHRINK_MILLIS} the connection
     * gives back what it grew (see {@link #shrinkIdle}), then waits out the
     * rest of :idle-timeout.
     */
    boolean awaitRequest() throws IOException {
        idleShrunk = false;
        while (true) {
            int n;
            try {
                n = socketRead(buf, limit, buf.length - limit);
            } catch (SocketTimeoutException e) {
                if (idleShrunk || !shrinksWhenIdle()) {
                    throw e;
                }
                shrinkIdle();
                idleShrunk = true;
                continue;
            }
            if (n < 0) {
                return false;
            }
            limit += n;
            return true;
        }
    }

    private boolean shrinksWhenIdle() {
        int idleMs = config.idleTimeoutMillis;
        return idleMs == 0 || idleMs > IDLE_SHRINK_MILLIS;
    }

    /** Socket timeout for the current stage of the idle wait (0 = none). */
    private int idleReadTimeout() {
        int idleMs = config.idleTimeoutMillis;
        if (!shrinksWhenIdle()) {
            return idleMs;
        }
        if (!idleShrunk) {
            return IDLE_SHRINK_MILLIS;
        }
        return idleMs == 0 ? 0 : idleMs - IDLE_SHRINK_MILLIS;
    }

    /**
     * An idle connection keeps only its initial buffers: grown parse and
     * output buffers, the body copy buffer, the cached values of the last
     * request and the TLS record buffers are dropped (allocated again by
     * the next request that needs them).
     */
    private void shrinkIdle() {
        if (buf.length > IDLE_REQUEST_BUFFER_BYTES) {
            buf = new byte[Math.min(IDLE_REQUEST_BUFFER_BYTES, config.maxHeaderBytes)];
        }
        writer.shrinkIdle();
        if (headerScratch.length > 32) {
            headerScratch = new Object[32];
        } else {
            Arrays.fill(headerScratch, null);
        }
        Arrays.fill(lastValues, null);
        lastUri = null;
        lastQuery = null;
        if (socket instanceof TlsSocket.AdapterSocket tls) {
            tls.tls().releaseIdleBuffers();
        }
    }

    /** The first byte of a request is here: no longer idle, header clock starts. */
    void startHead() {
        // Clearing idle here closes the shutdown race: a drain only
        // closes a socket while idle is still true, i.e. before any
        // request byte has been observed.
        connection.idle = false;
        phase = PHASE_HEAD;
        headerDeadlineNanos = config.headerTimeoutMillis > 0
            ? System.nanoTime() + config.headerTimeoutMillis * 1_000_000L : 0;
    }

    // ---- Request parsing ----------------------------------------------------

    Request parseRequest() throws IOException {
        headBytes = 0;
        int lineEnd = scanHeadLine();
        while (lineEnd == pos) {
            // Empty lines before the request line (RFC 9112 §2.2) are
            // skipped but count towards the head's size.
            consumeHeadLine(lineEnd);
            lineEnd = scanHeadLine();
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
        // Tunnels aren't served: CONNECT gets 501 whatever its target.
        if (method.equals("CONNECT")) {
            throw new HttpError(501, "Not Implemented");
        }
        String uri;
        String queryString;
        String targetAuthority = null;
        if (buf[sp1 + 1] == '/') {
            // origin-form, the common case.
            if (q < 0) {
                uri = lastUri = strOrLast(lastUri, sp1 + 1, sp2);
                queryString = null;
            } else {
                uri = lastUri = strOrLast(lastUri, sp1 + 1, q);
                queryString = lastQuery = strOrLast(lastQuery, q + 1, sp2);
            }
        } else if (sp2 - sp1 == 2 && buf[sp1 + 1] == '*') {
            // asterisk-form: server-wide OPTIONS only (RFC 9112 §3.2.4).
            if (!method.equals("OPTIONS")) {
                throw new HttpError(400, "Bad Request");
            }
            uri = "*";
            queryString = null;
        } else {
            // absolute-form (RFC 9112 §3.2.2); its authority replaces Host.
            RequestHead.AbsoluteForm target = RequestHead.parseAbsoluteForm(str(sp1 + 1, sp2));
            if (target == null) {
                throw new HttpError(400, "Bad Request");
            }
            uri = target.path();
            queryString = target.query();
            targetAuthority = target.authority();
        }
        consumeHeadLine(lineEnd);

        IPersistentMap headers = parseHeaders();

        // RFC 9112 §3.2: an HTTP/1.1 request lacking Host, or whose Host
        // isn't a valid authority, gets a 400. An empty Host is valid.
        String host = (String) headers.valAt("host");
        if (host == null) {
            if (protocol.equals("HTTP/1.1")) {
                throw new HttpError(400, "Bad Request");
            }
        } else if (!host.isEmpty() && !RequestHead.isValidAuthority(host)) {
            throw new HttpError(400, "Bad Request");
        }
        if (targetAuthority != null) {
            headers = headers.assoc("host", targetAuthority);
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
            long contentLength = HttpFields.parseDigits(contentLengthHeader);
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
                body.continuePending = true;
            }
        }
        currentBody = body;
        return new Request(method, uri, queryString, protocol, headers, body,
                           remoteAddress, localPort, scheme, socket);
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
        while (end > 0 && HttpFields.isOws(te.charAt(end - 1))) {
            end--;
        }
        int start = end;
        while (start > 0 && te.charAt(start - 1) != ',') {
            start--;
        }
        int s = start;
        while (s < end && HttpFields.isOws(te.charAt(s))) {
            s++;
        }
        boolean chunkedLast = end - s == 7 && te.regionMatches(true, s, "chunked", 0, 7);
        if (!chunkedLast || !protocol.equals("HTTP/1.1")) {
            throw new HttpError(400, "Bad Request");
        }
        for (int i = 0; i < start; i++) {
            char c = te.charAt(i);
            if (c != ',' && !HttpFields.isOws(c)) {
                String earlier = te.substring(0, start - 1);
                if (HttpFields.containsToken(earlier, "chunked")) {
                    throw new HttpError(400, "Bad Request");
                }
                throw new HttpError(501, "Not Implemented");
            }
        }
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
                if (headBytes + (limit - start) >= config.maxHeaderBytes) {
                    throw new HttpError(431, "Request Header Fields Too Large");
                }
                int n = socketRead(buf, limit, buf.length - limit);
                if (n < 0) {
                    throw new HttpError(400, "Bad Request");
                }
                limit += n;
            }
            int lineEnd = i;
            consumeHeadLine(start, lineEnd);
            if (lineEnd == start) {
                if (headerScratchLen == 0) {
                    return PersistentArrayMap.EMPTY;
                }
                // Copy first: mergeDuplicates hands back its input when it
                // has nothing to merge, and the scratch is reused. Its output
                // has unique keys, so the map skips a second dedupe pass.
                Object[] copy = Arrays.copyOf(headerScratch, headerScratchLen);
                return RingHeaders.toMap(RingHeaders.mergeDuplicates(copy, headerScratchLen));
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
            int known = HeaderNames.index(buf, start, colon);
            String name = known >= 0 ? HeaderNames.name(known) : lowerAscii(start, colon);
            int vs = colon + 1;
            while (vs < lineEnd && (buf[vs] == ' ' || buf[vs] == '\t')) {
                vs++;
            }
            int ve = lineEnd;
            while (ve > vs && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t')) {
                ve--;
            }
            validateFieldValueBytes(vs, ve);
            String value;
            if (known >= 0) {
                // A keep-alive client repeats most values (Host,
                // User-Agent, Accept*, Cookie): reuse the last String seen
                // for this name on this connection when the bytes match.
                String last = lastValues[known];
                if (last != null && sameBytes(last, vs, ve)) {
                    value = last;
                } else {
                    value = str(vs, ve);
                    lastValues[known] = value;
                }
            } else {
                value = str(vs, ve);
            }
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
            if (headerScratchLen == 2 * config.maxHeaderFields) {
                throw new HttpError(431, "Request Header Fields Too Large");
            }
            if (headerScratchLen + 2 > headerScratch.length) {
                headerScratch = Arrays.copyOf(headerScratch, headerScratch.length * 2);
            }
            headerScratch[headerScratchLen++] = name;
            headerScratch[headerScratchLen++] = value;
        }
    }

    /** Head line [pos, lineEnd) and its CRLF consumed, within :max-header-bytes. */
    private void consumeHeadLine(int lineEnd) {
        consumeHeadLine(pos, lineEnd);
    }

    private void consumeHeadLine(int start, int lineEnd) {
        headBytes += lineEnd - start + 2;
        if (headBytes > config.maxHeaderBytes) {
            throw new HttpError(431, "Request Header Fields Too Large");
        }
        pos = lineEnd + 2;
    }

    /** The next line of the request head; see {@link #scanLine}. */
    private int scanHeadLine() throws IOException {
        return scanLine(config.maxHeaderBytes - headBytes, 431);
    }

    void compact() {
        if (pos > 0) {
            if (pos < limit) {
                System.arraycopy(buf, pos, buf, 0, limit - pos);
            }
            limit -= pos;
            pos = 0;
        }
    }

    /**
     * Returns the index of the CR of the next CRLF, or -1 on EOF. A line
     * that can't end within {@code maxLineBytes} (CRLF included) fails
     * with {@code status} before more bytes are read for it.
     */
    private int scanLine(int maxLineBytes, int status) throws IOException {
        int i = pos;
        while (true) {
            while (i + 1 < limit) {
                if (buf[i] == '\r' && buf[i + 1] == '\n') {
                    if (i + 2 - pos > maxLineBytes) {
                        throw new HttpError(status, HttpStatus.reason(status));
                    }
                    return i;
                }
                i++;
            }
            if (limit - pos >= maxLineBytes) {
                throw new HttpError(status, HttpStatus.reason(status));
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

    /** Whether {@code s} is the ISO-8859-1 decoding of {@code buf[from, to)}. */
    private boolean sameBytes(String s, int from, int to) {
        int len = to - from;
        if (s.length() != len) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            if (s.charAt(i) != (char) (buf[from + i] & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    /** {@link #str}, reusing {@code last} when it holds the same bytes. */
    private String strOrLast(String last, int from, int to) {
        return last != null && sameBytes(last, from, to) ? last : str(from, to);
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

    /**
     * RFC 9110 §5.5 field value: no CTL but HTAB, the same rule as HTTP/2
     * and HTTP/3 (NUL, CR and LF are request-smuggling vectors; other
     * controls are invalid too and rejected rather than passed on).
     */
    private void validateFieldValueBytes(int from, int to) {
        for (int i = from; i < to; i++) {
            int c = buf[i] & 0xFF;
            if ((c < 0x20 && c != '\t') || c == 0x7F) {
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

    /**
     * A request body, read by the handler on the connection thread.
     * Anything wrong with it is the client's error and is kept in
     * {@link #failure}: framing (400), size (413), an early EOF (400) as a
     * {@link RequestBodyException}, a read timeout (408) as a
     * {@link RequestBodyTimeoutException}. The exchange answers that status
     * after the handler returns, whatever the handler did with the
     * exception, and never calls the error handler for it. Once failed,
     * every read throws the same exception.
     */
    abstract class RequestBody extends InputStream {

        // Reused single-byte scratch for read() so a client using
        // Reader.read()-style byte-at-a-time consumption doesn't allocate
        // per call. Thread-confined — one RequestBody per stream, and the
        // Ring handler runs on a single vthread.
        private final byte[] oneByte = new byte[1];
        IOException failure;
        // Body bytes read off the connection (by the handler or a drain), for events.
        long received;
        // Expect: 100-continue answered on the first read, so a handler
        // that never reads gets no body sent.
        boolean continuePending;

        @Override
        public final int read() throws IOException {
            return read(oneByte, 0, 1) < 0 ? -1 : oneByte[0] & 0xFF;
        }

        @Override
        public final int read(byte[] b, int off, int len) throws IOException {
            if (failure != null) {
                throw failure;
            }
            if (len == 0) {
                return 0;
            }
            if (continuePending) {
                continuePending = false;
                connection.sendContinue();
            }
            try {
                int n = readBody(b, off, len);
                if (n == 0) {
                    // An InputStream returns at least one byte for len > 0:
                    // a framing state that yields none would spin the reader.
                    throw new HttpError(400, "Bad Request");
                }
                if (n > 0) {
                    received += n;
                }
                return n;
            } catch (HttpError e) {
                failure = e.status == 408 ? new RequestBodyTimeoutException()
                    : new RequestBodyException(e.status, e.getMessage());
                throw failure;
            } catch (EOFException e) {
                failure = RequestBodyException.malformed("request body ended early");
                throw failure;
            }
        }

        abstract int readBody(byte[] b, int off, int len) throws IOException;

        abstract boolean isFinished();

        /** Unread body bytes when known, else -1. */
        abstract long remaining();

        /**
         * Reads and discards up to {@code maxBytes}; true when the body
         * ended within them.
         */
        boolean drain(long maxBytes) throws IOException {
            // hbuf may still hold a coalesced response, so drain into the
            // body copy buffer instead.
            byte[] scratch = writer.chunkScratch();
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

        /**
         * Discards what is already buffered, never waiting on the socket;
         * true when that finished the body. A body left unfinished here
         * must not be read again (its parser may be mid-line).
         */
        boolean drainBuffered() throws IOException {
            bufferedOnly = true;
            try {
                return drain(Long.MAX_VALUE) && isFinished();
            } catch (WouldBlock e) {
                return false;
            } finally {
                bufferedOnly = false;
            }
        }
    }

    /** Thrown by {@link #socketRead} while only buffered bytes may be read. */
    private static final class WouldBlock extends RuntimeException {
        static final WouldBlock INSTANCE = new WouldBlock();

        private WouldBlock() {
            super(null, null, false, false);
        }
    }

    private final class FixedLengthBody extends RequestBody {

        private long remaining;

        FixedLengthBody(long remaining) {
            this.remaining = remaining;
        }

        @Override
        int readBody(byte[] b, int off, int len) throws IOException {
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

        @Override
        long remaining() {
            return remaining;
        }
    }

    private final class ChunkedBody extends RequestBody {

        private long chunkRemaining;
        // Chunk data plus extension bytes, held to :max-request-body-bytes:
        // extensions are payload the handler never sees, so they can't be
        // a way around the cap.
        private long charged;
        private boolean finished;
        private boolean started;

        @Override
        int readBody(byte[] b, int off, int len) throws IOException {
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
                if (cap > 0 && charged + chunkRemaining > cap) {
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
            charged += n;
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

        @Override
        long remaining() {
            return -1;
        }

        /**
         * chunk-size [ BWS ";" chunk-ext ] CRLF (RFC 9112 §7.1, §7.1.1),
         * the line capped at {@link #MAX_CHUNK_LINE_BYTES}.
         */
        private long readChunkSize() throws IOException {
            int lineEnd = scanLine(Math.min(MAX_CHUNK_LINE_BYTES, config.maxHeaderBytes), 400);
            if (lineEnd < 0) {
                throw new EOFException("unexpected EOF in chunk size");
            }
            int end = lineEnd;
            int semi = indexOf(pos, lineEnd, (byte) ';');
            if (semi >= 0) {
                end = semi;
                while (end > pos && (buf[end - 1] == ' ' || buf[end - 1] == '\t')) {
                    end--;
                }
                // Extensions are ignored but must not smuggle a bare LF/CR
                // or other CTL that a different parser would treat as a
                // line break ("funky chunks").
                for (int i = semi + 1; i < lineEnd; i++) {
                    int c = buf[i] & 0xFF;
                    if ((c < 0x20 && c != '\t') || c == 0x7F) {
                        throw new HttpError(400, "Bad Request");
                    }
                }
                charged += lineEnd - semi;
                long cap = config.maxRequestBodyBytes;
                if (cap > 0 && charged > cap) {
                    throw new HttpError(413, "Content Too Large");
                }
            }
            long size = 0;
            int start = pos;
            if (start == end) {
                throw new HttpError(400, "Bad Request");
            }
            for (int i = start; i < end; i++) {
                int digit = hexDigit(buf[i]);
                if (digit < 0) {
                    throw new HttpError(400, "Bad Request");
                }
                // Reject before the shift whatever would not fit a positive
                // long after it (a 16th digit of 8 or more, any 17th digit)
                // instead of wrapping into a negative size.
                if (size > (Long.MAX_VALUE >>> 4)) {
                    throw new HttpError(400, "Bad Request");
                }
                size = (size << 4) | digit;
            }
            pos = lineEnd + 2;
            return size;
        }

        private void consumeCrlf() throws IOException {
            ensureBuffered(2);
            if (buf[pos] != '\r' || buf[pos + 1] != '\n') {
                throw new HttpError(400, "Bad Request");
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
                int lineEnd = scanLine(cap - totalBytes, 431);
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

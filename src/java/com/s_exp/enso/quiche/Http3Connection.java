package com.s_exp.enso.quiche;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.Request;
import com.s_exp.enso.Response;
import com.s_exp.enso.RingHandler;
import com.s_exp.enso.quiche.h3.H3Session;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One QUIC connection. Owns a {@code quiche_conn} at the transport layer
 * and a Java-space {@link H3Session} for HTTP/3 framing + QPACK. A single
 * owner platform thread drives everything — quiche's connection objects
 * aren't thread-safe.
 *
 * <p>Now backed by a JNI shim ({@link Quiche}), not FFM — see task #86
 * for the libmalloc corruption that pushed us off the FFM path.
 *
 * <p>Loop shape per iteration:
 * <ol>
 *   <li>Drain inbound datagrams from {@link #ingress} → {@code quiche_conn_recv}.
 *   <li>Once transport is established, initialise {@link #session} (opens
 *       control + QPACK streams, sends SETTINGS).
 *   <li>Iterate {@code quiche_conn_readable} streams; pull bytes via
 *       {@code quiche_conn_stream_recv} and hand them to
 *       {@link H3Session#onStreamData}, which dispatches HEADERS/DATA
 *       through a {@link H3Session.RequestSink} that spawns a worker
 *       vthread per request stream.
 *   <li>Drain {@link #outbound} response queue → session.writeResponse.
 *   <li>Drain {@code quiche_conn_send} → UDP.
 * </ol>
 */
final class Http3Connection implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Connection.class.getName());

    private static final int MAX_DATAGRAM_SIZE = 1350;
    private static final int INGRESS_CAPACITY = 256;
    private static final int OUTBOUND_CAPACITY = 1024;
    private static final int STREAM_RECV_BUF = 16 * 1024;

    // Zero-length datagram used by close() to wake the owner if it's parked
    // in ingress.poll(). drainIngress skips zero-length entries.
    private static final byte[] WAKE_SENTINEL = new byte[0];
    private static final byte[] EMPTY_REASON = new byte[0];

    private final byte[] cid;
    private final String cidHex; // computed once; used only in log messages
    private final long conn;
    private final DatagramChannel out;
    private final InetSocketAddress peer;
    private final byte[] localIp;
    private final int localPort;
    private final byte[] peerIp;
    private final int peerPort;
    private final RingHandler handler;
    private final long maxRequestBodyBytes;
    private final Runnable onClose;

    // ArrayBlockingQueue uses a single backing ring + one condition var
    // rather than allocating a Node per put — task #124 alloc profile
    // showed LinkedBlockingQueue$Node in the top 15.
    private final BlockingQueue<byte[]> ingress = new ArrayBlockingQueue<>(INGRESS_CAPACITY);
    private final BlockingQueue<ResponseTask> outbound = new ArrayBlockingQueue<>(OUTBOUND_CAPACITY);

    private final Future<?> ownerFuture;
    private volatile Thread ownerThread;
    private volatile boolean running = true;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private boolean loggedEstablished;

    // H3-layer state, created once transport handshake completes.
    private H3Session session;
    // Per-stream request body pipes (owner-thread only, no concurrent
    // mutation). Primitive-long-keyed to avoid Long autoboxing on
    // put/get/remove — task #122 alloc profile identified this as a
    // top boxed-primitive source.
    private final Long2ObjectHashMap<H3BodyPipe> bodyPipes = new Long2ObjectHashMap<>();

    Http3Connection(byte[] cid, long conn,
                    DatagramChannel out,
                    InetSocketAddress local, InetSocketAddress peer,
                    RingHandler handler,
                    long maxRequestBodyBytes,
                    Executor executor,
                    Runnable onClose) {
        this.cid = cid;
        this.cidHex = HexFormat.of().formatHex(cid);
        this.conn = conn;
        this.out = out;
        this.peer = peer;
        this.localIp = local.getAddress().getAddress();
        this.localPort = local.getPort();
        this.peerIp = peer.getAddress().getAddress();
        this.peerPort = peer.getPort();
        this.handler = handler;
        this.maxRequestBodyBytes = maxRequestBodyBytes;
        this.onClose = onClose;

        FutureTask<?> task = new FutureTask<>(this::run, null);
        this.ownerFuture = task;
        executor.execute(() -> {
            ownerThread = Thread.currentThread();
            String prev = ownerThread.getName();
            try {
                ownerThread.setName("enso-h3-conn-" + cidHex);
                task.run();
            } finally {
                ownerThread.setName(prev);
            }
        });
    }

    void enqueue(byte[] datagram) {
        // Short-circuit once the owner has begun shutdown: nothing will
        // drain the queue and holding refs delays GC.
        if (closed.get()) return;
        if (!ingress.offer(datagram)) {
            // Full queue → dropped. Would-be quiche packets are lost;
            // congestion control will eventually surface as retx storms.
            // Cap log rate (once per ~1024 drops) so we don't spam under
            // sustained overrun.
            long n = drops.incrementAndGet();
            if ((n & 0x3ffL) == 1L) {
                LOG.warning("h3 ingress queue full, dropped " + n
                    + " datagrams for cid=" + cidHex);
            }
        }
    }

    private final java.util.concurrent.atomic.AtomicLong drops =
        new java.util.concurrent.atomic.AtomicLong();

    private void run() {
        H3Session.RequestSink sink = new SinkImpl();
        try {
            while (running) {
                drainIngress();
                maybeInitH3();
                if (session != null) {
                    drainReadableStreams(sink);
                    drainOutbound();
                    // Retry deferred stream writes (task #104) — quiche
                    // may have accepted new flow-control credit from the
                    // peer since our last attempt.
                    session.drainPendingWrites();
                }
                processSend();
                if (Quiche.connIsClosed(conn)) return;
                if (!loggedEstablished && Quiche.connIsEstablished(conn)) {
                    loggedEstablished = true;
                    LOG.info("h3 handshake established with " + peer
                        + " cid=" + cidHex);
                }
                waitForWork();
            }
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 conn driver crash", t);
        } finally {
            // Owner-thread cleanup. This is the ONLY site that frees the
            // quiche conn. External close() only signals via
            // `running=false` + WAKE_SENTINEL. Guarantees no JNI call is
            // in-flight when we free.
            closed.set(true);
            bodyPipes.forEach((k, pipe) -> {
                try { pipe.signalEnd(); } catch (Throwable ignored) {}
            });
            bodyPipes.clear();
            // RFC 9114 §5.1 graceful close: if we haven't already been
            // closed (peer close, protocol error, timeout), emit a
            // H3_NO_ERROR CONNECTION_CLOSE and flush the resulting
            // datagram before freeing. Task #110.
            try {
                if (!Quiche.connIsClosed(conn)) {
                    Quiche.connClose(conn, true,
                        0x100L /* H3_NO_ERROR */, EMPTY_REASON);
                    try { processSend(); } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
            try {
                Quiche.connFree(conn);
            } finally {
                if (onClose != null) {
                    try { onClose.run(); } catch (Throwable ignored) {}
                }
            }
        }
    }

    private void waitForWork() throws InterruptedException {
        if (!ingress.isEmpty() || !outbound.isEmpty()) return;
        // Deferred writes drain on next ingress-triggered iteration —
        // peer flow-control credit only grows when we receive their
        // ACK / MAX_STREAM_DATA frames, so no point busy-spinning here.
        long timeoutNanos = Quiche.connTimeoutAsNanos(conn);
        long parkNanos = timeoutNanos == -1L ? 500_000_000L
            : Math.min(timeoutNanos, 500_000_000L);
        if (parkNanos <= 0) {
            Quiche.connOnTimeout(conn);
            return;
        }
        byte[] first = ingress.poll(parkNanos, TimeUnit.NANOSECONDS);
        if (first != null) ingress.offer(first);
        else if (timeoutNanos != -1L && timeoutNanos <= 500_000_000L) {
            Quiche.connOnTimeout(conn);
        }
    }

    private void drainIngress() throws IOException {
        byte[] datagram;
        while ((datagram = ingress.poll()) != null) {
            if (datagram.length == 0) continue; // wake sentinel
            processRecv(datagram);
        }
    }

    private void maybeInitH3() {
        if (session != null) return;
        if (!Quiche.connIsEstablished(conn)) return;
        session = new H3Session(conn);
        session.ensureInitialised();
    }

    /**
     * Iterate all readable streams once and pull whatever bytes each has,
     * handing them to {@link H3Session#onStreamData}. quiche_conn_readable
     * returns an iterator that we must free.
     */
    private void drainReadableStreams(H3Session.RequestSink sink) {
        long iter = Quiche.connReadable(conn);
        if (iter == 0) return;
        try {
            long[] sidOut = new long[1];
            while (Quiche.streamIterNext(iter, sidOut)) {
                readAllStream(sidOut[0], sink);
            }
        } finally {
            Quiche.streamIterFree(iter);
        }
    }

    // Owner-thread reusable scratch for stream_recv. finOut/errOut are
    // small out-arrays JNI writes into; recvBuf receives up to
    // STREAM_RECV_BUF bytes per call. Chunks that need to outlive the
    // call (body payload → H3BodyPipe → worker vthread) still get copied
    // to a fresh byte[], but header parsing feeds a rolling reader that
    // copies internally — no per-call allocation for those either.
    private final byte[] recvBuf = new byte[STREAM_RECV_BUF];
    private final boolean[] finOut = new boolean[1];
    private final long[] errOut = new long[1];

    private void readAllStream(long streamId, H3Session.RequestSink sink) {
        while (true) {
            finOut[0] = false;
            long rc = Quiche.connStreamRecv(conn, streamId,
                recvBuf, STREAM_RECV_BUF, finOut, errOut);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                LOG.info("h3 stream_recv stream=" + streamId
                    + " rc=" + rc + " err=" + errOut[0]);
                // Peer STOP_SENDING / RESET_STREAM / other terminal
                // error. Clean the stream out of all owner-thread maps
                // so entries don't accumulate under reset-flood (task
                // #140). Owner-side pipe/reader release; H3Session
                // scrubs its own maps.
                H3BodyPipe pipe = bodyPipes.remove(streamId);
                if (pipe != null) pipe.signalEnd();
                session.forgetStream(streamId);
                return;
            }
            boolean fin = finOut[0];
            byte[] chunk = new byte[(int) rc];
            System.arraycopy(recvBuf, 0, chunk, 0, (int) rc);
            session.onStreamData(streamId, chunk, fin, sink);
            if (fin) return;
            if (rc < STREAM_RECV_BUF) return;
        }
    }

    private void drainOutbound() {
        ResponseTask task;
        while ((task = outbound.poll()) != null) {
            sendResponse(task);
        }
    }

    private void sendResponse(ResponseTask task) {
        // Reusable owner-only headers list; cleared each call → no
        // ArrayList alloc per response (task #126).
        headersList.clear();
        String statusStr = statusString(task.status);
        headersList.add(statusPair(statusStr));
        for (Map.Entry<?, ?> e : task.headers.entrySet()) {
            String hn = String.valueOf(e.getKey()).toLowerCase();
            if (hn.equals("connection") || hn.equals("keep-alive")
                || hn.equals("transfer-encoding") || hn.equals("upgrade")
                || hn.equals("proxy-connection")) continue;
            Object v = e.getValue();
            String vs = v == null ? "" : v.toString();
            // RFC 9114 §4.2: header names/values MUST NOT contain CR,
            // LF, or NUL. A Ring app emitting these would allow a
            // response-splitting-style abuse over h3. Drop the header +
            // log (task #139).
            if (containsCtl(hn) || containsCtl(vs)) {
                LOG.warning("h3 dropping response header with CTL char: '"
                    + hn + "' streamId=" + task.streamId);
                continue;
            }
            headersList.add(new String[]{hn, vs});
        }
        session.writeResponse(task.streamId, headersList, task.body);
    }

    private static boolean containsCtl(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') return true;
        }
        return false;
    }

    // Init cap sized for typical Ring app headers (:status + a handful of
    // regular). Larger than default to skip the first grow (task #129).
    private final java.util.ArrayList<String[]> headersList =
        new java.util.ArrayList<>(64);

    // Cached ":status <N>" pair for common status codes. First-request
    // path pays a lookup miss + one alloc; every subsequent response w/
    // the same status reuses the cached String[] instance.
    private final java.util.HashMap<String, String[]> statusPairCache =
        new java.util.HashMap<>();

    private String[] statusPair(String statusStr) {
        String[] cached = statusPairCache.get(statusStr);
        if (cached != null) return cached;
        cached = new String[]{":status", statusStr};
        statusPairCache.put(statusStr, cached);
        return cached;
    }

    // Codes 100..599 pre-formatted. Index 0 = "100", index 499 = "599".
    // Anything outside falls back to Integer.toString (rare).
    private static final int STATUS_MIN = 100;
    private static final String[] STATUS_STRINGS = buildStatusStrings();
    private static String[] buildStatusStrings() {
        String[] s = new String[500];
        for (int i = 0; i < s.length; i++) s[i] = Integer.toString(STATUS_MIN + i);
        return s;
    }
    private static String statusString(int code) {
        int idx = code - STATUS_MIN;
        if (idx >= 0 && idx < STATUS_STRINGS.length) return STATUS_STRINGS[idx];
        return Integer.toString(code);
    }

    private void processRecv(byte[] datagram) throws IOException {
        long rc = Quiche.connRecv(conn, datagram, datagram.length,
            peerIp, peerPort, localIp, localPort);
        if (rc < 0 && rc != Quiche.QUICHE_ERR_DONE) {
            LOG.info("h3 quiche_conn_recv returned " + rc);
        }
    }

    // Owner-thread scratch. quiche fills sendBuf; sendView wraps it for
    // DatagramChannel.send. Both live for connection lifetime — no
    // per-call allocation.
    private final byte[] sendBuf = new byte[MAX_DATAGRAM_SIZE];
    private final ByteBuffer sendView = ByteBuffer.wrap(sendBuf);

    private void processSend() throws IOException {
        while (true) {
            long rc = Quiche.connSend(conn, sendBuf, MAX_DATAGRAM_SIZE);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                LOG.info("h3 quiche_conn_send returned " + rc);
                return;
            }
            sendView.clear().limit((int) rc);
            out.send(sendView, peer);
        }
    }

    @Override
    public void close() {
        // Signal-only. Native cleanup (quiche_conn_free) done exclusively
        // by the owner thread in run()'s finally block.
        if (!closed.compareAndSet(false, true)) return;
        running = false;
        ingress.offer(WAKE_SENTINEL);
        if (Thread.currentThread() == ownerThread) return;
        try {
            ownerFuture.get(3, TimeUnit.SECONDS);
        } catch (TimeoutException te) {
            Thread owner = ownerThread;
            if (owner != null) owner.interrupt();
            try { ownerFuture.get(1, TimeUnit.SECONDS); }
            catch (Throwable ignored) {}
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Throwable ignored) {}
    }

    byte[] cid() { return cid; }

    // -----------------------------------------------------------------

    private final class SinkImpl implements H3Session.RequestSink {
        @Override
        public void onHeaders(long streamId, List<String[]> headers) {
            // RFC 9114 §4.1: HEADERS may appear at most twice per stream
            // — request headers first, optional trailers after body. Ring
            // 1.x has no trailer surface, so we treat any second HEADERS
            // as a protocol error and close the connection (task #134).
            if (bodyPipes.containsKey(streamId)) {
                throw new com.s_exp.enso.quiche.h3.H3ConnectionException(
                    com.s_exp.enso.quiche.h3.H3ConnectionException.H3_FRAME_UNEXPECTED,
                    "unexpected second HEADERS on request stream " + streamId);
            }
            dispatchRequest(streamId, headers);
        }

        @Override
        public void onData(long streamId, byte[] chunk, boolean finalChunk) {
            H3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe == null) {
                // RFC 9114 §4.1: first frame on a request stream MUST
                // be HEADERS. DATA before dispatchRequest sets up the
                // pipe = malformed sequence → connection error (task
                // #136).
                throw new com.s_exp.enso.quiche.h3.H3ConnectionException(
                    com.s_exp.enso.quiche.h3.H3ConnectionException.H3_FRAME_UNEXPECTED,
                    "DATA frame before HEADERS on request stream " + streamId);
            }
            if (chunk.length > 0) {
                if (!pipe.enqueueChecked(chunk)) {
                    LOG.info("h3 body size cap exceeded, stream=" + streamId);
                    bodyPipes.remove(streamId);
                    pipe.signalEnd();
                    return;
                }
            }
            if (finalChunk) {
                bodyPipes.remove(streamId);
                pipe.signalEnd();
            }
        }

        @Override
        public void onFin(long streamId) {
            H3BodyPipe pipe = bodyPipes.remove(streamId);
            if (pipe != null) pipe.signalEnd();
        }
    }

    private void dispatchRequest(long streamId, List<String[]> headers) {
        String method = null, path = null, scheme = null, authority = null;
        int regularCount = 0;
        for (String[] hf : headers) {
            if (!hf[0].isEmpty() && hf[0].charAt(0) != ':') regularCount++;
        }
        // +1 slot for "host" — folded in directly so we can skip the
        // extra .assoc call + its Object[] alloc (task #148).
        Object[] regular = new Object[(regularCount + 1) * 2];
        int rp = 0;
        boolean seenRegular = false;
        for (String[] hf : headers) {
            String n = hf[0];
            String v = hf[1];
            if (n.startsWith(":")) {
                if (seenRegular) {
                    LOG.warning("h3 pseudo-header after regular, streamId=" + streamId);
                    return;
                }
                // RFC 9114 §4.3.1: pseudo-headers MUST NOT appear more
                // than once. Duplicate → malformed request; drop.
                switch (n) {
                    case ":method" -> {
                        if (method != null) {
                            LOG.warning("h3 duplicate :method, streamId=" + streamId);
                            return;
                        }
                        method = v;
                    }
                    case ":path" -> {
                        if (path != null) {
                            LOG.warning("h3 duplicate :path, streamId=" + streamId);
                            return;
                        }
                        path = v;
                    }
                    case ":scheme" -> {
                        if (scheme != null) {
                            LOG.warning("h3 duplicate :scheme, streamId=" + streamId);
                            return;
                        }
                        scheme = v;
                    }
                    case ":authority" -> {
                        if (authority != null) {
                            LOG.warning("h3 duplicate :authority, streamId=" + streamId);
                            return;
                        }
                        authority = v;
                    }
                    default -> { /* ignore unknown pseudo */ }
                }
            } else {
                seenRegular = true;
                // RFC 9114 §4.2: header field names MUST be lowercase.
                // Any uppercase char makes the request malformed.
                if (hasUppercase(n)) {
                    LOG.warning("h3 uppercase header name '" + n
                        + "' streamId=" + streamId);
                    return;
                }
                // §4.2 forbidden hop-by-hop headers. TE is allowed only if
                // its value is exactly "trailers".
                if (n.equals("connection") || n.equals("keep-alive")
                    || n.equals("proxy-connection") || n.equals("transfer-encoding")
                    || n.equals("upgrade")) {
                    LOG.warning("h3 forbidden header '" + n + "' streamId=" + streamId);
                    return;
                }
                if (n.equals("te") && !"trailers".equals(v)) {
                    LOG.warning("h3 TE header with non-trailers value, streamId="
                        + streamId);
                    return;
                }
                regular[rp++] = n;
                regular[rp++] = v;
            }
        }
        // RFC 9114 §4.3.1 request pseudo-header requirements:
        //   - non-CONNECT: :method, :scheme, :path, :authority all REQUIRED
        //   - CONNECT: :method + :authority REQUIRED, :scheme + :path MUST
        //     be omitted.
        boolean isConnect = "CONNECT".equals(method);
        if (method == null) {
            LOG.warning("h3 request missing :method, streamId=" + streamId);
            return;
        }
        if (isConnect) {
            if (authority == null || scheme != null || path != null) {
                LOG.warning("h3 malformed CONNECT pseudo-headers, streamId=" + streamId);
                return;
            }
            // Fill in placeholder scheme/path so downstream Ring code
            // doesn't NPE on the tunnel-style request.
            scheme = "https";
            path = "";
        } else {
            if (path == null || scheme == null) {
                LOG.warning("h3 request missing pseudo-headers, streamId=" + streamId);
                return;
            }
            if (path.isEmpty() && (scheme.equals("http") || scheme.equals("https"))) {
                LOG.warning("h3 empty :path for http(s), streamId=" + streamId);
                return;
            }
        }
        String uri;
        String query;
        int q = path.indexOf('?');
        if (q < 0) { uri = path; query = null; }
        else { uri = path.substring(0, q); query = path.substring(q + 1); }

        // Fold "host" pair directly into the pre-sized regular[] so we
        // build the Ring header map in a single createAsIfByAssoc call.
        regular[rp++] = "host";
        regular[rp++] = authority == null ? "" : authority;
        IPersistentMap hmap = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(regular);

        H3BodyPipe pipe = new H3BodyPipe(maxRequestBodyBytes);
        bodyPipes.put(streamId, pipe);

        Request request = new Request(
            method, uri, query, "HTTP/3.0",
            hmap,
            pipe.inputStream(),
            peer.getAddress(), localPort);

        Thread.ofVirtual()
            .name("enso-h3-worker-" + streamId)
            .start(() -> runHandler(streamId, request));
    }

    private static boolean hasUppercase(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') return true;
        }
        return false;
    }

    private void runHandler(long streamId, Request request) {
        try {
            Response response = handler.handle(request);
            ResponseTask task = response == null
                ? fallback500(streamId)
                : ResponseTask.of(streamId, response);
            outbound.put(task);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 handler threw for stream " + streamId, t);
            try { outbound.put(fallback500(streamId)); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static ResponseTask fallback500(long streamId) {
        return new ResponseTask(streamId, 500,
            java.util.Collections.singletonMap("content-type", "text/plain"),
            "500 internal error".getBytes(StandardCharsets.UTF_8));
    }

    private record ResponseTask(long streamId, int status,
                                Map<?, ?> headers, byte[] body) {
        static ResponseTask of(long streamId, Response r) {
            byte[] body = materialise(r.body);
            return new ResponseTask(streamId, r.status,
                r.headers == null ? java.util.Collections.emptyMap() : r.headers,
                body);
        }

        private static byte[] materialise(Object rb) {
            if (rb == null) return null;
            if (rb instanceof byte[] b) return b;
            if (rb instanceof String s) return s.getBytes(StandardCharsets.UTF_8);
            if (rb instanceof java.io.File f) {
                try (java.io.InputStream in = new java.io.FileInputStream(f)) {
                    return in.readAllBytes();
                } catch (java.io.IOException e) {
                    return ("read failed: " + e.getMessage())
                        .getBytes(StandardCharsets.UTF_8);
                }
            }
            if (rb instanceof java.io.InputStream in) {
                try (var s = in) {
                    return s.readAllBytes();
                } catch (java.io.IOException e) {
                    return ("read failed: " + e.getMessage())
                        .getBytes(StandardCharsets.UTF_8);
                }
            }
            return ("[unsupported body type: " + rb.getClass().getName() + "]")
                .getBytes(StandardCharsets.UTF_8);
        }
    }
}

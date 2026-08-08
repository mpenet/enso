package com.s_exp.enso.quiche;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.Request;
import com.s_exp.enso.Response;
import com.s_exp.enso.RingHandler;
import com.s_exp.enso.quiche.ffm.quiche_h;
import com.s_exp.enso.quiche.h3.H3Session;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One QUIC connection. Owns a {@code quiche_conn} at the transport layer
 * and a Java-space {@link H3Session} for HTTP/3 framing + QPACK. A single
 * owner platform thread drives everything — quiche's connection objects
 * aren't thread-safe.
 *
 * <p>The h3 layer used to be quiche's own {@code quiche_h3_conn} FFM
 * module, but that path corrupts libmalloc's freelist on macOS ARM64 +
 * JDK 25 under connection churn (task #79). We now implement H3 in Java
 * on top of quiche's transport-only stream primitives, matching what
 * Netty + Jetty do.
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

    private final byte[] cid;
    private final Arena arena;
    private final MemorySegment conn;
    private final DatagramChannel out;
    private final InetSocketAddress local;
    private final InetSocketAddress peer;
    private final RingHandler handler;
    private final long maxRequestBodyBytes;
    private final Runnable onClose;

    private final BlockingQueue<byte[]> ingress = new LinkedBlockingQueue<>(INGRESS_CAPACITY);
    private final BlockingQueue<ResponseTask> outbound = new LinkedBlockingQueue<>(OUTBOUND_CAPACITY);

    private final Future<?> ownerFuture;
    private volatile Thread ownerThread;
    private volatile boolean running = true;
    private volatile boolean closed = false;
    private boolean loggedEstablished;

    // H3-layer state, created once transport handshake completes.
    private H3Session session;
    // Per-stream request body pipes (owner-thread only, no concurrent
    // mutation).
    private final HashMap<Long, H3BodyPipe> bodyPipes = new HashMap<>();

    // Ctor-time reusable FFM scratch (owned by connection arena).
    private final MemorySegment inBuf;
    private final MemorySegment outBuf;
    private final MemorySegment sendInfo;
    private final MemorySegment recvInfo;
    private final MemorySegment streamRecvBuf;
    private final MemorySegment finOut;
    private final MemorySegment errOut;
    private final MemorySegment streamIdOut;
    private final MemorySegment peerSockaddr;
    private final int peerSockaddrLen;
    private final MemorySegment localSockaddr;
    private final int localSockaddrLen;

    Http3Connection(byte[] cid, MemorySegment conn, Arena arena,
                    DatagramChannel out,
                    InetSocketAddress local, InetSocketAddress peer,
                    RingHandler handler,
                    long maxRequestBodyBytes,
                    Executor executor,
                    Runnable onClose) {
        this.cid = cid;
        this.conn = conn;
        this.arena = arena;
        this.out = out;
        this.local = local;
        this.peer = peer;
        this.handler = handler;
        this.maxRequestBodyBytes = maxRequestBodyBytes;
        this.onClose = onClose;

        this.inBuf = arena.allocate(2 * MAX_DATAGRAM_SIZE);
        this.outBuf = arena.allocate(MAX_DATAGRAM_SIZE);
        this.sendInfo = arena.allocate(64);
        this.streamRecvBuf = arena.allocate(STREAM_RECV_BUF);
        this.finOut = arena.allocate(ValueLayout.JAVA_BOOLEAN);
        this.errOut = arena.allocate(ValueLayout.JAVA_LONG);
        this.streamIdOut = arena.allocate(ValueLayout.JAVA_LONG);

        Sockaddr.Encoded peerEnc = Sockaddr.encode(arena, peer);
        this.peerSockaddr = peerEnc.segment();
        this.peerSockaddrLen = peerEnc.length();
        Sockaddr.Encoded localEnc = Sockaddr.encode(arena, local);
        this.localSockaddr = localEnc.segment();
        this.localSockaddrLen = localEnc.length();
        this.recvInfo = arena.allocate(48);
        long rip = 0;
        recvInfo.set(ValueLayout.ADDRESS, rip, peerSockaddr); rip += 8;
        recvInfo.set(ValueLayout.JAVA_INT, rip, peerSockaddrLen); rip += 4;
        rip += 4;
        recvInfo.set(ValueLayout.ADDRESS, rip, localSockaddr); rip += 8;
        recvInfo.set(ValueLayout.JAVA_INT, rip, localSockaddrLen);

        FutureTask<?> task = new FutureTask<>(this::run, null);
        this.ownerFuture = task;
        executor.execute(() -> {
            ownerThread = Thread.currentThread();
            String prev = ownerThread.getName();
            try {
                ownerThread.setName("enso-h3-conn-" + HexFormat.of().formatHex(cid));
                task.run();
            } finally {
                ownerThread.setName(prev);
            }
        });
    }

    void enqueue(byte[] datagram) {
        ingress.offer(datagram);
    }

    private void run() {
        H3Session.RequestSink sink = new SinkImpl();
        try {
            while (running) {
                drainIngress();
                maybeInitH3();
                if (session != null) {
                    drainReadableStreams(sink);
                    drainOutbound();
                }
                processSend();
                if (quiche_h.quiche_conn_is_closed(conn)) return;
                if (!loggedEstablished && quiche_h.quiche_conn_is_established(conn)) {
                    loggedEstablished = true;
                    LOG.info("h3 handshake established with " + peer
                        + " cid=" + HexFormat.of().formatHex(cid));
                }
                waitForWork();
            }
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 conn driver crash", t);
        } finally {
            close();
        }
    }

    private void waitForWork() throws InterruptedException {
        if (!ingress.isEmpty() || !outbound.isEmpty()) return;
        long timeoutNanos = quiche_h.quiche_conn_timeout_as_nanos(conn);
        long parkNanos = timeoutNanos == -1L ? 500_000_000L
            : Math.min(timeoutNanos, 500_000_000L);
        if (parkNanos <= 0) {
            quiche_h.quiche_conn_on_timeout(conn);
            return;
        }
        byte[] first = ingress.poll(parkNanos, TimeUnit.NANOSECONDS);
        if (first != null) ingress.offer(first);
        else if (timeoutNanos != -1L && timeoutNanos <= 500_000_000L) {
            quiche_h.quiche_conn_on_timeout(conn);
        }
    }

    private void drainIngress() throws IOException {
        byte[] datagram;
        while ((datagram = ingress.poll()) != null) {
            processRecv(datagram);
        }
    }

    private void maybeInitH3() {
        if (session != null) return;
        if (!quiche_h.quiche_conn_is_established(conn)) return;
        session = new H3Session(conn, arena);
        session.ensureInitialised();
    }

    /**
     * Iterate all readable streams once and pull whatever bytes each has,
     * handing them to {@link H3Session#onStreamData}. quiche_conn_readable
     * returns an iterator that we must free.
     */
    private void drainReadableStreams(H3Session.RequestSink sink) {
        MemorySegment iter = QuicheStreams.readableIter(conn);
        if (iter == null || iter.address() == 0) return;
        try {
            while (QuicheStreams.iterNext(iter, streamIdOut)) {
                long streamId = streamIdOut.get(ValueLayout.JAVA_LONG, 0);
                readAllStream(streamId, sink);
            }
        } finally {
            QuicheStreams.iterFree(iter);
        }
    }

    private void readAllStream(long streamId, H3Session.RequestSink sink) {
        while (true) {
            finOut.set(ValueLayout.JAVA_BOOLEAN, 0, false);
            long rc = QuicheStreams.streamRecv(conn, streamId,
                streamRecvBuf, STREAM_RECV_BUF, finOut, errOut);
            if (rc == quiche_h.QUICHE_ERR_DONE()) return;
            if (rc < 0) {
                LOG.info("h3 stream_recv stream=" + streamId + " rc=" + rc);
                return;
            }
            boolean fin = finOut.get(ValueLayout.JAVA_BOOLEAN, 0);
            byte[] chunk = new byte[(int) rc];
            MemorySegment.copy(streamRecvBuf, ValueLayout.JAVA_BYTE, 0, chunk, 0, (int) rc);
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
        java.util.ArrayList<String[]> headers = new java.util.ArrayList<>();
        headers.add(new String[]{":status", Integer.toString(task.status)});
        for (Map.Entry<?, ?> e : task.headers.entrySet()) {
            String hn = String.valueOf(e.getKey()).toLowerCase();
            if (hn.equals("connection") || hn.equals("keep-alive")
                || hn.equals("transfer-encoding") || hn.equals("upgrade")
                || hn.equals("proxy-connection")) continue;
            Object v = e.getValue();
            headers.add(new String[]{hn, v == null ? "" : v.toString()});
        }
        session.writeResponse(task.streamId, headers, task.body);
    }

    private void processRecv(byte[] datagram) throws IOException {
        MemorySegment.copy(datagram, 0, inBuf, ValueLayout.JAVA_BYTE, 0, datagram.length);
        long rc = quiche_h.quiche_conn_recv(conn, inBuf, datagram.length, recvInfo);
        if (rc < 0 && rc != quiche_h.QUICHE_ERR_DONE()) {
            LOG.info("h3 quiche_conn_recv returned " + rc);
        }
    }

    private void processSend() throws IOException {
        while (true) {
            long rc = quiche_h.quiche_conn_send(conn, outBuf, MAX_DATAGRAM_SIZE, sendInfo);
            if (rc == quiche_h.QUICHE_ERR_DONE()) return;
            if (rc < 0) {
                LOG.info("h3 quiche_conn_send returned " + rc);
                return;
            }
            byte[] pkt = new byte[(int) rc];
            MemorySegment.copy(outBuf, ValueLayout.JAVA_BYTE, 0, pkt, 0, (int) rc);
            out.send(ByteBuffer.wrap(pkt), peer);
        }
    }

    @Override
    public void close() {
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        running = false;
        for (H3BodyPipe pipe : bodyPipes.values()) {
            try { pipe.signalEnd(); } catch (Throwable ignored) {}
        }
        bodyPipes.clear();
        Thread owner = ownerThread;
        if (owner != null && Thread.currentThread() != owner) {
            try {
                ownerFuture.get(1, TimeUnit.SECONDS);
            } catch (java.util.concurrent.CancellationException
                     | InterruptedException
                     | java.util.concurrent.ExecutionException
                     | TimeoutException ignored) {
                if (ignored instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        try {
            quiche_h.quiche_conn_free(conn);
        } catch (Throwable ignored) {
        } finally {
            try { arena.close(); } catch (Throwable ignored) {}
            if (onClose != null) onClose.run();
        }
    }

    byte[] cid() { return cid; }

    // -----------------------------------------------------------------

    private final class SinkImpl implements H3Session.RequestSink {
        @Override
        public void onHeaders(long streamId, List<String[]> headers) {
            dispatchRequest(streamId, headers);
        }

        @Override
        public void onData(long streamId, byte[] chunk, boolean finalChunk) {
            H3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe == null) return;
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
        Object[] regular = new Object[regularCount * 2];
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
                if (n.equals("connection") || n.equals("keep-alive")
                    || n.equals("proxy-connection") || n.equals("transfer-encoding")
                    || n.equals("upgrade")) {
                    LOG.warning("h3 forbidden header '" + n + "' streamId=" + streamId);
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

        IPersistentMap hmap;
        if (rp == 0) {
            hmap = PersistentArrayMap.EMPTY;
        } else {
            hmap = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(regular);
        }
        hmap = hmap.assoc("host", authority == null ? "" : authority);

        H3BodyPipe pipe = new H3BodyPipe(maxRequestBodyBytes);
        bodyPipes.put(streamId, pipe);

        Request request = new Request(
            method, uri, query, "HTTP/3.0",
            hmap,
            pipe.inputStream(),
            peer.getAddress(), local.getPort());

        Thread.ofVirtual()
            .name("enso-h3-worker-" + streamId)
            .start(() -> runHandler(streamId, request));
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

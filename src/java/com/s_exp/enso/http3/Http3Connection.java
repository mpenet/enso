package com.s_exp.enso.http3;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.quiche.Quiche;
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
 * and a Java-space {@link Http3Session} for HTTP/3 framing + QPACK. A single
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
 *       {@link Http3Session#onStreamData}, which dispatches HEADERS/DATA
 *       through a {@link Http3Session.RequestSink} that spawns a worker
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
    private final Config config;
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
    private Http3Session session;
    // Per-stream request body pipes (owner-thread only, no concurrent
    // mutation). Primitive-long-keyed to avoid Long autoboxing on
    // put/get/remove — task #122 alloc profile identified this as a
    // top boxed-primitive source.
    private final Long2ObjectHashMap<Http3BodyPipe> bodyPipes = new Long2ObjectHashMap<>();
    // Streaming responses paused mid-body waiting for their Pending
    // queue to drain (flow control). Owner-thread only; owner's main
    // loop calls resumeStreamingSources between drainOutbound and
    // processSend to feed the next chunk once space opens.
    private final Long2ObjectHashMap<java.io.InputStream> streamingSources =
        new Long2ObjectHashMap<>();

    Http3Connection(byte[] cid, long conn,
                    DatagramChannel out,
                    InetSocketAddress local, InetSocketAddress peer,
                    RingHandler handler,
                    Config config,
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
        this.config = config;
        this.maxRequestBodyBytes = config.maxRequestBodyBytes;
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
        Http3Session.RequestSink sink = new SinkImpl();
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
                    // Feed more body chunks into paused streaming
                    // responses whose Pending queues have since drained
                    // (task #201 — otherwise 1 GiB files pile up in
                    // Pending byte[]s and defeat the streaming fix).
                    resumeStreamingSources();
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
            // Close any streaming response sources (File handles, socket
            // streams) mid-flight so a dropped connection doesn't leak
            // file descriptors.
            streamingSources.forEach((sid, src) -> closeSourceQuiet(src));
            streamingSources.clear();
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
        session = new Http3Session(conn, config);
        session.ensureInitialised();
    }

    /**
     * Iterate all readable streams once and pull whatever bytes each has,
     * handing them to {@link Http3Session#onStreamData}. quiche_conn_readable
     * returns an iterator that we must free.
     */
    private void drainReadableStreams(Http3Session.RequestSink sink) {
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
    // call (body payload → Http3BodyPipe → worker vthread) still get copied
    // to a fresh byte[], but header parsing feeds a rolling reader that
    // copies internally — no per-call allocation for those either.
    private final byte[] recvBuf = new byte[STREAM_RECV_BUF];
    private final boolean[] finOut = new boolean[1];
    private final long[] errOut = new long[1];

    private void readAllStream(long streamId, Http3Session.RequestSink sink) {
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
                // #140). Owner-side pipe/reader release; Http3Session
                // scrubs its own maps.
                Http3BodyPipe pipe = bodyPipes.remove(streamId);
                if (pipe != null) pipe.signalEnd();
                session.forgetStream(streamId);
                return;
            }
            boolean fin = finOut[0];
            // Pass owner-thread recvBuf directly — Http3Session.onStreamData
            // copies into rolling reader buf immediately (or slices for
            // uni-stream type varint accum), so the buf is free to be
            // overwritten by the next stream_recv.
            session.onStreamData(streamId, recvBuf, 0, (int) rc, fin, sink);
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
        // ArrayList alloc per response (task #126). Per-pair String[]
        // slots come from a bounded pool (headerPairPool) so a hot
        // request path with N headers doesn't allocate N × 2-slot
        // String[] on every response.
        for (int i = 0, n = headersList.size(); i < n; i++) {
            releasePair(headersList.get(i));
        }
        headersList.clear();
        String statusStr = statusString(task.status);
        // :status pair stays cached (interned via statusPairCache) —
        // don't recycle it into the pool.
        headersList.add(statusPair(statusStr));
        boolean hasServer = false;
        for (Map.Entry<?, ?> e : task.headers.entrySet()) {
            String hn = String.valueOf(e.getKey()).toLowerCase(java.util.Locale.ROOT);
            if (hn.equals("connection") || hn.equals("keep-alive")
                || hn.equals("transfer-encoding") || hn.equals("upgrade")
                || hn.equals("proxy-connection")) continue;
            if (hn.equals("server")) hasServer = true;
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
            headersList.add(acquirePair(hn, vs));
        }
        if (!hasServer && config.serverHeader != null && !config.serverHeader.isEmpty()) {
            headersList.add(acquirePair("server", config.serverHeader));
        }
        // Fast path: fully-materialised byte[] body → single stream_send
        // for HEADERS + DATA + FIN (task #143 halved JNI hops here).
        // Streaming path: File/InputStream stayed on the source instead
        // of being read into a big byte[] (see ResponseTask.materialise).
        // Zero-length File short-circuits to the fast path so an empty
        // response emits a single HEADERS(fin) frame instead of
        // HEADERS(fin=false) + empty DATA(fin=true). InputStream can't
        // know its length upfront — accept the 2-frame cost there.
        if (task.bodySource == null) {
            session.writeResponse(task.streamId, headersList, task.body);
        } else if (task.bodySource instanceof java.io.File f && f.length() == 0) {
            session.writeResponse(task.streamId, headersList, null);
        } else {
            streamResponse(task);
        }
    }

    // Chunk size for streaming h3 responses. 256 KiB balances syscall
    // count against per-chunk memory pressure. Lazily allocated on the
    // first streaming response, released once the streaming loop
    // finishes so long-lived idle connections that streamed once don't
    // permanently pin 256 KiB. Owner-thread confined — no locking.
    private static final int STREAM_CHUNK_BYTES = 256 * 1024;
    private byte[] streamChunkBuf;

    private void streamResponse(ResponseTask task) {
        // Alloc scratch buf BEFORE writeHeadersOnly so the IOException
        // handler always has a non-null buf to hand to writeBodyChunk on
        // fin-emit fallback.
        if (streamChunkBuf == null) {
            streamChunkBuf = new byte[STREAM_CHUNK_BYTES];
        }
        session.writeHeadersOnly(task.streamId, headersList);
        java.io.InputStream src;
        try {
            src = openSource(task.bodySource);
        } catch (java.io.IOException e) {
            LOG.warning("h3 stream open failed stream=" + task.streamId
                + ": " + e.getMessage());
            try { session.writeBodyChunk(task.streamId, streamChunkBuf, 0, 0, true); }
            catch (Throwable ignored) {}
            return;
        }
        pumpStreaming(task.streamId, src);
    }

    /**
     * Read one chunk from {@code src} and emit as a DATA frame. If more
     * remains (no EOF), stash the source in {@link #streamingSources}
     * so {@link #resumeStreamingSources} pumps the next chunk on the
     * next owner-loop iteration. One-chunk-per-call bounds the worst-case
     * owner starvation window to a single {@code InputStream.read}
     * (≤ ~100ms on cold disk, sub-ms hot). Multi-chunk-in-one-iteration
     * would also block ingress + other streams' traffic for the full
     * duration.
     */
    private void pumpStreaming(long streamId, java.io.InputStream src) {
        byte[] buf = streamChunkBuf;
        try {
            int n = readFully(src, buf);
            boolean eof = n < buf.length;
            if (n > 0) {
                session.writeBodyChunk(streamId, buf, 0, n, eof);
            } else if (eof) {
                // Zero-body streaming — emit empty terminal DATA with
                // FIN so the peer sees EOM.
                session.writeBodyChunk(streamId, buf, 0, 0, true);
            }
            if (eof) {
                closeSourceQuiet(src);
                if (streamingSources.isEmpty()) {
                    // Reclaim the 256 KiB scratch once no streams are
                    // mid-body — otherwise a connection that streams
                    // once pins the buffer for its lifetime.
                    streamChunkBuf = null;
                }
                return;
            }
            // Not EOF — park source for the next owner iteration.
            // Also caps Pending pile-up: only one chunk enters per tick
            // even if flow control never blocks.
            streamingSources.put(streamId, src);
        } catch (java.io.IOException e) {
            LOG.warning("h3 stream body read failed stream=" + streamId
                + ": " + e.getMessage());
            try { session.writeBodyChunk(streamId, buf, 0, 0, true); }
            catch (Throwable ignored) {}
            closeSourceQuiet(src);
        }
    }

    private long[] streamResumeScratch = new long[8];
    private int streamResumeScratchLen;

    private void resumeStreamingSources() {
        if (streamingSources.isEmpty()) return;
        // Long2ObjectHashMap.forEach doesn't allow removal during
        // iteration — collect ready IDs into a scratch array first.
        // Typical paused count is small (a few concurrent streams).
        streamResumeScratchLen = 0;
        if (streamResumeScratch.length < streamingSources.size()) {
            streamResumeScratch = new long[streamingSources.size()];
        }
        streamingSources.forEach((sid, src) -> {
            // Bucket into resume vs abort. Stream can be gone (peer
            // STOP_SENDING/RESET) — without this check, src stays parked
            // forever and pins the fd until connection teardown.
            if (!session.streamAlive(sid)) {
                closeSourceQuiet(src);
                streamResumeScratch[streamResumeScratchLen++] = -sid - 1;
            } else if (!session.hasPendingWrites(sid)) {
                streamResumeScratch[streamResumeScratchLen++] = sid;
            }
        });
        for (int i = 0; i < streamResumeScratchLen; i++) {
            long marker = streamResumeScratch[i];
            if (marker < 0) {
                // Aborted stream — src already closed above.
                streamingSources.remove(-marker - 1);
                continue;
            }
            java.io.InputStream src = streamingSources.remove(marker);
            if (src != null) pumpStreaming(marker, src);
        }
        // Reclaim scratch buf if map drained via aborts (parallel to
        // the EOF path in pumpStreaming).
        if (streamingSources.isEmpty()) {
            streamChunkBuf = null;
        }
    }

    private static void closeSourceQuiet(java.io.InputStream src) {
        try { src.close(); } catch (java.io.IOException ignored) {}
    }

    private static java.io.InputStream openSource(Object src) throws java.io.IOException {
        // Wrap non-buffered sources in a BufferedInputStream — our
        // readFully hits the source in 256 KiB chunks, but decode /
        // decompression streams (InflaterInputStream, wrapped socket
        // streams) may otherwise do per-byte syscalls / decode work
        // even when the caller supplies a big destination.
        if (src instanceof java.io.BufferedInputStream bis) return bis;
        if (src instanceof java.io.InputStream is) {
            return new java.io.BufferedInputStream(is, STREAM_CHUNK_BYTES);
        }
        if (src instanceof java.io.File f) {
            return new java.io.BufferedInputStream(
                new java.io.FileInputStream(f), STREAM_CHUNK_BYTES);
        }
        throw new java.io.IOException("unsupported stream source: " + src.getClass());
    }

    private static int readFully(java.io.InputStream in, byte[] buf) throws java.io.IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) return total;
            total += n;
        }
        return total;
    }

    // Bounded pool of 2-slot String[] pairs reused across responses on
    // this connection. Cap kept small — typical responses have <15
    // headers; excess just falls back to fresh allocs.
    private static final int PAIR_POOL_CAP = 64;
    private final java.util.ArrayDeque<String[]> headerPairPool =
        new java.util.ArrayDeque<>(PAIR_POOL_CAP);

    private String[] acquirePair(String name, String value) {
        String[] p = headerPairPool.pollFirst();
        if (p == null) p = new String[2];
        p[0] = name; p[1] = value;
        return p;
    }

    private void releasePair(String[] p) {
        // Cached statusPair instances live forever in statusPairCache —
        // interning key is p[0]==":status". Do NOT return those to the
        // pool or their contents get clobbered.
        if (p == null || ":status".equals(p[0])) return;
        if (headerPairPool.size() < PAIR_POOL_CAP) {
            p[0] = null; p[1] = null; // help GC on referenced strings
            headerPairPool.offerFirst(p);
        }
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
        // Signal + join. Native cleanup (quiche_conn_free) done exclusively
        // by the owner thread in run()'s finally block.
        if (!signalClose()) return;
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

    /**
     * Non-blocking flag-flip + wake. Http3Listener.close fans this out
     * across all conns in parallel then waits on the shared connExecutor
     * once — replaces N × 3s serial waits.
     * Returns false if already closed (idempotent).
     */
    boolean signalClose() {
        if (!closed.compareAndSet(false, true)) return false;
        running = false;
        ingress.offer(WAKE_SENTINEL);
        return true;
    }

    byte[] cid() { return cid; }

    // -----------------------------------------------------------------

    private final class SinkImpl implements Http3Session.RequestSink {
        @Override
        public void onHeaders(long streamId, List<String[]> headers) {
            // RFC 9114 §4.1: HEADERS may appear at most twice per stream
            // — request headers first, optional trailers after body. Ring
            // 1.x has no trailer surface, so we treat any second HEADERS
            // as a protocol error and close the connection (task #134).
            if (bodyPipes.containsKey(streamId)) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "unexpected second HEADERS on request stream " + streamId);
            }
            dispatchRequest(streamId, headers);
        }

        @Override
        public void onData(long streamId, byte[] chunk, boolean finalChunk) {
            Http3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe == null) {
                // RFC 9114 §4.1: first frame on a request stream MUST
                // be HEADERS. DATA before dispatchRequest sets up the
                // pipe = malformed sequence → connection error (task
                // #136).
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_FRAME_UNEXPECTED,
                    "DATA frame before HEADERS on request stream " + streamId);
            }
            if (chunk.length > 0) {
                if (!pipe.enqueueChecked(chunk)) {
                    LOG.info("h3 body size cap exceeded, stream=" + streamId);
                    bodyPipes.remove(streamId);
                    pipe.signalTruncated();
                    // Reset the QUIC stream in both directions so the peer
                    // stops pushing DATA against a stream we already stopped
                    // consuming. Without this, the next DATA arrives with
                    // no pipe → "DATA before HEADERS" branch kills the
                    // whole connection for a per-stream overflow.
                    session.resetRequestStream(
                        streamId, Http3ConnectionException.H3_MESSAGE_ERROR);
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
            Http3BodyPipe pipe = bodyPipes.remove(streamId);
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
                // RFC 9114 §4.1.3: pseudo-headers MUST all precede regular
                // headers. Violation = H3_MESSAGE_ERROR at connection
                // level (h3spec 14 / task #153).
                if (seenRegular) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_MESSAGE_ERROR,
                        "pseudo-header '" + n + "' after regular header, streamId="
                            + streamId);
                }
                // RFC 9114 §4.1.1: request pseudo-headers MUST NOT appear
                // more than once. Duplicate = H3_MESSAGE_ERROR (h3spec 11
                // / task #150).
                switch (n) {
                    case ":method" -> {
                        if (method != null) throw pseudoDup(":method", streamId);
                        method = v;
                    }
                    case ":path" -> {
                        if (path != null) throw pseudoDup(":path", streamId);
                        path = v;
                    }
                    case ":scheme" -> {
                        if (scheme != null) throw pseudoDup(":scheme", streamId);
                        scheme = v;
                    }
                    case ":authority" -> {
                        if (authority != null) throw pseudoDup(":authority", streamId);
                        authority = v;
                    }
                    default -> {
                        // RFC 9114 §4.1.3: any pseudo not in the request
                        // pseudo-set is prohibited = H3_MESSAGE_ERROR
                        // (h3spec 13 / task #152).
                        throw new Http3ConnectionException(
                            Http3ConnectionException.H3_MESSAGE_ERROR,
                            "prohibited pseudo-header '" + n
                                + "' on request stream " + streamId);
                    }
                }
            } else {
                seenRegular = true;
                // RFC 9114 §4.2: header field names MUST be lowercase.
                // Any uppercase char = malformed = H3_MESSAGE_ERROR.
                if (hasUppercase(n)) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_MESSAGE_ERROR,
                        "uppercase header name '" + n + "' on stream " + streamId);
                }
                // §4.2 forbidden hop-by-hop headers = H3_MESSAGE_ERROR.
                // TE is allowed only if its value is exactly "trailers".
                if (n.equals("connection") || n.equals("keep-alive")
                    || n.equals("proxy-connection") || n.equals("transfer-encoding")
                    || n.equals("upgrade")) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_MESSAGE_ERROR,
                        "forbidden header '" + n + "' on stream " + streamId);
                }
                if (n.equals("te") && !"trailers".equals(v)) {
                    throw new Http3ConnectionException(
                        Http3ConnectionException.H3_MESSAGE_ERROR,
                        "TE header with non-trailers value on stream " + streamId);
                }
                regular[rp++] = n;
                regular[rp++] = v;
            }
        }
        // RFC 9114 §4.1.3 request pseudo-header requirements:
        //   - non-CONNECT: :method, :scheme, :path, :authority all REQUIRED
        //   - CONNECT: :method + :authority REQUIRED, :scheme + :path MUST
        //     be omitted.
        // Missing / prohibited combinations = H3_MESSAGE_ERROR at connection
        // level (h3spec 12 / task #151).
        boolean isConnect = "CONNECT".equals(method);
        if (method == null) {
            throw new Http3ConnectionException(
                Http3ConnectionException.H3_MESSAGE_ERROR,
                "missing :method pseudo-header on stream " + streamId);
        }
        if (isConnect) {
            if (authority == null || scheme != null || path != null) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_MESSAGE_ERROR,
                    "malformed CONNECT pseudo-headers on stream " + streamId);
            }
            // Fill in placeholder scheme/path so downstream Ring code
            // doesn't NPE on the tunnel-style request.
            scheme = "https";
            path = "";
        } else {
            if (path == null || scheme == null) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_MESSAGE_ERROR,
                    "missing required pseudo-header on stream " + streamId);
            }
            // RFC 9114 §4.3.1: for http/https scheme requests, :authority
            // is REQUIRED. Non-http(s) schemes may omit it — proxies +
            // gateways translate.
            if (authority == null
                    && (scheme.equals("http") || scheme.equals("https"))) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_MESSAGE_ERROR,
                    "missing :authority pseudo-header for " + scheme
                        + " on stream " + streamId);
            }
            if (path.isEmpty() && (scheme.equals("http") || scheme.equals("https"))) {
                throw new Http3ConnectionException(
                    Http3ConnectionException.H3_MESSAGE_ERROR,
                    "empty :path for http(s) on stream " + streamId);
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
        // Dedup duplicates before createAsIfByAssoc (which throws on
        // repeated keys). Combine repeated fields per RFC 9110 §5.3;
        // "cookie" uses "; " per RFC 9113 §8.2.3 (h3 inherits h2 rules).
        Object[] merged = mergeDuplicateHeaders(regular, rp);
        IPersistentMap hmap = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(merged);

        Http3BodyPipe pipe = new Http3BodyPipe(maxRequestBodyBytes);
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

    /**
     * Dedup name/value pairs in {@code arr[0..len]} (interleaved names +
     * values). Duplicate names get their values joined per HTTP list-value
     * combining: "; " for "cookie" (RFC 9113 §8.2.3), ", " otherwise
     * (RFC 9110 §5.3). Returns an exact-fit Object[] with no repeats so
     * the downstream {@code createAsIfByAssoc} won't throw.
     */
    static Object[] mergeDuplicateHeaders(Object[] arr, int len) {
        // Fast path — no dups in the common case. Detect first, allocate
        // second. len is even (name/value pairs).
        boolean dup = false;
        outer:
        for (int i = 0; i < len; i += 2) {
            String a = (String) arr[i];
            for (int j = i + 2; j < len; j += 2) {
                if (a.equals(arr[j])) { dup = true; break outer; }
            }
        }
        if (!dup) {
            if (arr.length == len) return arr;
            Object[] fit = new Object[len];
            System.arraycopy(arr, 0, fit, 0, len);
            return fit;
        }
        // Slow path: linear compact + join.
        Object[] out = new Object[len];
        int op = 0;
        for (int i = 0; i < len; i += 2) {
            String name = (String) arr[i];
            String value = (String) arr[i + 1];
            int existing = -1;
            for (int j = 0; j < op; j += 2) {
                if (name.equals(out[j])) { existing = j; break; }
            }
            if (existing < 0) {
                out[op++] = name;
                out[op++] = value;
            } else {
                String sep = name.equals("cookie") ? "; " : ", ";
                out[existing + 1] = out[existing + 1] + sep + value;
            }
        }
        if (op == out.length) return out;
        Object[] fit = new Object[op];
        System.arraycopy(out, 0, fit, 0, op);
        return fit;
    }

    private static boolean hasUppercase(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') return true;
        }
        return false;
    }

    private static Http3ConnectionException pseudoDup(String name, long streamId) {
        return new Http3ConnectionException(
            Http3ConnectionException.H3_MESSAGE_ERROR,
            "duplicate " + name + " on request stream " + streamId);
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
            "500 internal error".getBytes(StandardCharsets.UTF_8),
            null);
    }

    /**
     * A response task carries either a materialised {@code body} (byte[]
     * or String → single stream_send fast-path) or a {@code bodySource}
     * (File / InputStream → streamed as multiple DATA frames). Exactly
     * one of {@code body} / {@code bodySource} is non-null; nil body
     * means no DATA at all.
     */
    private record ResponseTask(long streamId, int status,
                                Map<?, ?> headers, byte[] body,
                                Object bodySource) {
        static ResponseTask of(long streamId, Response r) {
            Map<?, ?> hs = r.headers == null
                ? java.util.Collections.emptyMap() : r.headers;
            Object rb = r.body;
            if (rb == null) {
                return new ResponseTask(streamId, r.status, hs, null, null);
            }
            if (rb instanceof byte[] b) {
                return new ResponseTask(streamId, r.status, hs, b, null);
            }
            if (rb instanceof String s) {
                return new ResponseTask(streamId, r.status, hs,
                    s.getBytes(StandardCharsets.UTF_8), null);
            }
            if (rb instanceof java.io.File || rb instanceof java.io.InputStream) {
                // Defer read — sendResponse's streaming path pulls
                // chunks incrementally to keep large bodies off the heap.
                return new ResponseTask(streamId, r.status, hs, null, rb);
            }
            return new ResponseTask(streamId, r.status, hs,
                ("[unsupported body type: " + rb.getClass().getName() + "]")
                    .getBytes(StandardCharsets.UTF_8),
                null);
        }
    }
}

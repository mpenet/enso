package com.s_exp.enso.quiche;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.Request;
import com.s_exp.enso.Response;
import com.s_exp.enso.RingHandler;
import com.s_exp.enso.quiche.ffm.quiche_h;
import com.s_exp.enso.quiche.ffm.quiche_h3_event_for_each_header$cb;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
// Note: connection driver runs on a platform thread; FFM upcalls from
// vthreads pin carriers and caused header-decode hangs during Phase 3
// debugging (see task #63 notes).

/**
 * One QUIC connection. Owns a {@code quiche_conn} and (once the handshake
 * completes) a {@code quiche_h3_conn} layered on top. A single owner
 * virtual thread drives everything — quiche's connection objects aren't
 * thread-safe.
 *
 * <p>Loop shape:
 * <ol>
 *   <li>Drain inbound datagrams from {@link #ingress} and feed
 *       {@code quiche_conn_recv}.
 *   <li>Poll {@code quiche_h3_conn_poll} for stream events. HEADERS →
 *       build a Ring request, spawn a worker vthread that runs the Ring
 *       handler and drops a {@link ResponseTask} on {@link #outbound}.
 *   <li>Drain {@link #outbound} — call {@code quiche_h3_send_response}
 *       and, if there's a body, {@code quiche_h3_send_body}.
 *   <li>Drain {@code quiche_conn_send} — write outbound datagrams to the
 *       shared {@link DatagramChannel}.
 * </ol>
 *
 * <p>Body streaming (request + response) is Phase 4. For now request
 * bodies are always empty and responses are one-shot.
 */
final class Http3Connection implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Connection.class.getName());

    private static final int MAX_DATAGRAM_SIZE = 1350;
    private static final int INGRESS_CAPACITY = 256;

    private final byte[] cid;
    private final Arena arena;
    private final MemorySegment conn;              // quiche_conn*
    private MemorySegment h3conn;                  // quiche_h3_conn*, created lazily
    private final DatagramChannel out;
    private final InetSocketAddress local;
    private final InetSocketAddress peer;
    private final RingHandler handler;
    private final BlockingQueue<byte[]> ingress = new LinkedBlockingQueue<>(INGRESS_CAPACITY);
    // Bounded outbound queue — a handler burst that outpaces the send path
    // applies backpressure to workers via LinkedBlockingQueue.put's block
    // rather than growing heap. Sized generously; capped mostly against
    // pathological handler code.
    private static final int OUTBOUND_CAPACITY = 1024;
    private final BlockingQueue<ResponseTask> outbound = new LinkedBlockingQueue<>(OUTBOUND_CAPACITY);
    // Owner-thread work is submitted to a shared cached platform-thread
    // pool owned by Http3Listener rather than each connection spawning its
    // own thread — accept flood then never churns thread creation. Track
    // the runner and the thread it landed on for the close-side join.
    private final Future<?> ownerFuture;
    private volatile Thread ownerThread;
    private volatile boolean running = true;
    private final Runnable onClose;
    private boolean loggedEstablished;
    // Upcall stubs bound to the connection-lifetime arena so they survive
    // multiple event-poll iterations. Creating a fresh stub per call is
    // expensive and, per Jetty's pattern, unnecessary.
    // The header-decode bucket is a plain field — only ever touched by the
    // owner platform thread, so no ThreadLocal indirection.
    private final List<String[]> collector = new ArrayList<>(16);
    // Shared upcall stub — one instance for the whole listener. Owned by
    // Http3Listener, passed in ctor. Per-connection stubs were leaking
    // hidden classes into metaspace under connection churn (JDK 25 crashes
    // in MetaspaceArena::allocate_inner).
    private final MemorySegment forEachHeaderCbSeg;
    // Shared listener-lifetime HTTP/3 config. Passed in at ctor.
    private final MemorySegment h3Config;
    // ThreadLocal used by the shared upcall stub to find the current
    // connection's collector. The owner platform thread sets this once at
    // run() start; the stub's callback reads it per header. Reverts the
    // task-#73 optimisation because sharing the stub eliminates the
    // metaspace churn that caused SIGSEGVs.
    static final ThreadLocal<List<String[]>> CURRENT_COLLECTOR = new ThreadLocal<>();
    // Live request bodies keyed by stream_id. Owner-thread only, no
    // concurrent mutation — the map is unlocked.
    private final HashMap<Long, H3BodyPipe> bodyPipes = new HashMap<>();
    // Ctor-time reusable FFM scratch, all backed by the connection-lifetime
    // arena. Copies Jetty's pattern for the pieces where sharing across
    // iterations is safe (fixed-size buffers, single-thread reader).
    // sockaddrs stay per-call — pre-baking recvInfo caused subtle
    // second-connection handshake stalls; the confined-arena rebuild is
    // still cheap versus the datagram-copy cost.
    private MemorySegment inBuf;          // inbound datagram scratch
    private MemorySegment outBuf;         // outbound datagram scratch
    private MemorySegment sendInfo;       // quiche_send_info out param
    private MemorySegment recvInfo;       // quiche_recv_info out param
    private MemorySegment peerSockaddr;   // pre-baked peer sockaddr bytes
    private int peerSockaddrLen;
    private MemorySegment localSockaddr;  // pre-baked local sockaddr bytes
    private int localSockaddrLen;
    private MemorySegment evPtr;          // out-param for quiche_h3_conn_poll
    private MemorySegment bodyBuf;        // recv_body scratch (4 KiB)

    private final long maxRequestBodyBytes;

    Http3Connection(byte[] cid, MemorySegment conn, Arena arena,
                    DatagramChannel out,
                    InetSocketAddress local, InetSocketAddress peer,
                    RingHandler handler,
                    long maxRequestBodyBytes,
                    Executor executor,
                    MemorySegment forEachHeaderCbSeg,
                    MemorySegment h3Config,
                    Runnable onClose) {
        this.cid = cid;
        this.conn = conn;
        this.arena = arena;
        this.out = out;
        this.local = local;
        this.peer = peer;
        this.handler = handler;
        this.maxRequestBodyBytes = maxRequestBodyBytes;
        this.forEachHeaderCbSeg = forEachHeaderCbSeg;
        this.h3Config = h3Config;
        this.onClose = onClose;
        // Pre-allocate fixed-size FFM scratch on the connection arena.
        // Reused across every iteration of the recv/poll/send loop —
        // saves an Arena.allocate per iteration for these slots.
        this.inBuf = arena.allocate(2 * MAX_DATAGRAM_SIZE);
        this.outBuf = arena.allocate(MAX_DATAGRAM_SIZE);
        this.sendInfo = arena.allocate(64);
        this.evPtr = arena.allocate(ValueLayout.ADDRESS);
        this.bodyBuf = arena.allocate(4096);
        // Pre-bake sockaddrs + recvInfo on the connection arena. Sockaddrs
        // don't change over the connection lifetime (no migration support
        // yet). This eliminates the per-datagram Arena.ofConfined() churn
        // in processRecv, which under load was suspected of interacting
        // with libmalloc's freelist on JDK 25 (SIGTRAP-abort crashes).
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
        // Owner runs on a shared platform-thread pool (see Http3Listener).
        // FutureTask lets close() join it — cached pool + reuse means we
        // don't spin up a thread per connection.
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
        // Per-iteration variable-length scratch (header emission arrays,
        // occasional small allocations). Fixed-size FFM slots come from
        // the connection-lifetime `arena`.
        // Publish this connection's collector so the shared upcall stub can
        // reach it. Owner thread is dedicated to this loop for its lifetime,
        // so a plain ThreadLocal.set here + remove in finally is enough.
        CURRENT_COLLECTOR.set(collector);
        try (Arena scratch = Arena.ofConfined()) {
            while (running) {
                drainIngress();
                maybeCreateH3();
                pollH3Events(scratch);
                drainOutbound(scratch);
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
            CURRENT_COLLECTOR.remove();
            close();
        }
    }

    /**
     * Blocks briefly on the first inbound datagram or until the QUIC idle
     * timer fires. Prevents a tight spin between recv/send cycles when
     * neither peer nor handler has work to do.
     */
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

    private void maybeCreateH3() {
        if (h3conn != null) return;
        if (!quiche_h.quiche_conn_is_established(conn)) return;
        // Shared listener-lifetime h3 config — reused, not per-conn. Per-conn
        // quiche_h3_config_new/free churn on 0.29.3 triggers libmalloc
        // freelist corruption (task #79).
        MemorySegment cfg = h3Config;
        try {
            h3conn = quiche_h.quiche_h3_conn_new_with_transport(conn, cfg);
            if (h3conn.address() == 0) {
                LOG.warning("quiche_h3_conn_new_with_transport returned null");
                h3conn = null;
            } else {
                LOG.info("h3 layer created for cid=" + HexFormat.of().formatHex(cid));
            }
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "quiche_h3_conn_new_with_transport threw", t);
        }
    }

    private void pollH3Events(Arena scratch) {
        if (h3conn == null) return;
        while (true) {
            long streamId = quiche_h.quiche_h3_conn_poll(h3conn, conn, evPtr);
            if (streamId < 0) return; // QUICHE_H3_ERR_DONE or fatal
            MemorySegment ev = evPtr.get(ValueLayout.ADDRESS, 0);
            try {
                int type = quiche_h.quiche_h3_event_type(ev);
                if (type == quiche_h.QUICHE_H3_EVENT_HEADERS()) {
                    handleHeaders(scratch, streamId, ev);
                } else if (type == quiche_h.QUICHE_H3_EVENT_DATA()) {
                    pumpRequestBody(streamId);
                } else if (type == quiche_h.QUICHE_H3_EVENT_FINISHED()) {
                    H3BodyPipe pipe = bodyPipes.remove(streamId);
                    if (pipe != null) pipe.signalEnd();
                } else if (type == quiche_h.QUICHE_H3_EVENT_RESET()) {
                    H3BodyPipe pipe = bodyPipes.remove(streamId);
                    if (pipe != null) pipe.signalEnd();
                } else if (type == quiche_h.QUICHE_H3_EVENT_GOAWAY()) {
                    LOG.info("h3 GOAWAY received on cid=" + HexFormat.of().formatHex(cid));
                }
            } finally {
                quiche_h.quiche_h3_event_free(ev);
            }
        }
    }

    // Adversarial peer can spam small DATA frames on one stream. Bound the
    // in-loop iterations so pollH3Events() gets to service other streams'
    // events + fire timeouts. quiche re-fires the DATA event next poll if
    // there's more.
    private static final int PUMP_MAX_ITERS = 32;

    private void pumpRequestBody(long streamId) {
        H3BodyPipe pipe = bodyPipes.get(streamId);
        if (pipe == null) return;
        for (int iter = 0; iter < PUMP_MAX_ITERS; iter++) {
            long r = quiche_h.quiche_h3_recv_body(h3conn, conn, streamId,
                                                   bodyBuf, bodyBuf.byteSize());
            if (r == quiche_h.QUICHE_ERR_DONE()) return;
            if (r < 0) {
                LOG.info("h3 recv_body rc=" + r + " stream=" + streamId);
                return;
            }
            if (r == 0) return;
            byte[] chunk = new byte[(int) r];
            MemorySegment.copy(bodyBuf, ValueLayout.JAVA_BYTE, 0, chunk, 0, (int) r);
            if (!pipe.enqueueChecked(chunk)) {
                LOG.info("h3 body size cap exceeded, resetting stream " + streamId);
                bodyPipes.remove(streamId);
                pipe.signalEnd();
                return;
            }
        }
    }

    private void handleHeaders(Arena scratch, long streamId, MemorySegment ev) {
        collector.clear();
        try {
            quiche_h.quiche_h3_event_for_each_header(ev, forEachHeaderCbSeg, MemorySegment.NULL);
            // Snapshot before dispatch — the worker vthread mustn't share
            // the owner's collector, and this owner thread will reuse it
            // on the next handleHeaders call.
            List<String[]> snapshot = new ArrayList<>(collector);
            collector.clear();
            dispatchRequest(streamId, snapshot);
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 handleHeaders threw", t);
        }
    }

    private void dispatchRequest(long streamId, List<String[]> headers) {
        String method = null, path = null, scheme = null, authority = null;
        // Pre-count non-pseudo headers so the backing Object[] is sized
        // exactly. Same fix Http2Connection.buildRequest ended up with in
        // task #53 — pseudo-headers don't go in the map so
        // headers.size() * 2 over-allocates by the pseudo count.
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
                // Per RFC 9114 §4.3.1, pseudo-headers must precede regular
                // headers. Reject if we've already seen a regular one.
                if (seenRegular) {
                    LOG.warning("h3 pseudo-header after regular, streamId=" + streamId);
                    return;
                }
                switch (n) {
                    case ":method"    -> method    = v;
                    case ":path"      -> path      = v;
                    case ":scheme"    -> scheme    = v;
                    case ":authority" -> authority = v;
                    default           -> { /* ignore unknown pseudo */ }
                }
            } else {
                seenRegular = true;
                // Connection-specific headers are forbidden in HTTP/3
                // (RFC 9114 §4.2, same list as HTTP/2 §8.1.2.2). Drop
                // request rather than pass through — request smuggling
                // defence.
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
        // RFC 9114 §4.3.1: :method, :scheme, :path REQUIRED. :authority
        // required for http/https. Empty :path invalid for http/https.
        if (method == null || path == null || scheme == null) {
            LOG.warning("h3 request missing pseudo-headers, streamId=" + streamId);
            return;
        }
        if (path.isEmpty() && (scheme.equals("http") || scheme.equals("https"))) {
            LOG.warning("h3 empty :path for http(s), streamId=" + streamId);
            return;
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
            // regular is exactly rp long — pre-counted above.
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

        // Run the Ring handler on its own vthread so the owner keeps
        // draining events + datagrams while the handler does its work.
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
            // Backpressure: block until the send path has room. Worker
            // vthread parks harmlessly; unbounded queue would let handler
            // bursts inflate the heap.
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

    private void drainOutbound(Arena scratch) {
        if (h3conn == null) return;
        ResponseTask task;
        while ((task = outbound.poll()) != null) {
            sendResponse(scratch, task);
        }
    }

    private void sendResponse(Arena scratch, ResponseTask task) {
        // Build the h3_header array: status pseudo + regular headers.
        // Each header holds pointer+len for name and value (32 bytes on
        // 64-bit). Kept in the confined scratch arena so all backing bytes
        // die together on the next iteration.
        int n = 1 + task.headers.size();
        MemorySegment hdrs = scratch.allocate((long) n * 32);
        int idx = 0;
        writeHeader(scratch, hdrs, idx++, ":status", Integer.toString(task.status));
        for (Map.Entry<?, ?> e : task.headers.entrySet()) {
            String hn = String.valueOf(e.getKey()).toLowerCase();
            // HTTP/3 forbids connection-specific headers same as HTTP/2 §8.1.2.2.
            if (hn.equals("connection") || hn.equals("keep-alive")
                || hn.equals("transfer-encoding") || hn.equals("upgrade")
                || hn.equals("proxy-connection")) continue;
            Object v = e.getValue();
            writeHeader(scratch, hdrs, idx++, hn, v == null ? "" : v.toString());
        }
        boolean hasBody = task.body != null && task.body.length > 0;
        int rc = quiche_h.quiche_h3_send_response(h3conn, conn, task.streamId,
            hdrs, idx, !hasBody);
        if (rc != 0) {
            LOG.info("h3 send_response rc=" + rc + " stream=" + task.streamId);
            return;
        }
        if (hasBody) {
            MemorySegment body = scratch.allocate(task.body.length);
            MemorySegment.copy(task.body, 0, body, ValueLayout.JAVA_BYTE, 0, task.body.length);
            long sent = quiche_h.quiche_h3_send_body(h3conn, conn, task.streamId,
                body, task.body.length, true);
            if (sent < 0) {
                LOG.info("h3 send_body rc=" + sent + " stream=" + task.streamId);
            }
        }
    }

    private void writeHeader(Arena arena, MemorySegment array, int index,
                             String name, String value) {
        byte[] nb = name.getBytes(StandardCharsets.UTF_8);
        byte[] vb = value.getBytes(StandardCharsets.UTF_8);
        MemorySegment nSeg = arena.allocate(nb.length);
        MemorySegment.copy(nb, 0, nSeg, ValueLayout.JAVA_BYTE, 0, nb.length);
        MemorySegment vSeg = arena.allocate(vb.length);
        MemorySegment.copy(vb, 0, vSeg, ValueLayout.JAVA_BYTE, 0, vb.length);
        long base = (long) index * 32;
        array.set(ValueLayout.ADDRESS, base, nSeg);
        array.set(ValueLayout.JAVA_LONG, base + 8, nb.length);
        array.set(ValueLayout.ADDRESS, base + 16, vSeg);
        array.set(ValueLayout.JAVA_LONG, base + 24, vb.length);
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

    private volatile boolean closed = false;

    @Override
    public void close() {
        // Idempotent — close() is called from both the owner thread's
        // finally block and from Http3Listener.close(); the native frees
        // must not run twice.
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        running = false;
        // Unblock any worker vthreads parked on a body pipe's take() so
        // they see EOF and exit cleanly. Without this, an orphaned request
        // (HEADERS but no FINISHED/RESET before teardown) would leak a
        // vthread forever.
        for (H3BodyPipe pipe : bodyPipes.values()) {
            try { pipe.signalEnd(); } catch (Throwable ignored) {}
        }
        bodyPipes.clear();
        // If someone else is closing us (Http3Listener.close on shutdown),
        // wait briefly for the owner to unwind cleanly so we don't free
        // native resources while it's mid-call inside quiche_conn_recv or
        // _send. Skip when called from the owner itself.
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
            if (h3conn != null) quiche_h.quiche_h3_conn_free(h3conn);
        } catch (Throwable ignored) {}
        try {
            quiche_h.quiche_conn_free(conn);
        } catch (Throwable ignored) {
        } finally {
            try { arena.close(); } catch (Throwable ignored) {}
            if (onClose != null) onClose.run();
        }
    }

    byte[] cid() { return cid; }

    /**
     * Owner-thread work item: a completed Ring response ready to serialise.
     * Body materialised to byte[] on the worker thread — Phase 5 will move
     * to a chunk iterator for true streaming (File chunks, StreamingBody
     * callback).
     */
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
            // StreamingBody / ISeq / StreamableResponseBody land in Phase 5.
            return ("[unsupported body type: " + rb.getClass().getName() + "]")
                .getBytes(StandardCharsets.UTF_8);
        }
    }
}

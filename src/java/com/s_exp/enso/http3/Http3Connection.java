package com.s_exp.enso.http3;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.StreamingBody;
import com.s_exp.enso.core.HttpFields;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One QUIC connection. Owns a {@code quiche_conn} at the transport layer
 * and a Java-space {@link Http3Session} for HTTP/3 framing + QPACK. A single
 * owner platform thread drives everything — quiche's connection objects
 * aren't thread-safe.
 *
 * <p>quiche is reached through the JNI shim {@link Quiche}.
 *
 * <p>Loop shape per iteration:
 * <ol>
 *   <li>Drain inbound datagrams from {@link #ingress} → {@code quiche_conn_recv},
 *       then fire quiche's timers if their deadline passed.
 *   <li>Once transport is established, initialise {@link #session} (opens
 *       control + QPACK streams, sends SETTINGS).
 *   <li>Iterate {@code quiche_conn_readable} streams; pull bytes via
 *       {@code quiche_conn_stream_recv} and hand them to
 *       {@link Http3Session#onStreamData}, which dispatches HEADERS/DATA
 *       through a {@link Http3Session.RequestSink} that spawns a worker
 *       vthread per request stream.
 *   <li>Drain {@link #outbound} response queue → session.writeResponse.
 *   <li>Drain {@code quiche_conn_send} → UDP.
 *   <li>Park until quiche's next timer deadline or a {@link #wake} from
 *       the demux (datagram), a handler (response), a request-body reader
 *       (drained pipe) or {@link #signalClose}.
 * </ol>
 */
final class Http3Connection implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Connection.class.getName());

    private static final int INGRESS_CAPACITY = 256;
    private static final int OUTBOUND_CAPACITY = 1024;
    private static final int STREAM_RECV_BUF = 16 * 1024;
    // A connection whose handshake hasn't completed by then is dropped.
    // quiche's idle timer only covers this when the client advertises an
    // idle timeout; one that advertises none would keep its state (and
    // this platform thread) forever.
    private static final long HANDSHAKE_TIMEOUT_NANOS = 10_000_000_000L;

    private static final byte[] EMPTY_REASON = new byte[0];

    private final byte[] cid;
    private final String cidHex; // computed once; used only in log messages
    private final long conn;
    private final DatagramChannel out;
    private final byte[] localIp;
    private final int localPort;
    // Peer's current address. Owner thread only. Follows the source of
    // inbound datagrams (handed to quiche per packet, so it can validate a
    // NAT rebinding) and quiche's send_info.to for outbound ones.
    private InetSocketAddress peer;
    private byte[] peerIp;
    private InetSocketAddress recvPeer;
    private byte[] recvPeerIp;
    private final RingHandler handler;
    private final RingErrorHandler errorHandler;
    private final Config config;
    private final long maxRequestBodyBytes;
    // Handler threads still running, including those of abandoned
    // requests whose QUIC stream is already gone (and was handed back to
    // the peer as fresh stream credit). Capped at twice the advertised
    // stream limit: abandoned handlers are interrupted, but one that
    // ignores interrupts must not let a reset loop pile up threads, and
    // the slack leaves room for handlers finishing as their stream closes.
    private final AtomicInteger liveHandlers = new AtomicInteger();
    private final int maxLiveHandlers;
    private final Runnable onClose;

    private final Inbox ingress = new Inbox(INGRESS_CAPACITY);
    // ArrayBlockingQueue uses a single backing ring + one condition var
    // rather than allocating a Node per put — task #124 alloc profile
    // showed LinkedBlockingQueue$Node in the top 15. Holds at least one
    // response per live handler plus the timer's: after teardown drains
    // it once, those are the only puts left, so none blocks forever.
    private final BlockingQueue<ResponseTask> outbound;
    // Wake protocol (see #wake / #waitForWork): producers set
    // wakePending then unpark the owner if it announced it is parking.
    private volatile boolean wakePending;
    private volatile boolean parked;
    private final Runnable wakeTask = this::wake;

    private final Future<?> ownerFuture;
    private volatile Thread ownerThread;
    private volatile boolean running = true;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private boolean loggedEstablished;
    private final long handshakeDeadline = System.nanoTime() + HANDSHAKE_TIMEOUT_NANOS;

    // H3-layer state, created once transport handshake completes.
    private Http3Session session;
    // Per-stream request body pipes (owner-thread only, no concurrent
    // mutation). Primitive-long-keyed to avoid Long autoboxing on
    // put/get/remove — task #122 alloc profile identified this as a
    // top boxed-primitive source.
    private final Long2ObjectHashMap<Http3BodyPipe> bodyPipes = new Long2ObjectHashMap<>();
    // Streamed response bodies being sent (owner-thread only). Their
    // producers run on the handlers' virtual threads; the owner loop
    // pumps each one in pumpResponseBodies.
    private final Long2ObjectHashMap<Http3ResponseBody> responseBodies =
        new Long2ObjectHashMap<>();
    // In-flight requests (owner-thread only), for teardown and stream
    // resets. The handler thread and timeout timer hold their Exchange
    // directly, so no concurrent map (or Long boxing) is needed.
    private final Long2ObjectHashMap<Exchange> exchanges = new Long2ObjectHashMap<>();
    // Set by a drained request-body pipe: paused streams can be read again.
    private volatile boolean resumeReads;
    private final Runnable resumeReadsTask = () -> {
        resumeReads = true;
        wake();
    };
    // True when this iteration fed quiche a datagram (streams may have
    // become readable).
    private boolean receivedPackets;
    private final long[] sidOut = new long[1];

    // Daemon single-thread scheduler shared across all h3 connections.
    // Remove-on-cancel: nearly every request cancels its timer, and a
    // cancelled task (which references its connection) would otherwise
    // stay queued until its deadline.
    private static final java.util.concurrent.ScheduledThreadPoolExecutor TIMEOUT_SCHEDULER =
        newTimeoutScheduler();

    private static java.util.concurrent.ScheduledThreadPoolExecutor newTimeoutScheduler() {
        java.util.concurrent.ScheduledThreadPoolExecutor s =
            new java.util.concurrent.ScheduledThreadPoolExecutor(1, r -> {
                Thread th = new Thread(r, "enso-h3-request-timeout");
                th.setDaemon(true);
                return th;
            });
        s.setRemoveOnCancelPolicy(true);
        return s;
    }

    Http3Connection(byte[] cid, long conn,
                    DatagramChannel out,
                    InetSocketAddress local, InetSocketAddress peer,
                    RingHandler handler,
                    RingErrorHandler errorHandler,
                    Config config,
                    Executor executor,
                    Runnable onClose) {
        this.cid = cid;
        this.cidHex = HexFormat.of().formatHex(cid);
        this.conn = conn;
        this.out = out;
        this.peer = peer;
        this.peerIp = peer.getAddress().getAddress();
        this.recvPeer = peer;
        this.recvPeerIp = peer.getAddress().getAddress();
        this.localIp = local.getAddress().getAddress();
        this.localPort = local.getPort();
        this.sendView = ByteBuffer.allocateDirect(config.http3MaxUdpPayloadSize);
        this.handler = handler;
        this.errorHandler = errorHandler;
        this.config = config;
        this.maxRequestBodyBytes = config.maxRequestBodyBytes;
        this.maxLiveHandlers = 2 * config.http3InitialMaxStreamsBidi;
        this.outbound = new ArrayBlockingQueue<>(Math.max(OUTBOUND_CAPACITY, maxLiveHandlers + 1));
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

    /** Demux thread only: hand over one datagram received from {@code from}. */
    void enqueue(byte[] datagram, InetSocketAddress from) {
        // Short-circuit once the owner has begun shutdown: nothing will
        // drain the queue and holding refs delays GC.
        if (closed.get()) return;
        if (ingress.offer(datagram, from)) {
            wake();
        } else {
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

    /**
     * Wake the owner thread: new datagram, queued response, drained
     * request-body pipe or close. Cheap when the owner is busy (two
     * volatile accesses); unparks only when it is parked or about to.
     */
    void wake() {
        wakePending = true;
        if (parked) {
            Thread owner = ownerThread;
            if (owner != null) LockSupport.unpark(owner);
        }
    }

    private void run() {
        Http3Session.RequestSink sink = new SinkImpl();
        try {
            while (running) {
                wakePending = false;
                // Nobody interrupts the owner; an interrupt (executor
                // shutdownNow) is a stop request. Clearing it also keeps
                // the shared DatagramChannel safe: an I/O call on an
                // interrupted thread closes the channel for every
                // connection (ClosedByInterruptException).
                if (Thread.interrupted()) break;
                drainIngress();
                // Fire quiche's timers every iteration their deadline has
                // passed, even when ingress never lets the owner park.
                if (Quiche.connTimeoutAsNanos(conn) == 0) Quiche.connOnTimeout(conn);
                maybeInitH3();
                if (session != null) {
                    // Only new packets can carry a peer STOP_SENDING.
                    checkStoppedBodies = receivedPackets;
                    // Streams only become readable through new packets or
                    // a drained body pipe; skip the iterator otherwise.
                    if (receivedPackets || resumeReads) {
                        receivedPackets = false;
                        resumeReads = false;
                        drainReadableStreams(sink);
                    }
                    drainOutbound();
                    // Retry deferred stream writes (task #104) — quiche
                    // may have accepted new flow-control credit from the
                    // peer since our last attempt.
                    session.drainPendingWrites();
                    // Send what streamed response bodies have offered,
                    // as far as flow control allows.
                    pumpResponseBodies();
                }
                processSend();
                if (Quiche.connIsClosed(conn)) return;
                if (!loggedEstablished) {
                    if (Quiche.connIsEstablished(conn)) {
                        loggedEstablished = true;
                        LOG.info("h3 handshake established with " + peer
                            + " cid=" + cidHex);
                    } else if (System.nanoTime() - handshakeDeadline >= 0) {
                        LOG.fine("h3 handshake timed out cid=" + cidHex);
                        break;
                    }
                }
                waitForWork();
            }
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 conn driver crash", t);
            // An internal failure, not a graceful close: tell the peer.
            try {
                if (!Quiche.connIsClosed(conn)) {
                    Quiche.connClose(conn, true,
                        Http3ConnectionException.H3_INTERNAL_ERROR, EMPTY_REASON);
                }
            } catch (Throwable ignored) {}
        } finally {
            // Owner-thread cleanup. This is the ONLY site that frees the
            // quiche conn. External close() only signals via
            // `running=false` + wake(). Guarantees no JNI call is
            // in-flight when we free.
            closed.set(true);
            // Bodies still arriving are incomplete: readers must see an
            // error, not a clean EOF.
            bodyPipes.forEach((k, pipe) -> {
                try { pipe.signalTruncated(); } catch (Throwable ignored) {}
            });
            bodyPipes.clear();
            // Unblock streamed-body producers mid-flight: their next or
            // pending write throws, so they close their sources (File
            // handles, socket streams) instead of leaking them.
            responseBodies.forEach((sid, body) -> body.cancel());
            responseBodies.clear();
            // Abandon in-flight requests: their handlers are interrupted
            // and, should one carry on anyway, its claim fails so it
            // drops its response. A timer firing after this point finds
            // the exchange claimed and no-ops.
            exchanges.forEach((sid, ex) -> ex.abandon());
            exchanges.clear();
            // Responses queued but never sent: a streamed body's producer
            // would otherwise wait forever for this thread to take it.
            cancelQueuedResponses();
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

    /**
     * Park until quiche's next timer deadline or a {@link #wake}.
     * Deferred writes need no polling — peer flow-control credit only
     * grows when their ACK / MAX_STREAM_DATA frames arrive, which wakes us.
     * {@code parked} is published before the final emptiness checks so a
     * producer either sees it (and unparks) or its work is seen here.
     */
    private void waitForWork() {
        long timeoutNanos = Quiche.connTimeoutAsNanos(conn);
        if (timeoutNanos == 0) return;
        if (!loggedEstablished) {
            long untilDeadline = Math.max(1, handshakeDeadline - System.nanoTime());
            timeoutNanos = timeoutNanos < 0 ? untilDeadline : Math.min(timeoutNanos, untilDeadline);
        }
        parked = true;
        try {
            if (wakePending || !running || !ingress.isEmpty() || !outbound.isEmpty()) return;
            if (timeoutNanos < 0) LockSupport.park(this);
            else LockSupport.parkNanos(this, timeoutNanos);
        } finally {
            parked = false;
        }
    }

    private void drainIngress() throws IOException {
        byte[] datagram;
        while ((datagram = ingress.poll()) != null) {
            processRecv(datagram, ingress.lastFrom);
            receivedPackets = true;
        }
    }

    private void maybeInitH3() {
        if (session == null) {
            if (!Quiche.connIsEstablished(conn)) return;
            session = new Http3Session(conn, config);
        }
        // Retried every iteration until the control + QPACK streams are
        // open (e.g. peer hasn't granted uni-stream credit yet).
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
            // Body backpressure: leave the bytes in quiche (its flow
            // control then stalls the peer) while the handler hasn't
            // consumed what we already buffered; its read wakes us.
            Http3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe != null && !pipe.hasRoom()) {
                pipe.resumeWhenDrained(resumeReadsTask);
                return;
            }
            finOut[0] = false;
            long rc = Quiche.connStreamRecv(conn, streamId,
                recvBuf, STREAM_RECV_BUF, finOut, errOut);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                LOG.info("h3 stream_recv stream=" + streamId
                    + " rc=" + rc + " err=" + errOut[0]);
                // Peer RESET_STREAM (or the stream is gone). The request
                // body is incomplete and its read-side state is dropped,
                // so entries don't accumulate under reset floods (task
                // #140). Our sending side stays usable and the response
                // is still sent, unless the peer also stopped it
                // (STOP_SENDING) or the stream no longer exists: then
                // nobody will read a response.
                Http3BodyPipe reset = bodyPipes.remove(streamId);
                if (reset != null) reset.signalTruncated();
                session.onStreamReset(streamId);
                if (session.sendStopped(streamId)) abandonResponse(streamId);
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

    private void cancelQueuedResponses() {
        ResponseTask task;
        while ((task = outbound.poll()) != null) {
            if (task.stream != null) task.stream.cancel();
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
        boolean hasContentLength = false;
        for (Map.Entry<?, ?> e : task.headers.entrySet()) {
            String hn = String.valueOf(e.getKey()).toLowerCase(java.util.Locale.ROOT);
            if (hn.equals("connection") || hn.equals("keep-alive")
                || hn.equals("transfer-encoding") || hn.equals("upgrade")
                || hn.equals("proxy-connection")) continue;
            if (hn.equals("server")) hasServer = true;
            else if (hn.equals("content-length")) hasContentLength = true;
            Object v = e.getValue();
            if (v instanceof List<?> values) {
                // Ring: a seq of strings is one field per value.
                for (Object item : values) {
                    addResponsePair(hn, item, task.streamId);
                }
            } else {
                addResponsePair(hn, v, task.streamId);
            }
        }
        if (!hasServer && config.serverHeader != null && !config.serverHeader.isEmpty()) {
            headersList.add(acquirePair("server", config.serverHeader));
        }
        // RFC 9110 §9.3.2 / §8.6: HEAD response MUST NOT emit a body,
        // but SHOULD advertise the Content-Length the GET would return
        // (known for byte[] / String / File bodies, computed by the
        // handler thread in ResponseTask.of).
        if (task.head && !hasContentLength && task.contentLength >= 0) {
            headersList.add(acquirePair("content-length", Long.toString(task.contentLength)));
        }
        if (task.stream != null) {
            // Streamed body: HEADERS now, DATA as the producer offers it;
            // the response completes in pumpResponseBodies.
            session.writeHeadersOnly(task.streamId, headersList);
            responseBodies.put(task.streamId, task.stream);
            return;
        }
        // Materialised body (or none): HEADERS + DATA + FIN handed to
        // quiche together (task #143 halved JNI hops here).
        try {
            session.writeResponse(task.streamId, headersList, task.head ? null : task.body);
        } finally {
            responseComplete(task.streamId);
        }
    }

    /**
     * The request stream was reset (by us or the peer): claim the
     * response gate so whatever the handler returns is dropped instead of
     * written to a dead stream, and interrupt the handler.
     */
    private void abandonResponse(long streamId) {
        Exchange ex = exchanges.remove(streamId);
        if (ex != null) ex.abandon();
    }

    /**
     * Drop per-request state once the whole response was handed to the
     * session. A body pipe still registered means the request never saw
     * its FIN: the session stopped reading it, so it is truncated.
     */
    private void responseComplete(long streamId) {
        exchanges.remove(streamId);
        Http3BodyPipe pipe = bodyPipes.remove(streamId);
        if (pipe != null) pipe.signalTruncated();
    }

    // Stream ids whose body finished during the current forEach pass
    // (Long2ObjectHashMap can't remove while iterating). Negative-encoded
    // (-sid - 1) when aborted.
    private long[] finishedBodies = new long[8];
    private int finishedBodiesLen;
    // Set for loop iterations that fed quiche packets: idle bodies then
    // check whether the peer stopped their stream.
    private boolean checkStoppedBodies;
    private final Long2ObjectHashMap.EntryConsumer<Http3ResponseBody> pumpBody = (sid, body) -> {
        int st = body.pump(session, sid, checkStoppedBodies);
        if (st == Http3ResponseBody.SENDING) return;
        if (finishedBodiesLen == finishedBodies.length) {
            finishedBodies = java.util.Arrays.copyOf(finishedBodies, finishedBodiesLen * 2);
        }
        finishedBodies[finishedBodiesLen++] = st == Http3ResponseBody.COMPLETE ? sid : -sid - 1;
    };

    private void pumpResponseBodies() {
        if (responseBodies.isEmpty()) return;
        finishedBodiesLen = 0;
        responseBodies.forEach(pumpBody);
        for (int i = 0; i < finishedBodiesLen; i++) {
            long marker = finishedBodies[i];
            long sid = marker < 0 ? -marker - 1 : marker;
            responseBodies.remove(sid);
            if (marker < 0) {
                // Producer failed or the peer stopped the stream: a reset,
                // never a clean FIN, so a truncated body can't look whole.
                session.resetRequestStream(sid, Http3ConnectionException.H3_INTERNAL_ERROR);
                // The producer may be blocked outside write (an event
                // source waiting for its next event): interrupt it.
                abandonResponse(sid);
            }
            responseComplete(sid);
        }
    }

    // Read size for File / InputStream response bodies. Allocated per
    // streamed response on its handler thread.
    private static final int STREAM_CHUNK_BYTES = 64 * 1024;

    /**
     * Producer side of a streamed response, on the handler's virtual
     * thread: read / generate the body and hand it to the owner slice by
     * slice. Any failure resets the stream.
     */
    private void produceBody(long streamId, Http3ResponseBody out, Object source) {
        try {
            if (source instanceof StreamingBody sb) {
                ChunkedWriter writer = new ChunkedWriter(
                    out.outputStream(), config.chunkBufferSize, false);
                try {
                    sb.write(writer);
                } finally {
                    writer.closeInternal();
                }
            } else {
                try (java.io.InputStream in = source instanceof java.io.File f
                        ? new java.io.FileInputStream(f) : (java.io.InputStream) source) {
                    byte[] buf = new byte[STREAM_CHUNK_BYTES];
                    int n;
                    while ((n = in.read(buf)) >= 0) {
                        // Coalesce what's already available into one
                        // DATA frame without waiting for more.
                        int r;
                        while (n < buf.length && in.available() > 0
                                && (r = in.read(buf, n, buf.length - n)) > 0) {
                            n += r;
                        }
                        out.write(buf, 0, n);
                    }
                }
            }
            out.finish();
        } catch (Throwable t) {
            LOG.log(Level.FINE, "h3 response body failed stream=" + streamId, t);
            out.fail();
        }
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

    /**
     * Appends one response field. Values were validated on the handler
     * thread; a value whose toString() has since changed to carry CR, LF
     * or NUL (RFC 9114 §4.2) is dropped rather than sent.
     */
    private void addResponsePair(String name, Object value, long streamId) {
        String vs = value == null ? "" : value.toString();
        if (containsCtl(vs)) {
            LOG.warning("h3 dropping response header with CTL char: '"
                + name + "' streamId=" + streamId);
            return;
        }
        headersList.add(acquirePair(name, vs));
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

    private void processRecv(byte[] datagram, InetSocketAddress from) throws IOException {
        // Each datagram carries its own source: quiche detects a changed
        // peer address (NAT rebinding) from it and validates the new path.
        // The address bytes are re-extracted only when it changes.
        if (!from.equals(recvPeer)) {
            recvPeer = from;
            recvPeerIp = from.getAddress().getAddress();
        }
        long rc = Quiche.connRecv(conn, datagram, datagram.length,
            recvPeerIp, recvPeer.getPort(), localIp, localPort);
        if (rc < 0 && rc != Quiche.QUICHE_ERR_DONE) {
            LOG.info("h3 quiche_conn_recv returned " + rc);
        }
    }

    // Owner-thread scratch, connection lifetime — no per-packet
    // allocation. quiche writes each packet straight into the direct
    // sendView (sized to the max UDP payload we advertise), which
    // DatagramChannel.send uses without another copy; toIp/toMeta receive
    // the packet's destination.
    private final ByteBuffer sendView;
    private final byte[] toIp = new byte[16];
    private final int[] toMeta = new int[2];

    private void processSend() throws IOException {
        int cap = sendView.capacity();
        while (true) {
            long rc = Quiche.connSend(conn, sendView, cap, toIp, toMeta);
            if (rc == Quiche.QUICHE_ERR_DONE) return;
            if (rc < 0) {
                LOG.info("h3 quiche_conn_send returned " + rc);
                return;
            }
            sendView.clear().limit((int) rc);
            out.send(sendView, destination());
        }
    }

    /**
     * Where quiche wants the last packet sent (send_info.to): the current
     * peer unless it moved (validated NAT rebinding), in which case the
     * cached address is replaced.
     */
    private InetSocketAddress destination() throws IOException {
        int port = toMeta[0];
        int ipLen = toMeta[1];
        if (ipLen == 0) return peer;
        if (port != peer.getPort() || peerIp.length != ipLen
                || !java.util.Arrays.equals(peerIp, 0, ipLen, toIp, 0, ipLen)) {
            peerIp = java.util.Arrays.copyOf(toIp, ipLen);
            peer = new InetSocketAddress(java.net.InetAddress.getByAddress(peerIp), port);
            LOG.fine("h3 peer address now " + peer + " cid=" + cidHex);
        }
        return peer;
    }

    @Override
    public void close() {
        // Signal + join. Native cleanup (quiche_conn_free) done exclusively
        // by the owner thread in run()'s finally block.
        if (!signalClose()) return;
        if (Thread.currentThread() == ownerThread) return;
        // Never interrupt the owner: it does I/O on the listener's shared
        // DatagramChannel, which an interrupt would close for every
        // connection (ClosedByInterruptException).
        try {
            ownerFuture.get(3, TimeUnit.SECONDS);
        } catch (TimeoutException te) {
            LOG.warning("h3 connection owner still running 3s after close, cid=" + cidHex);
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
        wake();
        return true;
    }

    byte[] cid() { return cid; }

    // -----------------------------------------------------------------

    private final class SinkImpl implements Http3Session.RequestSink {
        @Override
        public void onHeaders(long streamId, List<String[]> headers) {
            dispatchRequest(streamId, headers);
        }

        @Override
        public void onData(long streamId, byte[] chunk) {
            // Frame order (HEADERS first) is enforced by the session; no
            // pipe means the body is no longer consumed (response already
            // complete).
            Http3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe == null) return;
            if (chunk.length > 0) {
                // RFC 9114 §4.1.2: more DATA than content-length = malformed.
                if (pipe.exceedsDeclaredLength(chunk.length)) {
                    throw malformed(streamId, "body longer than content-length");
                }
                if (!pipe.enqueueChecked(chunk)) {
                    LOG.info("h3 body size cap exceeded, stream=" + streamId);
                    // As a stream error the session resets the QUIC stream
                    // in both directions, so the peer stops pushing DATA
                    // against a stream we already stopped consuming
                    // (without that, the next DATA would land in the "DATA
                    // before HEADERS" branch and kill the whole connection
                    // for a per-stream overflow), and onReset abandons the
                    // request.
                    throw new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
                        "body exceeds maxRequestBodyBytes on stream " + streamId);
                }
            }
        }

        @Override
        public void onFin(long streamId) {
            Http3BodyPipe pipe = bodyPipes.get(streamId);
            if (pipe == null) return;
            if (!pipe.matchesDeclaredLength()) {
                throw malformed(streamId, "body shorter than content-length");
            }
            bodyPipes.remove(streamId);
            pipe.signalEnd();
        }

        @Override
        public void onReset(long streamId) {
            // The body will never complete and the response can't be sent.
            Http3BodyPipe pipe = bodyPipes.remove(streamId);
            if (pipe != null) pipe.signalTruncated();
            abandonResponse(streamId);
        }
    }

    /**
     * Validate a request field section and start its handler. Malformed
     * requests (RFC 9114 §4.1.2) throw {@link Http3StreamException}
     * (H3_MESSAGE_ERROR): the session resets just this stream.
     */
    private void dispatchRequest(long streamId, List<String[]> headers) {
        if (liveHandlers.get() >= maxLiveHandlers) {
            throw new Http3StreamException(Http3ConnectionException.H3_REQUEST_REJECTED,
                "too many running handlers on stream " + streamId);
        }
        String method = null, path = null, scheme = null, authority = null;
        String host = null;
        long contentLength = -1;
        int regularCount = 0;
        for (int i = 0, n = headers.size(); i < n; i++) {
            String name = headers.get(i)[0];
            if (name.isEmpty() || name.charAt(0) != ':') regularCount++;
        }
        // +1 slot for "host" — folded in directly so we can skip the
        // extra .assoc call + its Object[] alloc (task #148).
        Object[] regular = new Object[(regularCount + 1) * 2];
        int rp = 0;
        boolean seenRegular = false;
        for (int i = 0, hn = headers.size(); i < hn; i++) {
            String[] hf = headers.get(i);
            String n = hf[0];
            String v = hf[1];
            // RFC 9114 §4.2 / §10.3: CR, LF and NUL are never valid in a
            // field value (request smuggling through intermediaries).
            if (!Http3Session.validFieldValue(v)) {
                throw malformed(streamId, "invalid character in value of '" + n + "'");
            }
            if (!n.isEmpty() && n.charAt(0) == ':') {
                // RFC 9114 §4.1.3: pseudo-headers MUST all precede regular
                // headers (h3spec 14 / task #153).
                if (seenRegular) {
                    throw malformed(streamId, "pseudo-header '" + n + "' after regular header");
                }
                // RFC 9114 §4.1.1: request pseudo-headers MUST NOT appear
                // more than once (h3spec 11 / task #150).
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
                    // RFC 9114 §4.1.3: any pseudo not in the request
                    // pseudo-set is prohibited (h3spec 13 / task #152).
                    default -> throw malformed(streamId, "prohibited pseudo-header '" + n + "'");
                }
            } else {
                seenRegular = true;
                // RFC 9114 §4.2: names are lowercase tokens (RFC 9110
                // §5.1); uppercase or other characters = malformed.
                if (!Http3Session.validFieldName(n)) {
                    throw malformed(streamId, "invalid header name '" + n + "'");
                }
                // §4.2 forbidden hop-by-hop headers = H3_MESSAGE_ERROR.
                // TE is allowed only if its value is exactly "trailers".
                if (n.equals("connection") || n.equals("keep-alive")
                    || n.equals("proxy-connection") || n.equals("transfer-encoding")
                    || n.equals("upgrade")) {
                    throw malformed(streamId, "forbidden header '" + n + "'");
                }
                if (n.equals("te") && !"trailers".equals(v)) {
                    throw malformed(streamId, "TE header with non-trailers value");
                }
                if (n.equals("host")) {
                    // Folded with :authority below, never duplicated.
                    if (host != null) throw malformed(streamId, "duplicate host header");
                    host = v;
                    continue;
                }
                if (n.equals("content-length")) {
                    // RFC 9110 §8.6: repeated values must all agree.
                    long cl = parseContentLength(v);
                    if (cl < 0 || (contentLength >= 0 && cl != contentLength)) {
                        throw malformed(streamId, "invalid content-length '" + v + "'");
                    }
                    contentLength = cl;
                }
                regular[rp++] = n;
                regular[rp++] = v;
            }
        }
        // RFC 9114 §4.1.3 request pseudo-header requirements:
        //   - non-CONNECT: :method, :scheme, :path REQUIRED
        //   - CONNECT: :method + :authority REQUIRED, :scheme + :path MUST
        //     be omitted.
        // (h3spec 12 / task #151).
        if (method == null) throw malformed(streamId, "missing :method pseudo-header");
        boolean isConnect = "CONNECT".equals(method);
        if (isConnect) {
            if (authority == null || scheme != null || path != null) {
                throw malformed(streamId, "malformed CONNECT pseudo-headers");
            }
            // Fill in placeholder scheme/path so downstream Ring code
            // doesn't NPE on the tunnel-style request.
            scheme = "https";
            path = "";
        } else {
            if (path == null || scheme == null) {
                throw malformed(streamId, "missing required pseudo-header");
            }
            if (scheme.equals("http") || scheme.equals("https")) {
                // RFC 9114 §4.3.1: http(s) needs an authority, from
                // :authority or Host.
                if (authority == null && host == null) {
                    throw malformed(streamId, "missing :authority / host for " + scheme);
                }
                // :path is "/..." — or "*" for a server-wide OPTIONS.
                boolean asterisk = path.equals("*") && method.equals("OPTIONS");
                if (!asterisk && (path.isEmpty() || path.charAt(0) != '/')) {
                    throw malformed(streamId, "invalid :path for " + scheme);
                }
            }
        }
        // RFC 9114 §4.3.1: :authority / Host MUST NOT be empty and, when
        // both present, MUST be equal.
        if ((authority != null && authority.isEmpty()) || (host != null && host.isEmpty())) {
            throw malformed(streamId, "empty :authority / host");
        }
        if (authority != null && host != null && !authority.equals(host)) {
            throw malformed(streamId, ":authority and host differ");
        }
        String uri;
        String query;
        int q = path.indexOf('?');
        if (q < 0) { uri = path; query = null; }
        else { uri = path.substring(0, q); query = path.substring(q + 1); }

        // Fold "host" pair directly into the pre-sized regular[] so we
        // build the Ring header map in a single createAsIfByAssoc call.
        regular[rp++] = "host";
        regular[rp++] = authority != null ? authority : host != null ? host : "";
        // Dedup duplicates before createAsIfByAssoc (which throws on
        // repeated keys). Combine repeated fields per RFC 9110 §5.3;
        // "cookie" uses "; " per RFC 9113 §8.2.3 (h3 inherits h2 rules).
        Object[] merged = com.s_exp.enso.util.RingHeaders.mergeDuplicates(regular, rp);
        IPersistentMap hmap = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(merged);

        Http3BodyPipe pipe = new Http3BodyPipe(maxRequestBodyBytes, contentLength);
        bodyPipes.put(streamId, pipe);

        Request request = new Request(
            method, uri, query, "HTTP/3.0",
            hmap,
            pipe.inputStream(),
            peer.getAddress(), localPort, Request.K_HTTPS);

        // Per-request timeout gate: whichever side claims the Exchange
        // first (handler completion or timer expiry) owns the response.
        // Timer path enqueues a 408 ResponseTask + interrupts the vthread;
        // handler path enqueues its real response only if not already
        // claimed.
        Exchange ex = new Exchange(streamId);
        exchanges.put(streamId, ex);
        java.util.concurrent.ScheduledFuture<?> timeout = null;
        int timeoutMs = config.requestTimeoutMillis;
        if (timeoutMs > 0) {
            timeout = TIMEOUT_SCHEDULER.schedule(
                () -> onRequestTimeout(ex),
                timeoutMs,
                java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        final java.util.concurrent.ScheduledFuture<?> t = timeout;
        Thread worker = Thread.ofVirtual()
            .name("enso-h3-worker-" + streamId)
            .unstarted(() -> {
                try {
                    runHandler(ex, request);
                } finally {
                    if (t != null) t.cancel(false);
                    ex.handler = null;
                    liveHandlers.decrementAndGet();
                }
            });
        // Published before start so an abandon right after dispatch can
        // already interrupt it.
        ex.handler = worker;
        liveHandlers.incrementAndGet();
        worker.start();
    }

    private void onRequestTimeout(Exchange ex) {
        if (!ex.claim()) return;
        Thread ht = ex.handler;
        if (ht != null) ht.interrupt();
        // Enqueue 408 response. Owner thread picks it up + emits via
        // session.writeResponse. If the stream is already gone
        // (peer reset), the writeResponse just noops. offer, never put:
        // this timer thread is shared by every connection, and one whose
        // queue is full (a dead connection nobody drains) must not stall
        // all their timeouts.
        if (outbound.offer(ResponseTask.of(ex.streamId, 408,
                java.util.Collections.singletonMap("content-type", "text/plain"),
                "408 request timeout".getBytes(StandardCharsets.UTF_8), false))) {
            wake();
        } else {
            LOG.fine("h3 408 dropped, response queue full stream=" + ex.streamId);
        }
    }

    /** Non-negative decimal content-length, or -1 when invalid. */
    private static long parseContentLength(String s) {
        int n = s.length();
        if (n == 0 || n > 18) return -1;
        long v = 0;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return -1;
            v = v * 10 + (c - '0');
        }
        return v;
    }

    private static Http3StreamException malformed(long streamId, String why) {
        return new Http3StreamException(Http3ConnectionException.H3_MESSAGE_ERROR,
            "malformed request on stream " + streamId + ": " + why);
    }

    private static Http3StreamException pseudoDup(String name, long streamId) {
        return malformed(streamId, "duplicate " + name);
    }

    private void runHandler(Exchange ex, Request request) {
        long streamId = ex.streamId;
        boolean head = "HEAD".equals(request.method);
        try {
            Response response;
            try {
                response = handler.handle(request);
                if (response == null) {
                    throw new NullPointerException("handler returned null response");
                }
            } catch (Throwable t) {
                // null (no handler, or it failed too) falls to the 500 below.
                response = RingErrorHandler.respond(errorHandler, request, t);
            }
            Object source = null;
            ResponseTask task;
            if (response == null) {
                task = fallback500(streamId, head);
            } else if (response.webSocketListener != null) {
                // HTTP/3 has no 101 / Upgrade (RFC 9114 §4.5), so a
                // WebSocket handshake can't be honoured here.
                task = ResponseTask.of(streamId, 501, java.util.Collections.emptyMap(), null, head);
            } else if (!validResponseHeaders(response.headers, streamId)) {
                if (response.body instanceof java.io.Closeable c) closeQuietly(c);
                task = fallback500(streamId, head);
            } else {
                Map<?, ?> hs = response.headers == null
                    ? java.util.Collections.emptyMap() : response.headers;
                Object rb = response.body;
                if (rb == null) {
                    task = ResponseTask.of(streamId, response.status, hs, null, head);
                } else if (rb instanceof byte[] b) {
                    task = ResponseTask.of(streamId, response.status, hs, b, head);
                } else if (rb instanceof String s) {
                    task = ResponseTask.of(streamId, response.status, hs,
                        s.getBytes(HttpFields.responseCharset(hs)), head);
                } else if (rb instanceof java.io.File f) {
                    long len = f.length();
                    if (head || len == 0) {
                        task = new ResponseTask(streamId, response.status, hs,
                            null, null, len, head);
                    } else {
                        source = f;
                        task = new ResponseTask(streamId, response.status, hs,
                            null, new Http3ResponseBody(wakeTask), len, false);
                    }
                } else if (rb instanceof java.io.InputStream || rb instanceof StreamingBody) {
                    if (head) {
                        if (rb instanceof java.io.InputStream in) closeQuietly(in);
                        task = ResponseTask.of(streamId, response.status, hs, null, true);
                    } else {
                        source = rb;
                        task = new ResponseTask(streamId, response.status, hs,
                            null, new Http3ResponseBody(wakeTask), -1, false);
                    }
                } else {
                    LOG.warning("h3 unsupported response body type "
                        + rb.getClass().getName() + " stream=" + streamId);
                    task = fallback500(streamId, head);
                }
            }
            // First-writer-wins with the timeout task. If the timer
            // already sent 408, drop the real response — writing it
            // now would double-respond on the h3 stream.
            if (!ex.claim()) {
                // Timed out (408 already queued) or the stream was reset.
                if (source instanceof java.io.InputStream in) closeQuietly(in);
                return;
            }
            outbound.put(task);
            wake();
            if (task.stream != null) {
                // The owner may have shut down since our claim: then
                // nothing sends this response, and the producer must fail
                // fast instead of waiting for it.
                if (closed.get()) task.stream.cancel();
                produceBody(streamId, task.stream, source);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 handler threw for stream " + streamId, t);
            if (!ex.claim()) return;
            try {
                outbound.put(fallback500(streamId, head));
                wake();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Same response field rules as HTTP/1.1 and HTTP/2, checked on the
     * handler thread so a bad header turns the response into a 500 rather
     * than reaching the peer.
     */
    private static boolean validResponseHeaders(Map<?, ?> headers, long streamId) {
        if (headers == null) return true;
        try {
            for (Map.Entry<?, ?> e : headers.entrySet()) {
                HttpFields.checkResponseName(String.valueOf(e.getKey()));
                Object v = e.getValue();
                if (v instanceof List<?> values) {
                    for (Object item : values) {
                        HttpFields.checkResponseValue(item == null ? "" : item.toString());
                    }
                } else {
                    HttpFields.checkResponseValue(v == null ? "" : v.toString());
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            LOG.warning("h3 invalid response header, sending 500 stream=" + streamId
                + ": " + e.getMessage());
            return false;
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        try { c.close(); } catch (java.io.IOException ignored) {}
    }

    private static ResponseTask fallback500(long streamId, boolean head) {
        return ResponseTask.of(streamId, 500,
            java.util.Collections.singletonMap("content-type", "text/plain"),
            "500 internal error".getBytes(StandardCharsets.UTF_8), head);
    }

    /**
     * One request's response gate, shared by the owner, the handler's
     * virtual thread and the timeout timer: the first {@link #claim}
     * decides who responds (handler, 408 timer) or that nobody does
     * (stream reset).
     */
    private static final class Exchange {
        private static final java.lang.invoke.VarHandle RESPONDED;
        static {
            try {
                RESPONDED = java.lang.invoke.MethodHandles.lookup()
                    .findVarHandle(Exchange.class, "responded", int.class);
            } catch (ReflectiveOperationException e) {
                throw new ExceptionInInitializerError(e);
            }
        }

        final long streamId;
        @SuppressWarnings("unused") // accessed through RESPONDED
        private volatile int responded;
        volatile Thread handler;

        Exchange(long streamId) { this.streamId = streamId; }

        boolean claim() { return RESPONDED.compareAndSet(this, 0, 1); }

        /** Nobody responds; the handler is interrupted. */
        void abandon() {
            claim();
            Thread th = handler;
            if (th != null) th.interrupt();
        }
    }

    /**
     * Inbound datagrams with their source addresses. Single producer (the
     * listener's demux thread), single consumer (the owner). Parallel
     * arrays so carrying the address costs no per-datagram allocation;
     * the volatile {@code tail}/{@code head} writes publish slot contents.
     */
    private static final class Inbox {
        private final byte[][] data;
        private final InetSocketAddress[] from;
        private final int mask;
        private volatile long head;
        private volatile long tail;
        /** Source of the datagram last returned by {@link #poll}. */
        InetSocketAddress lastFrom;

        Inbox(int capacity) {
            int cap = Integer.highestOneBit(Math.max(2, capacity - 1)) << 1;
            this.data = new byte[cap][];
            this.from = new InetSocketAddress[cap];
            this.mask = cap - 1;
        }

        boolean offer(byte[] datagram, InetSocketAddress src) {
            long t = tail;
            if (t - head == data.length) return false;
            int i = (int) t & mask;
            data[i] = datagram;
            from[i] = src;
            tail = t + 1;
            return true;
        }

        byte[] poll() {
            long h = head;
            if (h == tail) return null;
            int i = (int) h & mask;
            byte[] d = data[i];
            lastFrom = from[i];
            data[i] = null;
            from[i] = null;
            head = h + 1;
            return d;
        }

        boolean isEmpty() { return head == tail; }
    }

    /**
     * A response for the owner to send: either a materialised {@code body}
     * (single stream_send fast path), a {@code stream} fed by the
     * handler's virtual thread, or neither (no DATA at all).
     * {@code contentLength} is the body size when known (HEAD).
     */
    private record ResponseTask(long streamId, int status,
                                Map<?, ?> headers, byte[] body,
                                Http3ResponseBody stream, long contentLength,
                                boolean head) {

        static ResponseTask of(long streamId, int status, Map<?, ?> headers,
                               byte[] body, boolean head) {
            return new ResponseTask(streamId, status, headers, body, null,
                body == null ? -1 : body.length, head);
        }
    }
}

package com.s_exp.enso.http2;

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
import com.s_exp.enso.core.HttpFields;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP/2 connection driver.
 *
 * <p>Three vthreads per connection:
 * <ul>
 *   <li>The <b>framer</b> vthread runs {@link #run} — reads incoming frames,
 *       decodes HEADERS via HPACK, spawns a worker per fully-received request.
 *   <li>A per-request <b>worker</b> vthread runs the Ring handler and calls
 *       {@link #writeResponse}. Multiple workers can be in flight concurrently.
 *   <li>The <b>writer</b> vthread ({@link #writerLoop}) drains the outbound
 *       frame queue in batches packed into one buffer, coalescing N
 *       concurrent responses into fewer socket writes and TLS records.
 * </ul>
 *
 * <p>{@link #streamLock} (unfair {@link java.util.concurrent.locks.ReentrantLock})
 * protects the HPACK encoder's mutable dynamic table and keeps header blocks
 * on the wire in encoding order; a split block's HEADERS + CONTINUATION
 * frames are enqueued in one go so they stay contiguous (RFC 9113 §4.3).
 *
 * <p>{@link #flowLock} guards flow-control window accounting; workers park on
 * {@link #flowChanged} when their stream's or the connection's send window is
 * exhausted.
 *
 * <p>{@link #queueLock} guards the outbound queue; workers append via
 * {@link #enqueue} (blocks on {@link #notFull} for back-pressure), the writer
 * drains via {@link #drainBatch}.
 */
public final class Http2Connection implements Runnable {

    private static final Logger LOG = Logger.getLogger(Http2Connection.class.getName());

    private final Socket socket;
    private final RingHandler handler;
    private final EnsoServer server;
    private final Config config;

    private InputStream in;
    private OutputStream out;

    // Header-emission lock. Held across HPACK encode + HEADERS/CONTINUATION
    // enqueue so header blocks reach the wire in the order they mutated
    // hpackEncoder's dynamic table. It does not stop DATA or control frames
    // (which never take it) from being enqueued concurrently: §4.3
    // contiguity of a split block is guaranteed by enqueueing all of its
    // frames under one queueLock hold (enqueueAll). Unfair — h2load `-c 8 -m 128` measured ~1-2% median /
    // ~3% p95 throughput above fair mode; the critical section is short
    // enough that starvation risk is bounded by the per-stream vthread
    // scheduler.
    private final ReentrantLock streamLock = new ReentrantLock();

    // Outbound write queue. Workers enqueue FrameSeg (9-byte header +
    // payload slice); a dedicated writer vthread drains and writes them to
    // the socket. Coalesces concurrent responses across streams into a
    // single flush cycle, cutting the per-response write() syscall cost.
    // FrameSeg references the payload buffer by (off, len) rather than
    // copying it.
    private final ArrayDeque<FrameSeg> writeQueue = new ArrayDeque<>();

    /**
     * Frame envelope: header prefix + payload segment. Header is a
     * freshly-allocated 9-byte array (cheap, TLAB-friendly). Payload is a
     * reference into a caller-owned buffer that must remain stable until
     * the writer drains it — typical sources (HPACK-encoded blocks,
     * response DATA byte[]s) are fresh so this holds.
     */
    private static final class FrameSeg {
        final byte[] header;
        final byte[] payload;
        final int off;
        final int len;

        FrameSeg(byte[] header, byte[] payload, int off, int len) {
            this.header = header;
            this.payload = payload;
            this.off = off;
            this.len = len;
        }
    }
    private final ReentrantLock queueLock = new ReentrantLock();
    private final Condition notEmpty = queueLock.newCondition();
    private final Condition notFull = queueLock.newCondition();
    private final Condition idle = queueLock.newCondition();
    private static final int WRITE_QUEUE_MAX = 1024;
    private static final int WRITE_BATCH_MAX = 128;
    private volatile boolean writerRunning = true;
    private Thread writerThread;
    // Frames ever enqueued / ever written to the socket, guarded by
    // queueLock. flushSync waits until everything enqueued before the call
    // has been written — not for the queue to go empty, which a busy
    // neighbour stream might never allow.
    private long enqueuedFrames = 0;
    private long writtenFrames = 0;
    // When the writer last took a batch or finished writing one, guarded by
    // queueLock. A writer making no progress for writeStallNanos (the idle
    // timeout; 0 = no limit) is stalled on a peer that stopped reading.
    private long writerProgressNanos = System.nanoTime();
    private final long writeStallNanos;

    private static final AtomicLong CONN_ID_SEQ = new AtomicLong();

    // Peer-advertised settings — start at RFC defaults, updated on SETTINGS frame.
    private int peerHeaderTableSize   = Http2.DEFAULT_HEADER_TABLE_SIZE;
    private int peerInitialWindowSize = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    // Read by handler threads when splitting header blocks.
    private volatile int peerMaxFrameSize = Http2.DEFAULT_MAX_FRAME_SIZE;
    private int peerMaxConcurrentStreams = Integer.MAX_VALUE;

    // Own settings — sourced from Config; advertised in initial SETTINGS.
    private final int ownInitialWindowSize;
    private final int ownMaxFrameSize;
    private final int ownMaxConcurrentStreams;
    private final int ownMaxHeaderListSize;

    // Streams.
    private final Map<Integer, Http2Stream> streams = new ConcurrentHashMap<>();
    private volatile int highestPeerStreamId = 0;
    // Highest stream id admitted for handling (admitStream); GOAWAY's
    // last-stream-id covers streams "possibly acted on" (§6.8).
    private volatile int lastProcessedStreamId = 0;
    // Set once the connection should stop reading: the peer sent GOAWAY
    // and every handler has finished.
    private volatile boolean shuttingDown = false;
    // Framer-thread only: whether run() registered with the server.
    private boolean registered = false;
    // Peer sent GOAWAY: no new streams will come; close once drained.
    private volatile boolean peerGoingAway = false;
    // Handler vthreads still running (a reset stream leaves the map while
    // its handler may keep going).
    private final java.util.concurrent.atomic.AtomicInteger activeHandlers =
        new java.util.concurrent.atomic.AtomicInteger();
    // Connection idle timeout (no stream in progress), from the keep-alive
    // timeout falling back to the idle timeout; 0 disables. Enforced by a
    // timer rather than SO_TIMEOUT: streams may legitimately stay quiet,
    // so only a connection with no stream in progress is idle.
    private final long idleTimeoutMillis;
    private volatile long idleSinceNanos = System.nanoTime();
    private volatile java.util.concurrent.ScheduledFuture<?> idleTimer;
    // Serialises GOAWAY emission with admitting new streams, so no handler
    // starts on a stream above the last-stream-id we announced.
    private final ReentrantLock goawayLock = new ReentrantLock();

    // Flow control (per RFC 9113 §5.2). Both directions carry a separate
    // connection-level window (stream 0); per-stream windows live on
    // Http2Stream. Read/write always through {@link #flowLock}; senders park
    // on {@link #flowChanged} until enough credit is available.
    private final ReentrantLock flowLock = new ReentrantLock();
    private final Condition flowChanged = flowLock.newCondition();
    private long connSendWindow = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    private long connRecvWindow;               // 65535, grown at handshake (§6.9.2)
    private long connRecvUncredited = 0;       // bytes consumed but not yet WINDOW_UPDATEd back

    // HPACK state (one per direction).
    private final Hpack.Decoder hpackDecoder = new Hpack.Decoder(Hpack.DEFAULT_MAX_TABLE_SIZE);
    private final Hpack.Encoder hpackEncoder = new Hpack.Encoder(Hpack.DEFAULT_MAX_TABLE_SIZE);

    // Pending header block awaiting more CONTINUATION frames. When
    // pendingStreamId != 0, the driver refuses any non-CONTINUATION frame per
    // §6.10. The accumulator buffer is reused across requests on the same
    // connection so back-to-back multi-frame requests don't reallocate.
    private int pendingStreamId = 0;
    private boolean pendingEndStream = false;
    private boolean pendingTrailers = false;
    private boolean pendingSelfDependent = false;
    private int pendingContinuationCount = 0;
    // Framer-confined; bounded by enforceHeaderListBudget.
    private byte[] pendingHeaderBytes = new byte[4096];
    private int pendingHeaderLen = 0;
    // CVE-2023-44487 mitigation: token bucket of RST_STREAM frames the
    // peer may send. Holds up to config.http2StreamResetLimit tokens and
    // refills at that many per RESET_REFILL_NANOS, so a burst over the limit
    // kills the connection with ENHANCE_YOUR_CALM while routine cancels on a
    // long-lived connection never do (0 disables). Framer-confined.
    private static final long RESET_REFILL_NANOS = 30_000_000_000L;
    private double resetTokens;
    private long resetTokensAt = System.nanoTime();

    // Scratch buffer for the framer thread's frame header reads. Writers
    // don't share it: frameSeg allocates each outbound frame's 9-byte
    // header.
    private final byte[] readHdrBuf = new byte[Http2.FRAME_HEADER_SIZE];

    // Connection-scoped socket addresses. Same value for every request on this
    // connection; caching avoids a getsockname()/getpeername() syscall per
    // request. Profile showed these two lookups accounting for ~10% of CPU
    // under h2load at 260k rps.
    private final int localPort;
    private final java.net.InetAddress remoteAddress;

    public Http2Connection(Socket socket, RingHandler handler, EnsoServer server) {
        this.socket = socket;
        this.handler = handler;
        this.server = server;
        this.config = server.config();
        this.ownInitialWindowSize    = config.http2InitialWindowSize;
        this.ownMaxFrameSize         = config.http2MaxFrameSize;
        this.ownMaxConcurrentStreams = config.http2MaxConcurrentStreams;
        this.ownMaxHeaderListSize    = config.http2MaxHeaderListSize;
        this.resetTokens = config.http2StreamResetLimit;
        this.idleTimeoutMillis = config.keepAliveTimeoutMillis > 0
            ? config.keepAliveTimeoutMillis : config.idleTimeoutMillis;
        this.writeStallNanos = config.idleTimeoutMillis * 1_000_000L;
        this.localPort = ((java.net.InetSocketAddress) socket.getLocalSocketAddress()).getPort();
        this.remoteAddress = socket.getInetAddress();
    }

    @Override
    public void run() {
        // The socket is closed explicitly in the finally block, not via
        // try-with-resources: resources close before catch/finally run,
        // which would drop the GOAWAY enqueued by the error path.
        Socket s = socket;
        try {
            in = s.getInputStream();
            // The writer thread packs each drain batch into its own scratch
            // buffer before writing, so there's no need to wrap the socket
            // output in a BufferedOutputStream — that would add an extra
            // copy for no coalescing benefit.
            out = s.getOutputStream();
            // RFC 9113 §6.9.2: SETTINGS_INITIAL_WINDOW_SIZE only applies to
            // streams; the connection window always starts at 65535 and is
            // grown by sendInitialSettings with a WINDOW_UPDATE on stream 0.
            connRecvWindow = Http2.DEFAULT_INITIAL_WINDOW_SIZE;

            long id = CONN_ID_SEQ.incrementAndGet();
            writerThread = Thread.ofVirtual()
                .name("enso-h2-writer-" + id)
                .start(this::writerLoop);

            readPreface();
            sendInitialSettings();
            Frame first = readFrame();
            if (first == null || first.type != Http2.TYPE_SETTINGS
                || (first.flags & Http2.FLAG_ACK) != 0) {
                sendGoaway(0, Http2.ERROR_PROTOCOL_ERROR, "expected initial SETTINGS");
                return;
            }
            applySettings(first);
            sendSettingsAck();
            // Until here reads were bounded by the accept-time SO_TIMEOUT,
            // so a peer that never completes the preface can't hold the
            // connection. From now on streams may legitimately stay quiet
            // (long-poll, SSE): idleness is judged by the idle timer, which
            // knows whether any stream is in progress.
            s.setSoTimeout(0);
            if (idleTimeoutMillis > 0) {
                scheduleIdleCheck(idleTimeoutMillis);
            }
            // Registered once SETTINGS are exchanged so a server stop can
            // GOAWAY it. A stop that already swept the registry before this
            // point is caught by the isRunning check.
            server.register(this);
            registered = true;
            if (!server.isRunning()) {
                goAway();
            }

            // Server stop goes through goAway(): the loop keeps reading so
            // in-flight streams still get WINDOW_UPDATE / DATA while they
            // drain, and ends when closeDrained() closes the socket.
            while (!shuttingDown) {
                Frame f = readFrame();
                if (f == null) {
                    return;
                }
                dispatch(f);
            }
        } catch (Http2.ConnectionError ce) {
            try {
                // Enqueues the GOAWAY; closeConnection() below drains the
                // queue before close, and TlsSocket.close then emits
                // close_notify + shutdownOutput so the peer sees an orderly
                // teardown.
                sendGoaway(lastProcessedStreamId, ce.code, ce.getMessage());
            } catch (IOException ignored) {
            }
        } catch (IOException e) {
            // client went away
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "unexpected HTTP/2 driver failure", t);
        } finally {
            shuttingDown = true;
            java.util.concurrent.ScheduledFuture<?> timer = idleTimer;
            if (timer != null) timer.cancel(false);
            // Writes out any queued frames (typically the GOAWAY just
            // enqueued), then closes the socket, aborting it if the peer
            // stopped reading.
            closeConnection();
            // Wake any workers still blocked on body reads or flow-control
            // credit so they can bail out cleanly.
            for (Http2Stream st : streams.values()) {
                st.state = Http2Stream.State.CLOSED;
                st.signalAbort();
            }
            wakeFlowWaiters();
            // Drop the map so retained stream state can be GC'd.
            streams.clear();
            // Release any pending CONTINUATION accumulator.
            clearPendingHeaderState();
            // Only now: until the socket is closed a server stop must still
            // find this connection to force-close it.
            if (registered) {
                server.unregister(this);
            }
        }
    }

    // ---- Writer thread + queue ------------------------------------------

    /**
     * Writer vthread loop. Drains up to {@link #WRITE_BATCH_MAX} frames per
     * cycle into a pre-sized array under {@link #queueLock}, then writes them
     * to the socket outside the lock. Signals {@link #idle} after each batch
     * so {@link #flushSync} can observe completion.
     *
     * <p>Multiple concurrent stream workers can enqueue while the writer is
     * inside {@code out.write} — those frames coalesce into the next drain
     * cycle, giving one syscall for N responses when the writer is the
     * bottleneck.
     */
    // Per-connection coalescing buffer. A batch's frames are packed into
    // it back to back, frames spanning fills, and it is written out each
    // time it is full, so its size — not the batch's — bounds memory.
    // TlsSocket emits one record (and one channel write) per 16 KiB of
    // plaintext, so full writes of a multiple of 16 KiB give the fewest
    // records. Two records per write keeps bulk transfer as fast as larger
    // buffers measured; one record per write costs ~10% in per-write
    // overhead.
    private static final int WRITER_SCRATCH_SIZE = 32 * 1024;

    private void writerLoop() {
        FrameSeg[] batch = new FrameSeg[WRITE_BATCH_MAX];
        byte[] scratch = new byte[WRITER_SCRATCH_SIZE];
        while (true) {
            int n = drainBatch(batch);
            if (n == 0) return;
            try {
                int p = 0;
                for (int i = 0; i < n; i++) {
                    FrameSeg fs = batch[i];
                    batch[i] = null;
                    p = pack(scratch, p, fs.header, 0, Http2.FRAME_HEADER_SIZE);
                    p = pack(scratch, p, fs.payload, fs.off, fs.len);
                }
                if (p > 0) {
                    out.write(scratch, 0, p);
                }
                out.flush();
            } catch (Throwable t) {
                // Peer/socket went away (or a bug). Stop accepting frames,
                // release every waiter, and close the socket so the framer's
                // blocked read unwinds the connection too. Aborted, not
                // closed: the output stream is broken mid-record, so there
                // is no orderly close_notify left to send.
                if (!(t instanceof IOException)) {
                    LOG.log(Level.WARNING, "HTTP/2 writer failure", t);
                }
                writerRunning = false;
                drainAndSignalClose();
                EnsoServer.forceClose(socket);
                return;
            }
            queueLock.lock();
            try {
                writtenFrames += n;
                writerProgressNanos = System.nanoTime();
                idle.signalAll();
            } finally {
                queueLock.unlock();
            }
        }
    }

    /**
     * Writer-thread helper: appends {@code src[off..off+len)} to
     * {@code scratch} at {@code p}, writing the buffer out each time it
     * fills. Returns the new fill position.
     */
    private int pack(byte[] scratch, int p, byte[] src, int off, int len) throws IOException {
        while (len > 0) {
            int k = Math.min(len, scratch.length - p);
            System.arraycopy(src, off, scratch, p, k);
            p += k;
            off += k;
            len -= k;
            if (p == scratch.length) {
                out.write(scratch, 0, p);
                p = 0;
            }
        }
        return p;
    }

    private int drainBatch(FrameSeg[] batch) {
        queueLock.lock();
        try {
            while (writeQueue.isEmpty()) {
                if (!writerRunning) return 0;
                try {
                    notEmpty.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return 0;
                }
            }
            int n = Math.min(writeQueue.size(), batch.length);
            for (int i = 0; i < n; i++) batch[i] = writeQueue.pollFirst();
            writerProgressNanos = System.nanoTime();
            notFull.signalAll();
            return n;
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Appends {@code seg} to the write queue. Blocks on {@link #notFull} when
     * the queue is at hi-water so a slow socket applies back-pressure to
     * workers instead of ballooning memory.
     */
    private void enqueue(FrameSeg seg) throws IOException {
        queueLock.lock();
        try {
            awaitQueueRoom();
            writeQueue.addLast(seg);
            enqueuedFrames++;
            notEmpty.signal();
        } finally {
            queueLock.unlock();
        }
    }

    /** Caller holds {@link #queueLock}. */
    private void awaitQueueRoom() throws IOException {
        if (!writerRunning) throw new IOException("write queue closed");
        if (writeQueue.size() < WRITE_QUEUE_MAX) return;
        long waitStart = System.nanoTime();
        while (writeQueue.size() >= WRITE_QUEUE_MAX) {
            if (!writerRunning) throw new IOException("write queue closed");
            try {
                if (!awaitWriter(notFull, waitStart)) {
                    throw new IOException("HTTP/2 peer stopped reading");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted waiting on write queue");
            }
        }
    }

    /**
     * Caller holds {@link #queueLock}. One wait on {@code cond} for the
     * writer. Returns false when the writer has made no progress for the
     * write-stall limit (the idle timeout), counted from its last progress
     * or {@code waitStart}, whichever is later: the peer stopped reading.
     * The socket is then aborted, which fails the stalled write and
     * unwinds every waiter through the writer's failure path.
     */
    private boolean awaitWriter(Condition cond, long waitStart) throws InterruptedException {
        if (writeStallNanos == 0) {
            cond.await();
            return true;
        }
        long since = writerProgressNanos - waitStart > 0 ? writerProgressNanos : waitStart;
        long left = since + writeStallNanos - System.nanoTime();
        if (left <= 0) {
            EnsoServer.forceClose(socket);
            return false;
        }
        cond.awaitNanos(left);
        return true;
    }

    /**
     * Appends {@code segs} as one contiguous run: no other frame can be
     * queued between them. Waits for room like {@link #enqueue} but may
     * overshoot {@link #WRITE_QUEUE_MAX} by the run's length.
     */
    private void enqueueAll(FrameSeg[] segs) throws IOException {
        queueLock.lock();
        try {
            awaitQueueRoom();
            for (FrameSeg seg : segs) writeQueue.addLast(seg);
            enqueuedFrames += segs.length;
            notEmpty.signal();
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Wait until every frame enqueued before this call has been written to
     * the socket. Used by user flushes and at connection shutdown (so a
     * final GOAWAY reaches the peer before the socket closes). Returns
     * false if they weren't: the writer failed or stalled (see
     * {@link #awaitWriter}).
     */
    private boolean flushSync() {
        queueLock.lock();
        try {
            long target = enqueuedFrames;
            long waitStart = System.nanoTime();
            while (writerRunning && writtenFrames < target) {
                try {
                    if (!awaitWriter(idle, waitStart)) return false;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return writtenFrames >= target;
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Drains what's queued (best effort — errors are already fatal at this
     * point), signals the writer to exit, and joins it so the socket isn't
     * closed while it's mid-write. Returns true once the writer has exited
     * with everything written.
     */
    private boolean shutdownWriter() {
        if (writerThread == null) return true;
        boolean flushed = flushSync();
        queueLock.lock();
        try {
            writerRunning = false;
            notEmpty.signalAll();
            notFull.signalAll();
            idle.signalAll();
        } finally {
            queueLock.unlock();
        }
        if (!flushed) return false;
        try {
            writerThread.join(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return !writerThread.isAlive();
    }

    /**
     * Connection teardown, from the framer or the last handler: writes out
     * what's queued, then closes the socket (TLS close_notify). If the
     * writer couldn't finish — the peer stopped reading — the socket is
     * aborted instead: an orderly TLS close would wait on the stalled
     * writer's lock forever.
     */
    private void closeConnection() {
        if (shutdownWriter()) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        } else {
            EnsoServer.forceClose(socket);
        }
    }

    /** Writer-side helper: on IO failure, clear the queue and unpark any
     *  worker still stuck waiting on {@link #notFull}. */
    private void drainAndSignalClose() {
        queueLock.lock();
        try {
            writeQueue.clear();
            notFull.signalAll();
            idle.signalAll();
        } finally {
            queueLock.unlock();
        }
    }

    // ---- Handshake ------------------------------------------------------

    private void readPreface() throws IOException {
        byte[] buf = new byte[Http2.PREFACE.length];
        readFully(buf, 0, buf.length);
        for (int i = 0; i < buf.length; i++) {
            if (buf[i] != Http2.PREFACE[i]) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "invalid connection preface");
            }
        }
    }

    private void sendInitialSettings() throws IOException {
        byte[] payload = new byte[4 * 6];
        int p = 0;
        p = putSetting(payload, p, Http2.SETTINGS_MAX_CONCURRENT_STREAMS, ownMaxConcurrentStreams);
        p = putSetting(payload, p, Http2.SETTINGS_INITIAL_WINDOW_SIZE, ownInitialWindowSize);
        p = putSetting(payload, p, Http2.SETTINGS_MAX_FRAME_SIZE, ownMaxFrameSize);
        // 0 configures "no limit", which has no SETTINGS encoding: the
        // setting's absence means unlimited (RFC 9113 §6.5.2).
        if (ownMaxHeaderListSize > 0) {
            p = putSetting(payload, p, Http2.SETTINGS_MAX_HEADER_LIST_SIZE, ownMaxHeaderListSize);
        }
        writeFrame(Http2.TYPE_SETTINGS, 0, 0, payload, 0, p);
        // Raise the connection receive window to a multiple of the stream
        // window: credit only comes back as handlers consume their body, so
        // with equal windows a single handler that doesn't read would stall
        // every other upload on the connection. The connection window still
        // bounds the body bytes buffered per connection.
        long connTarget = Math.min((long) ownInitialWindowSize * CONN_WINDOW_STREAM_MULTIPLE,
                                   Http2.MAX_ALLOWED_WINDOW_SIZE);
        int connGrowth = (int) (connTarget - Http2.DEFAULT_INITIAL_WINDOW_SIZE);
        if (connGrowth > 0) {
            connRecvWindow += connGrowth;
            sendWindowUpdate(0, connGrowth);
        }
    }

    // Connection receive window, in stream windows: how many streams can
    // hold unread body data before the others stall.
    private static final int CONN_WINDOW_STREAM_MULTIPLE = 4;

    private static int putSetting(byte[] buf, int p, int id, int value) {
        buf[p]   = (byte) ((id >>> 8) & 0xFF);
        buf[p+1] = (byte) (id & 0xFF);
        buf[p+2] = (byte) ((value >>> 24) & 0xFF);
        buf[p+3] = (byte) ((value >>> 16) & 0xFF);
        buf[p+4] = (byte) ((value >>>  8) & 0xFF);
        buf[p+5] = (byte) (value & 0xFF);
        return p + 6;
    }

    private void sendSettingsAck() throws IOException {
        writeFrame(Http2.TYPE_SETTINGS, Http2.FLAG_ACK, 0, null, 0, 0);
    }

    // ---- Frame dispatch -------------------------------------------------

    private void dispatch(Frame f) throws IOException {
        // Per RFC 9113 §6.10: while a header block spans HEADERS + CONTINUATION,
        // no other frame type may interleave. Refuse anything else with a
        // connection-level PROTOCOL_ERROR.
        if (pendingStreamId != 0) {
            if (f.type != Http2.TYPE_CONTINUATION || f.streamId != pendingStreamId) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR,
                    "expected CONTINUATION for stream " + pendingStreamId);
            }
        }
        switch (f.type) {
            case Http2.TYPE_SETTINGS -> {
                if ((f.flags & Http2.FLAG_ACK) != 0) {
                    if (f.length != 0) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_FRAME_SIZE_ERROR, "SETTINGS ACK with payload");
                    }
                } else {
                    applySettings(f);
                    sendSettingsAck();
                }
            }
            case Http2.TYPE_PING -> {
                if (f.length != 8 || f.streamId != 0) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_FRAME_SIZE_ERROR, "malformed PING");
                }
                if ((f.flags & Http2.FLAG_ACK) == 0) {
                    writeFrame(Http2.TYPE_PING, Http2.FLAG_ACK, 0, f.payload, 0, 8);
                }
            }
            case Http2.TYPE_GOAWAY -> handleGoaway(f);
            case Http2.TYPE_WINDOW_UPDATE -> handleWindowUpdate(f);
            case Http2.TYPE_PRIORITY -> {
                if (f.streamId == 0) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_PROTOCOL_ERROR, "PRIORITY on stream 0");
                }
                // Both checks below are stream errors (§6.3, §5.3.1), but
                // RST_STREAM must not be sent on an idle stream (§6.4), so
                // there they escalate to a connection error.
                if (f.length != 5) {
                    priorityStreamError(f.streamId, Http2.ERROR_FRAME_SIZE_ERROR,
                                        "PRIORITY length must be 5");
                    return;
                }
                int depStream = ((f.payload[0] & 0x7F) << 24)
                              | ((f.payload[1] & 0xFF) << 16)
                              | ((f.payload[2] & 0xFF) <<  8)
                              |  (f.payload[3] & 0xFF);
                if (depStream == f.streamId) {
                    priorityStreamError(f.streamId, Http2.ERROR_PROTOCOL_ERROR,
                                        "PRIORITY self-dependency");
                }
                // Priority itself is deprecated; content otherwise ignored.
            }
            case Http2.TYPE_HEADERS -> handleHeaders(f);
            case Http2.TYPE_DATA -> handleData(f);
            case Http2.TYPE_RST_STREAM -> handleRstStream(f);
            case Http2.TYPE_CONTINUATION -> handleContinuation(f);
            case Http2.TYPE_PUSH_PROMISE -> throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "client cannot send PUSH_PROMISE");
            default -> {
                // Unknown frame types MUST be ignored (RFC 9113 §4.1).
            }
        }
    }

    /**
     * Peer GOAWAY (§6.8): it opens no new streams, but the ones in flight
     * still complete. The connection closes once the last handler is done
     * (here if none is running, else in {@link #onHandlerDone}).
     */
    private void handleGoaway(Frame f) throws IOException {
        if (f.streamId != 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "GOAWAY on non-zero stream");
        }
        if (f.length < 8) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "GOAWAY shorter than 8 octets");
        }
        peerGoingAway = true;
        if (activeHandlers.get() == 0) {
            shuttingDown = true;
        }
    }

    /**
     * Last step of every handler vthread. After a peer GOAWAY the framer is
     * typically parked in a socket read with nothing left to wait for:
     * flush the final responses and close the socket to unwind it.
     */
    private void onHandlerDone() {
        if (activeHandlers.decrementAndGet() == 0) {
            idleSinceNanos = System.nanoTime();
            if (peerGoingAway || lastGoawayStreamId != Integer.MAX_VALUE) {
                closeDrained();
            }
        }
    }

    /** All handlers are done and no new stream will be served: close. */
    private void closeDrained() {
        shuttingDown = true;
        closeConnection();
    }

    /**
     * Graceful close (§6.8): GOAWAY(NO_ERROR) naming the last stream handed
     * to a handler, ignore streams above it, close once running handlers
     * finish. Safe to call from any thread.
     */
    public void goAway() {
        goawayLock.lock();
        try {
            if (lastGoawayStreamId != Integer.MAX_VALUE) return;
            sendGoaway(lastProcessedStreamId, Http2.ERROR_NO_ERROR, null);
        } catch (IOException ignored) {
            // Connection already dying.
        } finally {
            goawayLock.unlock();
        }
        if (activeHandlers.get() == 0) {
            closeDrained();
        }
    }

    private void scheduleIdleCheck(long delayMillis) {
        java.util.concurrent.ScheduledFuture<?> t = TIMEOUT_SCHEDULER.schedule(
            this::onIdleCheck, delayMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
        idleTimer = t;
        // Teardown sets shuttingDown, then cancels idleTimer: if it ran
        // between onIdleCheck's check and the write above, it cancelled the
        // previous timer and this one is ours to cancel.
        if (shuttingDown) {
            t.cancel(false);
        }
    }

    /**
     * Idle timer tick. Re-arms itself while streams are in progress or the
     * idle period hasn't elapsed; otherwise closes gracefully off the
     * scheduler thread (goAway blocks on the writer).
     */
    private void onIdleCheck() {
        if (shuttingDown) return;
        long delay = idleTimeoutMillis;
        if (activeHandlers.get() == 0 && streams.isEmpty()) {
            long idleFor = (System.nanoTime() - idleSinceNanos) / 1_000_000L;
            if (idleFor >= idleTimeoutMillis) {
                Thread.ofVirtual().name("enso-h2-idle-close").start(this::goAway);
                return;
            }
            delay = idleTimeoutMillis - idleFor;
        }
        scheduleIdleCheck(delay);
    }

    /**
     * Records {@code streamId} as handed to a handler unless a GOAWAY
     * already announced a lower last-stream-id, in which case the stream is
     * ignored (§6.8). An admitted stream counts in {@link #activeHandlers}
     * from here, atomically with the GOAWAY check, so a concurrent
     * {@link #goAway} that names this stream can't see zero handlers and
     * close the connection before it is served; the caller balances it
     * with {@link #onHandlerDone}.
     */
    private boolean admitStream(int streamId) {
        goawayLock.lock();
        try {
            if (streamId > lastGoawayStreamId) return false;
            lastProcessedStreamId = streamId;
            activeHandlers.incrementAndGet();
            return true;
        } finally {
            goawayLock.unlock();
        }
    }

    private void priorityStreamError(int streamId, int code, String message)
        throws Http2.ConnectionError {
        if (streamId > highestPeerStreamId) {
            throw new Http2.ConnectionError(code, message + " on idle stream " + streamId);
        }
        resetStreamQuiet(streamId, code);
    }

    private void handleWindowUpdate(Frame f) throws IOException {
        if (f.length != 4) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "malformed WINDOW_UPDATE");
        }
        long increment = ((long)(f.payload[0] & 0x7F) << 24)
                       | ((long)(f.payload[1] & 0xFF) << 16)
                       | ((long)(f.payload[2] & 0xFF) <<  8)
                       |  (long)(f.payload[3] & 0xFF);
        if (increment == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "WINDOW_UPDATE with 0 increment");
        }
        if (f.streamId != 0 && f.streamId > highestPeerStreamId) {
            // WINDOW_UPDATE on an idle stream is a connection PROTOCOL_ERROR (§5.1).
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream " + f.streamId);
        }
        flowLock.lock();
        try {
            if (f.streamId == 0) {
                connSendWindow += increment;
                if (connSendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_FLOW_CONTROL_ERROR, "connection window overflow");
                }
            } else {
                Http2Stream st = streams.get(f.streamId);
                if (st != null) {
                    st.sendWindow += increment;
                    if (st.sendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                        // Per §6.9.1 this is a stream error, not connection.
                        resetStreamQuiet(f.streamId, Http2.ERROR_FLOW_CONTROL_ERROR);
                        return;
                    }
                }
            }
            flowChanged.signalAll();
        } finally {
            flowLock.unlock();
        }
    }

    private void handleRstStream(Frame f) throws IOException {
        if (f.streamId == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "RST_STREAM on stream 0");
        }
        if (f.length != 4) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "malformed RST_STREAM");
        }
        // RST_STREAM on an idle stream (one we've never seen) is a
        // connection-level PROTOCOL_ERROR per §5.1.
        if (f.streamId > highestPeerStreamId) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "RST_STREAM on idle stream " + f.streamId);
        }
        // CVE-2023-44487 rapid-reset mitigation.
        int cap = config.http2StreamResetLimit;
        if (cap > 0) {
            long now = System.nanoTime();
            resetTokens = Math.min(cap,
                resetTokens + (double) (now - resetTokensAt) * cap / RESET_REFILL_NANOS);
            resetTokensAt = now;
            if (resetTokens < 1) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_ENHANCE_YOUR_CALM,
                    "RST_STREAM rate exceeded limit " + cap);
            }
            resetTokens -= 1;
        }
        Http2Stream st = streams.remove(f.streamId);
        if (st != null) {
            st.state = Http2Stream.State.CLOSED;
            st.signalAbort(); // wake worker if blocked reading
            abandonReceiveBuffer(st);
            wakeFlowWaiters();
        }
    }

    // ---- HEADERS + DATA -------------------------------------------------

    private void handleHeaders(Frame f) throws IOException {
        if (f.streamId == 0 || (f.streamId & 1) == 0) {
            // Per RFC 9113 §5.1.1: client-initiated streams must have odd IDs
            // > 0. Server-initiated (push) IDs are even, but we never push.
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "invalid stream ID for HEADERS");
        }
        Http2Stream existing = streams.get(f.streamId);
        boolean trailers = existing != null;
        if (!trailers) {
            if (f.streamId <= highestPeerStreamId) {
                if (f.streamId <= lastGoawayStreamId && !wasResetByUs(f.streamId)) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_PROTOCOL_ERROR, "stream ID not strictly increasing");
                }
                // A stream we reset, or ignored after our GOAWAY (§6.8):
                // the peer may still have had frames in flight, which are
                // ignored (§5.1 "closed"). The block is still decoded to
                // keep the HPACK state in sync; onHeaderBlock then drops
                // it since the stream isn't in the map.
                trailers = true;
            } else {
                // The stream leaves the idle state with this frame (§5.1),
                // whether or not we end up serving it: later DATA/RST_STREAM on
                // a refused or reset stream must not look like idle-stream
                // errors. GOAWAY reports lastProcessedStreamId instead.
                highestPeerStreamId = f.streamId;
            }
        } else {
            // RFC 9113 §8.1: a second HEADERS on an existing stream is a
            // trailers block and must set END_STREAM. (On a stream already
            // half-closed by the peer it is a stream error, applied by
            // onHeaderBlock once the block has been decoded.)
            if ((f.flags & Http2.FLAG_END_STREAM) == 0) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "trailer HEADERS without END_STREAM");
            }
        }

        // Peel padding, priority prefix.
        byte[] payload = f.payload;
        int off = 0;
        int len = f.length;
        if ((f.flags & Http2.FLAG_PADDED) != 0) {
            if (len < 1) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS PADDED with no pad-length byte");
            }
            int padLen = payload[0] & 0xFF;
            off = 1;
            len = len - 1 - padLen;
            if (len < 0) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS padding too large");
            }
        }
        boolean selfDependent = false;
        if ((f.flags & Http2.FLAG_PRIORITY) != 0) {
            if (len < 5) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS priority prefix too large");
            }
            // Self-dependency is a stream error (§5.3.1), applied once the
            // block has been decoded.
            int depStream = ((payload[off]     & 0x7F) << 24)
                          | ((payload[off + 1] & 0xFF) << 16)
                          | ((payload[off + 2] & 0xFF) <<  8)
                          |  (payload[off + 3] & 0xFF);
            selfDependent = depStream == f.streamId;
            off += 5;
            len -= 5;
        }

        boolean endStream = (f.flags & Http2.FLAG_END_STREAM) != 0;
        boolean endHeaders = (f.flags & Http2.FLAG_END_HEADERS) != 0;

        if (endHeaders) {
            onHeaderBlock(f.streamId, endStream, trailers, selfDependent, payload, off, len);
        } else {
            // Start accumulating; the next frame MUST be CONTINUATION on this
            // same stream (§6.10). The dispatch guard enforces the ordering.
            enforceHeaderListBudget(len);
            pendingStreamId = f.streamId;
            pendingEndStream = endStream;
            pendingTrailers = trailers;
            pendingSelfDependent = selfDependent;
            pendingHeaderLen = 0;
            appendPendingHeader(payload, off, len);
        }
    }

    private void appendPendingHeader(byte[] src, int off, int len) {
        int need = pendingHeaderLen + len;
        if (need > pendingHeaderBytes.length) {
            pendingHeaderBytes = java.util.Arrays.copyOf(
                pendingHeaderBytes, Math.max(need, pendingHeaderBytes.length * 2));
        }
        System.arraycopy(src, off, pendingHeaderBytes, pendingHeaderLen, len);
        pendingHeaderLen = need;
    }

    private void handleContinuation(Frame f) throws IOException {
        // A CONTINUATION frame outside a pending header block is a
        // connection-level error per §6.10.
        if (pendingStreamId == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "CONTINUATION without preceding HEADERS");
        }
        // Cap CONTINUATION frames per HEADERS to bound HPACK work.
        int contCap = server.config().http2ContinuationLimit;
        if (contCap > 0 && ++pendingContinuationCount > contCap) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM,
                "CONTINUATION count exceeded limit " + contCap);
        }
        enforceHeaderListBudget(pendingHeaderLen + f.length);
        appendPendingHeader(f.payload, 0, f.length);
        if ((f.flags & Http2.FLAG_END_HEADERS) != 0) {
            // Decoded in place: the buffer isn't touched again until the
            // next header block starts.
            byte[] block = pendingHeaderBytes;
            int blockLen = pendingHeaderLen;
            int streamId = pendingStreamId;
            boolean endStream = pendingEndStream;
            boolean trailers = pendingTrailers;
            boolean selfDependent = pendingSelfDependent;
            clearPendingHeaderState();
            onHeaderBlock(streamId, endStream, trailers, selfDependent, block, 0, blockLen);
        }
    }

    /**
     * Cap the total encoded header block size to protect against a peer that
     * streams unbounded CONTINUATION frames to exhaust memory. Uses the value
     * advertised in {@code SETTINGS_MAX_HEADER_LIST_SIZE}. Strictly speaking
     * that setting bounds the *decoded* list size; enforcing on the encoded
     * bytes is a superset that's easier to check inline.
     */
    private void enforceHeaderListBudget(int accumulatedBytes) throws Http2.ConnectionError {
        if (ownMaxHeaderListSize > 0 && accumulatedBytes > ownMaxHeaderListSize) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM,
                "header block exceeds SETTINGS_MAX_HEADER_LIST_SIZE");
        }
    }

    private void clearPendingHeaderState() {
        pendingStreamId = 0;
        pendingEndStream = false;
        pendingTrailers = false;
        pendingSelfDependent = false;
        pendingContinuationCount = 0;
        pendingHeaderLen = 0;
    }

    /**
     * A complete header block arrived. It is always HPACK-decoded first —
     * even for streams we then refuse or reset — because every block
     * mutates the shared dynamic table (RFC 9113 §4.3); skipping one would
     * desynchronise the decoder for every later request on the connection.
     */
    private void onHeaderBlock(int streamId, boolean endStream, boolean trailers,
                               boolean selfDependent, byte[] block, int off, int len)
        throws IOException {
        List<Hpack.HeaderField> fields = decodeHeaderBlock(block, off, len);
        enforceDecodedHeaderListSize(fields);
        Http2Stream st = trailers ? streams.get(streamId) : null;
        if (trailers && st == null) {
            // Stream already closed on our side (reset, possibly while
            // CONTINUATIONs were in flight, or ignored after GOAWAY).
            return;
        }
        if (selfDependent) {
            resetStreamQuiet(streamId, Http2.ERROR_PROTOCOL_ERROR);
            return;
        }
        if (trailers) {
            if (st.state != Http2Stream.State.OPEN) {
                // Peer already ended the stream: stream error (§5.1).
                resetStreamQuiet(streamId, Http2.ERROR_STREAM_CLOSED);
                return;
            }
            finalizeTrailerBlock(st, fields);
            return;
        }
        // Enforce our advertised SETTINGS_MAX_CONCURRENT_STREAMS. Running
        // handlers count too: a reset stream leaves the map but its handler
        // keeps working (CVE-2023-44487).
        if (streams.size() >= ownMaxConcurrentStreams
            || activeHandlers.get() >= ownMaxConcurrentStreams) {
            resetStreamQuiet(streamId, Http2.ERROR_REFUSED_STREAM);
            return;
        }
        if (!admitStream(streamId)) {
            return;
        }
        boolean started = false;
        try {
            started = finalizeHeaderBlock(streamId, endStream, fields);
        } finally {
            if (!started) {
                onHandlerDone();
            }
        }
    }

    // RFC 9113 §6.5.2: SETTINGS_MAX_HEADER_LIST_SIZE bounds the
    // *decoded* size (32 + name + value octets per field), for header and
    // trailer blocks alike. The earlier enforceHeaderListBudget check on
    // encoded bytes gates memory pressure during accumulation, but a
    // Huffman-compressed peer could bypass the advertised cap by ~40%.
    // Post-decode check enforces the spec-defined limit.
    private void enforceDecodedHeaderListSize(List<Hpack.HeaderField> fields)
        throws Http2.ConnectionError {
        if (ownMaxHeaderListSize > 0) {
            long decodedSize = 0;
            for (int i = 0, n = fields.size(); i < n; i++) {
                Hpack.HeaderField hf = fields.get(i);
                decodedSize += 32L + hf.name.length() + hf.value.length();
            }
            if (decodedSize > ownMaxHeaderListSize) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_ENHANCE_YOUR_CALM,
                    "decoded header list " + decodedSize + " exceeds SETTINGS_MAX_HEADER_LIST_SIZE " + ownMaxHeaderListSize);
            }
        }
    }

    private List<Hpack.HeaderField> decodeHeaderBlock(byte[] block, int off, int len)
        throws Http2.ConnectionError {
        try {
            return hpackDecoder.decode(block, off, len);
        } catch (IOException | RuntimeException e) {
            // Any decoding failure leaves the dynamic table in an unknown
            // state: connection error (RFC 9113 §4.3).
            throw new Http2.ConnectionError(
                Http2.ERROR_COMPRESSION_ERROR, "HPACK decode failed: " + e.getMessage());
        }
    }

    /**
     * Trailer HEADERS on an already-open stream (RFC 9113 §8.1). Validate
     * no pseudo-headers appear, then signal end-of-body to the handler's
     * request InputStream. Ring 1.5 has no trailer surface so the fields
     * are dropped.
     */
    private void finalizeTrailerBlock(Http2Stream stream, List<Hpack.HeaderField> fields)
        throws IOException {
        for (Hpack.HeaderField hf : fields) {
            if (!hf.name.isEmpty() && hf.name.charAt(0) == ':') {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "pseudo-header in trailers");
            }
        }
        // Trailers end the request: the body must match Content-Length
        // (§8.1.1), as on a DATA frame carrying END_STREAM.
        if (stream.declaredContentLength >= 0
            && stream.receivedBodyBytes != stream.declaredContentLength) {
            resetStreamQuiet(stream.id, Http2.ERROR_PROTOCOL_ERROR);
            return;
        }
        stream.state = Http2Stream.State.HALF_CLOSED_REMOTE;
        stream.signalEndOfBody();
    }

    /**
     * Sets up the admitted stream and starts its handler vthread. Returns
     * false when the request is rejected instead (stream reset), in which
     * case no handler will call {@link #onHandlerDone}.
     */
    private boolean finalizeHeaderBlock(int streamId, boolean endStream,
                                     List<Hpack.HeaderField> fields) throws IOException {
        Http2Stream stream = new Http2Stream(
            this, streamId, peerInitialWindowSize, ownInitialWindowSize);
        stream.state = endStream ? Http2Stream.State.HALF_CLOSED_REMOTE
                                 : Http2Stream.State.OPEN;
        if (endStream) {
            stream.signalEndOfBody();
        }
        streams.put(streamId, stream);


        Request request = buildRequest(fields, stream);
        if (request == null) {
            resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
            return false;
        }

        // Track declared Content-Length so we can enforce §8.1.2.6 (declared
        // length must match total DATA payload).
        String cl = request.header("content-length");
        if (cl != null) {
            try {
                long declared = Long.parseLong(cl);
                if (declared < 0) {
                    resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                    return false;
                }
                stream.declaredContentLength = declared;
                if (config.maxRequestBodyBytes > 0 && declared > config.maxRequestBodyBytes) {
                    // Answered 413 without running the handler (runHandler);
                    // any DATA that still arrives is discarded.
                    stream.bodyTooLarge = true;
                }
                if (endStream && declared != 0) {
                    // No body but Content-Length says otherwise → mismatch.
                    resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                    return false;
                }
            } catch (NumberFormatException e) {
                resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                return false;
            }
        }

        // Per-request timeout. Shared scheduler fires at deadline; if
        // the handler hasn't already produced a response (CAS on
        // stream.responded), we emit a 408 + reset stream + interrupt
        // the handler vthread. Handler races the timer on the same CAS
        // — first to flip owns the response.
        java.util.concurrent.ScheduledFuture<?> timeout = null;
        if (config.requestTimeoutMillis > 0) {
            final int timeoutMs = config.requestTimeoutMillis;
            timeout = TIMEOUT_SCHEDULER.schedule(
                () -> Thread.ofVirtual().name("enso-h2-timeout-" + streamId)
                    .start(() -> onRequestTimeout(stream)),
                timeoutMs,
                java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        final java.util.concurrent.ScheduledFuture<?> t = timeout;
        Thread.ofVirtual()
            .name("enso-h2-stream-" + streamId)
            .start(() -> {
                stream.handlerThread = Thread.currentThread();
                try {
                    runHandler(stream, request);
                } finally {
                    if (t != null) t.cancel(false);
                    stream.handlerThread = null;
                    onHandlerDone();
                }
            });
        return true;
    }

    // Daemon single-thread scheduler shared by all Http2Connections in
    // this JVM (request and idle timers). Its tasks only flip state or hand
    // work to a virtual thread, so one thread is plenty. Cancelled timers
    // are removed eagerly: almost every request timer is cancelled, and at
    // high request rates the default policy would retain them until their
    // deadline. Daemon so JVM shutdown doesn't wait on it.
    private static final java.util.concurrent.ScheduledExecutorService TIMEOUT_SCHEDULER =
        newTimeoutScheduler();

    private static java.util.concurrent.ScheduledExecutorService newTimeoutScheduler() {
        java.util.concurrent.ScheduledThreadPoolExecutor ex =
            new java.util.concurrent.ScheduledThreadPoolExecutor(1, r -> {
                Thread th = new Thread(r, "enso-h2-request-timeout");
                th.setDaemon(true);
                return th;
            });
        ex.setRemoveOnCancelPolicy(true);
        return ex;
    }

    /**
     * Runs on its own vthread: writing can block on the write queue, so it
     * stays off the shared scheduler thread. It counts in
     * {@link #activeHandlers} like a handler, from before it claims the
     * response: the stream's handler stays counted until it has seen the
     * claim, so a draining connection can't close before the 408 is out.
     */
    private void onRequestTimeout(Http2Stream stream) {
        activeHandlers.incrementAndGet();
        try {
            if (!stream.responded.compareAndSet(false, true)) return;
            Thread ht = stream.handlerThread;
            if (ht != null) ht.interrupt();
            try {
                writeResponseInternal(stream, 408, PersistentArrayMap.EMPTY, null, false);
                if (stream.state == Http2Stream.State.OPEN) {
                    // Complete 408 sent while the request body is still
                    // arriving: ask the client to stop sending (§8.1).
                    resetStreamQuiet(stream.id, Http2.ERROR_NO_ERROR);
                }
            } catch (Throwable t) {
                if (stream.state != Http2Stream.State.CLOSED) {
                    resetStreamQuiet(stream.id, Http2.ERROR_INTERNAL_ERROR);
                }
            } finally {
                closeStream(stream);
            }
        } finally {
            onHandlerDone();
        }
    }

    // Consecutive empty DATA frames (without END_STREAM) tolerated per
    // stream; same default as Netty's empty-frame guard.
    private static final int EMPTY_DATA_FRAME_LIMIT = 10;

    private void handleData(Frame f) throws IOException {
        if (f.streamId == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "DATA on stream 0");
        }
        Http2Stream stream = streams.get(f.streamId);
        if (stream == null) {
            if (f.streamId > highestPeerStreamId) {
                // DATA on an idle stream: connection error (§5.1).
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "DATA on idle stream " + f.streamId);
            }
            // Stream we already closed (handler finished, refused or
            // reset): the peer may legitimately still have DATA in flight
            // and we MUST ignore it (§5.1 "closed"), while keeping the
            // connection window in step.
            discardData(f.length, null);
            return;
        }
        if (stream.state == Http2Stream.State.HALF_CLOSED_REMOTE
            || stream.state == Http2Stream.State.CLOSED) {
            // Peer has already sent END_STREAM; further DATA is a stream error
            // per §5.1. Reset and close.
            discardData(f.length, null);
            resetStreamQuiet(f.streamId, Http2.ERROR_STREAM_CLOSED);
            return;
        }
        if (stream.bodyTooLarge) {
            // Over max-request-body-bytes: nobody reads further body bytes.
            // Only the connection window is credited, so the stream stalls
            // until the 413 goes out and the stream is reset. The stream
            // window is still charged: the peer must not overrun it.
            discardData(f.length, stream);
            return;
        }

        // Decrement receive windows against the *full* frame length including
        // padding — flow control accounting is per RFC 9113 §6.9.1. The
        // bytes stay charged (bufferedBytes) until the handler consumes
        // them; creditConsumed hands the credit back. Only the framer
        // decrements the windows, so the overrun check outside flowLock
        // can only observe a concurrent increase.
        int frameLen = f.length;
        int abandonedIncrement = 0;
        flowLock.lock();
        try {
            connRecvWindow -= frameLen;
            stream.recvWindow -= frameLen;
            if (stream.abandoned) {
                // Handler already gone (racing its removal from the map):
                // nobody will consume these bytes.
                abandonedIncrement = takeConnCredit(frameLen);
            } else {
                stream.bufferedBytes += frameLen;
            }
        } finally {
            flowLock.unlock();
        }
        if (stream.recvWindow < 0 || connRecvWindow < 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FLOW_CONTROL_ERROR, "peer overran receive window");
        }
        if (abandonedIncrement > 0) {
            sendWindowUpdate(0, abandonedIncrement);
        }

        byte[] payload = f.payload;
        int off = 0;
        int len = frameLen;
        if ((f.flags & Http2.FLAG_PADDED) != 0) {
            if (len < 1) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "DATA PADDED with no pad-length byte");
            }
            int padLen = payload[0] & 0xFF;
            off = 1;
            len = len - 1 - padLen;
            if (len < 0) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "DATA padding too large");
            }
        }
        if (len == 0 && (f.flags & Http2.FLAG_END_STREAM) == 0) {
            // CVE-2019-9518: cap consecutive empty non-final DATA frames.
            if (++stream.emptyDataFrames > EMPTY_DATA_FRAME_LIMIT) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_ENHANCE_YOUR_CALM, "too many empty DATA frames");
            }
        }
        if (len > 0) {
            stream.emptyDataFrames = 0;
            stream.receivedBodyBytes += len;
            long cap = config.maxRequestBodyBytes;
            if (cap > 0 && stream.receivedBodyBytes > cap) {
                // The frame's bytes are charged to the stream but never
                // queued: hand the connection share back, then fail the
                // handler's read.
                creditConsumed(stream, frameLen);
                stream.signalBodyTooLarge();
                return;
            }
            if (stream.declaredContentLength >= 0
                && stream.receivedBodyBytes > stream.declaredContentLength) {
                // More body than declared — §8.1.2.6 stream error.
                resetStreamQuiet(f.streamId, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            // readFrame allocates a fresh payload per frame: hand it over
            // as-is unless padding has to be stripped.
            byte[] chunk = len == payload.length
                ? payload
                : java.util.Arrays.copyOfRange(payload, off, off + len);
            stream.enqueueBody(chunk);
        }
        if ((f.flags & Http2.FLAG_END_STREAM) != 0) {
            if (stream.declaredContentLength >= 0
                && stream.receivedBodyBytes != stream.declaredContentLength) {
                resetStreamQuiet(f.streamId, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            stream.signalEndOfBody();
            stream.state = Http2Stream.State.HALF_CLOSED_REMOTE;
        }
        // Padding and the pad-length octet never reach the handler; their
        // credit is returned straight away.
        if (frameLen > len) {
            creditConsumed(stream, frameLen - len);
        }
    }

    /**
     * Returns receive credit for {@code n} bytes of {@code stream}'s DATA
     * once they've left the server's hands (read by the handler, or
     * padding). WINDOW_UPDATEs are batched: one per stream / connection
     * each time half the window has been consumed. Called from the framer
     * and from the handler's body reads.
     */
    void creditConsumed(Http2Stream stream, int n) throws IOException {
        int streamIncrement = 0;
        int connIncrement;
        flowLock.lock();
        try {
            if (stream.abandoned) {
                // Already returned to the connection window wholesale.
                return;
            }
            stream.bufferedBytes -= n;
            if (stream.state == Http2Stream.State.OPEN) {
                // Peer can still send on this stream: replenish its window.
                stream.recvUncredited += n;
                if (stream.recvUncredited >= recvCreditThreshold()) {
                    streamIncrement = (int) stream.recvUncredited;
                    stream.recvUncredited = 0;
                    stream.recvWindow += streamIncrement;
                }
            }
            connIncrement = takeConnCredit(n);
        } finally {
            flowLock.unlock();
        }
        if (streamIncrement > 0) {
            sendWindowUpdate(stream.id, streamIncrement);
        }
        if (connIncrement > 0) {
            sendWindowUpdate(0, connIncrement);
        }
    }

    /**
     * DATA that no handler will read: charge the connection window (the
     * peer did) and immediately return the credit. {@code stream}, when
     * non-null, has its window charged too, without credit.
     */
    private void discardData(int frameLen, Http2Stream stream) throws IOException {
        int connIncrement;
        flowLock.lock();
        try {
            connRecvWindow -= frameLen;
            if (stream != null) {
                stream.recvWindow -= frameLen;
            }
            if (connRecvWindow < 0 || (stream != null && stream.recvWindow < 0)) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_FLOW_CONTROL_ERROR, "peer overran receive window");
            }
            connIncrement = takeConnCredit(frameLen);
        } finally {
            flowLock.unlock();
        }
        if (connIncrement > 0) {
            sendWindowUpdate(0, connIncrement);
        }
    }

    /**
     * Stream is gone (handler done or reset): whatever DATA it still had
     * buffered will never be read, so return that credit to the
     * connection window.
     */
    private void abandonReceiveBuffer(Http2Stream stream) {
        int connIncrement;
        flowLock.lock();
        try {
            if (stream.abandoned) {
                return;
            }
            stream.abandoned = true;
            connIncrement = takeConnCredit(stream.bufferedBytes);
            stream.bufferedBytes = 0;
        } finally {
            flowLock.unlock();
        }
        if (connIncrement > 0) {
            try {
                sendWindowUpdate(0, connIncrement);
            } catch (IOException ignored) {
                // Connection is going down.
            }
        }
    }

    /**
     * Accumulates {@code n} consumed bytes against the connection window
     * and returns the WINDOW_UPDATE increment to send now (0 = keep
     * batching). Caller holds {@link #flowLock}.
     */
    private int takeConnCredit(long n) {
        connRecvUncredited += n;
        if (connRecvUncredited < recvCreditThreshold()) {
            return 0;
        }
        int increment = (int) connRecvUncredited;
        connRecvUncredited = 0;
        connRecvWindow += increment;
        return increment;
    }

    private int recvCreditThreshold() {
        return Math.max(1, ownInitialWindowSize / 2);
    }

    // ---- Request build --------------------------------------------------

    private Request buildRequest(List<Hpack.HeaderField> fields, Http2Stream stream) {
        String method = null, path = null, scheme = null, authority = null;
        boolean seenRegular = false;
        boolean seenContentLength = false;
        // Pre-count non-pseudo headers so the backing Object[] is sized
        // exactly. Avoids the oversized worst-case allocation (fields.size()
        // * 2 slots when pseudo-headers don't go in the map) and the
        // trailing Arrays.copyOf. Pseudo detection here is permissive — the
        // main loop still validates ordering + duplicates.
        int regularCount = 0;
        for (Hpack.HeaderField hf : fields) {
            String n = hf.name;
            if (!n.isEmpty() && n.charAt(0) != ':') regularCount++;
        }
        Object[] regular = new Object[regularCount * 2];
        int rp = 0;
        for (Hpack.HeaderField hf : fields) {
            String name = hf.name;
            if (name.isEmpty()) {
                return null;
            }
            // §8.2.1: names are lowercase tokens; ':' only as the
            // pseudo-header prefix. Values carry no NUL/CR/LF and no
            // leading/trailing whitespace.
            if (!HttpFields.isLowercaseToken(name, name.charAt(0) == ':' ? 1 : 0)
                || !isValidFieldValue(hf.value)) {
                return null;
            }
            if (name.charAt(0) == ':') {
                // Pseudo-header. Must precede all regular headers (§8.1.2.1).
                if (seenRegular) {
                    return null;
                }
                switch (name) {
                    case ":method" -> {
                        if (method != null) return null;
                        if (!HttpFields.isToken(hf.value)) return null;
                        method = hf.value;
                    }
                    case ":path" -> {
                        if (path != null) return null;
                        // Empty :path invalid for http/https schemes (§8.1.2.3).
                        if (hf.value.isEmpty()) return null;
                        path = hf.value;
                    }
                    case ":scheme" -> {
                        if (scheme != null) return null;
                        scheme = hf.value;
                    }
                    case ":authority" -> {
                        if (authority != null) return null;
                        authority = hf.value;
                    }
                    default -> {
                        // Unknown request pseudo-header rejected (§8.1.2.3).
                        return null;
                    }
                }
            } else {
                seenRegular = true;
                // Connection-specific headers forbidden in HTTP/2 (§8.1.2.2).
                if (name.equals("connection") || name.equals("keep-alive")
                    || name.equals("proxy-connection") || name.equals("transfer-encoding")
                    || name.equals("upgrade")) {
                    return null;
                }
                if (name.equals("te") && !hf.value.equals("trailers")) {
                    // The only permitted TE value in HTTP/2 is exactly "trailers".
                    return null;
                }
                // Multiple Content-Length values are a request-smuggling vector
                // per RFC 9113 §8.1.2.6.
                if (name.equals("content-length")) {
                    // 1*DIGIT (RFC 9110 §8.6); Long.parseLong alone would
                    // accept a sign.
                    if (seenContentLength || !isDigits(hf.value)) {
                        return null;
                    }
                    seenContentLength = true;
                }
                regular[rp++] = name;
                regular[rp++] = hf.value;
            }
        }
        if (method == null || path == null || scheme == null) {
            return null;
        }
        // §8.3.1: origin-form, or "*" for OPTIONS (asterisk-form).
        if (path.charAt(0) != '/' && !(path.equals("*") && method.equals("OPTIONS"))) {
            return null;
        }

        String uri;
        String query;
        int q = path.indexOf('?');
        if (q < 0) {
            uri = path;
            query = null;
        } else {
            uri = path.substring(0, q);
            query = path.substring(q + 1);
        }

        IPersistentMap headers;
        if (rp == 0) {
            headers = PersistentArrayMap.EMPTY;
        } else {
            // Dedup duplicates before createAsIfByAssoc (throws on repeats).
            // "cookie" per RFC 9113 §8.2.3, others per RFC 9110 §5.3.
            Object[] merged = com.s_exp.enso.util.RingHeaders
                .mergeDuplicates(regular, rp);
            headers = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(merged);
        }
        // :authority stands in for Host (§8.3.1); without it a Host header,
        // if any, is kept as sent.
        if (authority != null) {
            headers = headers.assoc("host", authority);
        }

        return new Request(method, uri, query, "HTTP/2.0",
                           headers,
                           stream.bodyInputStream(),
                           remoteAddress, localPort, Request.K_HTTPS);
    }

    // RFC 9113 §8.2.1. A downstream proxy re-emitting into HTTP/1 would
    // smuggle on embedded NUL/CR/LF.
    private static boolean isValidFieldValue(String v) {
        int n = v.length();
        if (n > 0) {
            char first = v.charAt(0);
            char last = v.charAt(n - 1);
            if (first == ' ' || first == '\t' || last == ' ' || last == '\t') return false;
        }
        for (int i = 0; i < n; i++) {
            char c = v.charAt(i);
            if (c == 0 || c == '\r' || c == '\n') return false;
        }
        return true;
    }

    private static boolean isDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    // ---- Response writing ----------------------------------------------

    private void runHandler(Http2Stream stream, Request request) {
        Response response = null;
        if (stream.bodyTooLarge) {
            response = CONTENT_TOO_LARGE;
        } else {
            try {
                response = handler.handle(request);
                if (response == null) {
                    throw new NullPointerException("handler returned null response");
                }
            } catch (Throwable t) {
                response = stream.bodyTooLarge
                    ? CONTENT_TOO_LARGE
                    : RingErrorHandler.respond(server.errorHandler(), request, t);
            }
        }
        boolean head = "HEAD".equals(request.method);
        // First-writer-wins with the timeout task. If the timeout has
        // already claimed the response (408), drop what the handler
        // built — writing it now would either double-respond on the
        // stream (protocol error) or race with the reset already sent.
        // The stream itself is the 408 writer's to close.
        if (!stream.responded.compareAndSet(false, true)) {
            if (response != null) {
                closeBody(response.body);
            }
            return;
        }
        try {
            if (response == null) {
                writeResponseInternal(stream, 500, PersistentArrayMap.EMPTY, null, head);
            } else if (response.webSocketListener != null) {
                // RFC 9113 §8.6: no 101 / Upgrade over HTTP/2, and Extended
                // CONNECT (RFC 8441) isn't offered.
                writeResponseInternal(stream, 501, PersistentArrayMap.EMPTY, null, head);
            } else {
                try {
                    writeResponseInternal(stream, response.status, response.headers,
                                          response.body, head);
                } catch (InvalidResponseException e) {
                    LOG.log(Level.WARNING, "invalid HTTP/2 response, sending 500", e);
                    closeBody(response.body);
                    writeResponseInternal(stream, 500, PersistentArrayMap.EMPTY, null, head);
                }
            }
            if (stream.state == Http2Stream.State.OPEN) {
                // Complete response sent while the request body is still
                // arriving: ask the client to stop sending (§8.1).
                resetStreamQuiet(stream.id, Http2.ERROR_NO_ERROR);
            }
        } catch (Throwable t) {
            // Socket died, the stream was reset mid-write, or building the
            // response failed. Never answer a peer's RST_STREAM with
            // another one (§5.4.2).
            if (!(t instanceof IOException)) {
                LOG.log(Level.WARNING, "HTTP/2 response write failed", t);
            }
            if (stream.state != Http2Stream.State.CLOSED) {
                resetStreamQuiet(stream.id, Http2.ERROR_INTERNAL_ERROR);
            }
        } finally {
            closeStream(stream);
        }
    }

    /** The response is done or abandoned: the stream is closed on our side. */
    private void closeStream(Http2Stream stream) {
        stream.state = Http2Stream.State.CLOSED;
        streams.remove(stream.id);
        abandonReceiveBuffer(stream);
    }

    private static final Response CONTENT_TOO_LARGE =
        new Response(413, PersistentArrayMap.EMPTY, null);

    /** Releases a response body that will never be written. */
    private static void closeBody(Object body) {
        if (body instanceof java.io.Closeable c) {
            try {
                c.close();
            } catch (IOException ignored) {
            }
        }
    }

    // Codes 100..599 pre-formatted so hot-path :status pseudo-header
    // skips Integer.toString per response.
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

    private static boolean hasUpperAscii(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') return true;
        }
        return false;
    }

    private void writeResponseInternal(Http2Stream stream, int status,
                                       Map<?, ?> respHeaders, Object body,
                                       boolean head) throws IOException {
        // Assemble the header block: :status pseudo-header first, then user headers.
        List<Hpack.HeaderField> fields = new ArrayList<>(
            (respHeaders == null ? 0 : respHeaders.size()) + 1);
        fields.add(new Hpack.HeaderField(":status", statusString(status)));
        boolean hasAltSvc = false;
        boolean hasServer = false;
        boolean hasContentLength = false;
        if (respHeaders != null) {
            for (Map.Entry<?, ?> e : respHeaders.entrySet()) {
                String rawName = String.valueOf(e.getKey());
                if (!HttpFields.isToken(rawName)) {
                    throw new InvalidResponseException("response header name is not a token: " + rawName);
                }
                // Skip toLowerCase alloc when caller already normalised
                // — most Ring middleware emits lowercase names.
                String name = hasUpperAscii(rawName)
                    ? rawName.toLowerCase(java.util.Locale.ROOT)
                    : rawName;
                if (name.equals("connection") || name.equals("transfer-encoding")
                    || name.equals("keep-alive") || name.equals("upgrade")
                    || name.equals("proxy-connection")) {
                    // Forbidden in HTTP/2 responses per §8.1.2.2.
                    continue;
                }
                if (name.equals("alt-svc")) hasAltSvc = true;
                else if (name.equals("server")) hasServer = true;
                else if (name.equals("content-length")) hasContentLength = true;
                Object v = e.getValue();
                if (v instanceof List<?> values) {
                    // Ring: a seq of strings is one field per value.
                    for (Object item : values) {
                        addResponseField(fields, name, item);
                    }
                } else {
                    addResponseField(fields, name, v);
                }
            }
        }
        // Advertise h3 endpoint (RFC 7838). Handler-supplied Alt-Svc wins.
        if (!hasAltSvc && config.altSvcValue != null) {
            fields.add(new Hpack.HeaderField("alt-svc", config.altSvcValue));
        }
        if (!hasServer && config.serverHeader != null && !config.serverHeader.isEmpty()) {
            fields.add(new Hpack.HeaderField("server", config.serverHeader));
        }
        boolean hasBody = body != null && !(body instanceof byte[] b && b.length == 0)
                                       && !(body instanceof String s && s.isEmpty());
        if (body != null && !(body instanceof byte[] || body instanceof String
                              || body instanceof java.io.File || body instanceof InputStream
                              || body instanceof StreamingBody)) {
            throw new InvalidResponseException(
                "unsupported response body type: " + body.getClass().getName());
        }
        java.nio.charset.Charset charset = null;
        if (body instanceof String) {
            try {
                charset = HttpFields.responseCharset(respHeaders);
            } catch (IllegalArgumentException e) {
                throw new InvalidResponseException(e.getMessage());
            }
        }
        // RFC 9110 §9.3.2 / §8.6: HEAD response MUST NOT include a body
        // but SHOULD carry the same Content-Length the GET would return.
        // Compute from byte[] or String bodies where we know the size;
        // stream / File / StreamingBody sizes are unknown here so skip.
        if (head) {
            if (!hasContentLength && hasBody) {
                long len = -1;
                if (body instanceof byte[] bb) len = bb.length;
                else if (body instanceof String ss)
                    len = ss.getBytes(charset).length;
                if (len >= 0) {
                    fields.add(new Hpack.HeaderField("content-length",
                                                    Long.toString(len)));
                }
            }
            // HEAD response is body-less on the wire regardless of the
            // body type the handler returned.
            hasBody = false;
        }

        // HPACK encoder state (dynamic table) mutates as encode() runs. The
        // emitted header block must reach the peer in the same order the table
        // updates happened, otherwise the peer's decoder ends up out of sync:
        // streamLock is held from encode to enqueue. §4.3 also forbids
        // interleaving HEADERS/CONTINUATION with any other frame — a split
        // block is queued as one contiguous run by enqueueAll.
        streamLock.lock();
        try {
            // Nothing may be sent on a stream the peer reset (§5.1), and
            // the encoder's table must only change for blocks that are.
            ensureWritable(stream);
            byte[] headerBlock = hpackEncoder.encode(fields);
            int max = peerMaxFrameSize;
            if (headerBlock.length <= max) {
                int flags = Http2.FLAG_END_HEADERS | (hasBody ? 0 : Http2.FLAG_END_STREAM);
                writeFrame(Http2.TYPE_HEADERS, flags, stream.id,
                           headerBlock, 0, headerBlock.length);
            } else {
                // §4.3: HEADERS + CONTINUATIONs must be contiguous on the
                // wire, so the whole block is enqueued in one go.
                FrameSeg[] segs = new FrameSeg[(headerBlock.length + max - 1) / max];
                int firstFlags = hasBody ? 0 : Http2.FLAG_END_STREAM;
                segs[0] = frameSeg(Http2.TYPE_HEADERS, firstFlags, stream.id,
                                   headerBlock, 0, max);
                int p = max;
                for (int i = 1; i < segs.length; i++) {
                    int n = Math.min(max, headerBlock.length - p);
                    int contFlags = (p + n == headerBlock.length) ? Http2.FLAG_END_HEADERS : 0;
                    segs[i] = frameSeg(Http2.TYPE_CONTINUATION, contFlags, stream.id,
                                       headerBlock, p, n);
                    p += n;
                }
                enqueueAll(segs);
            }
        } finally {
            streamLock.unlock();
        }

        if (!hasBody) {
            // HEAD or empty body: a stream/closeable source is never read.
            closeBody(body);
            return;
        }
        writeBody(stream, body, charset);
    }

    /**
     * Dispatches by body type and emits DATA frames. Buffered types (String,
     * byte[]) are chunked by {@link #DATA_FRAME_MAX}; live-source types
     * (InputStream, File, StreamingBody) stream incrementally — each read/
     * flush produces its own DATA frame. Flow control is honoured per frame
     * via {@link #acquireSendCredit}. Always closes the stream with an
     * END_STREAM-flagged frame on the last chunk.
     */
    private void writeBody(Http2Stream stream, Object body, java.nio.charset.Charset charset) throws IOException {
        if (body instanceof byte[] bytes) {
            emitData(stream, bytes, 0, bytes.length, true, false);
        } else if (body instanceof String s) {
            byte[] bytes = s.getBytes(charset);
            emitData(stream, bytes, 0, bytes.length, true, true);
        } else if (body instanceof java.io.File file) {
            try (InputStream in = new java.io.FileInputStream(file)) {
                streamInputStream(stream, in);
            }
        } else if (body instanceof InputStream in) {
            try (InputStream ins = in) {
                streamInputStream(stream, ins);
            }
        } else if (body instanceof StreamingBody sb) {
            Http2DataOutputStream out = new Http2DataOutputStream(this, stream);
            ChunkedWriter writer = new ChunkedWriter(out, DATA_FRAME_MAX, false);
            try {
                sb.write(writer);
            } finally {
                writer.closeInternal();
            }
            // Close the stream: the writer may have flushed the last data but
            // no END_STREAM was ever sent, so send an empty DATA(END_STREAM).
            emitEndStream(stream);
        }
    }

    /**
     * Snapshots {@code value} to a String once and validates that exact
     * snapshot, so a value whose toString() changes can't slip past.
     */
    private static void addResponseField(List<Hpack.HeaderField> fields, String name, Object value) {
        String vs = value == null ? "" : value.toString();
        try {
            HttpFields.checkResponseValue(vs);
        } catch (IllegalArgumentException e) {
            throw new InvalidResponseException(e.getMessage() + " (" + name + ")");
        }
        fields.add(new Hpack.HeaderField(name, vs));
    }

    /**
     * The handler's response can't be written as given (bad header, unknown
     * body type). Thrown before any frame of it is queued, so a 500 can
     * still be sent in its place.
     */
    private static final class InvalidResponseException extends IllegalArgumentException {
        InvalidResponseException(String message) {
            super(message);
        }
    }

    // Outbound DATA payload cap. Every peer accepts 16 KiB frames; a peer
    // advertising a larger SETTINGS_MAX_FRAME_SIZE (up to 16 MiB) must not
    // dictate our buffer sizes and copy granularity.
    private static final int DATA_FRAME_MAX = Http2.DEFAULT_MAX_FRAME_SIZE;

    private void streamInputStream(Http2Stream stream, InputStream in) throws IOException {
        byte[] scratch = new byte[DATA_FRAME_MAX];
        while (true) {
            int r = in.read(scratch);
            if (r < 0) {
                emitEndStream(stream);
                return;
            }
            if (r == 0) {
                continue;
            }
            emitData(stream, scratch, 0, r, false, false);
        }
    }

    /**
     * Emits {@code buf[off..off+len)} as DATA frames. {@code privateBuf}:
     * the caller never touches {@code buf} again, so frames may reference
     * it directly instead of copying.
     */
    private void emitData(Http2Stream stream, byte[] buf, int off, int len,
                          boolean endStream, boolean privateBuf) throws IOException {
        if (len == 0 && endStream) {
            emitEndStream(stream);
            return;
        }
        int p = off;
        int endOff = off + len;
        while (p < endOff) {
            int remaining = endOff - p;
            int want = Math.min(remaining, DATA_FRAME_MAX);
            int granted = acquireSendCredit(stream, want);
            boolean last = (p + granted == endOff);
            int flags = (last && endStream) ? Http2.FLAG_END_STREAM : 0;
            if (privateBuf) {
                writeFrame(Http2.TYPE_DATA, flags, stream.id, buf, p, granted);
            } else {
                // Copy the chunk into a fresh byte[] so FrameSeg's byref
                // payload holds a stable buffer. Streaming callers
                // (streamInputStream, Http2DataOutputStream) reuse `buf`
                // across iterations; without the copy the writer thread's
                // batch coalesce could race the next in.read overwriting
                // bytes it hasn't flushed yet. Handler-supplied byte[]
                // bodies are copied too: the handler may still reuse them.
                byte[] chunk = new byte[granted];
                System.arraycopy(buf, p, chunk, 0, granted);
                writeFrame(Http2.TYPE_DATA, flags, stream.id, chunk, 0, granted);
            }
            p += granted;
        }
    }

    private void emitEndStream(Http2Stream stream) throws IOException {
        // Empty DATA frame with END_STREAM closes the stream. No flow-control
        // credit required for zero-length payloads (§6.9.1).
        ensureWritable(stream);
        writeFrame(Http2.TYPE_DATA, Http2.FLAG_END_STREAM, stream.id, EMPTY, 0, 0);
    }

    /**
     * OutputStream façade for streaming user-code writes into HTTP/2 DATA
     * frames. Used to bridge {@link StreamingBody} responses (which normally
     * emit HTTP/1.1 chunked encoding through {@link ChunkedWriter}) onto the
     * HTTP/2 wire.
     */
    private static final class Http2DataOutputStream extends OutputStream {
        private final Http2Connection conn;
        private final Http2Stream stream;

        Http2DataOutputStream(Http2Connection conn, Http2Stream stream) {
            this.conn = conn;
            this.stream = stream;
        }

        @Override
        public void write(int b) throws IOException {
            byte[] one = {(byte) b};
            conn.emitData(stream, one, 0, 1, false, true);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len > 0) {
                conn.emitData(stream, b, off, len, false, false);
            }
        }

        @Override
        public void flush() throws IOException {
            // User's flush! must push bytes to the wire — SSE etc. rely on it.
            // With the writer-thread queue, flushSync waits for the writer to
            // drain everything currently queued and complete its in-progress
            // socket write.
            ensureWritable(stream);
            conn.flushSync();
        }
    }

    /**
     * Blocks until both the stream and the connection have flow-control
     * capacity to send at least one byte, up to {@code want}. Returns the
     * granted byte count. Throws if the stream is (or gets) reset or the
     * connection dies, so the handler stops producing output.
     */
    private int acquireSendCredit(Http2Stream stream, int want) throws IOException {
        flowLock.lock();
        try {
            while (true) {
                ensureWritable(stream);
                long available = Math.min(stream.sendWindow, connSendWindow);
                if (available > 0) {
                    int granted = (int) Math.min((long) want, available);
                    stream.sendWindow -= granted;
                    connSendWindow -= granted;
                    return granted;
                }
                // About to block on the flow-control window. Frames we've
                // enqueued are already in the writer's queue and will hit
                // the wire independently of this vthread, so no explicit
                // flush is needed here.
                try {
                    flowChanged.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted while awaiting flow-control credit");
                }
            }
        } finally {
            flowLock.unlock();
        }
    }

    private static void ensureWritable(Http2Stream stream) throws IOException {
        if (stream.state == Http2Stream.State.CLOSED) {
            throw new IOException("HTTP/2 stream " + stream.id + " closed");
        }
    }

    /** Stream closed under a worker: wake it if it is parked on flow control. */
    private void wakeFlowWaiters() {
        flowLock.lock();
        try {
            flowChanged.signalAll();
        } finally {
            flowLock.unlock();
        }
    }

    private void resetStream(int streamId, int code) throws IOException {
        byte[] payload = new byte[4];
        payload[0] = (byte) ((code >>> 24) & 0xFF);
        payload[1] = (byte) ((code >>> 16) & 0xFF);
        payload[2] = (byte) ((code >>>  8) & 0xFF);
        payload[3] = (byte) (code & 0xFF);
        writeFrame(Http2.TYPE_RST_STREAM, 0, streamId, payload, 0, 4);
        rememberReset(streamId);
        Http2Stream st = streams.remove(streamId);
        if (st != null) {
            st.state = Http2Stream.State.CLOSED;
            st.signalAbort();
            abandonReceiveBuffer(st);
            wakeFlowWaiters();
        }
    }

    // The streams we reset most recently. Frames the peer sent before
    // seeing our RST_STREAM must be ignored (§5.1 "closed"), so HEADERS on
    // these ids is dropped rather than taken as a reused stream id. §5.1
    // lets that period be limited: older resets are forgotten.
    private static final int RECENT_RESETS_MAX = 128;
    private final int[] recentResets = new int[RECENT_RESETS_MAX];
    private int recentResetsNext = 0;

    private void rememberReset(int streamId) {
        synchronized (recentResets) {
            recentResets[recentResetsNext] = streamId;
            recentResetsNext = (recentResetsNext + 1) % RECENT_RESETS_MAX;
        }
    }

    private boolean wasResetByUs(int streamId) {
        synchronized (recentResets) {
            for (int id : recentResets) {
                if (id == streamId) return true;
            }
            return false;
        }
    }

    private void resetStreamQuiet(int streamId, int code) {
        try {
            resetStream(streamId, code);
        } catch (IOException ignored) {
        }
    }

    private void sendWindowUpdate(int streamId, int increment) throws IOException {
        byte[] payload = new byte[4];
        // RFC 9113 §6.9: reserved (high) bit of the increment must be 0.
        payload[0] = (byte) ((increment >>> 24) & 0x7F);
        payload[1] = (byte) ((increment >>> 16) & 0xFF);
        payload[2] = (byte) ((increment >>>  8) & 0xFF);
        payload[3] = (byte) (increment & 0xFF);
        writeFrame(Http2.TYPE_WINDOW_UPDATE, 0, streamId, payload, 0, 4);
    }

    // ---- SETTINGS application ------------------------------------------

    private void applySettings(Frame f) throws IOException {
        if (f.streamId != 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "SETTINGS on non-zero stream");
        }
        if (f.length % 6 != 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "SETTINGS payload not multiple of 6");
        }
        for (int i = 0; i < f.length; i += 6) {
            int id  = ((f.payload[i]     & 0xFF) << 8)
                    |  (f.payload[i + 1] & 0xFF);
            long v  = ((long)(f.payload[i + 2] & 0xFF) << 24)
                    | ((long)(f.payload[i + 3] & 0xFF) << 16)
                    | ((long)(f.payload[i + 4] & 0xFF) <<  8)
                    |  (long)(f.payload[i + 5] & 0xFF);
            switch (id) {
                case Http2.SETTINGS_HEADER_TABLE_SIZE -> {
                    // Cap our advertised max at whatever we've statically
                    // configured — peer can only shrink, never force us
                    // to grow past DEFAULT_HEADER_TABLE_SIZE.
                    long clamped = Math.min(v, Http2.DEFAULT_HEADER_TABLE_SIZE);
                    peerHeaderTableSize = (int) clamped;
                    // Push through to the encoder so it emits a Dynamic
                    // Table Size Update before the next HEADERS block.
                    // Serialise with the writer path (hpackEncoder is
                    // mutated under streamLock during encode).
                    streamLock.lock();
                    try {
                        hpackEncoder.setMaxTableSize((int) clamped);
                    } finally {
                        streamLock.unlock();
                    }
                }
                case Http2.SETTINGS_ENABLE_PUSH -> {
                    if (v != 0 && v != 1) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_PROTOCOL_ERROR, "ENABLE_PUSH not 0/1");
                    }
                }
                case Http2.SETTINGS_MAX_CONCURRENT_STREAMS ->
                    peerMaxConcurrentStreams = (v > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) v;
                case Http2.SETTINGS_INITIAL_WINDOW_SIZE -> {
                    if (v > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE too large");
                    }
                    int oldInitial = peerInitialWindowSize;
                    peerInitialWindowSize = (int) v;
                    // Adjust every existing stream's send window by the delta
                    // per RFC 9113 §6.9.2. Wake any parked senders.
                    long delta = (long) peerInitialWindowSize - oldInitial;
                    if (delta != 0 && !streams.isEmpty()) {
                        flowLock.lock();
                        try {
                            for (Http2Stream st : streams.values()) {
                                st.sendWindow += delta;
                                if (st.sendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                                    throw new Http2.ConnectionError(
                                        Http2.ERROR_FLOW_CONTROL_ERROR,
                                        "stream window overflow via SETTINGS delta");
                                }
                            }
                            flowChanged.signalAll();
                        } finally {
                            flowLock.unlock();
                        }
                    }
                }
                case Http2.SETTINGS_MAX_FRAME_SIZE -> {
                    if (v < Http2.DEFAULT_MAX_FRAME_SIZE || v > Http2.MAX_ALLOWED_FRAME_SIZE) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_PROTOCOL_ERROR, "MAX_FRAME_SIZE out of range");
                    }
                    peerMaxFrameSize = (int) v;
                }
                default -> {
                    // Unknown SETTINGS MUST be ignored.
                }
            }
        }
    }

    // ---- Frame reader ---------------------------------------------------

    private Frame readFrame() throws IOException {
        int r = 0;
        while (r < readHdrBuf.length) {
            int n = in.read(readHdrBuf, r, readHdrBuf.length - r);
            if (n < 0) {
                return null;
            }
            r += n;
        }
        int length =  ((readHdrBuf[0] & 0xFF) << 16)
                    | ((readHdrBuf[1] & 0xFF) <<  8)
                    |  (readHdrBuf[2] & 0xFF);
        int type     = readHdrBuf[3] & 0xFF;
        int flags    = readHdrBuf[4] & 0xFF;
        int streamId = ((readHdrBuf[5] & 0x7F) << 24)
                     | ((readHdrBuf[6] & 0xFF) << 16)
                     | ((readHdrBuf[7] & 0xFF) <<  8)
                     |  (readHdrBuf[8] & 0xFF);
        if (length > ownMaxFrameSize) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "frame exceeds our MAX_FRAME_SIZE");
        }
        byte[] payload = length == 0 ? EMPTY : new byte[length];
        if (length > 0) {
            readFully(payload, 0, length);
        }
        return new Frame(length, type, flags, streamId, payload);
    }

    private void readFully(byte[] dst, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(dst, off, len);
            if (n < 0) {
                throw new EOFException("truncated HTTP/2 stream");
            }
            off += n;
            len -= n;
        }
    }

    // ---- Frame writer ---------------------------------------------------

    /**
     * Builds a frame (9-byte header + payload slice) and hands it to the
     * writer thread via {@link #enqueue}. Frames that must stay contiguous
     * on the wire (§4.3 HEADERS/CONTINUATION) go through
     * {@link #enqueueAll} instead.
     */
    private void writeFrame(int type, int flags, int streamId,
                            byte[] payload, int off, int len) throws IOException {
        enqueue(frameSeg(type, flags, streamId, payload, off, len));
    }

    private static FrameSeg frameSeg(int type, int flags, int streamId,
                                     byte[] payload, int off, int len) {
        byte[] header = new byte[Http2.FRAME_HEADER_SIZE];
        header[0] = (byte) ((len >>> 16) & 0xFF);
        header[1] = (byte) ((len >>>  8) & 0xFF);
        header[2] = (byte) (len & 0xFF);
        header[3] = (byte) type;
        header[4] = (byte) flags;
        header[5] = (byte) ((streamId >>> 24) & 0x7F);
        header[6] = (byte) ((streamId >>> 16) & 0xFF);
        header[7] = (byte) ((streamId >>>  8) & 0xFF);
        header[8] = (byte) (streamId & 0xFF);
        return new FrameSeg(header, payload, off, len);
    }

    /** The underlying socket, for a forced server shutdown. */
    public Socket socketRef() {
        return socket;
    }

    // Integer.MAX_VALUE until a GOAWAY is sent. Written under goawayLock.
    private volatile int lastGoawayStreamId = Integer.MAX_VALUE;

    private void sendGoaway(int lastStreamId, int errorCode, String debugData) throws IOException {
        goawayLock.lock();
        try {
            sendGoawayLocked(lastStreamId, errorCode, debugData);
        } finally {
            goawayLock.unlock();
        }
    }

    private void sendGoawayLocked(int lastStreamId, int errorCode, String debugData) throws IOException {
        // RFC 9113 §6.8: subsequent GOAWAYs on the same connection MUST
        // carry a last-stream-ID <= the previous one. Clamp to the
        // previous value so a second GOAWAY (e.g. writer thread failure
        // firing after the framer's error path) doesn't advance the ID.
        if (lastStreamId > lastGoawayStreamId) {
            lastStreamId = lastGoawayStreamId;
        }
        lastGoawayStreamId = lastStreamId;
        byte[] debug = debugData == null ? EMPTY
            : debugData.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[8 + debug.length];
        // RFC 9113 §6.8: high bit of stream identifiers is a reserved bit;
        // the sender MUST set it to 0 on transmission.
        payload[0] = (byte) ((lastStreamId >>> 24) & 0x7F);
        payload[1] = (byte) ((lastStreamId >>> 16) & 0xFF);
        payload[2] = (byte) ((lastStreamId >>>  8) & 0xFF);
        payload[3] = (byte) (lastStreamId & 0xFF);
        payload[4] = (byte) ((errorCode >>> 24) & 0xFF);
        payload[5] = (byte) ((errorCode >>> 16) & 0xFF);
        payload[6] = (byte) ((errorCode >>>  8) & 0xFF);
        payload[7] = (byte) (errorCode & 0xFF);
        if (debug.length > 0) {
            System.arraycopy(debug, 0, payload, 8, debug.length);
        }
        writeFrame(Http2.TYPE_GOAWAY, 0, 0, payload, 0, payload.length);
    }

    // ---- Helpers --------------------------------------------------------

    private static final byte[] EMPTY = new byte[0];

    private static final class Frame {
        final int length;
        final int type;
        final int flags;
        final int streamId;
        final byte[] payload;

        Frame(int length, int type, int flags, int streamId, byte[] payload) {
            this.length = length;
            this.type = type;
            this.flags = flags;
            this.streamId = streamId;
            this.payload = payload;
        }
    }
}

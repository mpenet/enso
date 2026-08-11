package com.s_exp.enso.http2;

import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.ChunkedWriter;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.StreamingBody;
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
 *       frame queue in batches and issues one socket write per drain cycle,
 *       coalescing N concurrent responses into fewer TLS records.
 * </ul>
 *
 * <p>{@link #streamLock} (fair {@link java.util.concurrent.locks.ReentrantLock})
 * protects the HPACK encoder's mutable dynamic table and keeps HEADERS +
 * CONTINUATION frames for a single stream contiguous on the wire per RFC 9113
 * §4.3.
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

    // Frame-emission lock. Held across HPACK encode + HEADERS/CONTINUATION
    // enqueue for a single stream so §4.3 atomicity is preserved (nothing
    // else can slip between HEADERS and its trailing CONTINUATIONs on the
    // wire, since the queue is drained in FIFO order and enqueue happens
    // under this lock). Also serialises access to hpackEncoder's mutable
    // dynamic table. Unfair — h2load `-c 8 -m 128` measured ~1-2% median /
    // ~3% p95 throughput above fair mode; the critical section is short
    // enough that starvation risk is bounded by the per-stream vthread
    // scheduler.
    private final ReentrantLock streamLock = new ReentrantLock();

    // Outbound write queue. Workers enqueue framed byte[]s; a dedicated writer
    // vthread drains and writes them to the socket. Coalesces concurrent
    // responses across streams into a single flush cycle, cutting the
    // per-response write() syscall cost. See DESIGN-http2.md, Phase 9.
    private final ArrayDeque<byte[]> writeQueue = new ArrayDeque<>();
    private final ReentrantLock queueLock = new ReentrantLock();
    private final Condition notEmpty = queueLock.newCondition();
    private final Condition notFull = queueLock.newCondition();
    private final Condition idle = queueLock.newCondition();
    private static final int WRITE_QUEUE_MAX = 1024;
    private static final int WRITE_BATCH_MAX = 128;
    private volatile boolean writerRunning = true;
    private Thread writerThread;
    // Tracks whether the writer is currently draining a batch. flush() waits
    // for both an empty queue AND writing=false so callers see bytes actually
    // hit the socket, not just leave the queue.
    private volatile boolean writing = false;

    private static final AtomicLong CONN_ID_SEQ = new AtomicLong();

    // Peer-advertised settings — start at RFC defaults, updated on SETTINGS frame.
    private int peerHeaderTableSize   = Http2.DEFAULT_HEADER_TABLE_SIZE;
    private int peerInitialWindowSize = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    private int peerMaxFrameSize      = Http2.DEFAULT_MAX_FRAME_SIZE;
    private int peerMaxConcurrentStreams = Integer.MAX_VALUE;

    // Own settings — sourced from Config; advertised in initial SETTINGS.
    private final int ownInitialWindowSize;
    private final int ownMaxFrameSize;
    private final int ownMaxConcurrentStreams;
    private final int ownMaxHeaderListSize;

    // Streams.
    private final Map<Integer, Http2Stream> streams = new ConcurrentHashMap<>();
    private volatile int highestPeerStreamId = 0;
    private volatile boolean shuttingDown = false;

    // Flow control (per RFC 9113 §5.2). Both directions carry a separate
    // connection-level window (stream 0); per-stream windows live on
    // Http2Stream. Read/write always through {@link #flowLock}; senders park
    // on {@link #flowChanged} until enough credit is available.
    private final ReentrantLock flowLock = new ReentrantLock();
    private final Condition flowChanged = flowLock.newCondition();
    private long connSendWindow = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    private long connRecvWindow;               // set at handshake to our advertised value
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
    private int pendingContinuationCount = 0;
    private final java.io.ByteArrayOutputStream pendingHeaderBytes =
        new java.io.ByteArrayOutputStream(4096);
    // CVE-2023-44487 mitigation counter. Total RST_STREAM frames received
    // on this connection; kill the connection with ENHANCE_YOUR_CALM once
    // it crosses config.http2StreamResetLimit (0 disables).
    private int totalRstStreamsReceived = 0;

    // Scratch buffer for the framer thread's frame header reads. Writers
    // don't share it: writeFrame allocates a per-frame byte[] that carries
    // the header inline before being enqueued.
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
        this.localPort = ((java.net.InetSocketAddress) socket.getLocalSocketAddress()).getPort();
        this.remoteAddress = socket.getInetAddress();
    }

    @Override
    public void run() {
        try (Socket s = socket) {
            in = s.getInputStream();
            // Writer thread memcpys each drain batch into a single scratch
            // byte[] and issues one out.write per cycle, so there's no need
            // to wrap the socket output in a BufferedOutputStream — that
            // would add an extra copy for no coalescing benefit.
            out = s.getOutputStream();
            connRecvWindow = ownInitialWindowSize;

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

            while (server.isRunning() && !shuttingDown) {
                Frame f = readFrame();
                if (f == null) {
                    return;
                }
                dispatch(f);
            }
        } catch (Http2.ConnectionError ce) {
            try {
                // Enqueues the GOAWAY; shutdownWriter() below drains the
                // queue before close, and TlsSocket.close then emits
                // close_notify + shutdownOutput so the peer sees an orderly
                // teardown.
                sendGoaway(highestPeerStreamId, ce.code, ce.getMessage());
            } catch (IOException ignored) {
            }
        } catch (IOException e) {
            // client went away
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "unexpected HTTP/2 driver failure", t);
        } finally {
            // Drain any queued frames (typically the GOAWAY we just enqueued)
            // before tearing the writer down, then wait briefly for it to
            // exit so we don't close the socket out from under an in-progress
            // socket write.
            shutdownWriter();
            // Wake any workers still blocked on body reads or flow-control
            // credit so they can bail out cleanly.
            for (Http2Stream st : streams.values()) {
                st.state = Http2Stream.State.CLOSED;
                st.signalEndOfBody();
            }
            flowLock.lock();
            try {
                flowChanged.signalAll();
            } finally {
                flowLock.unlock();
            }
            // #4: drop the map so retained stream state can be GC'd.
            streams.clear();
            // #1: release any pending CONTINUATION accumulator.
            clearPendingHeaderState();
        }
    }

    // ---- Writer thread + queue ------------------------------------------

    /**
     * Writer vthread loop. Drains up to {@link #WRITE_BATCH_MAX} frames per
     * cycle into a pre-sized array under {@link #queueLock}, then writes them
     * to the socket outside the lock. Signals {@link #idle} when the queue
     * drains to empty so {@link #flushSync} can observe completion.
     *
     * <p>Multiple concurrent stream workers can enqueue while the writer is
     * inside {@code out.write} — those frames coalesce into the next drain
     * cycle, giving one syscall for N responses when the writer is the
     * bottleneck.
     */
    // Cap the retained per-connection scratch buffer. Above this, an
    // over-sized batch gets a one-shot buffer that isn't kept around, so an
    // adversarial peer flooding oversized DATA frames can't inflate our
    // steady-state heap footprint per connection.
    private static final int WRITER_SCRATCH_MAX = 1 << 20; // 1 MiB

    private void writerLoop() {
        byte[][] batch = new byte[WRITE_BATCH_MAX][];
        byte[] scratch = new byte[16 * 1024];
        while (true) {
            int n = drainBatch(batch);
            if (n == 0) return;
            try {
                int total = 0;
                for (int i = 0; i < n; i++) total += batch[i].length;
                byte[] dst;
                if (total <= scratch.length) {
                    dst = scratch;
                } else if (total <= WRITER_SCRATCH_MAX) {
                    // Grow the retained scratch buffer (doubling, up to the
                    // cap) so bursty large batches don't reallocate every time.
                    scratch = new byte[Math.min(
                        WRITER_SCRATCH_MAX,
                        Math.max(total, scratch.length * 2))];
                    dst = scratch;
                } else {
                    // One-shot buffer: batch is bigger than we're willing to
                    // hold. GC reclaims it after this iteration; scratch
                    // stays at its previous (bounded) size.
                    dst = new byte[total];
                }
                int p = 0;
                for (int i = 0; i < n; i++) {
                    byte[] b = batch[i];
                    System.arraycopy(b, 0, dst, p, b.length);
                    p += b.length;
                    batch[i] = null;
                }
                out.write(dst, 0, total);
                out.flush();
            } catch (IOException e) {
                // Peer/socket went away. Stop; framer will notice on its
                // next read and unwind the connection.
                writerRunning = false;
                drainAndSignalClose();
                return;
            }
            queueLock.lock();
            try {
                writing = false;
                if (writeQueue.isEmpty()) idle.signalAll();
            } finally {
                queueLock.unlock();
            }
        }
    }

    private int drainBatch(byte[][] batch) {
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
            writing = true;
            int n = Math.min(writeQueue.size(), batch.length);
            for (int i = 0; i < n; i++) batch[i] = writeQueue.pollFirst();
            notFull.signalAll();
            return n;
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Appends {@code data} to the write queue. Blocks on {@link #notFull} when
     * the queue is at hi-water so a slow socket applies back-pressure to
     * workers instead of ballooning memory.
     */
    private void enqueue(byte[] data) throws IOException {
        queueLock.lock();
        try {
            while (writeQueue.size() >= WRITE_QUEUE_MAX) {
                if (!writerRunning) throw new IOException("write queue closed");
                try {
                    notFull.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted waiting on write queue");
                }
            }
            writeQueue.addLast(data);
            notEmpty.signal();
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Wait for the writer thread to drain everything currently queued and
     * finish its in-progress socket write. Used at connection shutdown to
     * make sure a final GOAWAY reaches the peer before we close the socket.
     */
    private void flushSync() {
        queueLock.lock();
        try {
            while (writerRunning && (!writeQueue.isEmpty() || writing)) {
                try {
                    idle.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {
            queueLock.unlock();
        }
    }

    /**
     * Called by the framer on connection teardown. Drains what's queued (best
     * effort — errors are already fatal at this point), signals the writer to
     * exit, and joins it so we don't close the socket while it's mid-write.
     */
    private void shutdownWriter() {
        if (writerThread == null) return;
        flushSync();
        queueLock.lock();
        try {
            writerRunning = false;
            notEmpty.signalAll();
            notFull.signalAll();
            idle.signalAll();
        } finally {
            queueLock.unlock();
        }
        try {
            writerThread.join(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Writer-side helper: on IO failure, clear the queue and unpark any
     *  worker still stuck waiting on {@link #notFull}. */
    private void drainAndSignalClose() {
        queueLock.lock();
        try {
            writeQueue.clear();
            writing = false;
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
        p = putSetting(payload, p, Http2.SETTINGS_MAX_HEADER_LIST_SIZE, ownMaxHeaderListSize);
        writeFrameFlush(Http2.TYPE_SETTINGS, 0, 0, payload, 0, payload.length);
    }

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
        writeFrameFlush(Http2.TYPE_SETTINGS, Http2.FLAG_ACK, 0, null, 0, 0);
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
                    writeFrameFlush(Http2.TYPE_PING, Http2.FLAG_ACK, 0, f.payload, 0, 8);
                }
            }
            case Http2.TYPE_GOAWAY -> throw new EOFException("peer sent GOAWAY");
            case Http2.TYPE_WINDOW_UPDATE -> handleWindowUpdate(f);
            case Http2.TYPE_PRIORITY -> {
                if (f.streamId == 0) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_PROTOCOL_ERROR, "PRIORITY on stream 0");
                }
                if (f.length != 5) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_FRAME_SIZE_ERROR, "PRIORITY length must be 5");
                }
                int depStream = ((f.payload[0] & 0x7F) << 24)
                              | ((f.payload[1] & 0xFF) << 16)
                              | ((f.payload[2] & 0xFF) <<  8)
                              |  (f.payload[3] & 0xFF);
                if (depStream == f.streamId) {
                    // Self-dependency is a stream error (§5.3.1).
                    resetStreamQuiet(f.streamId, Http2.ERROR_PROTOCOL_ERROR);
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
        int cap = server.config().http2StreamResetLimit;
        if (cap > 0 && ++totalRstStreamsReceived > cap) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM,
                "RST_STREAM count exceeded limit " + cap);
        }
        Http2Stream st = streams.remove(f.streamId);
        if (st != null) {
            st.state = Http2Stream.State.CLOSED;
            st.signalEndOfBody(); // wake worker if blocked reading
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
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "stream ID not strictly increasing");
            }
            highestPeerStreamId = f.streamId;
        } else {
            // RFC 9113 §8.1: a second HEADERS on an existing stream is a
            // trailers block. Must set END_STREAM, must not appear on a
            // stream that's already half-closed by the peer.
            if ((f.flags & Http2.FLAG_END_STREAM) == 0) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "trailer HEADERS without END_STREAM");
            }
            if (existing.state != Http2Stream.State.OPEN) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR,
                    "HEADERS on stream in state " + existing.state);
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
        if ((f.flags & Http2.FLAG_PRIORITY) != 0) {
            if (len < 5) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS priority prefix too large");
            }
            // Reject self-dependency (§5.3.1).
            int depStream = ((payload[off]     & 0x7F) << 24)
                          | ((payload[off + 1] & 0xFF) << 16)
                          | ((payload[off + 2] & 0xFF) <<  8)
                          |  (payload[off + 3] & 0xFF);
            if (depStream == f.streamId) {
                resetStreamQuiet(f.streamId, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            off += 5;
            len -= 5;
        }

        // Enforce our advertised SETTINGS_MAX_CONCURRENT_STREAMS.
        if (streams.size() >= ownMaxConcurrentStreams) {
            resetStreamQuiet(f.streamId, Http2.ERROR_REFUSED_STREAM);
            return;
        }

        boolean endStream = (f.flags & Http2.FLAG_END_STREAM) != 0;
        boolean endHeaders = (f.flags & Http2.FLAG_END_HEADERS) != 0;

        if (endHeaders) {
            if (trailers) {
                finalizeTrailerBlock(existing, payload, off, len);
            } else {
                finalizeHeaderBlock(f.streamId, endStream, payload, off, len);
            }
        } else {
            // Start accumulating; the next frame MUST be CONTINUATION on this
            // same stream (§6.10). The dispatch guard enforces the ordering.
            enforceHeaderListBudget(len);
            pendingStreamId = f.streamId;
            pendingEndStream = endStream;
            pendingTrailers = trailers;
            pendingHeaderBytes.reset();
            pendingHeaderBytes.write(payload, off, len);
        }
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
        enforceHeaderListBudget(pendingHeaderBytes.size() + f.length);
        pendingHeaderBytes.write(f.payload, 0, f.length);
        if ((f.flags & Http2.FLAG_END_HEADERS) != 0) {
            byte[] block = pendingHeaderBytes.toByteArray();
            int streamId = pendingStreamId;
            boolean endStream = pendingEndStream;
            boolean trailers = pendingTrailers;
            clearPendingHeaderState();
            if (trailers) {
                Http2Stream st = streams.get(streamId);
                if (st == null) {
                    // Stream vanished mid-CONTINUATION (RST). Drop the
                    // trailers but still decode to keep HPACK in sync.
                    try { hpackDecoder.decode(block, 0, block.length); }
                    catch (IOException e) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_COMPRESSION_ERROR, "HPACK decode failed: " + e.getMessage());
                    }
                    return;
                }
                finalizeTrailerBlock(st, block, 0, block.length);
            } else {
                finalizeHeaderBlock(streamId, endStream, block, 0, block.length);
            }
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
        pendingContinuationCount = 0;
        pendingHeaderBytes.reset();
    }

    /**
     * Trailer HEADERS on an already-open stream (RFC 9113 §8.1). Decode
     * to keep HPACK in sync, validate no pseudo-headers appear, then
     * signal end-of-body to the handler's request InputStream. Ring 1.5
     * has no trailer surface so the fields are dropped.
     */
    private void finalizeTrailerBlock(Http2Stream stream, byte[] block,
                                      int off, int len) throws IOException {
        List<Hpack.HeaderField> fields;
        try {
            fields = hpackDecoder.decode(block, off, len);
        } catch (IOException e) {
            throw new Http2.ConnectionError(
                Http2.ERROR_COMPRESSION_ERROR, "HPACK decode failed: " + e.getMessage());
        }
        for (Hpack.HeaderField hf : fields) {
            if (!hf.name.isEmpty() && hf.name.charAt(0) == ':') {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "pseudo-header in trailers");
            }
        }
        stream.state = Http2Stream.State.HALF_CLOSED_REMOTE;
        stream.signalEndOfBody();
    }

    private void finalizeHeaderBlock(int streamId, boolean endStream,
                                     byte[] block, int off, int len) throws IOException {
        List<Hpack.HeaderField> fields;
        try {
            fields = hpackDecoder.decode(block, off, len);
        } catch (IOException e) {
            throw new Http2.ConnectionError(
                Http2.ERROR_COMPRESSION_ERROR, "HPACK decode failed: " + e.getMessage());
        }
        // RFC 9113 §6.5.2: SETTINGS_MAX_HEADER_LIST_SIZE bounds the
        // *decoded* size (32 + name + value bytes per field). The
        // earlier enforceHeaderListBudget check on encoded bytes gates
        // memory pressure during accumulation, but a Huffman-compressed
        // peer could bypass the advertised cap by ~40%. Post-decode
        // check enforces the spec-defined limit.
        if (ownMaxHeaderListSize > 0) {
            long decodedSize = 0;
            for (int i = 0, n = fields.size(); i < n; i++) {
                Hpack.HeaderField hf = fields.get(i);
                decodedSize += 32L
                    + (hf.name == null ? 0 : hf.name.length())
                    + (hf.value == null ? 0 : hf.value.length());
            }
            if (decodedSize > ownMaxHeaderListSize) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_ENHANCE_YOUR_CALM,
                    "decoded header list " + decodedSize + " exceeds SETTINGS_MAX_HEADER_LIST_SIZE " + ownMaxHeaderListSize);
            }
        }

        Http2Stream stream = new Http2Stream(
            streamId, peerInitialWindowSize, ownInitialWindowSize);
        stream.state = endStream ? Http2Stream.State.HALF_CLOSED_REMOTE
                                 : Http2Stream.State.OPEN;
        if (endStream) {
            stream.signalEndOfBody();
        }
        streams.put(streamId, stream);

        Request request = buildRequest(fields, stream);
        if (request == null) {
            resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
            return;
        }

        // Track declared Content-Length so we can enforce §8.1.2.6 (declared
        // length must match total DATA payload).
        String cl = request.header("content-length");
        if (cl != null) {
            try {
                long declared = Long.parseLong(cl);
                if (declared < 0) {
                    resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                    return;
                }
                stream.declaredContentLength = declared;
                if (endStream && declared != 0) {
                    // No body but Content-Length says otherwise → mismatch.
                    resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                    return;
                }
            } catch (NumberFormatException e) {
                resetStream(streamId, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
        }

        Thread.ofVirtual()
            .name("enso-h2-stream-" + streamId)
            .start(() -> runHandler(stream, request));
    }

    private void handleData(Frame f) throws IOException {
        if (f.streamId == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "DATA on stream 0");
        }
        Http2Stream stream = streams.get(f.streamId);
        if (stream == null) {
            // If we've seen this stream ID, it's closed; otherwise idle.
            // Per §5.1 both cases yield a connection-level error, but the code
            // differs: STREAM_CLOSED for closed, PROTOCOL_ERROR for idle.
            int code = (f.streamId <= highestPeerStreamId)
                ? Http2.ERROR_STREAM_CLOSED
                : Http2.ERROR_PROTOCOL_ERROR;
            throw new Http2.ConnectionError(code, "DATA on inactive stream " + f.streamId);
        }
        if (stream.state == Http2Stream.State.HALF_CLOSED_REMOTE
            || stream.state == Http2Stream.State.CLOSED) {
            // Peer has already sent END_STREAM; further DATA is a stream error
            // per §5.1. Reset and close.
            resetStreamQuiet(f.streamId, Http2.ERROR_STREAM_CLOSED);
            return;
        }

        // Decrement receive windows against the *full* frame length including
        // padding — flow control accounting is per RFC 9113 §6.9.1.
        // Threading: handleData only runs on the framer vthread (single
        // reader/writer of recvWindow + connRecvWindow), so the check
        // outside flowLock cannot race a concurrent mutation. flowLock
        // is only needed to serialise with the credit-return path further
        // down (which touches connRecvUncredited).
        int frameLen = f.length;
        stream.recvWindow -= frameLen;
        flowLock.lock();
        try {
            connRecvWindow -= frameLen;
            connRecvUncredited += frameLen;
        } finally {
            flowLock.unlock();
        }
        if (stream.recvWindow < 0 || connRecvWindow < 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FLOW_CONTROL_ERROR, "peer overran receive window");
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
        if (len > 0) {
            stream.receivedBodyBytes += len;
            if (stream.declaredContentLength >= 0
                && stream.receivedBodyBytes > stream.declaredContentLength) {
                // More body than declared — §8.1.2.6 stream error.
                resetStreamQuiet(f.streamId, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            byte[] chunk = new byte[len];
            System.arraycopy(payload, off, chunk, 0, len);
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
        // Return receive credit to the peer for the whole padded frame. Batch
        // when we've eaten more than half the initial window to keep sends
        // flowing without WINDOW_UPDATE storms.
        int threshold = ownInitialWindowSize / 2;
        // Per-stream: cheap enough to send inline unless stream is done.
        if (stream.state != Http2Stream.State.CLOSED
            && stream.state != Http2Stream.State.HALF_CLOSED_REMOTE) {
            stream.recvWindow += frameLen;
            sendWindowUpdate(f.streamId, frameLen);
        }
        // Connection-level: batch above threshold.
        flowLock.lock();
        long pending;
        try {
            pending = connRecvUncredited;
            if (pending >= threshold) {
                connRecvUncredited = 0;
                connRecvWindow += pending;
            } else {
                pending = 0;
            }
        } finally {
            flowLock.unlock();
        }
        if (pending > 0) {
            sendWindowUpdate(0, (int) pending);
        }
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
            // Per §8.1.2: header names must be lowercase.
            for (int i = 0; i < name.length(); i++) {
                char c = name.charAt(i);
                if (c >= 'A' && c <= 'Z') {
                    return null;
                }
            }
            if (name.charAt(0) == ':') {
                // Pseudo-header. Must precede all regular headers (§8.1.2.1).
                if (seenRegular) {
                    return null;
                }
                switch (name) {
                    case ":method" -> {
                        if (method != null) return null;
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
                    if (seenContentLength) {
                        return null;
                    }
                    seenContentLength = true;
                }
                // RFC 9113 §8.2.1: field values MUST NOT contain NUL, CR, LF.
                // A downstream reverse proxy that re-emits into HTTP/1 would
                // smuggle if we accepted these.
                String v = hf.value;
                for (int j = 0, n = v.length(); j < n; j++) {
                    char c = v.charAt(j);
                    if (c == 0 || c == '\r' || c == '\n') {
                        return null;
                    }
                }
                regular[rp++] = name;
                regular[rp++] = v;
            }
        }
        if (method == null || path == null || scheme == null) {
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
            // regular is already exactly rp long — pre-counted above.
            headers = (IPersistentMap) PersistentArrayMap.createAsIfByAssoc(regular);
        }

        return new Request(method, uri, query, "HTTP/2.0",
                           headers.assoc("host", authority == null ? "" : authority),
                           stream.bodyInputStream(),
                           remoteAddress, localPort);
    }

    // ---- Response writing ----------------------------------------------

    private void runHandler(Http2Stream stream, Request request) {
        Response response = null;
        try {
            response = handler.handle(request);
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "HTTP/2 handler threw", t);
        }
        try {
            if (response == null) {
                writeResponse(stream, 500, PersistentArrayMap.EMPTY, null);
            } else {
                writeResponse(stream, response.status, response.headers, response.body);
            }
        } catch (IOException e) {
            // socket died mid-write; just drop the stream
            resetStreamQuiet(stream.id, Http2.ERROR_INTERNAL_ERROR);
        } finally {
            stream.state = Http2Stream.State.CLOSED;
            streams.remove(stream.id);
        }
    }

    private void writeResponse(Http2Stream stream, int status,
                               Map<?, ?> respHeaders, Object body) throws IOException {
        // Assemble the header block: :status pseudo-header first, then user headers.
        List<Hpack.HeaderField> fields = new ArrayList<>(
            (respHeaders == null ? 0 : respHeaders.size()) + 1);
        fields.add(new Hpack.HeaderField(":status", Integer.toString(status)));
        boolean hasAltSvc = false;
        boolean hasServer = false;
        if (respHeaders != null) {
            for (Map.Entry<?, ?> e : respHeaders.entrySet()) {
                String name = String.valueOf(e.getKey()).toLowerCase(java.util.Locale.ROOT);
                if (name.equals("connection") || name.equals("transfer-encoding")
                    || name.equals("keep-alive") || name.equals("upgrade")
                    || name.equals("proxy-connection")) {
                    // Forbidden in HTTP/2 responses per §8.1.2.2.
                    continue;
                }
                if (name.equals("alt-svc")) hasAltSvc = true;
                else if (name.equals("server")) hasServer = true;
                Object v = e.getValue();
                fields.add(new Hpack.HeaderField(name, v == null ? "" : v.toString()));
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

        // HPACK encoder state (dynamic table) mutates as encode() runs. The
        // emitted header block must reach the peer in the same order the table
        // updates happened, otherwise the peer's decoder ends up out of sync.
        // §4.3 also forbids interleaving HEADERS/CONTINUATION for the same
        // stream with any other frame — solved because writeFrame enqueues in
        // FIFO order and streamLock keeps consecutive calls contiguous.
        streamLock.lock();
        try {
            byte[] headerBlock = hpackEncoder.encode(fields);
            int max = peerMaxFrameSize;
            if (headerBlock.length <= max) {
                int flags = Http2.FLAG_END_HEADERS | (hasBody ? 0 : Http2.FLAG_END_STREAM);
                writeFrame(Http2.TYPE_HEADERS, flags, stream.id,
                           headerBlock, 0, headerBlock.length);
            } else {
                int firstFlags = hasBody ? 0 : Http2.FLAG_END_STREAM;
                writeFrame(Http2.TYPE_HEADERS, firstFlags, stream.id,
                           headerBlock, 0, max);
                int p = max;
                while (p < headerBlock.length) {
                    int n = Math.min(max, headerBlock.length - p);
                    int contFlags = (p + n == headerBlock.length) ? Http2.FLAG_END_HEADERS : 0;
                    writeFrame(Http2.TYPE_CONTINUATION, contFlags, stream.id,
                               headerBlock, p, n);
                    p += n;
                }
            }
        } finally {
            streamLock.unlock();
        }

        if (!hasBody) return;
        writeBody(stream, body);
    }

    /**
     * Dispatches by body type and emits DATA frames. Buffered types (String,
     * byte[]) are chunked by {@code peerMaxFrameSize}; live-source types
     * (InputStream, File, StreamingBody) stream incrementally — each read/
     * flush produces its own DATA frame. Flow control is honoured per frame
     * via {@link #acquireSendCredit}. Always closes the stream with an
     * END_STREAM-flagged frame on the last chunk.
     */
    private void writeBody(Http2Stream stream, Object body) throws IOException {
        if (body instanceof byte[] bytes) {
            emitData(stream, bytes, 0, bytes.length, true);
        } else if (body instanceof String s) {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            emitData(stream, bytes, 0, bytes.length, true);
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
            ChunkedWriter writer = new ChunkedWriter(out, peerMaxFrameSize, false);
            try {
                sb.write(writer);
            } finally {
                writer.closeInternal();
            }
            // Close the stream: the writer may have flushed the last data but
            // no END_STREAM was ever sent, so send an empty DATA(END_STREAM).
            emitEndStream(stream);
        } else {
            byte[] fallback = body.toString().getBytes(StandardCharsets.UTF_8);
            emitData(stream, fallback, 0, fallback.length, true);
        }
    }

    private void streamInputStream(Http2Stream stream, InputStream in) throws IOException {
        byte[] scratch = new byte[peerMaxFrameSize];
        while (true) {
            int r = in.read(scratch);
            if (r < 0) {
                emitEndStream(stream);
                return;
            }
            if (r == 0) {
                continue;
            }
            emitData(stream, scratch, 0, r, false);
        }
    }

    private void emitData(Http2Stream stream, byte[] buf, int off, int len,
                          boolean endStream) throws IOException {
        if (len == 0 && endStream) {
            emitEndStream(stream);
            return;
        }
        int p = off;
        int endOff = off + len;
        while (p < endOff) {
            int remaining = endOff - p;
            int want = Math.min(remaining, peerMaxFrameSize);
            int granted = acquireSendCredit(stream, want);
            if (granted <= 0) {
                return;
            }
            boolean last = (p + granted == endOff);
            int flags = (last && endStream) ? Http2.FLAG_END_STREAM : 0;
            writeFrame(Http2.TYPE_DATA, flags, stream.id, buf, p, granted);
            p += granted;
        }
    }

    private void emitEndStream(Http2Stream stream) throws IOException {
        // Empty DATA frame with END_STREAM closes the stream. No flow-control
        // credit required for zero-length payloads (§6.9.1).
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
            conn.emitData(stream, one, 0, 1, false);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len > 0) {
                conn.emitData(stream, b, off, len, false);
            }
        }

        @Override
        public void flush() throws IOException {
            // User's flush! must push bytes to the wire — SSE etc. rely on it.
            // With the writer-thread queue, flushSync waits for the writer to
            // drain everything currently queued and complete its in-progress
            // socket write.
            conn.flushSync();
        }
    }

    /**
     * Blocks until both the stream and the connection have flow-control
     * capacity to send at least one byte, up to {@code want}. Returns the
     * granted byte count. Returns 0 if the stream is reset while we wait.
     */
    private int acquireSendCredit(Http2Stream stream, int want) throws IOException {
        flowLock.lock();
        try {
            while (true) {
                if (stream.state == Http2Stream.State.CLOSED) {
                    return 0;
                }
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
                // flush is needed here — unlike the pre-writer-thread model.
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

    private void resetStream(int streamId, int code) throws IOException {
        byte[] payload = new byte[4];
        payload[0] = (byte) ((code >>> 24) & 0xFF);
        payload[1] = (byte) ((code >>> 16) & 0xFF);
        payload[2] = (byte) ((code >>>  8) & 0xFF);
        payload[3] = (byte) (code & 0xFF);
        writeFrameFlush(Http2.TYPE_RST_STREAM, 0, streamId, payload, 0, 4);
        Http2Stream st = streams.remove(streamId);
        if (st != null) {
            st.state = Http2Stream.State.CLOSED;
            st.signalEndOfBody();
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
        writeFrameFlush(Http2.TYPE_WINDOW_UPDATE, 0, streamId, payload, 0, 4);
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
     * Builds a self-contained frame byte[] (9-byte header + payload) and hands
     * it to the writer thread via {@link #enqueue}. Any per-stream atomicity
     * requirement (§4.3 HEADERS/CONTINUATION) is enforced by the caller
     * holding {@link #streamLock} across consecutive {@code writeFrame} calls,
     * which — because {@code enqueue} appends under {@link #queueLock} in
     * FIFO order — keeps the frames contiguous in the writer's drain batch
     * and on the wire.
     */
    private void writeFrame(int type, int flags, int streamId,
                            byte[] payload, int off, int len) throws IOException {
        byte[] frame = new byte[Http2.FRAME_HEADER_SIZE + len];
        frame[0] = (byte) ((len >>> 16) & 0xFF);
        frame[1] = (byte) ((len >>>  8) & 0xFF);
        frame[2] = (byte) (len & 0xFF);
        frame[3] = (byte) type;
        frame[4] = (byte) flags;
        frame[5] = (byte) ((streamId >>> 24) & 0x7F);
        frame[6] = (byte) ((streamId >>> 16) & 0xFF);
        frame[7] = (byte) ((streamId >>>  8) & 0xFF);
        frame[8] = (byte) (streamId & 0xFF);
        if (len > 0) {
            System.arraycopy(payload, off, frame, Http2.FRAME_HEADER_SIZE, len);
        }
        enqueue(frame);
    }

    /**
     * Compatibility shim for existing call sites. In the writer-thread model
     * the writer flushes on every drain cycle, so there is no per-caller
     * flush — {@link #writeFrame} already hands the byte[] off. Kept as a
     * documentation anchor for spots that historically demanded an immediate
     * push to the wire (control frames); those still just enqueue and rely
     * on the writer draining promptly.
     */
    private void writeFrameFlush(int type, int flags, int streamId,
                                 byte[] payload, int off, int len) throws IOException {
        writeFrame(type, flags, streamId, payload, off, len);
    }

    private int lastGoawayStreamId = Integer.MAX_VALUE;

    private void sendGoaway(int lastStreamId, int errorCode, String debugData) throws IOException {
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
        writeFrameFlush(Http2.TYPE_GOAWAY, 0, 0, payload, 0, payload.length);
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

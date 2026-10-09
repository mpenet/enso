// ABOUTME: HTTP/2 connection driver: the framer (frame reads, HPACK decode, stream admission),
// ABOUTME: the connection and closed-stream state machines, deadlines and graceful shutdown.
package com.s_exp.enso.http2;

import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.core.Drainable;
import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.core.WriteWatchdog;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP/2 connection driver.
 *
 * <p>Threads: the <b>framer</b> (the connection's virtual thread, running
 * {@link #run}) reads frames, decodes header blocks and admits streams;
 * one virtual thread per stream runs the Ring handler ({@link Http2Stream}
 * is its Runnable) and produces the response. There is no writer thread:
 * see {@link Http2Writer} for how output reaches the socket. The framer
 * never blocks on output. It reads ahead into one input buffer and parses
 * frames in place, so one socket read serves every frame that arrived;
 * after a quiet second it gives back what the connection grew (buffers,
 * TLS records, closed streams) and waits for the next frame with ~64 bytes.
 *
 * <p>Connection state machine ({@link #state}, CAS):
 * <pre>
 *  HANDSHAKE ──first SETTINGS──► OPEN ──GOAWAY sent / received──► DRAINING
 *      │                           │                                  │ last handler done
 *      └──────── error / EOF ──────┴──────────────────────────────────┴──► CLOSING ──► CLOSED
 * </pre>
 * A graceful close is two-phase (RFC 9113 §6.8): GOAWAY(2^31-1) and a
 * PING, then, once the PING is answered (or after a second), GOAWAY with
 * the last stream actually served. CLOSING flushes what can still be sent
 * (a final GOAWAY), shuts the output down (TLS close_notify, FIN) and
 * reads and discards for a bounded time before closing, so the peer
 * isn't sent a TCP reset that would lose the GOAWAY.
 *
 * <p>Streams live in a framer-confined {@link Http2StreamTable}; a stream
 * closed by another thread is pushed on a lock-free retired stack that the
 * framer drains before every frame. The last streams to close (twice the
 * concurrency limit, between 64 and 8192) are remembered with why they
 * closed ({@link ClosedStreams}, constant-time lookup), which decides how
 * late frames are answered (§5.1): after the peer's END_STREAM,
 * a connection error STREAM_CLOSED; after the peer's RST_STREAM, a stream
 * error STREAM_CLOSED; after our RST_STREAM, ignored.
 *
 * <p>Every deadline of the connection (handshake, idle, CONTINUATION
 * header timeout, flow-control stalls, graceful-close PING, lingering
 * close) is one {@link Timer} node.
 */
public final class Http2Connection implements Runnable, Drainable {

    private static final Logger LOG = Logger.getLogger(Http2Connection.class.getName());
    private static final LogLimiter FAILURES = new LogLimiter(LOG, Level.WARNING);

    private static final int HANDSHAKE = 0;
    private static final int OPEN = 1;
    private static final int DRAINING = 2;
    private static final int CLOSING = 3;
    private static final int CLOSED = 4;

    // Consecutive empty DATA frames (without END_STREAM) tolerated per
    // stream; same default as Netty's empty-frame guard.
    private static final int EMPTY_DATA_FRAME_LIMIT = 10;
    // CVE-2023-44487 mitigation: token bucket of RST_STREAM frames (the
    // peer's, and ours caused by its frames). Holds up to
    // config.http2StreamResetLimit tokens and refills at that many per
    // RESET_REFILL_NANOS, so a burst over the limit kills the connection
    // with ENHANCE_YOUR_CALM while routine cancels on a long-lived
    // connection never do (0 disables).
    private static final long RESET_REFILL_NANOS = 30_000_000_000L;
    // Connection receive window, in stream windows: how many streams can
    // hold unread body data before the others stall.
    private static final int CONN_WINDOW_STREAM_MULTIPLE = 4;
    // Floor of the decoded header section ceiling (4x :max-header-bytes):
    // above it a block is a connection error rather than a 431.
    private static final long HEADER_LIST_CEILING_MIN = 64 * 1024;
    private static final long DRAIN_PING_NANOS = 1_000_000_000L;
    private static final long LINGER_NANOS = 2_000_000_000L;
    private static final long LINGER_MAX_BYTES = 1 << 20;
    private static final byte[] DRAIN_PING = {'e', 'n', 's', 'o', 'd', 'r', 'a', 'i'};
    // Input buffer: allocated at this size, grown to hold a whole frame of
    // up to the default maximum size (larger ones are read past it).
    private static final int INPUT_INITIAL = 2048;
    private static final int INPUT_MAX = Http2.DEFAULT_MAX_FRAME_SIZE + Http2.FRAME_HEADER_SIZE;
    // Input buffer of an idle connection: room for the next read to land;
    // the frame it starts grows the buffer back.
    private static final int INPUT_IDLE = 64;
    // Quiet this long (no frame), the connection gives back what it grew
    // and waits for the next frame with only what that needs.
    private static final int IDLE_RELEASE_MILLIS = 1000;

    private static final VarHandle STATE;
    private static final VarHandle LIVE_STREAMS;
    private static final VarHandle RETIRED;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            STATE = l.findVarHandle(Http2Connection.class, "state", int.class);
            LIVE_STREAMS = l.findVarHandle(Http2Connection.class, "liveStreams", int.class);
            RETIRED = l.findVarHandle(Http2Connection.class, "retired", Http2Stream.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final Socket socket;
    // Set for TLS connections.
    private final TlsSocket tls;
    // The client preface was already read (h2c: the listener detected it).
    private final boolean prefaceRead;
    // "h2" over TLS, "h2c" in cleartext: events, JFR and protocol errors.
    final String protocol;
    private final EnsoServer server;
    private final Service service;
    private final Config config;
    private final Timer timer;
    private final Http2Exchange exchange;
    // Spreads this connection's streams over the shared ResponseHead pool.
    final int poolSeed = System.identityHashCode(this);
    private InputStream in;
    private Http2Writer writer;

    @SuppressWarnings("unused") // accessed through STATE
    private volatile int state = HANDSHAKE;
    // Streams not yet closed (counted against our MAX_CONCURRENT_STREAMS).
    @SuppressWarnings("unused") // accessed through LIVE_STREAMS
    private volatile int liveStreams;
    // Lock-free stack of streams closed off the framer, for it to forget.
    @SuppressWarnings("unused") // accessed through RETIRED
    private volatile Http2Stream retired;
    // Handler threads still running (a reset stream closes while its
    // handler may keep going).
    private final AtomicInteger activeHandlers = new AtomicInteger();
    // The framer parked at exit until the handlers are done, or null.
    private volatile Thread awaitingHandlers;
    // Grants held-back connection credit once the memory budget has room;
    // allocated on first need.
    private volatile MemoryBudget.Waiter creditWaiter;

    // Own settings, advertised in the initial SETTINGS.
    private final int ownInitialWindowSize;
    private final int ownMaxFrameSize;
    private final int ownMaxConcurrentStreams;
    private final long headerListSoftLimit;
    private final long headerListHardLimit;
    private final int recvCreditThreshold;

    // ---- Framer-confined ----
    private int peerInitialWindowSize = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    private final Http2StreamTable streams = new Http2StreamTable();
    private int highestPeerStreamId;
    private final Hpack.Decoder hpackDecoder = new Hpack.Decoder(Hpack.DEFAULT_MAX_TABLE_SIZE);
    private double resetTokens;
    private long resetTokensAt = System.nanoTime();
    // Recently closed streams and why they closed.
    private final ClosedStreams closed;
    // Consecutive empty non-final DATA frames on closed streams.
    private int closedEmptyDataFrames;
    // Header block spread over CONTINUATION frames (§6.10): while
    // pendingStreamId != 0 only CONTINUATION on that stream may arrive.
    private int pendingStreamId;
    private boolean pendingFresh;
    private boolean pendingEndStream;
    private boolean pendingSelfDependent;
    private int pendingContinuationCount;
    private byte[] pendingHeaderBytes;
    private int pendingHeaderLen;
    // Bytes read ahead: frames are parsed from inBuf[inPos, inLim), so a
    // read of the socket (a syscall, or a TLS record's plaintext under its
    // lock) yields as many frames as arrived.
    private byte[] inBuf = new byte[INPUT_INITIAL];
    private int inPos;
    private int inLim;
    // A frame larger than INPUT_MAX is read here; null until one arrives.
    private byte[] large;
    // The frame being handled; its payload is payload[payloadOff, payloadOff + frameLength).
    private byte[] payload;
    private int payloadOff;
    // Buffers were given back after a quiet second; restored by the next read.
    private boolean idleReleased;
    private int frameLength;
    private int frameType;
    private int frameFlags;
    private int frameStreamId;

    // Receive flow control, connection level: the framer charges DATA,
    // readers credit it back.
    private final AtomicLong connRecvWindow = new AtomicLong(Http2.DEFAULT_INITIAL_WINDOW_SIZE);
    private final AtomicLong connRecvUncredited = new AtomicLong();

    // Serialises GOAWAY emission with admitting new streams, so no handler
    // starts on a stream above the last-stream-id we announced.
    private final ReentrantLock goawayLock = new ReentrantLock();
    // Highest stream id admitted for handling; GOAWAY's last-stream-id
    // covers streams "possibly acted on" (§6.8).
    private volatile int lastProcessedStreamId;
    // Integer.MAX_VALUE until the final GOAWAY. Written under goawayLock.
    private volatile int lastGoawayStreamId = Integer.MAX_VALUE;
    // 0: no graceful close; 1: GOAWAY(2^31-1) + PING sent; 2: final GOAWAY sent.
    private int drainPhase;
    private volatile boolean peerGoaway;
    private volatile long idleSinceNanos = System.nanoTime();

    private final Deadlines deadlines = new Deadlines();
    private final long idleTimeoutNanos;

    /**
     * {@code handshakeDeadlineNanos}: end of the {@code :handshake-timeout}
     * budget started at accept (System.nanoTime), or 0 for none.
     */
    public Http2Connection(Socket socket, RingHandler handler, EnsoServer server,
                           long handshakeDeadlineNanos) {
        this(socket, handler, server, handshakeDeadlineNanos, false);
    }

    /**
     * {@code prefaceRead}: the 24-octet client preface was already consumed
     * from the socket (cleartext prior knowledge, detected by the listener).
     */
    public Http2Connection(Socket socket, RingHandler handler, EnsoServer server,
                           long handshakeDeadlineNanos, boolean prefaceRead) {
        this.socket = socket;
        this.tls = socket instanceof TlsSocket.AdapterSocket a ? a.tls() : null;
        this.prefaceRead = prefaceRead;
        this.protocol = tls != null ? EnsoServer.H2 : EnsoServer.H2C;
        this.server = server;
        this.service = server.service();
        this.config = service.config;
        this.timer = service.timer;
        this.ownInitialWindowSize = config.http2InitialWindowBytes;
        this.ownMaxFrameSize = config.http2MaxFrameBytes;
        this.ownMaxConcurrentStreams = config.http2MaxConcurrentStreams;
        // :max-header-bytes is SETTINGS_MAX_HEADER_LIST_SIZE: 431 over it,
        // the connection ends over 4x (at least 64 KiB).
        this.headerListSoftLimit = config.maxHeaderBytes;
        this.headerListHardLimit = Math.max(4L * config.maxHeaderBytes, HEADER_LIST_CEILING_MIN);
        this.recvCreditThreshold = Math.max(1, ownInitialWindowSize / 2);
        this.resetTokens = config.http2StreamResetLimit;
        this.idleTimeoutNanos = config.idleTimeoutMillis * 1_000_000L;
        int ring = Math.min(8192, Math.max(64, 2 * ownMaxConcurrentStreams));
        this.closed = new ClosedStreams(ring);
        this.deadlines.handshake = handshakeDeadlineNanos;
        // Connection-scoped addresses: same for every request, so looked
        // up once rather than with a syscall per request.
        int localPort = ((java.net.InetSocketAddress) socket.getLocalSocketAddress()).getPort();
        InetAddress remote = socket.getInetAddress();
        this.exchange = new Http2Exchange(this, handler, config, remote, localPort,
                                          tls != null ? Request.K_HTTPS : Request.K_HTTP);
    }

    /** Octets of the client connection preface (RFC 9113 §3.4). */
    public static final int PREFACE_LENGTH = 24;

    /**
     * Whether {@code b[0, n)} (at most {@link #PREFACE_LENGTH} octets) is
     * the start of the client preface: all of it when {@code n} is its length.
     */
    public static boolean isPreface(byte[] b, int n) {
        return java.util.Arrays.equals(b, 0, n, Http2.PREFACE, 0, n);
    }

    Http2Writer writer() {
        return writer;
    }

    Service service() {
        return service;
    }

    private int state() {
        return (int) STATE.getVolatile(this);
    }

    /** Moves to {@code to} unless already there or past it; true when this call moved it. */
    private boolean advance(int to) {
        while (true) {
            int s = state();
            if (s >= to) return false;
            if (STATE.compareAndSet(this, s, to)) return true;
        }
    }

    @Override
    public void run() {
        // Whether the peer may still be sending when we close: then the
        // input is read out before the socket closes (lingering close).
        boolean linger = false;
        try {
            in = socket.getInputStream();
            if (tls != null) {
                // Output goes through writeRecords with pooled buffers: the
                // socket's own record buffer only carries a close_notify.
                tls.releaseOutputBuffer();
            }
            writer = new Http2Writer(this, socket, config, timer, ownMaxConcurrentStreams);
            // :handshake-timeout covers the preface and the first SETTINGS,
            // wall clock however the bytes trickle in.
            rearm();
            sendInitialSettings();
            if (!prefaceRead) {
                readPreface();
            }
            if (!readHeader() || frameType != Http2.TYPE_SETTINGS || (frameFlags & Http2.FLAG_ACK) != 0) {
                throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "expected initial SETTINGS");
            }
            readPayload();
            applySettings();
            writer.settingsAck();
            // Until here reads were also bounded by the accept-time
            // SO_TIMEOUT (the idle timeout), so a silent peer is dropped even
            // with the handshake timeout disabled. From now on streams may
            // legitimately stay quiet (long-poll, SSE): idleness is judged by
            // the deadline node, which knows whether any stream is in progress.
            // A read timing out only means a quiet second (see fill).
            socket.setSoTimeout(IDLE_RELEASE_MILLIS);
            deadlines.handshake = 0;
            idleSinceNanos = System.nanoTime();
            // From here a server stop can GOAWAY it (beginDrain). A stop that
            // began earlier is caught by the isRunning check.
            advance(OPEN);
            rearm();
            if (!server.isRunning()) {
                beginGracefulClose();
            }
            while (state() < CLOSING) {
                if (!readHeader()) {
                    return;
                }
                retireClosed();
                dispatch();
            }
            linger = true;
        } catch (Http2.ConnectionError ce) {
            linger = true;
            connectionError(ce.code, ce.getMessage());
        } catch (IOException e) {
            // client went away
        } catch (Throwable t) {
            FAILURES.log("unexpected HTTP/2 driver failure", t);
        } finally {
            teardown(linger);
        }
    }

    /** GOAWAY once SETTINGS are exchanged (before that, run() checks the server state). */
    @Override
    public void beginDrain() {
        if (state() == OPEN) {
            Thread.startVirtualThread(this::beginGracefulClose);
        }
    }

    @Override
    public void forceClose() {
        EnsoServer.forceClose(socket);
    }

    // ---- Handshake ----------------------------------------------------------------

    private void readPreface() throws IOException {
        int n = Http2.PREFACE.length;
        if (!buffer(n)) {
            throw new EOFException("truncated HTTP/2 stream");
        }
        if (!java.util.Arrays.equals(inBuf, inPos, inPos + n, Http2.PREFACE, 0, n)) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "invalid connection preface");
        }
        inPos += n;
    }

    private void sendInitialSettings() throws IOException {
        byte[] payload = new byte[4 * 6];
        int p = 0;
        p = putSetting(payload, p, Http2.SETTINGS_MAX_CONCURRENT_STREAMS, ownMaxConcurrentStreams);
        p = putSetting(payload, p, Http2.SETTINGS_INITIAL_WINDOW_SIZE, ownInitialWindowSize);
        p = putSetting(payload, p, Http2.SETTINGS_MAX_FRAME_SIZE, ownMaxFrameSize);
        p = putSetting(payload, p, Http2.SETTINGS_MAX_HEADER_LIST_SIZE, (int) headerListSoftLimit);
        // Raise the connection receive window to a multiple of the stream
        // window: credit only comes back as handlers consume their body, so
        // with equal windows a single handler that doesn't read would stall
        // every other upload on the connection. The connection window still
        // bounds the body bytes buffered per connection. RFC 9113 §6.9.2:
        // SETTINGS_INITIAL_WINDOW_SIZE only applies to streams; the
        // connection window starts at 65535 and grows by WINDOW_UPDATE.
        long connTarget = Math.min((long) ownInitialWindowSize * CONN_WINDOW_STREAM_MULTIPLE,
                                   Http2.MAX_ALLOWED_WINDOW_SIZE);
        int connGrowth = (int) (connTarget - Http2.DEFAULT_INITIAL_WINDOW_SIZE);
        if (connGrowth > 0) {
            connRecvWindow.addAndGet(connGrowth);
        }
        writer.initialSettings(payload, p, connGrowth);
    }

    private static int putSetting(byte[] b, int p, int id, int value) {
        b[p] = (byte) (id >>> 8);
        b[p + 1] = (byte) id;
        b[p + 2] = (byte) (value >>> 24);
        b[p + 3] = (byte) (value >>> 16);
        b[p + 4] = (byte) (value >>> 8);
        b[p + 5] = (byte) value;
        return p + 6;
    }

    // ---- Frame reading -------------------------------------------------------------

    /** Reads the next frame header; false at an end of input. */
    private boolean readHeader() throws IOException {
        if (!buffer(Http2.FRAME_HEADER_SIZE)) {
            return false;
        }
        byte[] h = inBuf;
        int p = inPos;
        frameLength = ((h[p] & 0xFF) << 16) | ((h[p + 1] & 0xFF) << 8) | (h[p + 2] & 0xFF);
        frameType = h[p + 3] & 0xFF;
        frameFlags = h[p + 4] & 0xFF;
        frameStreamId = ((h[p + 5] & 0x7F) << 24) | ((h[p + 6] & 0xFF) << 16)
            | ((h[p + 7] & 0xFF) << 8) | (h[p + 8] & 0xFF);
        inPos = p + Http2.FRAME_HEADER_SIZE;
        if (frameLength > ownMaxFrameSize) {
            throw new Http2.ConnectionError(
                Http2.ERROR_FRAME_SIZE_ERROR, "frame exceeds our MAX_FRAME_SIZE");
        }
        return true;
    }

    /** Makes the current frame's payload available at {@link #payload}. */
    private void readPayload() throws IOException {
        int n = frameLength;
        if (n <= INPUT_MAX) {
            if (!buffer(n)) {
                throw new EOFException("truncated HTTP/2 stream");
            }
            payload = inBuf;
            payloadOff = inPos;
            inPos += n;
            return;
        }
        if (large == null || large.length < n) {
            large = new byte[Integer.highestOneBit(n - 1) << 1];
        }
        int have = Math.min(n, inLim - inPos);
        System.arraycopy(inBuf, inPos, large, 0, have);
        inPos += have;
        readFully(large, have, n - have);
        payload = large;
        payloadOff = 0;
    }

    /** Consumes the current frame's payload without keeping it. */
    private void skipPayload() throws IOException {
        int left = frameLength;
        while (left > 0) {
            if (inPos == inLim && !buffer(1)) {
                throw new EOFException("truncated HTTP/2 stream");
            }
            int n = Math.min(left, inLim - inPos);
            inPos += n;
            left -= n;
        }
    }

    /**
     * Until {@code n} (at most {@link #INPUT_MAX}) bytes are buffered at
     * {@link #inPos}, reads what the socket has; false when the input ends
     * first.
     */
    private boolean buffer(int n) throws IOException {
        while (inLim - inPos < n) {
            byte[] b = inBuf;
            if (b.length < n) {
                int size = Math.max(b.length, INPUT_INITIAL);
                while (size < n) size <<= 1;
                byte[] bigger = new byte[Math.min(size, INPUT_MAX)];
                System.arraycopy(b, inPos, bigger, 0, inLim - inPos);
                inLim -= inPos;
                inPos = 0;
                inBuf = bigger;
            } else if (b.length - inPos < n) {
                System.arraycopy(b, inPos, b, 0, inLim - inPos);
                inLim -= inPos;
                inPos = 0;
            }
            if (!fill()) {
                return false;
            }
        }
        return true;
    }

    /**
     * One read into the free end of {@link #inBuf}; false at the end of
     * input. Once the connection is open a read times out after a quiet
     * second: between frames the connection then gives its grown buffers
     * back ({@link #releaseIdle}) and waits without a timeout; inside a
     * frame it keeps waiting (the frame-level deadlines bound a slow peer).
     */
    private boolean fill() throws IOException {
        while (true) {
            int n;
            try {
                n = in.read(inBuf, inLim, inBuf.length - inLim);
            } catch (java.net.SocketTimeoutException e) {
                if (state() == HANDSHAKE) throw e;
                if (inPos == inLim && !idleReleased) {
                    releaseIdle();
                }
                continue;
            }
            if (n < 0) {
                return false;
            }
            inLim += n;
            if (idleReleased) {
                idleReleased = false;
                socket.setSoTimeout(IDLE_RELEASE_MILLIS);
            }
            return true;
        }
    }

    /** Reads exactly {@code len} bytes into {@code dst} straight from the socket. */
    private void readFully(byte[] dst, int off, int len) throws IOException {
        while (len > 0) {
            int n;
            try {
                n = in.read(dst, off, len);
            } catch (java.net.SocketTimeoutException e) {
                if (state() == HANDSHAKE) throw e;
                continue;
            }
            if (n < 0) {
                throw new EOFException("truncated HTTP/2 stream");
            }
            off += n;
            len -= n;
        }
    }

    /**
     * Framer, a quiet second between frames: closed streams are forgotten
     * and what grew is given back (input and header-block buffers, the
     * HPACK scratch, the TLS input records, the writer's buffers); the
     * next frame regrows what it needs. Reads wait without a timeout until then.
     */
    private void releaseIdle() throws IOException {
        idleReleased = true;
        socket.setSoTimeout(0);
        retireClosed();
        inBuf = new byte[INPUT_IDLE];
        inPos = 0;
        inLim = 0;
        large = null;
        payload = null;
        if (pendingStreamId == 0) {
            pendingHeaderBytes = null;
        }
        hpackDecoder.releaseScratch();
        exchange.releaseIdle();
        if (tls != null) {
            tls.releaseIdleInputBuffers();
        }
        writer.releaseIdle();
    }

    private int payloadInt(int off) {
        byte[] b = payload;
        int p = payloadOff + off;
        return ((b[p] & 0x7F) << 24) | ((b[p + 1] & 0xFF) << 16)
            | ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
    }

    // ---- Frame dispatch ------------------------------------------------------------

    private void dispatch() throws IOException {
        // §6.10: while a header block spans HEADERS + CONTINUATION, no
        // other frame may interleave.
        if (pendingStreamId != 0
            && (frameType != Http2.TYPE_CONTINUATION || frameStreamId != pendingStreamId)) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "expected CONTINUATION for stream " + pendingStreamId);
        }
        switch (frameType) {
            case Http2.TYPE_DATA -> handleData();
            case Http2.TYPE_HEADERS -> {
                readPayload();
                handleHeaders();
            }
            case Http2.TYPE_CONTINUATION -> {
                readPayload();
                handleContinuation();
            }
            case Http2.TYPE_SETTINGS -> {
                readPayload();
                if ((frameFlags & Http2.FLAG_ACK) != 0) {
                    if (frameLength != 0) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_FRAME_SIZE_ERROR, "SETTINGS ACK with payload");
                    }
                } else {
                    applySettings();
                    writer.settingsAck();
                }
            }
            case Http2.TYPE_PING -> {
                readPayload();
                if (frameLength != 8 || frameStreamId != 0) {
                    throw new Http2.ConnectionError(Http2.ERROR_FRAME_SIZE_ERROR, "malformed PING");
                }
                if ((frameFlags & Http2.FLAG_ACK) == 0) {
                    writer.ping(payload, payloadOff, true);
                } else if (java.util.Arrays.equals(payload, payloadOff, payloadOff + 8, DRAIN_PING, 0, 8)) {
                    finalGoaway();
                }
            }
            case Http2.TYPE_WINDOW_UPDATE -> {
                readPayload();
                handleWindowUpdate();
            }
            case Http2.TYPE_RST_STREAM -> {
                readPayload();
                handleRstStream();
            }
            case Http2.TYPE_PRIORITY -> {
                readPayload();
                handlePriority();
            }
            case Http2.TYPE_GOAWAY -> {
                readPayload();
                handleGoaway();
            }
            case Http2.TYPE_PUSH_PROMISE -> throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "client cannot send PUSH_PROMISE");
            // Unknown frame types MUST be ignored (RFC 9113 §4.1).
            default -> skipPayload();
        }
    }

    private void handlePriority() throws IOException {
        int id = frameStreamId;
        if (id == 0) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "PRIORITY on stream 0");
        }
        // Both checks below are stream errors (§6.3, §5.3.1), but RST_STREAM
        // must not be sent on an idle stream (§6.4), so there they escalate
        // to a connection error. Priority itself is deprecated; its content
        // is otherwise ignored.
        if (frameLength != 5) {
            priorityStreamError(id, Http2.ERROR_FRAME_SIZE_ERROR, "PRIORITY length must be 5");
        } else if (payloadInt(0) == id) {
            priorityStreamError(id, Http2.ERROR_PROTOCOL_ERROR, "PRIORITY self-dependency");
        }
    }

    private void priorityStreamError(int id, int code, String message) throws IOException {
        if (id > highestPeerStreamId || (id & 1) == 0) {
            throw new Http2.ConnectionError(code, message + " on idle stream " + id);
        }
        streamError(id, code);
    }

    /**
     * Peer GOAWAY (§6.8): it opens no new streams, but the ones in flight
     * still complete. The connection closes once the last handler is done.
     */
    private void handleGoaway() throws IOException {
        if (frameStreamId != 0) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "GOAWAY on non-zero stream");
        }
        if (frameLength < 8) {
            throw new Http2.ConnectionError(Http2.ERROR_FRAME_SIZE_ERROR, "GOAWAY shorter than 8 octets");
        }
        peerGoaway = true;
        advance(DRAINING);
        if (activeHandlers.get() == 0) {
            closeDrained();
        }
    }

    private void handleWindowUpdate() throws IOException {
        if (frameLength != 4) {
            throw new Http2.ConnectionError(Http2.ERROR_FRAME_SIZE_ERROR, "malformed WINDOW_UPDATE");
        }
        int id = frameStreamId;
        int increment = payloadInt(0);
        if (id == 0) {
            if (increment == 0) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "WINDOW_UPDATE with 0 increment");
            }
            writer.connectionWindowUpdate(increment);
            return;
        }
        // Even ids would be server-initiated: never opened, so idle (§5.1).
        if ((id & 1) == 0 || id > highestPeerStreamId) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream " + id);
        }
        Http2Stream st = streams.get(id);
        if (st == null || st.isClosed()) {
            // Closed streams may still see credit in flight (§5.1).
            return;
        }
        if (increment == 0) {
            // §6.9: a stream error on a stream window.
            streamError(st, Http2.ERROR_PROTOCOL_ERROR);
        } else if (!writer.streamWindowUpdate(st, increment)) {
            // §6.9.1: overflowing a stream window is a stream error.
            streamError(st, Http2.ERROR_FLOW_CONTROL_ERROR);
        }
    }

    private void handleRstStream() throws IOException {
        int id = frameStreamId;
        if (id == 0) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "RST_STREAM on stream 0");
        }
        if (frameLength != 4) {
            throw new Http2.ConnectionError(Http2.ERROR_FRAME_SIZE_ERROR, "malformed RST_STREAM");
        }
        // RST_STREAM on an idle stream is a connection error (§5.1).
        if ((id & 1) == 0 || id > highestPeerStreamId) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "RST_STREAM on idle stream " + id);
        }
        chargeReset();
        Http2Stream st = streams.get(id);
        if (st != null) {
            st.reset(Http2Stream.PEER_RESET);
        }
    }

    // ---- HEADERS --------------------------------------------------------------------

    private void handleHeaders() throws IOException {
        int id = frameStreamId;
        if (id == 0 || (id & 1) == 0) {
            // §5.1.1: client-initiated streams have odd ids > 0.
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "invalid stream ID for HEADERS");
        }
        byte[] payload = this.payload;
        int off = 0;
        int len = frameLength;
        if ((frameFlags & Http2.FLAG_PADDED) != 0) {
            if (len < 1) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS PADDED with no pad-length byte");
            }
            int padLen = payload[payloadOff] & 0xFF;
            off = 1;
            len = len - 1 - padLen;
            if (len < 0) {
                throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "HEADERS padding too large");
            }
        }
        boolean selfDependent = false;
        if ((frameFlags & Http2.FLAG_PRIORITY) != 0) {
            if (len < 5) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "HEADERS priority prefix too large");
            }
            // Self-dependency is a stream error (§5.3.1), applied once the
            // block has been decoded.
            selfDependent = payloadInt(off) == id;
            off += 5;
            len -= 5;
        }
        boolean fresh = id > highestPeerStreamId;
        if (fresh) {
            // The stream leaves the idle state with this frame (§5.1),
            // whether or not we end up serving it: later frames on a refused
            // or reset stream must not look like idle-stream errors.
            highestPeerStreamId = id;
        }
        boolean endStream = (frameFlags & Http2.FLAG_END_STREAM) != 0;
        if ((frameFlags & Http2.FLAG_END_HEADERS) != 0) {
            onHeaderBlock(id, fresh, endStream, selfDependent, payload, payloadOff + off, len);
        } else {
            // The next frames MUST be CONTINUATION on this stream (§6.10);
            // dispatch enforces it, :header-timeout bounds how long it takes.
            checkEncodedHeaderSize(len);
            pendingStreamId = id;
            pendingFresh = fresh;
            pendingEndStream = endStream;
            pendingSelfDependent = selfDependent;
            pendingContinuationCount = 0;
            pendingHeaderLen = 0;
            appendPendingHeader(payload, payloadOff + off, len);
            if (config.headerTimeoutMillis > 0) {
                deadlines.header = System.nanoTime() + config.headerTimeoutMillis * 1_000_000L;
                rearm();
            }
        }
    }

    private void handleContinuation() throws IOException {
        // A CONTINUATION frame outside a pending header block is a
        // connection-level error per §6.10.
        if (pendingStreamId == 0) {
            throw new Http2.ConnectionError(
                Http2.ERROR_PROTOCOL_ERROR, "CONTINUATION without preceding HEADERS");
        }
        // Cap CONTINUATION frames per HEADERS to bound HPACK work.
        int contCap = config.http2ContinuationLimit;
        if (contCap > 0 && ++pendingContinuationCount > contCap) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM, "CONTINUATION count exceeded limit " + contCap);
        }
        checkEncodedHeaderSize(pendingHeaderLen + frameLength);
        appendPendingHeader(payload, payloadOff, frameLength);
        if ((frameFlags & Http2.FLAG_END_HEADERS) != 0) {
            int id = pendingStreamId;
            pendingStreamId = 0;
            deadlines.header = 0;
            // Decoded in place: the buffer isn't touched again until the
            // next header block starts.
            onHeaderBlock(id, pendingFresh, pendingEndStream, pendingSelfDependent,
                          pendingHeaderBytes, 0, pendingHeaderLen);
            pendingHeaderLen = 0;
            if (pendingHeaderBytes.length > 64 * 1024) {
                pendingHeaderBytes = null;
            }
        }
    }

    private void appendPendingHeader(byte[] src, int off, int len) {
        int need = pendingHeaderLen + len;
        if (pendingHeaderBytes == null) {
            pendingHeaderBytes = new byte[Math.max(4096, need)];
        } else if (need > pendingHeaderBytes.length) {
            pendingHeaderBytes = java.util.Arrays.copyOf(
                pendingHeaderBytes, Math.max(need, pendingHeaderBytes.length * 2));
        }
        System.arraycopy(src, off, pendingHeaderBytes, pendingHeaderLen, len);
        pendingHeaderLen = need;
    }

    /**
     * The encoded block can't decode to less than it holds without padding
     * tricks (size updates), so blocks over the decoded hard limit end the
     * connection before they are buffered.
     */
    private void checkEncodedHeaderSize(long encoded) throws Http2.ConnectionError {
        if (encoded > headerListHardLimit) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM, "header block exceeds " + headerListHardLimit + " bytes");
        }
    }

    /**
     * A complete header block arrived. It is always HPACK-decoded first,
     * even for streams we then refuse, reset or ignore, because every block
     * mutates the shared dynamic table (RFC 9113 §4.3): skipping one would
     * desynchronise the decoder for every later block on the connection.
     */
    private void onHeaderBlock(int id, boolean fresh, boolean endStream, boolean selfDependent,
                               byte[] block, int off, int len) throws IOException {
        checkEncodedHeaderSize(len);
        Http2Stream st = fresh ? null : streams.get(id);
        if (fresh) {
            exchange.beginRequest();
        } else {
            exchange.beginTrailers();
        }
        long size = decodeHeaderBlock(block, off, len);
        if (!fresh) {
            onTrailerBlock(id, st, endStream, selfDependent, size);
            return;
        }
        if (selfDependent) {
            streamError(id, Http2.ERROR_PROTOCOL_ERROR);
            return;
        }
        // A stream above our final GOAWAY's last-stream-id is ignored (§6.8).
        if (id > lastGoawayStreamId) {
            rememberClosed(id, Http2Stream.WE_RESET);
            return;
        }
        // Enforce our advertised SETTINGS_MAX_CONCURRENT_STREAMS. Running
        // handlers count too: a reset stream closes but its handler keeps
        // working (CVE-2023-44487).
        if ((int) LIVE_STREAMS.getVolatile(this) >= ownMaxConcurrentStreams
            || activeHandlers.get() >= ownMaxConcurrentStreams) {
            streamError(id, Http2.ERROR_REFUSED_STREAM);
            return;
        }
        Http2Stream stream = new Http2Stream(this, id, peerInitialWindowSize);
        if (!endStream) {
            stream.body = new RequestBody(this, stream, ownInitialWindowSize,
                                          config.readTimeoutMillis, recvCreditThreshold);
        }
        // Ring: :body is present only when the request has one.
        Request request = exchange.buildRequest(stream.body);
        if (size > headerListSoftLimit || exchange.tooManyFields()) {
            // §10.5.1: decoded (HPACK in sync) but too large to serve: 431.
            protocolError("header-too-large");
            stream.earlyStatus = 431;
        } else if (request == null) {
            protocolError("bad-request");
            streamError(id, Http2.ERROR_PROTOCOL_ERROR);
            return;
        } else {
            long declared = exchange.contentLength();
            if (declared >= 0) {
                if (endStream && declared != 0) {
                    // No body but Content-Length says otherwise (§8.1.1).
                    protocolError("bad-request");
                    streamError(id, Http2.ERROR_PROTOCOL_ERROR);
                    return;
                }
                stream.declaredContentLength = declared;
                if (config.maxRequestBodyBytes > 0 && declared > config.maxRequestBodyBytes) {
                    // Answered 413 without running the handler; DATA that
                    // still arrives is discarded.
                    protocolError("body-too-large");
                    stream.earlyStatus = 413;
                    stream.body.tooLarge();
                }
            }
            String expect = exchange.expectation();
            if (expect != null && stream.earlyStatus == 0) {
                // RFC 9110 §10.1.1 (RFC 9113 §8.6 for the interim
                // response), as on HTTP/1.1: 100-continue is answered on
                // the body's first read, anything else gets 417.
                if (!expect.equalsIgnoreCase("100-continue")) {
                    protocolError("bad-request");
                    stream.earlyStatus = 417;
                } else if (!endStream) {
                    stream.continuePending = true;
                }
            }
        }
        if (!admitStream(id)) {
            rememberClosed(id, Http2Stream.WE_RESET);
            return;
        }
        stream.request = request;
        stream.begin();
        streams.put(id, stream);
        LIVE_STREAMS.getAndAdd(this, 1);
        if (endStream) {
            stream.receiveEnd();
        }
        Thread.startVirtualThread(stream);
    }

    private void onTrailerBlock(int id, Http2Stream st, boolean endStream, boolean selfDependent,
                                long size) throws IOException {
        if (st == null || st.isClosed()) {
            int reason = st != null ? st.closedReason() : closed.reasonOf(id);
            switch (reason) {
                case Http2Stream.ENDED -> throw new Http2.ConnectionError(
                    Http2.ERROR_STREAM_CLOSED, "HEADERS on closed stream " + id);
                case ClosedStreams.NEVER_OPENED -> throw new Http2.ConnectionError(
                    Http2.ERROR_PROTOCOL_ERROR, "stream ID not strictly increasing");
                case Http2Stream.PEER_RESET -> resetClosedStream(id, Http2.ERROR_STREAM_CLOSED);
                // A stream we reset, ignored after our GOAWAY, or older than
                // the ring: the peer may still have had trailers in flight,
                // which are ignored. A request head reuses the id (§5.1.1).
                default -> {
                    if (exchange.pseudoInTrailers()) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_PROTOCOL_ERROR, "stream ID " + id + " reused");
                    }
                }
            }
            return;
        }
        if (selfDependent) {
            streamError(st, Http2.ERROR_PROTOCOL_ERROR);
        } else if (st.remoteEnded()) {
            // Half-closed (remote): any further HEADERS is a stream error (§5.1).
            streamError(st, Http2.ERROR_STREAM_CLOSED);
        } else if (!endStream || exchange.malformedTrailers()) {
            // §8.1: a trailer section ends the stream and follows the field
            // rules (no pseudo-headers); otherwise the request is malformed.
            streamError(st, Http2.ERROR_PROTOCOL_ERROR);
        } else if (size > headerListSoftLimit) {
            protocolError("header-too-large");
            streamError(st, Http2.ERROR_ENHANCE_YOUR_CALM);
        } else if (st.declaredContentLength >= 0
                   && st.receivedBodyBytes != st.declaredContentLength) {
            // Trailers end the request: the body must match Content-Length
            // (§8.1.1), as on a DATA frame carrying END_STREAM.
            streamError(st, Http2.ERROR_PROTOCOL_ERROR);
        } else {
            // Ring 1.5 has no trailer surface: the fields are dropped.
            endBody(st);
        }
    }

    private long decodeHeaderBlock(byte[] block, int off, int len) throws Http2.ConnectionError {
        try {
            return hpackDecoder.decode(block, off, len, exchange, headerListSoftLimit, headerListHardLimit);
        } catch (Hpack.HeaderListTooLarge e) {
            protocolError("header-too-large");
            throw new Http2.ConnectionError(Http2.ERROR_ENHANCE_YOUR_CALM, e.getMessage());
        } catch (IOException | RuntimeException e) {
            // Any decoding failure leaves the dynamic table in an unknown
            // state: connection error (RFC 9113 §4.3).
            throw new Http2.ConnectionError(
                Http2.ERROR_COMPRESSION_ERROR, "HPACK decode failed: " + e.getMessage());
        }
    }

    /** Peer END_STREAM: the state moves first, then the reader sees the end (no needless reset). */
    private void endBody(Http2Stream st) {
        st.receiveEnd();
        if (st.body != null) {
            st.body.end();
        }
    }

    /**
     * Records {@code id} as handed to a handler unless a GOAWAY already
     * announced a lower last-stream-id or the connection is closing (after
     * the peer's GOAWAY, its last handler finished). An admitted stream
     * counts in {@link #activeHandlers} from here, atomically with both
     * checks: {@link #closeDrained} decides under the same lock, so either
     * it sees this handler and doesn't close, or this stream sees CLOSING
     * and isn't served.
     */
    private boolean admitStream(int id) {
        goawayLock.lock();
        try {
            if (id > lastGoawayStreamId || state() >= CLOSING) return false;
            lastProcessedStreamId = id;
            activeHandlers.incrementAndGet();
            return true;
        } finally {
            goawayLock.unlock();
        }
    }

    // ---- DATA -----------------------------------------------------------------------

    private void handleData() throws IOException {
        int id = frameStreamId;
        if (id == 0) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "DATA on stream 0");
        }
        if ((id & 1) == 0 || id > highestPeerStreamId) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "DATA on idle stream " + id);
        }
        readPayload();
        int frameLen = frameLength;
        // Every DATA frame counts against the connection window, whatever
        // becomes of it (§6.9).
        if (connRecvWindow.addAndGet(-frameLen) < 0) {
            throw new Http2.ConnectionError(Http2.ERROR_FLOW_CONTROL_ERROR, "peer overran receive window");
        }
        Http2Stream st = streams.get(id);
        if (st == null || st.isClosed()) {
            creditConnection(frameLen);
            if (frameLen > 0 || (frameFlags & Http2.FLAG_END_STREAM) != 0) {
                closedEmptyDataFrames = 0;
            } else if (++closedEmptyDataFrames > EMPTY_DATA_FRAME_LIMIT) {
                // CVE-2019-9518 on streams that are gone: ignored frames
                // would otherwise cost a closed-ring lookup each, unbounded.
                throw new Http2.ConnectionError(Http2.ERROR_ENHANCE_YOUR_CALM, "too many empty DATA frames");
            }
            int reason = st != null ? st.closedReason() : closed.reasonOf(id);
            switch (reason) {
                // §5.1: after the peer's END_STREAM: connection error.
                case Http2Stream.ENDED, ClosedStreams.NEVER_OPENED -> throw new Http2.ConnectionError(
                    Http2.ERROR_STREAM_CLOSED, "DATA on closed stream " + id);
                // After the peer's own RST_STREAM: stream error.
                case Http2Stream.PEER_RESET -> resetClosedStream(id, Http2.ERROR_STREAM_CLOSED);
                // After ours (or long forgotten): possibly in flight, ignored.
                default -> {
                }
            }
            return;
        }
        RequestBody body = st.body;
        if (body == null || st.remoteEnded()) {
            // Half-closed (remote): DATA is a stream error (§5.1).
            creditConnection(frameLen);
            streamError(st, Http2.ERROR_STREAM_CLOSED);
            return;
        }
        if (!body.charge(frameLen)) {
            throw new Http2.ConnectionError(Http2.ERROR_FLOW_CONTROL_ERROR, "peer overran stream window");
        }
        int off = 0;
        int len = frameLen;
        if ((frameFlags & Http2.FLAG_PADDED) != 0) {
            if (len < 1) {
                throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "DATA PADDED with no pad-length byte");
            }
            int padLen = payload[payloadOff] & 0xFF;
            off = 1;
            len = len - 1 - padLen;
            if (len < 0) {
                throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "DATA padding too large");
            }
        }
        boolean endStream = (frameFlags & Http2.FLAG_END_STREAM) != 0;
        if (len == 0 && !endStream) {
            // CVE-2019-9518: cap consecutive empty non-final DATA frames.
            if (++st.emptyDataFrames > EMPTY_DATA_FRAME_LIMIT) {
                throw new Http2.ConnectionError(Http2.ERROR_ENHANCE_YOUR_CALM, "too many empty DATA frames");
            }
        }
        if (len > 0) {
            st.emptyDataFrames = 0;
            st.receivedBodyBytes += len;
            long cap = config.maxRequestBodyBytes;
            if (cap > 0 && st.receivedBodyBytes > cap) {
                // Over max-request-body-bytes: nobody reads further bytes.
                // Only the connection window is credited, so the stream
                // stalls until the 413 goes out and the stream is reset; the
                // stream window stays charged: the peer must not overrun it.
                body.tooLarge();
                creditConnection(frameLen);
                return;
            }
            if (st.declaredContentLength >= 0 && st.receivedBodyBytes > st.declaredContentLength) {
                // More body than declared: malformed (§8.1.1).
                creditConnection(frameLen);
                streamError(st, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            if (!body.append(payload, payloadOff + off, len)) {
                // Nobody will read it: hand the connection share back.
                creditConnection(len);
            }
        }
        if (endStream) {
            if (st.declaredContentLength >= 0 && st.receivedBodyBytes != st.declaredContentLength) {
                // The appended bytes come back with the aborted body; the
                // padding never reached it.
                creditConnection(frameLen - len);
                streamError(st, Http2.ERROR_PROTOCOL_ERROR);
                return;
            }
            endBody(st);
        }
        // Padding and the pad-length octet never reach the handler; their
        // credit is returned straight away.
        if (frameLen > len) {
            body.credit(frameLen - len);
        }
    }

    /**
     * {@code n} octets of DATA left the server's hands: returns them to the
     * connection window, one WINDOW_UPDATE per half stream window. Any
     * thread; never writes itself.
     */
    void creditConnection(long n) {
        if (n <= 0) return;
        long u = connRecvUncredited.addAndGet(n);
        if (u >= recvCreditThreshold) {
            if (service.budget.exhausted()) {
                // Over :max-buffered-bytes: the peer gets this credit once
                // the budget has room again (backpressure, not an error).
                service.budget.await(creditWaiter());
                return;
            }
            if (connRecvUncredited.compareAndSet(u, 0)) {
                connRecvWindow.addAndGet(u);
                writer.windowUpdate(0, (int) u);
            }
        }
    }

    private MemoryBudget.Waiter creditWaiter() {
        MemoryBudget.Waiter w = creditWaiter;
        if (w == null) {
            w = new MemoryBudget.Waiter() {
                @Override
                protected void budgetAvailable() {
                    grantHeldCredit();
                }
            };
            creditWaiter = w;
        }
        return w;
    }

    /** The memory budget has room again: the held-back connection credit goes out, whatever its size. */
    private void grantHeldCredit() {
        long u = connRecvUncredited.getAndSet(0);
        if (u > 0) {
            connRecvWindow.addAndGet(u);
            writer.windowUpdate(0, (int) u);
        }
    }

    /** Stream WINDOW_UPDATE for consumed body bytes. Any thread; never writes itself. */
    void sendWindowUpdate(int streamId, int increment) {
        writer.windowUpdate(streamId, increment);
    }

    // ---- Stream errors and resets ---------------------------------------------------

    /**
     * Stream error caused by the peer's frames (framer): charged to the
     * reset budget (CVE-2025-8671, MadeYouReset), then RST_STREAM.
     */
    private void streamError(Http2Stream st, int code) throws IOException {
        chargeReset();
        if (st.reset(Http2Stream.WE_RESET)) {
            writer.rstStream(st.id, code, true, false);
        }
    }

    /** {@link #streamError} for a stream that isn't in the table (refused, closed). */
    private void streamError(int id, int code) throws IOException {
        Http2Stream st = streams.get(id);
        if (st != null) {
            streamError(st, code);
            return;
        }
        chargeReset();
        rememberClosed(id, Http2Stream.WE_RESET);
        writer.rstStream(id, code, true, false);
    }

    /** Stream error on a stream already closed (by the peer's reset): RST_STREAM, charged. */
    private void resetClosedStream(int id, int code) throws IOException {
        chargeReset();
        writer.rstStream(id, code, true, false);
    }

    private void chargeReset() throws Http2.ConnectionError {
        int cap = config.http2StreamResetLimit;
        if (cap <= 0) return;
        long now = System.nanoTime();
        resetTokens = Math.min(cap, resetTokens + (double) (now - resetTokensAt) * cap / RESET_REFILL_NANOS);
        resetTokensAt = now;
        if (resetTokens < 1) {
            protocolError("reset-flood");
            throw new Http2.ConnectionError(Http2.ERROR_ENHANCE_YOUR_CALM, "RST_STREAM rate exceeded limit " + cap);
        }
        resetTokens -= 1;
    }

    /** The connection's socket, for TLS session details (client certificate). */
    Socket socket() {
        return socket;
    }

    /**
     * Resets {@code s} from our side unless it is already closed (never
     * answering a peer's RST_STREAM with one, §5.4.2). Any thread.
     * {@code mayWrite}: the caller owns the stream's response and may
     * become the writer.
     */
    void resetStream(Http2Stream s, int code, boolean mayWrite) {
        if (s.reset(Http2Stream.WE_RESET)) {
            try {
                writer.rstStream(s.id, code, false, mayWrite);
            } catch (IOException ignored) {
                // Connection already failing.
            }
        }
    }

    /**
     * {@link Http2Stream} reached CLOSED; runs on the thread whose
     * transition closed it. Drops pending output and request body, returns
     * the body's connection credit and hands the stream to the framer to
     * forget.
     */
    void onStreamClosed(Http2Stream s, int reason) {
        LIVE_STREAMS.getAndAdd(this, -1);
        if (reason != Http2Stream.ENDED) {
            // Reset (by either side) or torn down: nobody will read a
            // response; a handler still at work is interrupted.
            s.cancel();
        }
        if (reason != Http2Stream.ENDED && writer != null) {
            writer.purge(s);
        }
        if (s.body != null) {
            creditConnection(s.body.abort());
        }
        Http2Stream head;
        do {
            head = (Http2Stream) RETIRED.getVolatile(this);
            s.nextRetired = head;
        } while (!RETIRED.compareAndSet(this, head, s));
    }

    /** Framer: forget streams closed since the last frame, remembering why. */
    private void retireClosed() {
        if (RETIRED.getVolatile(this) == null) return;
        Http2Stream s = (Http2Stream) RETIRED.getAndSet(this, null);
        while (s != null) {
            Http2Stream next = s.nextRetired;
            s.nextRetired = null;
            if (streams.get(s.id) == s) {
                streams.remove(s.id);
                rememberClosed(s.id, s.closedReason());
            }
            s = next;
        }
    }

    private void rememberClosed(int id, int reason) {
        closed.add(id, reason);
    }

    // ---- SETTINGS -------------------------------------------------------------------

    /**
     * Applies a SETTINGS frame. Values apply in order (§6.5.3), but a frame
     * repeating a setting costs what one occurrence does: only the last
     * value of each takes effect, the smallest HEADER_TABLE_SIZE is
     * signalled first (RFC 7541 §4.2), and the largest INITIAL_WINDOW_SIZE
     * decides whether a stream window overflowed on the way (§6.9.2), in
     * one pass over the streams.
     */
    private void applySettings() throws IOException {
        if (frameStreamId != 0) {
            throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "SETTINGS on non-zero stream");
        }
        if (frameLength % 6 != 0) {
            throw new Http2.ConnectionError(Http2.ERROR_FRAME_SIZE_ERROR, "SETTINGS payload not multiple of 6");
        }
        long tableSize = -1;
        long minTableSize = -1;
        long window = -1;
        long maxWindow = -1;
        long frameSize = -1;
        byte[] b = payload;
        for (int i = payloadOff, end = payloadOff + frameLength; i < end; i += 6) {
            int id = ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            long v = ((long) (b[i + 2] & 0xFF) << 24) | ((b[i + 3] & 0xFF) << 16)
                | ((b[i + 4] & 0xFF) << 8) | (b[i + 5] & 0xFF);
            switch (id) {
                case Http2.SETTINGS_HEADER_TABLE_SIZE -> {
                    tableSize = v;
                    minTableSize = minTableSize < 0 ? v : Math.min(minTableSize, v);
                }
                case Http2.SETTINGS_ENABLE_PUSH -> {
                    if (v != 0 && v != 1) {
                        throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "ENABLE_PUSH not 0/1");
                    }
                }
                case Http2.SETTINGS_INITIAL_WINDOW_SIZE -> {
                    if (v > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                        throw new Http2.ConnectionError(
                            Http2.ERROR_FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE too large");
                    }
                    window = v;
                    maxWindow = Math.max(maxWindow, v);
                }
                case Http2.SETTINGS_MAX_FRAME_SIZE -> {
                    if (v < Http2.DEFAULT_MAX_FRAME_SIZE || v > Http2.MAX_ALLOWED_FRAME_SIZE) {
                        throw new Http2.ConnectionError(Http2.ERROR_PROTOCOL_ERROR, "MAX_FRAME_SIZE out of range");
                    }
                    frameSize = v;
                }
                // MAX_CONCURRENT_STREAMS bounds server push, which we never
                // do; unknown SETTINGS MUST be ignored.
                default -> {
                }
            }
        }
        if (tableSize >= 0) {
            // Cap at the size we encode with: the peer can only shrink
            // the encoder's table, never force it to grow.
            if (minTableSize < tableSize) {
                writer.setPeerHeaderTableSize((int) Math.min(minTableSize, Http2.DEFAULT_HEADER_TABLE_SIZE));
            }
            writer.setPeerHeaderTableSize((int) Math.min(tableSize, Http2.DEFAULT_HEADER_TABLE_SIZE));
        }
        if (window >= 0) {
            long delta = window - peerInitialWindowSize;
            long maxDelta = maxWindow - peerInitialWindowSize;
            peerInitialWindowSize = (int) window;
            // Every live stream's send window moves by the delta (§6.9.2).
            if (delta != 0 || maxDelta > 0) {
                writer.adjustInitialWindow(delta, maxDelta, streams);
            }
        }
        if (frameSize >= 0) {
            writer.setPeerMaxFrameSize((int) frameSize);
        }
    }

    // ---- Handlers ---------------------------------------------------------------------

    /** The stream's handler thread ({@link Http2Stream#run}). */
    void serve(Http2Stream s) {
        s.handlerThread = Thread.currentThread();
        if (s.isClosed() && s.closedReason() != Http2Stream.ENDED) {
            // Reset before this thread got here: nothing will be served.
            s.cancel();
        }
        // :handler-timeout: the stream is its own timer node. On expiry,
        // if the handler hasn't produced a response, a 503 goes out and the
        // handler is interrupted; both race on the stream's response claim.
        boolean timed = config.handlerTimeoutMillis > 0;
        if (timed) timer.schedule(s, config.handlerTimeoutMillis);
        try {
            exchange.serve(s);
        } finally {
            if (timed) timer.retire(s);
            s.handlerThread = null;
            releaseSlot(s);
        }
    }

    /**
     * Gives back {@code s}'s admission slot (counted in
     * {@link #activeHandlers} since {@link #admitStream}) the first time
     * either its response is complete or its handler is gone. A response
     * counts as complete when its END_STREAM is packed, before it leaves:
     * a client sending its next request on seeing it must find the slot free.
     */
    void releaseSlot(Http2Stream s) {
        if (s.releaseSlot()) {
            onHandlerDone();
        }
    }

    /**
     * {@code s}'s END_STREAM was packed, or its handed-over exchange was
     * aborted (writer, or whoever reset the stream; before the batch is
     * written). A handed-over exchange is finished here, sent or aborted:
     * events (the status the handler chose, the DATA taken so far), and
     * RST_STREAM(NO_ERROR) if END_STREAM went out ({@code sent}) while the
     * request body is still open.
     */
    void exchangeFinished(Http2Stream s, boolean sent) {
        if (s.detached) {
            if (sent && !s.remoteEnded()) {
                // Complete response while the request body is still
                // arriving: ask the client to stop sending (§8.1).
                resetStream(s, Http2.ERROR_NO_ERROR, false);
            }
            requestCompleted(s, s.status);
        }
        if (s.claimed() == Exchange.TIMED_OUT && s.handlerThread != null) {
            // The 503 is out but the handler still runs (it may ignore its
            // interrupt): it keeps counting against the concurrency limit
            // until its thread gives the slot back (serve's finally clears
            // handlerThread before releasing, so one of the two does it).
            return;
        }
        releaseSlot(s);
    }

    /** {@link Http2Stream#onTimeout}: on the timer thread, so the 503 goes out from a virtual thread. */
    void onHandlerTimeout(Http2Stream s) {
        // Counted like a handler from before it claims the response, so a
        // draining connection can't close before the 503 is out.
        activeHandlers.incrementAndGet();
        Thread.startVirtualThread(() -> {
            try {
                exchange.respondTimeout(s);
            } finally {
                onHandlerDone();
            }
        });
    }

    /**
     * Last step of every handler thread. After a GOAWAY either way, the
     * framer may be parked in a read with nothing left to wait for: the
     * last handler closes the connection.
     */
    private void onHandlerDone() {
        if (activeHandlers.decrementAndGet() == 0) {
            idleSinceNanos = System.nanoTime();
            if (peerGoaway || lastGoawayStreamId != Integer.MAX_VALUE) {
                closeDrained();
            }
            Thread t = awaitingHandlers;
            if (t != null) {
                LockSupport.unpark(t);
            }
        }
    }

    /**
     * Framer exit: waits until every handler of the connection is done
     * (they were interrupted by the teardown), so the connection keeps its
     * limiter slot and registry entry while any of them runs: closing TCP
     * can't be a way to leave handlers running and open more. A handler
     * that ignores its interrupt holds the connection until it returns;
     * server stop bounds that wait with its own deadline.
     */
    private void awaitHandlers() {
        if (activeHandlers.get() == 0) return;
        boolean interrupted = false;
        awaitingHandlers = Thread.currentThread();
        try {
            while (activeHandlers.get() > 0) {
                LockSupport.parkNanos(this, 10_000_000L);
                if (Thread.interrupted()) {
                    interrupted = true;
                }
            }
        } finally {
            awaitingHandlers = null;
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** {@code s}'s response with {@code status} is finished: reported once. */
    void requestCompleted(Http2Stream s, int status) {
        s.status = status;
        s.complete();
    }

    void protocolError(String kind) {
        service.protocolError(protocol, kind);
    }

    /** The handler's first body read on a request that said Expect: 100-continue. */
    void sendContinue(Http2Stream s) {
        if (s.claimed() != Exchange.OPEN) return;
        writer.interimContinue(s);
    }

    private static String errorKind(int code) {
        return switch (code) {
            case Http2.ERROR_FLOW_CONTROL_ERROR -> "flow-control-error";
            case Http2.ERROR_COMPRESSION_ERROR -> "compression-error";
            case Http2.ERROR_FRAME_SIZE_ERROR -> "frame-size-error";
            case Http2.ERROR_STREAM_CLOSED -> "stream-closed";
            case Http2.ERROR_ENHANCE_YOUR_CALM -> "enhance-your-calm";
            default -> "protocol-error";
        };
    }

    // ---- Writer callbacks -------------------------------------------------------------

    /** The socket write failed: the connection is gone; unblock the framer. */
    void onWriteFailure(Throwable e) {
        if (!(e instanceof IOException)) {
            FAILURES.log("HTTP/2 writer failure", e);
        }
        EnsoServer.forceClose(socket);
    }

    /** A socket write made no progress for :write-timeout (timer thread). */
    void onWriteStall() {
        protocolError("write-timeout");
        WriteWatchdog.forceCloseAsync(socket);
    }

    /** A stream couldn't send for :write-timeout because its window stayed shut. */
    void cancelStalledStream(Http2Stream s) {
        protocolError("flow-control-timeout");
        resetStream(s, Http2.ERROR_CANCEL, false);
    }

    /** No stream could send for :write-timeout because the connection window stayed shut. */
    void connectionWindowStalled() {
        protocolError("flow-control-timeout");
        connectionErrorAsync(Http2.ERROR_ENHANCE_YOUR_CALM, "connection flow-control window stalled");
    }

    /** A flow-control wait needs attention at {@code nanos}. */
    void armFlowDeadline(long nanos) {
        synchronized (deadlines) {
            long current = deadlines.flow;
            if (current == 0 || nanos - current < 0) {
                deadlines.flow = nanos;
                rearmLocked();
            }
        }
    }

    // ---- Shutdown ---------------------------------------------------------------------

    /**
     * Graceful close, first phase (§6.8): GOAWAY(2^31-1, NO_ERROR) tells
     * the peer to open no more streams while requests already on their way
     * are still served; the PING times the second phase. Any thread.
     */
    private void beginGracefulClose() {
        goawayLock.lock();
        try {
            if (drainPhase != 0 || state() >= CLOSING || state() == HANDSHAKE) return;
            drainPhase = 1;
            advance(DRAINING);
            writer.goaway(Integer.MAX_VALUE, Http2.ERROR_NO_ERROR, null);
            writer.ping(DRAIN_PING, 0, false);
        } catch (IOException ignored) {
            // Connection already dying.
        } finally {
            goawayLock.unlock();
        }
        deadlines.drainPing = System.nanoTime() + DRAIN_PING_NANOS;
        rearm();
    }

    /**
     * Second phase: GOAWAY naming the last stream handed to a handler;
     * streams above it are ignored, and the connection closes once the
     * running handlers finish.
     */
    private void finalGoaway() {
        goawayLock.lock();
        try {
            if (drainPhase != 1) return;
            drainPhase = 2;
            lastGoawayStreamId = lastProcessedStreamId;
            writer.goaway(lastGoawayStreamId, Http2.ERROR_NO_ERROR, null);
        } finally {
            goawayLock.unlock();
        }
        deadlines.drainPing = 0;
        if (activeHandlers.get() == 0) {
            closeDrained();
        }
    }

    /** Framer: GOAWAY with {@code code} for a connection error; teardown follows. */
    private void connectionError(int code, String message) {
        protocolError(errorKind(code));
        goawayLock.lock();
        try {
            if (lastProcessedStreamId < lastGoawayStreamId) {
                lastGoawayStreamId = lastProcessedStreamId;
            }
            writer.goaway(lastGoawayStreamId, code, message);
            writer.controlOnly();
        } finally {
            goawayLock.unlock();
        }
    }

    /** A connection error found off the framer (timer, flow check): GOAWAY, flush, close. */
    private void connectionErrorAsync(int code, String message) {
        Thread.startVirtualThread(() -> {
            if (!advance(CLOSING)) return;
            connectionError(code, message);
            writer.shutdown();
            forceClose();
        });
    }

    /**
     * All handlers are done and no new stream will be served: flush, shut
     * the output down and let the framer read out what the peer still
     * sends. Called from handler or writer threads, so the flush runs on
     * its own thread.
     */
    private void closeDrained() {
        goawayLock.lock();
        try {
            if (activeHandlers.get() != 0 || !advance(CLOSING)) return;
        } finally {
            goawayLock.unlock();
        }
        Thread.startVirtualThread(() -> {
            writer.shutdown();
            if (server.isRunning()) {
                shutdownOutput();
                deadlines.linger = System.nanoTime() + LINGER_NANOS;
                rearm();
            } else {
                forceClose();
            }
        });
    }

    private void shutdownOutput() {
        try {
            if (socket instanceof TlsSocket.AdapterSocket a) {
                a.tls().shutdownOutput();
            } else {
                socket.shutdownOutput();
            }
        } catch (IOException | UnsupportedOperationException ignored) {
        }
    }

    /**
     * Framer exit: every stream still open is aborted and the writer
     * flushes what it can (a GOAWAY). When the peer may still be sending,
     * the flush and output shutdown run on their own thread while the
     * framer reads the input out for a bounded time (a peer that doesn't
     * read can't stall a peer that doesn't stop writing), then the socket
     * closes.
     */
    private void teardown(boolean linger) {
        advance(CLOSING);
        try {
            for (int i = 0, n = streams.capacity(); i < n; i++) {
                Http2Stream s = streams.slot(i);
                if (s != null) {
                    s.reset(Http2Stream.WE_RESET);
                }
            }
            if (writer != null) {
                if (linger && server.isRunning()) {
                    Thread.startVirtualThread(() -> {
                        writer.shutdown();
                        shutdownOutput();
                    });
                    lingerRead();
                } else {
                    writer.shutdown();
                }
            }
        } finally {
            STATE.setVolatile(this, CLOSED);
            timer.retire(deadlines);
            if (writer != null) {
                writer.retire(timer);
            }
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            streams.clear();
            pendingHeaderBytes = null;
            awaitHandlers();
        }
    }

    /** Reads and discards what the peer still sends, until it closes or the linger bound. */
    private void lingerRead() {
        deadlines.linger = System.nanoTime() + LINGER_NANOS;
        rearm();
        long read = 0;
        byte[] discard = inBuf;
        try {
            while (read < LINGER_MAX_BYTES) {
                int n = in.read(discard, 0, discard.length);
                if (n < 0) return;
                read += n;
            }
        } catch (IOException ignored) {
        }
    }

    // ---- Deadlines --------------------------------------------------------------------

    /** The connection's single timer node: whichever deadline is next. */
    private final class Deadlines extends Timer.Task {
        // System.nanoTime instants, 0 = none. Written by the thread that
        // sets them, read by onTimeout.
        volatile long handshake;
        volatile long header;
        volatile long flow;
        volatile long drainPing;
        volatile long linger;

        @Override
        protected void onTimeout() {
            onDeadline();
        }
    }

    /** Timer thread: act on whatever is due (off the timer thread when it may block), re-arm. */
    private void onDeadline() {
        long now = System.nanoTime();
        int st = state();
        if (st == CLOSED) return;
        Deadlines d = deadlines;
        if (due(d.handshake, now) && st == HANDSHAKE) {
            protocolError("handshake-timeout");
            WriteWatchdog.forceCloseAsync(socket);
            return;
        }
        if (due(d.linger, now)) {
            WriteWatchdog.forceCloseAsync(socket);
            return;
        }
        if (due(d.header, now)) {
            d.header = 0;
            protocolError("header-timeout");
            connectionErrorAsync(Http2.ERROR_ENHANCE_YOUR_CALM, "header block not completed in time");
        }
        if (due(d.drainPing, now)) {
            d.drainPing = 0;
            Thread.startVirtualThread(this::finalGoaway);
        }
        long flow = d.flow;
        if (due(flow, now)) {
            synchronized (d) {
                if (d.flow == flow) d.flow = 0;
            }
            Thread.startVirtualThread(() -> {
                long next = writer.checkFlow(System.nanoTime());
                if (next != 0) armFlowDeadline(next);
            });
        }
        if (st == OPEN && idleTimeoutNanos > 0 && activeHandlers.get() == 0
            && (int) LIVE_STREAMS.getVolatile(this) == 0
            && now - idleSinceNanos >= idleTimeoutNanos) {
            Thread.startVirtualThread(this::beginGracefulClose);
        }
        rearm();
    }

    private static boolean due(long deadline, long now) {
        return deadline != 0 && now - deadline >= 0;
    }

    private void rearm() {
        synchronized (deadlines) {
            rearmLocked();
        }
    }

    /** Schedules the node for the earliest pending deadline. Caller holds the deadlines monitor. */
    private void rearmLocked() {
        Deadlines d = deadlines;
        long now = System.nanoTime();
        long next = Long.MAX_VALUE;
        next = earliest(next, d.handshake);
        next = earliest(next, d.header);
        next = earliest(next, d.flow);
        next = earliest(next, d.drainPing);
        next = earliest(next, d.linger);
        int st = state();
        if (st == OPEN && idleTimeoutNanos > 0) {
            long base = activeHandlers.get() == 0 && (int) LIVE_STREAMS.getVolatile(this) == 0
                ? idleSinceNanos : now;
            next = earliest(next, base + idleTimeoutNanos);
        }
        if (next == Long.MAX_VALUE || st == CLOSED) {
            timer.cancel(d);
            return;
        }
        // An instant already behind fires on the next tick.
        timer.schedule(d, Math.max(0, (next - now + 999_999L) / 1_000_000L));
    }

    private static long earliest(long a, long deadline) {
        if (deadline == 0) return a;
        if (a == Long.MAX_VALUE) return deadline;
        return deadline - a < 0 ? deadline : a;
    }
}

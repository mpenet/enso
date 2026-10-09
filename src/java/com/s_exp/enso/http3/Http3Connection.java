// ABOUTME: One QUIC connection on its event loop: quiche packet I/O, stream reads and ordered writes,
// ABOUTME: connection timers (handshake, idle, header, write, pacing), GOAWAY drain and teardown.
package com.s_exp.enso.http3;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.core.Drainable;
import com.s_exp.enso.core.Jfr;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.quiche.NativeBuffer;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.QuicheConfig;
import com.s_exp.enso.quiche.QuicheConnection;
import com.s_exp.enso.quiche.Records;
import com.s_exp.enso.util.Long2ObjectHashMap;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A QUIC connection and its HTTP/3 state. Everything here runs on the
 * owning {@link Http3Loop}'s thread except the cross-thread entry points
 * ({@link #beginDrain}, {@link #forceClose}, {@link #signalled},
 * {@link #handlerFinished}), which only set flags and queue work for the
 * loop. quiche is reached exclusively through {@link #quiche}.
 *
 * <p>Writes keep per-stream order: what quiche's flow or congestion
 * control doesn't take waits on the stream ({@link Http3Stream}) and is
 * resumed when quiche reports the stream writable again
 * ({@code quiche_conn_stream_writable_next}), so the cost of an ACK is
 * proportional to the streams it unblocks, not to the open ones.
 */
final class Http3Connection implements Drainable, DeadlineHeap.Node,
        SignalStack.Node<Http3Connection>, Http3ControlStreams.Output {

    private static final Logger LOG = Logger.getLogger(Http3Connection.class.getName());
    private static final LogLimiter PEER_FAILURES = new LogLimiter(LOG, Level.FINE);
    private static final LogLimiter INTERNAL_FAILURES = new LogLimiter(LOG, Level.WARNING);

    private static final VarHandle SCHEDULED;
    private static final VarHandle RELEASED;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            SCHEDULED = l.findVarHandle(Http3Connection.class, "scheduled", int.class);
            RELEASED = l.findVarHandle(Http3Connection.class, "released", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static final byte[] NO_REASON = new byte[0];
    private static final long NONE = Long.MAX_VALUE;
    /** Pacing delays shorter than this are sent at once. */
    private static final long PACING_GRANULARITY_NANOS = 1_000_000L;
    /** How often idle streamed bodies are checked for a peer STOP_SENDING. */
    private static final long STOP_CHECK_NANOS = 50_000_000L;
    /** CVE-2023-44487-style rapid reset: tokens refill over this window. */
    private static final long RESET_REFILL_NANOS = 30_000_000_000L;
    /**
     * After handlers were dispatched, quiche's packets (its ACK of the
     * request, sent at once otherwise) wait this long for a response to
     * share them: one packet per request instead of two. Within the 25 ms
     * max_ack_delay we advertise.
     */
    private static final long RESPONSE_HOLD_NANOS = 500_000L;
    /** How often, while packets arrive, our critical streams are checked for a peer STOP_SENDING. */
    private static final long CRITICAL_CHECK_NANOS = 100_000_000L;

    final Http3Loop loop;
    final Http3Listener listener;
    final Config config;
    final QuicheConnection quiche;
    // The configuration quiche accepted this connection with; a reference
    // is held until the connection is freed.
    private final QuicheConfig quicheConfig;
    final byte[] cid;
    /** The client's original destination id while it may still use it, else null. */
    byte[] alias;
    /** The client's source id until the handshake completes, else null. */
    private byte[] clientScid;
    final InetAddress remote;

    // Loop bookkeeping.
    boolean dirty;
    /** The listener was told the connection closed (once). */
    boolean closedReported;
    private int heapIndex = -1;
    private long deadline = NONE;
    @SuppressWarnings("unused") // accessed through SCHEDULED
    private volatile int scheduled;
    private Http3Connection pushNext;
    private Http3Connection takeNext;

    // Requests from other threads.
    private volatile boolean drainAsked;
    private volatile boolean forceAsked;
    /** Freed: nothing may reach quiche any more. */
    private volatile boolean gone;
    /** 1 once the limiter slot and registry entry were given back. */
    @SuppressWarnings("unused") // accessed through RELEASED
    private volatile int released;

    private boolean established;
    private boolean receivedPackets;
    /** quiche wrote at least one packet for this connection. */
    private boolean sentPackets;
    private boolean closing;
    private boolean destroyNow;
    private final Http3ControlStreams control;
    Long2ObjectHashMap<Http3Exchange> exchanges = new Long2ObjectHashMap<>();
    // Most exchanges open at once since the map was last replaced: a map
    // grown by a burst is swapped for a small one once the connection was
    // idle for IDLE_RELEASE_NANOS (not at every pause between bursts).
    private int exchangesPeak;
    private static final int EXCHANGES_KEPT = 16;
    private static final long IDLE_RELEASE_NANOS = 1_000_000_000L;
    private final SignalStack<Http3Exchange> signalled = new SignalStack<>();
    final AtomicInteger liveHandlers = new AtomicInteger();
    final int maxLiveHandlers;
    private int blockedStreams;
    /** Highest client request stream id seen, -4 before the first. */
    long highestRequestStream = -4;

    // Graceful drain (RFC 9114 §5.2).
    private boolean draining;
    long goawayId = Long.MAX_VALUE;
    /** The largest client-initiated bidirectional stream id: a GOAWAY that refuses nothing. */
    static final long GOAWAY_ANY = (1L << 62) - 4;
    // Bounds of the wait between the two GOAWAYs (twice the RTT estimate).
    private static final long GOAWAY_GRACE_MIN_NANOS = 10_000_000L;
    private static final long GOAWAY_GRACE_MAX_NANOS = 1_000_000_000L;
    /** When the second GOAWAY (the real id) is due, NONE once sent. */
    private long finalGoawayAt = NONE;
    /** Request streams the peer opened that were seen (served or refused), for the drain. */
    int requestStreams;
    /** Longest wait, once drained, for the last responses to be acknowledged. */
    private static final long DRAIN_LINGER_NANOS = 2_000_000_000L;
    private long lingerUntil = NONE;
    // The most recently finished request streams: closing the connection
    // discards unacknowledged stream data, so a drained connection waits
    // until quiche collected these (fully acknowledged). Older ones had
    // dozens of round trips to complete. Allocated when the drain starts
    // (seeded with the highest finished ids), so idle connections hold none.
    private static final int RECENT_STREAMS = 64;
    private long[] recentStreams;
    private int recentCount;

    // Deadlines, System.nanoTime.
    private final long handshakeDeadline;
    private long idleSince;
    private final long idleNanos;
    private long paceUntil;
    // The packet quiche's pacer released for paceUntil (Linux), kept out of
    // the batch until then: its bytes and its SEND record. Made on first need.
    private byte[] pacedPacket;
    private byte[] pacedRecord;
    private int pacedLength;
    private long quicheDeadline = NONE;
    private long headerCheckAt = NONE;
    private long writeCheckAt = NONE;
    private long stopCheckAt = NONE;
    private long criticalCheckAt;
    /** Until when flushing waits for a response (see RESPONSE_HOLD_NANOS), NONE when not. */
    private long holdUntil = NONE;
    final long headerTimeoutNanos;
    final long writeTimeoutNanos;

    // Peer-controlled resources.
    /** Unread request-body bytes of this connection's pipes, bounded by its window; made on first need. */
    private MemoryBudget bodyBudget;
    int bufferedHeaderBytes;
    final int headerBudget;
    private double resetTokens;
    private long resetTokensAt;

    // Observability.
    private long openedNanos;
    private Jfr.ConnectionEvent jfr;

    final Http3RequestReader reader;
    final Http3ResponseWriter writer;

    Http3Connection(Http3Loop loop, QuicheConnection quiche, QuicheConfig quicheConfig, byte[] cid,
                    byte[] alias, byte[] clientScid, InetAddress remote, long now) {
        this.loop = loop;
        this.listener = loop.listener;
        this.config = listener.config;
        this.quiche = quiche;
        this.quicheConfig = quicheConfig;
        this.cid = cid;
        this.alias = alias;
        this.clientScid = clientScid;
        this.remote = remote;
        this.maxLiveHandlers = 2 * config.http3InitialMaxStreamsBidi;
        this.handshakeDeadline = config.handshakeTimeoutMillis > 0
            ? now + config.handshakeTimeoutMillis * 1_000_000L : NONE;
        this.idleNanos = config.idleTimeoutMillis * 1_000_000L;
        this.headerTimeoutNanos = config.headerTimeoutMillis * 1_000_000L;
        this.writeTimeoutNanos = config.writeTimeoutMillis * 1_000_000L;
        // :max-header-bytes is SETTINGS_MAX_FIELD_SECTION_SIZE; partial
        // sections of one connection may buffer up to the hard ceiling.
        int fieldCap = config.maxHeaderBytes;
        this.headerBudget = Http3RequestReader.hardCap(fieldCap);
        this.resetTokens = config.http3StreamResetLimit;
        this.resetTokensAt = now;
        this.control = new Http3ControlStreams(this, fieldCap);
        this.reader = new Http3RequestReader(this, fieldCap, config.maxHeaderFields);
        this.writer = new Http3ResponseWriter(this);
    }

    // ---- loop bookkeeping ------------------------------------------------------

    @Override public long deadline() { return deadline; }
    @Override public int heapIndex() { return heapIndex; }
    @Override public void heapIndex(int i) { heapIndex = i; }
    @Override public Http3Connection pushNext() { return pushNext; }
    @Override public void pushNext(Http3Connection n) { pushNext = n; }
    @Override public Http3Connection takeNext() { return takeNext; }
    @Override public void takeNext(Http3Connection n) { takeNext = n; }

    void unschedule() {
        SCHEDULED.setVolatile(this, 0);
    }

    private void schedule() {
        if (!gone && SCHEDULED.compareAndSet(this, 0, 1)) loop.schedule(this);
    }

    // ---- cross-thread entry points -----------------------------------------------

    /** Any thread: an exchange has events for the loop. */
    void signalled(Http3Exchange ex) {
        if (gone) return;
        signalled.push(ex);
        schedule();
    }

    /**
     * Handler thread: its handler returned (or gave up). The last handler
     * of a connection already freed gives back its limiter slot and
     * registry entry (see {@link Http3Listener#released}).
     */
    void handlerFinished(Http3Exchange ex) {
        if (ex.timed) listener.timer.retire(ex);
        ex.handlerThread = null;
        if (liveHandlers.decrementAndGet() == 0 && gone) {
            listener.released(this);
        }
    }

    RingHandler handler() { return listener.handler; }

    HeadPool heads() { return loop.heads; }

    /** True once the connection was freed: responses can no longer be sent. */
    boolean isGone() { return gone; }

    /** True for the first caller only: the connection's slot is given back once. */
    boolean release() {
        return RELEASED.compareAndSet(this, 0, 1);
    }

    @Override
    public void beginDrain() {
        drainAsked = true;
        schedule();
    }

    @Override
    public void forceClose() {
        forceAsked = true;
        schedule();
    }

    // ---- packets -------------------------------------------------------------------

    /** Feeds one datagram ({@code meta[rec]} is its RECV record). */
    void recv(NativeBuffer buf, int off, int len, NativeBuffer meta, int rec) {
        if (gone || destroyNow) return;
        long rc = quiche.recv(buf, off, len, meta, rec + Records.RECV_PEER, rec + Records.RECV_LOCAL);
        if (rc < 0 && rc != Quiche.QUICHE_ERR_DONE) {
            PEER_FAILURES.log("h3 quiche_conn_recv returned " + rc);
            if (!sentPackets && clientScid != null) refuseHandshake(meta, rec);
        }
        receivedPackets = true;
    }

    /**
     * quiche refused the client's first flight (e.g. TRANSPORT_PARAMETER_ERROR,
     * RFC 9000 §7.4) and queued its CONNECTION_CLOSE at the Handshake level,
     * which this client can't decrypt: nothing of ours reached it, so no
     * ServerHello. The close is also sent as our first Initial (§10.2.3),
     * then the connection is freed.
     */
    private void refuseHandshake(NativeBuffer meta, int rec) {
        long[] err = new long[2];
        if (!quiche.localError(err) || err[0] != 0) return;
        listener.protocolError("protocol-error");
        loop.sendInitialClose((int) err[1], alias != null ? alias : cid, clientScid, meta, rec);
        destroyNow = true;
    }

    /**
     * Lets quiche write its packets into the loop's send batch. False when
     * the socket blocked first (the loop retries once it can send).
     */
    boolean flush(long now) {
        if (gone) return true;
        if (holdUntil != NONE) {
            if (now - holdUntil < 0 && !closing && !destroyNow) return true;
            holdUntil = NONE;
        }
        // A connection being closed sends its CONNECTION_CLOSE now: it may
        // be freed right after this flush.
        if (paceUntil != 0 && !closing && !destroyNow) {
            if (paceUntil - now > 0) return true;
            paceUntil = 0;
        }
        if (pacedLength > 0) {
            if (!loop.ensureSendRoom()) return false;
            loop.commitPacket(pacedPacket, pacedLength, pacedRecord);
            pacedLength = 0;
        }
        while (loop.ensureSendRoom()) {
            int off = loop.sendOffset();
            int rec = loop.sendRecord();
            long rc = quiche.send(loop.sendSlab, off, loop.maxPayload, loop.sendMeta, rec);
            if (rc == Quiche.QUICHE_ERR_DONE) return true;
            if (rc < 0) {
                PEER_FAILURES.log("h3 quiche_conn_send returned " + rc);
                return true;
            }
            sentPackets = true;
            // Coarse pacing: quiche wants this packet sent later (its delay
            // is from the moment of the call). It waits out of the batch
            // and sending resumes at its release time.
            long delay = loop.sendRecords.getLong(rec + Records.PKT_DELAY);
            if (delay > PACING_GRANULARITY_NANOS && !closing && !destroyNow) {
                holdPaced(off, (int) rc, rec);
                paceUntil = System.nanoTime() + delay;
                return true;
            }
            loop.commitPacket((int) rc);
        }
        return false;
    }

    /** Copies the packet quiche just wrote at {@code loop.sendSlab[off]} (record {@code rec}) aside. */
    private void holdPaced(int off, int len, int rec) {
        if (pacedPacket == null || pacedPacket.length < len) {
            pacedPacket = new byte[loop.maxPayload];
            pacedRecord = new byte[Records.SEND_META_LEN];
        }
        loop.sendSlab.buffer.get(off, pacedPacket, 0, len);
        loop.sendRecords.get(rec, pacedRecord, 0, Records.SEND_META_LEN);
        pacedLength = len;
    }

    /**
     * After processing: false when the connection should be freed, else
     * recomputes its deadline ({@link #deadline}, NONE when nothing is
     * armed). One call into quiche for both questions.
     */
    boolean settle(long now) {
        if (gone || destroyNow) return false;
        long t = quiche.timeoutNanosOrClosed();
        if (t == QuicheConnection.CLOSED) return false;
        updateDeadline(now, t);
        return true;
    }

    /** True while a deadline is armed (see {@link #settle}). */
    boolean armed() {
        return deadline != NONE;
    }

    /** A handler was started: the next flush waits briefly for its response. */
    void handlerDispatched(long now) {
        if (holdUntil == NONE) holdUntil = now + RESPONSE_HOLD_NANOS;
    }

    /** A response (or interim response) was handed to quiche: flush without waiting. */
    void responseWritten() {
        holdUntil = NONE;
    }

    boolean wasEstablished() {
        return established;
    }

    // ---- timers ---------------------------------------------------------------------

    /** The loop's timer for this connection expired. */
    void onTimer(long now) {
        if (gone) return;
        if (quicheDeadline != NONE && now - quicheDeadline >= 0) {
            quicheDeadline = NONE;
            quiche.onTimeout();
        }
    }

    /** Recomputes the next deadline from quiche's timer {@code t} (-1: none). */
    private void updateDeadline(long now, long t) {
        long d = NONE;
        quicheDeadline = t >= 0 ? now + t : NONE;
        d = Math.min(d, quicheDeadline);
        if (paceUntil != 0) d = Math.min(d, paceUntil);
        d = Math.min(d, holdUntil);
        if (!established) {
            d = Math.min(d, handshakeDeadline);
        } else if (exchanges.isEmpty() && !closing) {
            if (idleNanos > 0) d = Math.min(d, idleSince + idleNanos);
            if (exchangesPeak > EXCHANGES_KEPT) d = Math.min(d, idleSince + IDLE_RELEASE_NANOS);
        }
        d = Math.min(d, Math.min(headerCheckAt, Math.min(writeCheckAt, stopCheckAt)));
        if (!closing) d = Math.min(d, Math.min(lingerUntil, finalGoawayAt));
        deadline = d;
    }

    // ---- processing --------------------------------------------------------------------

    /** Handles everything pending for this connection (loop thread). */
    void process(long now) {
        if (gone) return;
        if (forceAsked) {
            closeNow();
            return;
        }
        if (drainAsked && !draining) startDrain();
        if (destroyNow) return;
        if (!established) {
            if (!quiche.isEstablished()) {
                if (now - handshakeDeadline >= 0) {
                    // A client that advertises no idle timeout would keep
                    // its half-open state forever without this.
                    listener.protocolError("handshake-timeout");
                    PEER_FAILURES.log("h3 handshake timed out");
                    closeNow();
                }
                receivedPackets = false;
                return;
            }
            onEstablished(now);
        }
        if (!control.isOpen()) control.open();
        boolean packets = receivedPackets;
        receivedPackets = false;
        if (packets && !closing && now - criticalCheckAt >= 0) {
            criticalCheckAt = now + CRITICAL_CHECK_NANOS;
            checkCriticalStreams();
        }
        if (packets && !closing) reader.readStreams(now);
        handleSignals(now);
        if (packets && blockedStreams > 0 && !closing) drainWritable(now);
        appTimers(now, packets);
        if (finalGoawayAt != NONE && now - finalGoawayAt >= 0 && !closing) {
            finalGoawayAt = NONE;
            goawayId = highestRequestStream + 4;
            sendGoaway(goawayId);
        }
        if (draining && finalGoawayAt == NONE && exchanges.isEmpty() && !closing) {
            if (lingerUntil == NONE) lingerUntil = now + DRAIN_LINGER_NANOS;
            if ((allRequestsArrived() && responsesDelivered()) || now - lingerUntil >= 0) closeGracefully();
        }
    }

    /**
     * True when every request stream below the highest one seen arrived:
     * the GOAWAY promised to process those, and one may still be on its
     * way (reordered, or lost and being resent).
     */
    private boolean allRequestsArrived() {
        return requestStreams == (highestRequestStream >> 2) + 1;
    }

    /** True once quiche collected every recently finished request stream. */
    private boolean responsesDelivered() {
        if (recentStreams == null) return true;
        int n = Math.min(recentCount, recentStreams.length);
        for (int i = 0; i < n; i++) {
            long rc = quiche.streamCapacity(recentStreams[i]);
            if (rc != Quiche.QUICHE_ERR_INVALID_STREAM_STATE) return false;
        }
        return true;
    }

    /**
     * RFC 9114 §6.2.1: a peer may not ask us to close our control or QPACK
     * streams; STOP_SENDING on one is H3_CLOSED_CRITICAL_STREAM. quiche
     * reports it only through the stream's send capacity.
     */
    private void checkCriticalStreams() {
        if (!control.isOpen()) return;
        if (stopped(control.control) || stopped(control.qpackEncoder) || stopped(control.qpackDecoder)) {
            closeWithError(new Http3ConnectionException(Http3ConnectionException.H3_CLOSED_CRITICAL_STREAM,
                "peer sent STOP_SENDING on a critical stream"));
        }
    }

    private boolean stopped(Http3Stream s) {
        return quiche.streamCapacity(s.id) == Quiche.QUICHE_ERR_STREAM_STOPPED;
    }

    private void onEstablished(long now) {
        established = true;
        criticalCheckAt = now;
        clientScid = null;
        idleSince = now;
        listener.established(this);
        loop.unalias(this);
        if (listener.events != null || Jfr.connections()) {
            openedNanos = System.nanoTime();
            listener.service.connectionOpened(Http3Listener.PROTOCOL, remote);
            if (Jfr.connections()) {
                jfr = new Jfr.ConnectionEvent();
                jfr.begin();
            }
        }
    }

    private void handleSignals(long now) {
        Http3Exchange ex = signalled.takeAll();
        while (ex != null) {
            Http3Exchange next = ex.takeNext();
            ex.takeNext(null);
            int bits = ex.takeEvents();
            if (ex.finished || closing) {
                writer.discard(ex);
            } else {
                if ((bits & Http3Exchange.EV_RESUME_READ) != 0) reader.resume(ex, now);
                // Before the response: a 100 (Continue) can't follow it.
                if ((bits & Http3Exchange.EV_CONTINUE) != 0) writer.sendContinue(ex, now);
                if ((bits & Http3Exchange.EV_RESPONSE) != 0) writer.respond(ex, now);
                if ((bits & Http3Exchange.EV_BODY) != 0) writer.pumpBody(ex, now);
            }
            ex = next;
        }
    }

    /** Resumes streams whose send capacity grew (or that the peer stopped). */
    private void drainWritable(long now) {
        long sid;
        while (blockedStreams > 0 && (sid = quiche.writableNext()) >= 0) {
            Http3Stream s = streamFor(sid);
            if (s == null || !s.blocked) continue;
            if (s instanceof Http3Exchange ex) {
                writer.resume(ex, now);
            } else {
                drainPending(s, now);
            }
        }
    }

    private Http3Stream streamFor(long sid) {
        if ((sid & 0x3) == 0) return exchanges.get(sid);
        if (sid == control.control.id) return control.control;
        if (sid == control.qpackEncoder.id) return control.qpackEncoder;
        if (sid == control.qpackDecoder.id) return control.qpackDecoder;
        return null;
    }

    // ---- writes ---------------------------------------------------------------------------

    /** Control-stream output (for {@link Http3ControlStreams}). */
    @Override
    public boolean write(Http3Stream s, byte[] b, int off, int len, boolean fin) {
        return write(s, b, off, len, fin, true, System.nanoTime());
    }

    @Override
    public void stopSending(long streamId, long errorCode) {
        quiche.streamShutdown(streamId, Quiche.QUICHE_SHUTDOWN_READ, errorCode);
    }

    /**
     * Hands {@code b[off, off + len)} to quiche on {@code s}, deferring what
     * it doesn't take behind earlier deferred bytes. {@code copy}: the
     * array is reused by the caller, so deferred bytes are copied (else it
     * is referenced, e.g. a response body). False when the stream can no
     * longer take data (reset, stopped, not openable).
     */
    boolean write(Http3Stream s, byte[] b, int off, int len, boolean fin, boolean copy, long now) {
        if (s.sendClosed) return false;
        if (s.hasPending()) {
            defer(s, b, off, len, fin, copy);
            return true;
        }
        long rc = quiche.streamSend(s.id, b, off, len, fin);
        if (rc == Quiche.QUICHE_ERR_DONE) rc = 0;
        // A stream of ours the peer's stream limit doesn't allow yet: the
        // caller retries once credit arrives; the stream isn't dead.
        if (rc == Quiche.QUICHE_ERR_STREAM_LIMIT) return false;
        if (rc < 0) {
            sendFailed(s, rc);
            return false;
        }
        if (rc == len) {
            if (fin) s.sendClosed = true;
            return true;
        }
        defer(s, b, off + (int) rc, len - (int) rc, fin, copy);
        markBlocked(s, now);
        return true;
    }

    private static void defer(Http3Stream s, byte[] b, int off, int len, boolean fin, boolean copy) {
        if (copy) {
            byte[] own = new byte[len];
            System.arraycopy(b, off, own, 0, len);
            s.enqueue(new Http3Stream.Pending(own, 0, len, fin));
        } else {
            s.enqueue(new Http3Stream.Pending(b, off, len, fin));
        }
    }

    /** Retries {@code s}'s deferred bytes; false when the stream failed. */
    boolean drainPending(Http3Stream s, long now) {
        Http3Stream.Pending p;
        while ((p = s.pendingHead) != null) {
            long rc = quiche.streamSend(s.id, p.buf, p.off, p.len, p.fin);
            if (rc == Quiche.QUICHE_ERR_DONE || rc == 0) {
                if (p.len > 0) return true;
                rc = 0;
            }
            if (rc < 0) {
                s.clearPending();
                unmarkBlocked(s);
                sendFailed(s, rc);
                return false;
            }
            if (rc > 0) s.writeProgressNanos = now;
            p.off += (int) rc;
            p.len -= (int) rc;
            s.pendingBytes -= rc;
            if (p.len > 0) return true;
            if (p.fin) s.sendClosed = true;
            s.pendingHead = p.next;
            if (s.pendingHead == null) s.pendingTail = null;
        }
        unmarkBlocked(s);
        return true;
    }

    private void sendFailed(Http3Stream s, long rc) {
        s.sendClosed = true;
        // Stopped / reset by the peer is routine; anything else is ours.
        if (rc != Quiche.QUICHE_ERR_STREAM_STOPPED && rc != Quiche.QUICHE_ERR_STREAM_RESET
                && rc != Quiche.QUICHE_ERR_INVALID_STREAM_STATE) {
            INTERNAL_FAILURES.log("h3 stream_send stream=" + s.id + " rc=" + rc);
        }
    }

    void markBlocked(Http3Stream s, long now) {
        if (s.blocked) return;
        s.blocked = true;
        s.writeProgressNanos = now;
        blockedStreams++;
        if (writeTimeoutNanos > 0 && writeCheckAt == NONE) writeCheckAt = now + writeTimeoutNanos;
    }

    void unmarkBlocked(Http3Stream s) {
        if (!s.blocked) return;
        s.blocked = false;
        blockedStreams--;
    }

    // ---- request stream lifecycle ------------------------------------------------------------

    /** Registers a new request stream. */
    void addExchange(Http3Exchange ex) {
        exchanges.put(ex.id, ex);
        int n = exchanges.size();
        if (n > exchangesPeak) exchangesPeak = n;
    }

    /** A request stream entered its header phase (first byte). */
    void headerPhaseStarted(Http3Exchange ex) {
        if (headerTimeoutNanos > 0 && headerCheckAt == NONE) headerCheckAt = ex.firstByteNanos + headerTimeoutNanos;
    }

    /**
     * Ends an exchange whose stream is done (both directions, or reset):
     * forgets it and reports the request.
     */
    void finish(Http3Exchange ex, long now) {
        if (ex.finished) return;
        ex.finished = true;
        // Whatever direction is still open is terminated, so quiche can
        // collect the stream and hand the peer its credit back.
        if (ex.readPhase != Http3Exchange.READ_DONE) {
            quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_READ, Http3ConnectionException.H3_NO_ERROR);
            ex.readPhase = Http3Exchange.READ_DONE;
        }
        if (!ex.sendClosed) {
            quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_WRITE,
                Http3ConnectionException.H3_REQUEST_CANCELLED);
            ex.sendClosed = true;
        }
        ex.clearPending();
        exchanges.remove(ex.id);
        if (recentStreams != null) recentStreams[recentCount++ & (RECENT_STREAMS - 1)] = ex.id;
        unmarkBlocked(ex);
        reader.release(ex);
        if (ex.pipe != null) {
            ex.pipe.signalTruncated();
            ex.pipe.discard();
        }
        if (exchanges.isEmpty()) idleSince = now;
        writer.completed(ex);
    }

    /** Ends an exchange whose read and send sides are both complete. */
    void maybeFinish(Http3Exchange ex, long now) {
        if (!ex.finished && ex.sendClosed && !ex.hasPending()
                && ex.readPhase == Http3Exchange.READ_DONE) {
            finish(ex, now);
        }
    }

    /**
     * Stream error (RFC 9114 §8): resets {@code ex} in both directions with
     * {@code code}; nobody receives a response.
     */
    void resetStream(Http3Exchange ex, long code, long now) {
        quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_READ, code);
        quiche.streamShutdown(ex.id, Quiche.QUICHE_SHUTDOWN_WRITE, code);
        ex.sendClosed = true;
        ex.clearPending();
        ex.readPhase = Http3Exchange.READ_DONE;
        ex.abandon();
        finish(ex, now);
    }

    /**
     * The peer reset the sending side of a request stream. Counted against
     * the rapid-reset budget; over it, the connection closes with
     * H3_EXCESSIVE_LOAD.
     */
    boolean peerReset() {
        int cap = config.http3StreamResetLimit;
        if (cap <= 0) return true;
        long now = System.nanoTime();
        resetTokens = Math.min(cap, resetTokens + (double) (now - resetTokensAt) * cap / RESET_REFILL_NANOS);
        resetTokensAt = now;
        if (resetTokens < 1) {
            listener.protocolError("rapid-reset");
            closeWithError(new Http3ConnectionException(Http3ConnectionException.H3_EXCESSIVE_LOAD,
                "stream reset rate exceeded " + cap + " per 30 s"));
            return false;
        }
        resetTokens -= 1;
        return true;
    }

    // ---- application timers ----------------------------------------------------------------------

    private void appTimers(long now, boolean packets) {
        if (headerCheckAt != NONE && now - headerCheckAt >= 0) checkHeaderTimeouts(now);
        if (writeCheckAt != NONE && now - writeCheckAt >= 0) checkWriteTimeouts(now);
        if (stopCheckAt != NONE && now - stopCheckAt >= 0) {
            stopCheckAt = NONE;
            writer.checkStoppedBodies(now);
        }
        if (packets && stopCheckAt == NONE && writer.idleBodies() > 0) stopCheckAt = now + STOP_CHECK_NANOS;
        if (exchangesPeak > EXCHANGES_KEPT && exchanges.isEmpty() && now - idleSince >= IDLE_RELEASE_NANOS) {
            exchanges = new Long2ObjectHashMap<>();
            exchangesPeak = 0;
        }
        if (established && !closing && !draining && idleNanos > 0 && exchanges.isEmpty()
                && now - idleSince >= idleNanos) {
            // :idle-timeout with no request in flight: quiche's idle timer
            // can't see this when the peer keeps the path alive with PINGs.
            startDrain();
        }
    }

    private static final int SCAN_HEADERS = 0;
    private static final int SCAN_WRITES = 1;
    private int scanKind;
    private long scanNow;
    private long scanNext;
    private int scanCount;
    // One reusable visitor for the timer scans (rare: at most once per timeout period).
    private final Long2ObjectHashMap.EntryConsumer<Http3Exchange> scanner = this::scanOne;

    private void scanOne(long id, Http3Exchange ex) {
        long due;
        if (scanKind == SCAN_HEADERS) {
            if (ex.readPhase != Http3Exchange.READ_HEADERS) return;
            due = ex.firstByteNanos + headerTimeoutNanos;
        } else {
            if (!ex.blocked) return;
            due = ex.writeProgressNanos + writeTimeoutNanos;
        }
        if (scanNow - due >= 0) {
            long[] expired = loop.scanIds;
            if (scanCount < expired.length) expired[scanCount++] = id;
        } else {
            scanNext = Math.min(scanNext, due);
        }
    }

    /** Collects expired exchanges into the loop's {@code scanIds}; returns the next due time. */
    private long scan(int kind, long now) {
        scanKind = kind;
        scanNow = now;
        scanNext = NONE;
        scanCount = 0;
        exchanges.forEach(scanner);
        // More expired than fit: look again right after these are handled.
        return scanCount == loop.scanIds.length ? now : scanNext;
    }

    /** {@code :header-timeout}: requests whose header section isn't complete in time are refused. */
    private void checkHeaderTimeouts(long now) {
        headerCheckAt = scan(SCAN_HEADERS, now);
        int n = scanCount;
        long[] expired = loop.scanIds;
        for (int i = 0; i < n; i++) {
            Http3Exchange ex = exchanges.get(expired[i]);
            if (ex == null) continue;
            listener.protocolError("header-timeout");
            PEER_FAILURES.log("h3 request header section timed out stream=" + ex.id);
            resetStream(ex, Http3ConnectionException.H3_REQUEST_REJECTED, now);
        }
    }

    /**
     * {@code :write-timeout}: a stream whose waiting bytes made no progress
     * for the timeout (the peer stopped reading it) is reset and its
     * streamed body producer fails.
     */
    private void checkWriteTimeouts(long now) {
        writeCheckAt = scan(SCAN_WRITES, now);
        int n = scanCount;
        long[] expired = loop.scanIds;
        for (int i = 0; i < n; i++) {
            Http3Exchange ex = exchanges.get(expired[i]);
            if (ex == null) continue;
            listener.protocolError("write-timeout");
            PEER_FAILURES.log("h3 response write timed out stream=" + ex.id);
            resetStream(ex, Http3ConnectionException.H3_REQUEST_CANCELLED, now);
        }
    }

    // ---- closing ----------------------------------------------------------------------------------

    /** Connection error (RFC 9114 §8): CONNECTION_CLOSE with its code; no more streams are read. */
    void closeWithError(Http3ConnectionException e) {
        if (closing) return;
        PEER_FAILURES.log("h3 closing connection code=0x" + Long.toHexString(e.errorCode()) + ": "
            + e.getMessage());
        listener.protocolError("protocol-error");
        closing = true;
        // An empty reason: some peers (h3spec) reject non-empty ones.
        quiche.close(true, e.errorCode(), NO_REASON);
        abandonAll();
    }

    /** An unexpected failure processing this connection: H3_INTERNAL_ERROR, then freed. */
    void internalError() {
        if (gone) return;
        try {
            if (!closing) {
                closing = true;
                quiche.close(true, Http3ConnectionException.H3_INTERNAL_ERROR, NO_REASON);
            }
            flush(System.nanoTime());
        } catch (Throwable ignored) {
        }
        destroyNow = true;
    }

    /**
     * Graceful close (RFC 9114 §5.2), in two GOAWAYs. The first carries
     * the largest stream id and refuses nothing: requests the client sent
     * before it learnt of the drain still arrive and are served. One round
     * trip later (twice the RTT estimate, within bounds) the second names
     * the first request that won't be processed; newer ones are refused
     * (H3_REQUEST_REJECTED). Once every request below that id arrived and
     * was answered, the connection closes.
     */
    void startDrain() {
        if (gone || draining || closing) return;
        draining = true;
        if (!established) {
            closeNow();
            return;
        }
        sendGoaway(GOAWAY_ANY);
        trackRecentStreams();
        long rtt = quiche.rttNanos();
        long grace = Math.max(GOAWAY_GRACE_MIN_NANOS, Math.min(GOAWAY_GRACE_MAX_NANOS, 2 * Math.max(rtt, 0)));
        finalGoawayAt = System.nanoTime() + grace;
    }

    /**
     * Starts recording finished request streams for the drain, seeded with
     * the highest stream ids already finished (those not in flight).
     */
    private void trackRecentStreams() {
        recentStreams = new long[RECENT_STREAMS];
        for (long sid = highestRequestStream; sid >= 0 && recentCount < RECENT_STREAMS; sid -= 4) {
            if (exchanges.get(sid) == null) recentStreams[recentCount++] = sid;
        }
    }

    private void sendGoaway(long id) {
        // Without our control stream (no uni-stream credit yet) a GOAWAY
        // can't be announced; draining still refuses newer requests.
        if (control.isOpen() || control.open()) control.sendGoaway(id);
    }

    private void closeGracefully() {
        closing = true;
        quiche.close(true, Http3ConnectionException.H3_NO_ERROR, NO_REASON);
    }

    /** Closes now: CONNECTION_CLOSE (H3_NO_ERROR) is sent with the next flush, then the state is freed. */
    void closeNow() {
        if (gone || destroyNow) return;
        if (!closing) {
            closing = true;
            quiche.close(true, Http3ConnectionException.H3_NO_ERROR, NO_REASON);
        }
        abandonAll();
        destroyNow = true;
    }

    private void abandonAll() {
        long now = System.nanoTime();
        writer.abandonAll(now);
    }

    /**
     * Frees everything (loop thread, once). Handlers still running find
     * their exchange abandoned. The native connection and its configuration
     * reference are freed even when abandoning the requests fails: a second
     * call is a no-op, so nothing else would free them.
     */
    void destroy() {
        if (gone) return;
        gone = true;
        try {
            writer.abandonAll(System.nanoTime());
            Http3Exchange ex = signalled.takeAll();
            while (ex != null) {
                Http3Exchange next = ex.takeNext();
                ex.takeNext(null);
                ex.takeEvents();
                writer.discard(ex);
                ex = next;
            }
        } finally {
            try {
                quiche.free();
            } finally {
                quicheConfig.release();
            }
        }
        if (openedNanos != 0) {
            listener.service.connectionClosed(Http3Listener.PROTOCOL, remote, System.nanoTime() - openedNanos);
        }
        if (jfr != null) {
            jfr.protocol = Http3Listener.PROTOCOL;
            jfr.remoteAddress = remote.getHostAddress();
            jfr.commit();
        }
    }

    // ---- accessors for the reader / writer ------------------------------------------------------------

    /** True once a request body was buffered on this connection (its body budget exists). */
    boolean bodyBudgetUsed() {
        return bodyBudget != null;
    }

    /** What this connection's request-body pipes may hold together: its connection window (loop thread). */
    MemoryBudget bodyBudget() {
        MemoryBudget b = bodyBudget;
        if (b == null) {
            b = new MemoryBudget(config.http3InitialMaxDataBytes);
            bodyBudget = b;
        }
        return b;
    }

    Http3ControlStreams control() { return control; }

    boolean draining() { return draining; }

    boolean closing() { return closing; }
}

// ABOUTME: One HTTP/3 event loop: a platform thread owning a shard of QUIC connections, receiving
// ABOUTME: and sending UDP in batches, feeding quiche inline, and running the shard's timers.
package com.s_exp.enso.http3;

import com.s_exp.enso.core.HttpDates;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.RequestHead;
import com.s_exp.enso.http3.qpack.QpackDecoder;
import com.s_exp.enso.http3.qpack.QpackFieldSection;
import com.s_exp.enso.quiche.InitialClose;
import com.s_exp.enso.quiche.NativeBuffer;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.QuicheConfig;
import com.s_exp.enso.quiche.QuicheConnection;
import com.s_exp.enso.quiche.Records;
import com.s_exp.enso.quiche.UdpSocket;
import com.s_exp.enso.quiche.VersionNegotiation;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An event loop. Every connection belongs to exactly one loop (the index
 * in the first byte of its connection ids) and every quiche call for it
 * happens on that loop's thread, so quiche's non-thread-safe connections
 * need no locking and request handling never touches them.
 *
 * <p>Per iteration: receive a batch of datagrams (recvmmsg on Linux) from
 * this loop's socket straight into a direct slab, route each by
 * connection id (forwarding the rare one owned by another loop to it),
 * feed it to quiche; take datagrams forwarded by other loops and the
 * connections signalled by handler threads; fire expired timers; then
 * process every connection that had any of this, and let quiche write its
 * packets into the send slab, sent in batches (sendmmsg, UDP GSO). Then
 * park in poll() on the socket and the loop's wake-up channel until the
 * next timer.
 *
 * <p>Handlers run on virtual threads and reach the loop only through
 * {@link Http3Exchange#signal}: a lock-free push and, when the loop is
 * parked, one write to its wake-up channel.
 *
 * <p>Failure containment: a failure handling one connection (a datagram,
 * a timer, its processing) closes that connection with H3_INTERNAL_ERROR
 * and nothing else; a failure in a loop-wide step is logged and the
 * iteration goes on. Anything that still escapes (a VirtualMachineError,
 * a broken invariant of the loop itself) reaches the supervisor in
 * {@link #run}: logged loudly, reported as an "event-loop-failure" protocol
 * error, every connection of the loop closed, and the loop restarted on
 * the same thread after a short pause, so the listener never silently
 * loses a shard.
 */
final class Http3Loop implements Runnable {

    private static final Logger LOG = Logger.getLogger(Http3Loop.class.getName());
    private static final LogLimiter FAILURES = new LogLimiter(LOG, Level.WARNING);
    private static final LogLimiter LOOP_FAILURES = new LogLimiter(LOG, Level.SEVERE);
    private static final LogLimiter DROPS = new LogLimiter(LOG, Level.FINE);
    // Pause before a failed loop restarts, so a failure that persists
    // doesn't spin.
    private static final long RESTART_PAUSE_NANOS = 100_000_000L;

    private static final VarHandle WAKE_REQUESTED;

    static {
        try {
            WAKE_REQUESTED = MethodHandles.lookup().findVarHandle(Http3Loop.class, "wakeRequested", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** Datagrams per receive call. */
    static final int RECV_BATCH = 32;
    /** Receive calls per iteration before other work gets a turn. */
    private static final int RECV_ROUNDS = 4;
    /** Packets per send call. */
    private static final int SEND_BATCH = 64;
    /** Datagrams other loops may queue here before more are dropped. */
    private static final int INBOX_SLOTS = 512;
    // RFC 9000 §14.1: a client Initial travels in a datagram of at least
    // 1200 bytes; smaller ones are discarded. Also the floor for answering
    // with Version Negotiation or Retry, keeping those replies below the
    // 3x anti-amplification limit for a spoofed source.
    static final int MIN_INITIAL_DATAGRAM = 1200;
    // RFC 9000 §7.2: the Destination Connection ID a client picks for its
    // first Initial is at least 8 bytes; shorter ones are dropped.
    private static final int MIN_CLIENT_DCID = 8;
    // quiche_header_info packet types.
    private static final int TYPE_INITIAL = 1;
    private static final int TYPE_SHORT = 5;
    private static final int TYPE_VERSION_NEGOTIATION = 6;

    final Http3Listener listener;
    final int index;
    final int loops;
    private final UdpSocket recvSocket;
    private final UdpSocket sendSocket;
    private final UdpSocket.Waker waker;
    final Thread thread;

    // Receive: RECV_BATCH slots of slotSize bytes, records after them.
    private final int slotSize;
    private final NativeBuffer recvSlab;
    private final NativeBuffer recvMeta;

    // Send: packets appended to the slab, one SEND record each.
    final int maxPayload;
    final NativeBuffer sendSlab;
    final NativeBuffer sendMeta;
    /** Java view of {@link #sendMeta}. */
    final ByteBuffer sendRecords;
    private int sendCount;
    private int sendOff;
    private int sendFlags;
    private boolean sendBlocked;

    // Accept-path scratch.
    private final NativeBuffer hdr = NativeBuffer.allocate(Records.HDR_LEN);
    // This loop's own generator: the platform default (NativePRNG on Linux)
    // serialises every caller on one lock.
    private final SecureRandom rng = loopRandom();
    // The arbitrary bits of Version Negotiation's first byte.
    private int vnBits;

    // Per-thread scratch for the connections of this loop: one copy per
    // loop rather than per connection, which an idle connection would hold.
    final byte[] recvBuf = new byte[32 * 1024];
    /** Exchange ids collected by a connection's timer scans (header, write, stop checks). */
    final long[] scanIds = new long[256];
    /** Request fields as decoded (name, value pairs) before they become the Ring header map. */
    Object[] fields = new Object[32];
    // Gathering buffers for header sections split across reads, reused
    // by the loop's connections.
    private final byte[][] fieldPool = new byte[FIELD_POOL_MAX][];
    private int fieldPoolSize;
    /** Gathering buffers of this size are pooled; larger ones are dropped. */
    static final int POOLED_FIELD_BUF = 4096;
    private static final int FIELD_POOL_MAX = 8;
    final RequestHead requestHead = new RequestHead();
    final QpackDecoder qpack = new QpackDecoder();
    final HeadPool heads = new HeadPool(64);
    private ByteBuffer frame = ByteBuffer.allocate(4096);
    private static final int FRAME_KEEP_MAX = 256 * 1024;
    private String dateValue;
    private byte[] dateField;

    // Connections of this loop.
    // Replaced (with the timers) when a failed loop restarts: its state
    // can't be trusted.
    private ConnectionIds.Map<Http3Connection> conns = new ConnectionIds.Map<>(256);
    // Client-chosen destination ids of handshaking connections (the
    // client's Initials before it learnt ours).
    private final HashMap<AliasKey, Http3Connection> aliases = new HashMap<>();
    private final AliasKey lookup = new AliasKey();
    private DeadlineHeap<Http3Connection> timers = new DeadlineHeap<>();
    private Http3Connection[] dirty = new Http3Connection[64];
    private int dirtyCount;
    private final SignalStack<Http3Connection> ready = new SignalStack<>();
    private final Inbox inbox;

    private volatile boolean parked;
    // False when the last poll found the socket not readable: a receive
    // call would only return EAGAIN. True whenever the loop didn't poll.
    private boolean mayReceive = true;
    @SuppressWarnings("unused") // accessed through WAKE_REQUESTED
    private volatile int wakeRequested;
    private volatile boolean stopRequested;
    private volatile boolean drainRequested;
    private volatile boolean forceCloseRequested;

    Http3Loop(Http3Listener listener, int index, int loops, UdpSocket recvSocket, UdpSocket sendSocket,
              UdpSocket.Waker waker, int maxPayload, int sendFlags) throws java.io.IOException {
        this.listener = listener;
        this.index = index;
        this.loops = loops;
        this.recvSocket = recvSocket;
        this.sendSocket = sendSocket;
        this.waker = waker;
        this.maxPayload = maxPayload;
        this.sendFlags = sendFlags;
        // Room for any datagram a client sends before it learns our
        // max_udp_payload_size (RFC 9000 §14.1: Initials sized to its own
        // guess, in practice up to the path MTU); larger ones are counted
        // and dropped (MSG_TRUNC).
        this.slotSize = Math.max(2048, (maxPayload + 63) & ~63);
        this.recvSlab = recvSocket == null ? null : NativeBuffer.allocate(slotSize * RECV_BATCH);
        this.recvMeta = recvSocket == null ? null
            : NativeBuffer.allocate(Records.RECV_META_LEN * (RECV_BATCH + 1));
        if (recvSocket != null) {
            recvSocket.localAddress(recvMeta, Records.RECV_META_LEN * RECV_BATCH);
        }
        this.sendSlab = NativeBuffer.allocate(maxPayload * SEND_BATCH);
        this.sendMeta = NativeBuffer.allocate(Records.SEND_HEADER_LEN + Records.SEND_META_LEN * SEND_BATCH);
        this.sendRecords = sendMeta.buffer;
        this.inbox = new Inbox(INBOX_SLOTS, slotSize);
        this.thread = Thread.ofPlatform().name("enso-h3-loop-" + index).daemon(true).unstarted(this);
    }

    /** A DRBG instance of its own, seeded from the platform; the default generator when DRBG is missing. */
    private static SecureRandom loopRandom() {
        try {
            return SecureRandom.getInstance("DRBG");
        } catch (java.security.NoSuchAlgorithmException e) {
            return new SecureRandom();
        }
    }

    // ---- cross-thread entry points ---------------------------------------

    /** Wakes the loop if it is parked (or about to). Any thread. */
    void wake() {
        if (parked && WAKE_REQUESTED.compareAndSet(this, 0, 1)) waker.signal();
    }

    /** A connection of this loop has events (any thread). */
    void schedule(Http3Connection c) {
        ready.push(c);
        wake();
    }

    /** Asks every connection to drain (RFC 9114 §5.2 GOAWAY). Any thread. */
    void requestDrain() {
        drainRequested = true;
        wake();
    }

    /** Asks every connection to close now. Any thread. */
    void requestForceClose() {
        forceCloseRequested = true;
        wake();
    }

    /** Stops the loop: remaining connections are closed and freed. Any thread. */
    void requestStop() {
        stopRequested = true;
        wake();
    }

    // ---- the loop --------------------------------------------------------

    /** The supervisor: runs the loop, and restarts it after a failure that escaped every guard. */
    @Override
    public void run() {
        try {
            while (!stopRequested) {
                try {
                    loop();
                } catch (Throwable t) {
                    loopFailed(t);
                }
            }
        } finally {
            closeAll();
        }
    }

    private void loop() {
        while (true) {
            long now = System.nanoTime();
            int received = 0;
            if (recvSocket != null && mayReceive) {
                try {
                    received = receive(now);
                } catch (Throwable t) {
                    phaseFailed("receive", t);
                }
            }
            try {
                drainInbox(now);
            } catch (Throwable t) {
                phaseFailed("inbox", t);
            }
            drainReady();
            if (drainRequested) {
                drainRequested = false;
                forEachConnection(DRAIN);
            }
            if (forceCloseRequested) {
                forceCloseRequested = false;
                forEachConnection(FORCE_CLOSE);
            }
            runTimers(now);
            processDirty(now);
            try {
                flushSend();
            } catch (Throwable t) {
                phaseFailed("send", t);
            }
            if (stopRequested) return;
            if (received == RECV_BATCH * RECV_ROUNDS && !sendBlocked) continue;
            park(now);
        }
    }

    /** A loop-wide step failed: logged, the iteration goes on. Fatal errors go to the supervisor. */
    private void phaseFailed(String phase, Throwable t) {
        if (t instanceof VirtualMachineError e) throw e;
        FAILURES.log("h3 event loop " + index + " " + phase + " failed", t);
    }

    /** One connection's handling failed: only that connection closes (H3_INTERNAL_ERROR). */
    private void connectionFailed(Http3Connection c, String what, Throwable t) {
        if (t instanceof VirtualMachineError e) throw e;
        FAILURES.log("h3 connection " + what + " failed", t);
        c.internalError();
        markDirty(c);
    }

    /**
     * A failure escaped the loop: fail loudly, close the loop's connections
     * (their state can't be trusted) and let {@link #run} restart it.
     */
    private void loopFailed(Throwable t) {
        // Nothing here may escape: the supervisor must get to the restart.
        try {
            listener.stats.loopRestarts.increment();
            LOOP_FAILURES.log("h3 event loop " + index + " failed; closing its connections and restarting it", t);
            listener.protocolError("event-loop-failure");
        } catch (Throwable ignored) {
            // Out of memory reporting it: the restart matters more.
        }
        try {
            closeAll();
        } catch (Throwable inner) {
            LOOP_FAILURES.log("h3 event loop " + index + " cleanup failed", inner);
        }
        resetState();
        if (!stopRequested) {
            java.util.concurrent.locks.LockSupport.parkNanos(this, RESTART_PAUSE_NANOS);
        }
    }

    /**
     * After a failure: the restarted loop starts from fresh tables, timers
     * and an empty send batch (whatever a broken step left half-done in
     * them is dropped; closeAll freed every connection they named).
     */
    private void resetState() {
        conns = new ConnectionIds.Map<>(256);
        aliases.clear();
        timers = new DeadlineHeap<>();
        dirty = new Http3Connection[64];
        dirtyCount = 0;
        sendCount = 0;
        sendOff = 0;
        sendBlocked = false;
        mayReceive = true;
    }

    private void park(long now) {
        try {
            parkUntilWork();
        } catch (Throwable t) {
            phaseFailed("poll", t);
        }
    }

    private void parkUntilWork() {
        long timeout = -1;
        Http3Connection next = timers.peek();
        if (next != null) timeout = Math.max(0, next.deadline() - System.nanoTime());
        parked = true;
        mayReceive = true;
        try {
            // Dirty connections wait for the socket when sending blocked.
            if (!ready.isEmpty() || !inbox.isEmpty() || (dirtyCount > 0 && !sendBlocked)
                    || stopRequested || drainRequested || forceCloseRequested) {
                return;
            }
            int bits = waker.poll(recvSocket, sendSocket, sendBlocked, timeout);
            if (bits < 0) FAILURES.log("h3 poll failed (errno " + -bits + ")");
            mayReceive = bits < 0 || (bits & UdpSocket.Waker.READABLE) != 0;
            if ((bits & UdpSocket.Waker.WRITABLE) != 0) sendBlocked = false;
        } finally {
            parked = false;
            WAKE_REQUESTED.setVolatile(this, 0);
        }
    }

    // ---- receive & route -------------------------------------------------

    private int receive(long now) {
        int total = 0;
        for (int round = 0; round < RECV_ROUNDS; round++) {
            int n = recvSocket.recvBatch(recvSlab, slotSize, RECV_BATCH, recvMeta);
            if (n <= 0) {
                if (n < 0) FAILURES.log("h3 receive failed (errno " + -n + ")");
                break;
            }
            ByteBuffer m = recvMeta.buffer;
            for (int i = 0; i < n; i++) {
                int rec = i * Records.RECV_META_LEN;
                onDatagram(recvSlab, i * slotSize, m.getInt(rec + Records.RECV_LEN),
                           m.getInt(rec + Records.RECV_FLAGS), recvMeta, rec, now);
            }
            total += n;
            if (n < RECV_BATCH) break;
        }
        return total;
    }

    /** Routes one datagram: its connection, the owning loop, or the accept path. */
    private void onDatagram(NativeBuffer packets, int off, int len, int flags, NativeBuffer meta, int rec,
                            long now) {
        ByteBuffer buf = packets.buffer;
        if ((flags & Records.RECV_FLAG_TRUNCATED) != 0) {
            listener.stats.truncated.increment();
            return;
        }
        if (len < 1) return;
        int b0 = buf.get(off) & 0xFF;
        boolean longHeader = (b0 & 0x80) != 0;
        int dcidOff;
        int dcidLen;
        if (!longHeader) {
            if (len < 1 + ConnectionIds.LENGTH) return;
            dcidOff = off + 1;
            dcidLen = ConnectionIds.LENGTH;
        } else {
            if (len < 7) return;
            int version = VersionNegotiation.version(buf, off);
            if (version != Quiche.QUICHE_PROTOCOL_VERSION && !QuicheConnection.versionIsSupported(version)) {
                // RFC 8999 §6: whatever its connection ids (up to 255
                // bytes, possibly empty) and the other bits of its first
                // byte. Answered by the receiving loop: there is no
                // connection to route to. Never a VN (version 0) itself.
                if (version != 0 && len >= MIN_INITIAL_DATAGRAM) negotiateVersion(packets, off, len, meta, rec);
                return;
            }
            dcidLen = buf.get(off + 5) & 0xFF;
            if (dcidLen == 0 || dcidLen > 20 || len < 6 + dcidLen) return;
            dcidOff = off + 6;
        }
        // Initial and 0-RTT packets (long header, type bits 00 / 01) of a
        // client that doesn't know our id yet. With per-loop sockets the
        // kernel spread them by 4-tuple (an id the client chose must not
        // pick the loop): accepted where they land.
        boolean clientChosen = longHeader && (b0 & 0x20) == 0;
        if (loops > 1 && (listener.sharedSocket || !clientChosen)) {
            int owner = ConnectionIds.owner(buf.get(dcidOff), loops);
            if (owner != index) {
                listener.loops[owner].forward(buf, off, len, meta.buffer, rec);
                return;
            }
        }
        Http3Connection c = null;
        if (dcidLen == ConnectionIds.LENGTH) c = conns.get(buf, dcidOff);
        if (c == null && longHeader) c = aliases.get(lookup.view(buf, dcidOff, dcidLen));
        if (c != null) {
            try {
                c.recv(packets, off, len, meta, rec);
            } catch (Throwable t) {
                connectionFailed(c, "receive", t);
            }
            markDirty(c);
            return;
        }
        if (clientChosen) {
            try {
                accept(packets, off, len, meta, rec, now);
            } catch (Throwable t) {
                phaseFailed("accept", t);
            }
        }
        // Anything else names no connection: dropped, no stateless reset.
    }

    /** Called by another loop: queues a datagram this loop owns. */
    private void forward(ByteBuffer buf, int off, int len, ByteBuffer meta, int rec) {
        listener.stats.forwarded.increment();
        if (inbox.offer(buf, off, len, meta, rec)) {
            wake();
        } else {
            listener.stats.inboxDrops.increment();
            DROPS.log("h3 loop " + index + " inbox full, datagram dropped");
        }
    }

    private void drainInbox(long now) {
        int n = inbox.snapshot();
        for (int i = 0; i < n; i++) {
            int slot = inbox.slot(i);
            int rec = slot * Records.RECV_META_LEN;
            onDatagram(inbox.slab, slot * inbox.slotSize, inbox.meta.buffer.getInt(rec + Records.RECV_LEN), 0,
                       inbox.meta, rec, now);
        }
        inbox.release(n);
    }

    // ---- accept ------------------------------------------------------------

    /** A long-header packet for an unknown id: maybe a new connection. */
    private void accept(NativeBuffer buf, int off, int len, NativeBuffer meta, int rec, long now) {
        // Only a full-size client Initial may allocate state or get a reply.
        if (len < MIN_INITIAL_DATAGRAM) return;
        int rc = QuicheConnection.headerInfo(buf, off, len, ConnectionIds.LENGTH, hdr, 0);
        if (rc < 0) return;
        ByteBuffer h = hdr.buffer;
        int type = h.get(Records.HDR_TYPE);
        if (type == TYPE_SHORT || type == TYPE_VERSION_NEGOTIATION) return;
        byte[] scid = bytes(h, Records.HDR_SCID, h.get(Records.HDR_SCID_LEN) & 0xFF);
        byte[] dcid = bytes(h, Records.HDR_DCID, h.get(Records.HDR_DCID_LEN) & 0xFF);
        int version = h.getInt(Records.HDR_VERSION);
        if (type != TYPE_INITIAL || !listener.accepting || dcid.length < MIN_CLIENT_DCID) return;
        int tokenLen = h.getInt(Records.HDR_TOKEN_LEN);
        if (tokenLen > 0 && loops > 1 && dcid.length == ConnectionIds.LENGTH) {
            // The Initial after our Retry is addressed to the id that loop
            // generated: the connection must live there. The same 4-tuple
            // hashes to the same socket, so this is rare (a client that
            // moved between its Initials).
            int owner = ConnectionIds.owner(dcid[0], loops);
            if (owner != index) {
                listener.loops[owner].forward(buf.buffer, off, len, meta.buffer, rec);
                return;
            }
        }
        Http3Listener.Admission a = listener.admit(h, tokenLen, meta.buffer, rec + Records.RECV_PEER, dcid);
        switch (a.verdict) {
            case Http3Listener.Admission.DROP -> {
                return;
            }
            case Http3Listener.Admission.RETRY -> {
                byte[] newScid = ConnectionIds.generate(rng, index, loops);
                byte[] token = listener.retryToken.mint(Records.socketAddress(meta.buffer, rec + Records.RECV_PEER),
                                                        dcid, newScid);
                if (ensureSendRoom()) {
                    writePacket(meta, rec, QuicheConnection.retry(scid, dcid, newScid, token, version,
                                                                   sendSlab, sendOff, maxPayload));
                }
                return;
            }
            case Http3Listener.Admission.INVALID_TOKEN -> {
                if (ensureSendRoom()) {
                    writePacket(meta, rec, InitialClose.invalidToken(dcid, scid, version, sendSlab.buffer,
                                                                    sendOff, maxPayload));
                }
                return;
            }
            default -> {
            }
        }
        // Accepted: a.odcid is the original id after a Retry (null without).
        byte[] cid;
        byte[] alias;
        if (a.odcid != null) {
            // The token binds the Retry's source id, which we generated.
            cid = dcid;
            alias = null;
        } else {
            cid = ConnectionIds.generate(rng, index, loops);
            while (conns.get(cid) != null) cid = ConnectionIds.generate(rng, index, loops);
            alias = dcid;
        }
        InetAddress remote = a.remote;
        QuicheConfig cfg = listener.acquireConfig();
        QuicheConnection q = QuicheConnection.accept(cfg, cid, a.odcid, meta,
                                                     rec + Records.RECV_LOCAL, rec + Records.RECV_PEER);
        if (q == null) {
            cfg.release();
            listener.admissionFailed(remote);
            return;
        }
        Http3Connection c = null;
        Throwable failure = null;
        try {
            c = new Http3Connection(this, q, cfg, cid, alias, scid, remote, now);
            // A retried Initial for a connection that exists can't get
            // here: that one would have been found first.
            if (conns.putIfAbsent(cid, c) != null) c = null;
        } catch (Throwable t) {
            c = null;
            failure = t;
        }
        if (c == null) {
            q.free();
            cfg.release();
            listener.admissionFailed(remote);
            if (failure != null) phaseFailed("accept", failure);
            return;
        }
        // Registered: from here a failure closes the connection like any
        // other, so its slot, timer and native state are given back.
        try {
            if (alias != null) aliases.put(new AliasKey(alias), c);
            listener.opened(c);
            c.recv(buf, off, len, meta, rec);
        } catch (Throwable t) {
            connectionFailed(c, "accept", t);
        }
        markDirty(c);
    }

    /** Answers the unsupported-version long header {@code buf[off, off + len)} with Version Negotiation. */
    private void negotiateVersion(NativeBuffer buf, int off, int len, NativeBuffer meta, int rec) {
        // RFC 9000 §6.1: never for a short header (none reaches here).
        if (!ensureSendRoom()) return;
        writePacket(meta, rec, VersionNegotiation.write(buf.buffer, off, len, vnBits++, sendSlab.buffer, sendOff,
                                                        maxPayload));
    }

    private static byte[] bytes(ByteBuffer b, int off, int len) {
        byte[] out = new byte[len];
        b.get(off, out);
        return out;
    }

    // ---- connections -------------------------------------------------------

    void markDirty(Http3Connection c) {
        if (c.dirty) return;
        c.dirty = true;
        if (dirtyCount == dirty.length) dirty = Arrays.copyOf(dirty, dirtyCount * 2);
        dirty[dirtyCount++] = c;
    }

    private void drainReady() {
        Http3Connection c = ready.takeAll();
        while (c != null) {
            Http3Connection next = c.takeNext();
            c.takeNext(null);
            c.unschedule();
            // A handler may signal a connection the loop freed meanwhile
            // (it checked before the free): nothing to process.
            if (!c.isGone()) markDirty(c);
            c = next;
        }
    }

    private void runTimers(long now) {
        Http3Connection c;
        while ((c = timers.peek()) != null && c.deadline() - now <= 0) {
            timers.poll();
            try {
                c.onTimer(now);
            } catch (Throwable t) {
                connectionFailed(c, "timer", t);
            }
            markDirty(c);
        }
    }

    private void processDirty(long now) {
        int i = 0;
        for (; i < dirtyCount; i++) {
            if (sendBlocked) break;
            Http3Connection c = dirty[i];
            dirty[i] = null;
            c.dirty = false;
            boolean flushed = true;
            try {
                c.process(now);
                flushed = c.flush(now);
            } catch (Throwable t) {
                if (t instanceof VirtualMachineError e) throw e;
                FAILURES.log("h3 connection processing failed", t);
                c.internalError();
            }
            try {
                settle(c, now);
            } catch (Throwable t) {
                if (t instanceof VirtualMachineError e) throw e;
                FAILURES.log("h3 connection teardown failed", t);
                forget(c);
            }
            // The socket blocked mid-flush: quiche has more for this one.
            if (!flushed && !c.isGone()) markDirty(c);
        }
        if (i < dirtyCount) {
            // Sending blocked: the rest are processed once the socket drains.
            int left = dirtyCount - i;
            System.arraycopy(dirty, i, dirty, 0, left);
            Arrays.fill(dirty, left, dirtyCount, null);
            dirtyCount = left;
        } else {
            dirtyCount = 0;
        }
    }

    /** After processing: free a closed connection, else re-arm its timer. */
    private void settle(Http3Connection c, long now) {
        if (!c.settle(now)) {
            destroy(c);
            return;
        }
        if (c.armed()) {
            timers.update(c);
        } else {
            timers.remove(c);
        }
    }

    private void destroy(Http3Connection c) {
        if (c.closedReported) return;
        timers.remove(c);
        conns.remove(c.cid, c);
        unalias(c);
        try {
            c.destroy();
        } finally {
            listener.closed(c);
        }
    }

    /**
     * Drops a connection whose settling (or the loop) failed, so the loop
     * holds nothing of it: every step runs even when an earlier one throws.
     */
    private void forget(Http3Connection c) {
        try {
            timers.remove(c);
        } catch (Throwable ignored) {
        }
        try {
            conns.remove(c.cid, c);
            if (c.alias != null) aliases.remove(new AliasKey(c.alias), c);
        } catch (Throwable ignored) {
        }
        try {
            c.destroy();
        } catch (Throwable t) {
            FAILURES.log("h3 connection teardown failed", t);
        } finally {
            listener.closed(c);
        }
    }

    /** The connection completed its handshake: the client uses our id from now on. */
    void unalias(Http3Connection c) {
        if (c.alias != null) {
            aliases.remove(new AliasKey(c.alias), c);
            c.alias = null;
        }
    }

    private interface ConnectionAction {
        void apply(Http3Connection c);
    }

    private static final ConnectionAction DRAIN = Http3Connection::startDrain;
    private static final ConnectionAction FORCE_CLOSE = Http3Connection::closeNow;

    private void forEachConnection(ConnectionAction action) {
        Http3Connection[] all = connections();
        for (Http3Connection c : all) {
            try {
                action.apply(c);
            } catch (Throwable t) {
                connectionFailed(c, "shutdown", t);
            }
            markDirty(c);
        }
    }

    private Http3Connection[] connections() {
        java.util.ArrayList<Http3Connection> all = new java.util.ArrayList<>();
        conns.forEach(all::add);
        return all.toArray(new Http3Connection[0]);
    }

    /** On exit: every connection still here is closed (one CONNECTION_CLOSE flushed) and freed. */
    private void closeAll() {
        try {
            for (Http3Connection c : connections()) {
                try {
                    c.closeNow();
                    c.flush(System.nanoTime());
                } catch (Throwable t) {
                    FAILURES.log("h3 connection close failed", t);
                }
            }
            flushSend();
        } catch (Throwable t) {
            FAILURES.log("h3 final flush failed", t);
        }
        // Each step guarded: a broken timer entry or table must not keep a
        // connection (its quiche state, limiter slot, native credit) alive.
        for (Http3Connection c : connections()) forget(c);
        aliases.clear();
    }

    int connectionCount() {
        return conns.size();
    }

    // ---- send ----------------------------------------------------------------

    /**
     * Makes room for one more packet in the send slab, flushing if needed.
     * False when the socket can't take more right now.
     */
    boolean ensureSendRoom() {
        if (sendCount < SEND_BATCH && sendSlab.capacity - sendOff >= maxPayload) return true;
        flushSend();
        return sendCount < SEND_BATCH && sendSlab.capacity - sendOff >= maxPayload;
    }

    int sendOffset() { return sendOff; }

    int sendRecord() { return Records.SEND_HEADER_LEN + sendCount * Records.SEND_META_LEN; }

    /** Records the packet quiche just wrote at {@link #sendOffset()} (its addresses are in the record). */
    void commitPacket(int len) {
        int rec = sendRecord();
        sendRecords.putInt(rec + Records.SEND_OFF, sendOff);
        sendRecords.putInt(rec + Records.SEND_LEN, len);
        sendOff += len;
        sendCount++;
    }

    /** Appends a packet held aside ({@code record}: its SEND record, addresses included). */
    void commitPacket(byte[] packet, int len, byte[] record) {
        sendSlab.buffer.put(sendOff, packet, 0, len);
        sendRecords.put(sendRecord(), record, 0, Records.SEND_META_LEN);
        commitPacket(len);
    }

    /**
     * A server Initial closing with transport error {@code code}, answering
     * the datagram of {@code meta[rec]}: Initial keys from {@code keysDcid},
     * addressed to {@code clientScid}.
     */
    void sendInitialClose(int code, byte[] keysDcid, byte[] clientScid, NativeBuffer meta, int rec) {
        if (!ensureSendRoom()) return;
        writePacket(meta, rec, InitialClose.transportClose(code, keysDcid, clientScid,
            Quiche.QUICHE_PROTOCOL_VERSION, sendSlab.buffer, sendOff, maxPayload));
    }

    /** A stateless reply (Retry, Version Negotiation, close) to the datagram of {@code meta[rec]}. */
    private void writePacket(NativeBuffer meta, int rec, long rc) {
        if (rc <= 0) return;
        int r = sendRecord();
        Records.copyAddress(meta.buffer, rec + Records.RECV_PEER, sendRecords, r + Records.SEND_TO);
        Records.copyAddress(meta.buffer, rec + Records.RECV_LOCAL, sendRecords, r + Records.SEND_FROM);
        commitPacket((int) rc);
    }

    /** Sends what the slab holds; keeps the rest when the socket buffer is full. */
    void flushSend() {
        if (sendCount == 0) return;
        int n = sendSocket.sendBatch(sendSlab, sendMeta, sendCount, sendFlags);
        if (n < 0) {
            // A socket-level failure (or a batch the shim refused, which
            // sent nothing): the packets are lost, quiche's loss recovery
            // resends what matters.
            FAILURES.log("h3 send failed (" + (n == Quiche.SHIM_ERR_INVALID_ARGUMENT ? "invalid batch" : "errno " + -n)
                + "), " + sendCount + " packets dropped");
            n = sendCount;
        }
        int dropped = sendRecords.getInt(Records.SEND_STATUS_DROPPED);
        if (dropped > 0) {
            listener.stats.sendDrops.add(dropped);
            DROPS.log("h3 " + dropped + " packets dropped on send (errno "
                + sendRecords.getInt(Records.SEND_STATUS_ERRNO) + ")");
        }
        if ((sendRecords.getInt(Records.SEND_STATUS_FLAGS) & Records.SEND_STATUS_GSO_DISABLED) != 0) {
            sendFlags &= ~UdpSocket.SEND_GSO;
        }
        if (n >= sendCount) {
            sendCount = 0;
            sendOff = 0;
            return;
        }
        // EAGAIN: keep the unsent records (their payloads stay in place).
        int left = sendCount - n;
        for (int i = 0; i < left; i++) {
            int from = Records.SEND_HEADER_LEN + (n + i) * Records.SEND_META_LEN;
            int to = Records.SEND_HEADER_LEN + i * Records.SEND_META_LEN;
            sendRecords.put(to, sendRecords, from, Records.SEND_META_LEN);
        }
        sendCount = left;
        sendBlocked = true;
        listener.stats.sendBlocked.increment();
    }

    // ---- per-thread scratch ---------------------------------------------------

    /** The loop's frame-encoding buffer, cleared, with room for {@code need} bytes. */
    ByteBuffer frame(int need) {
        if (frame.capacity() < need) {
            ByteBuffer bigger = ByteBuffer.allocate(Math.max(need, frame.capacity() * 2));
            // A one-off monster response doesn't pin a huge buffer.
            if (bigger.capacity() <= FRAME_KEEP_MAX) frame = bigger;
            bigger.clear();
            return bigger;
        }
        frame.clear();
        return frame;
    }

    /** A gathering buffer of {@link #POOLED_FIELD_BUF} bytes. */
    byte[] takeFieldBuf() {
        if (fieldPoolSize == 0) return new byte[POOLED_FIELD_BUF];
        byte[] b = fieldPool[--fieldPoolSize];
        fieldPool[fieldPoolSize] = null;
        return b;
    }

    /** Returns a gathering buffer; kept when it is pool-sized and the pool has room. */
    void giveFieldBuf(byte[] b) {
        if (b.length == POOLED_FIELD_BUF && fieldPoolSize < FIELD_POOL_MAX) fieldPool[fieldPoolSize++] = b;
    }

    /** The encoded "date" field line for the current second. */
    byte[] dateField() {
        String now = HttpDates.now();
        if (now != dateValue) {
            ByteBuffer b = ByteBuffer.allocate(64);
            QpackFieldSection.encodeField(b, "date", now);
            dateField = Arrays.copyOf(b.array(), b.position());
            dateValue = now;
        }
        return dateField;
    }

    // ---- forwarded datagrams -----------------------------------------------------

    /**
     * Datagrams other loops received for connections of this one, copied
     * into fixed slots. Producers append under the lock; the loop reads a
     * snapshot of filled slots without it, then releases them. The slots
     * (direct memory) are allocated by the first datagram handed over: a
     * single loop, or kernel steering, may never need them.
     */
    private static final class Inbox {
        // Set once, under the lock; read by the loop after a snapshot.
        NativeBuffer slab;
        NativeBuffer meta;
        final int slotSize;
        private final int capacity;
        private long head;
        private long tail;
        private volatile boolean nonEmpty;

        Inbox(int capacity, int slotSize) {
            this.capacity = capacity;
            this.slotSize = slotSize;
        }

        synchronized boolean offer(ByteBuffer src, int off, int len, ByteBuffer srcMeta, int rec) {
            if (tail - head == capacity || len > slotSize) return false;
            if (slab == null) {
                slab = NativeBuffer.allocate(capacity * slotSize);
                meta = NativeBuffer.allocate(capacity * Records.RECV_META_LEN);
            }
            int slot = (int) (tail % capacity);
            slab.buffer.put(slot * slotSize, src, off, len);
            int m = slot * Records.RECV_META_LEN;
            meta.buffer.put(m, srcMeta, rec, Records.RECV_META_LEN);
            meta.buffer.putInt(m + Records.RECV_LEN, len);
            tail++;
            nonEmpty = true;
            return true;
        }

        boolean isEmpty() {
            return !nonEmpty;
        }

        /** Filled slots now readable without the lock. */
        synchronized int snapshot() {
            nonEmpty = false;
            return (int) (tail - head);
        }

        int slot(int i) {
            return (int) ((head + i) % capacity);
        }

        synchronized void release(int n) {
            head += n;
            if (head != tail) nonEmpty = true;
        }
    }

    /**
     * Hash key over a client-chosen connection id (8 to 20 bytes). The hash
     * is keyed with a per-process secret so a client choosing ids can't
     * aim them at one bucket.
     */
    static final class AliasKey {
        private static final int SEED = new SecureRandom().nextInt() | 1;

        private byte[] bytes;
        private int len;
        private int hash;
        private ByteBuffer view;
        private int viewOff;

        AliasKey() {}

        AliasKey(byte[] id) {
            this.bytes = id;
            this.len = id.length;
            this.hash = hash(id, len);
        }

        /** Re-points this lookup key at {@code b[off, off + len)}; never stored. */
        AliasKey view(ByteBuffer b, int off, int len) {
            this.view = b;
            this.viewOff = off;
            this.len = len;
            this.bytes = null;
            int h = SEED;
            for (int i = 0; i < len; i++) h = mix(h, b.get(off + i));
            this.hash = h;
            return this;
        }

        private static int hash(byte[] a, int len) {
            int h = SEED;
            for (int i = 0; i < len; i++) h = mix(h, a[i]);
            return h;
        }

        private static int mix(int h, byte b) {
            return Integer.rotateLeft((h ^ (b & 0xFF)) * 0x9E3779B1, 13);
        }

        private byte at(int i) {
            return bytes != null ? bytes[i] : view.get(viewOff + i);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof AliasKey k) || k.len != len || k.hash != hash) return false;
            for (int i = 0; i < len; i++) {
                if (k.at(i) != at(i)) return false;
            }
            return true;
        }
    }
}

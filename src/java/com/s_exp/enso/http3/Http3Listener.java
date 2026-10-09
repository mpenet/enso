// ABOUTME: HTTP/3 listener: binds the UDP socket(s), starts the sharded event loops, admits new
// ABOUTME: QUIC connections (Retry, half-open and connection limits) and drains them on close.
package com.s_exp.enso.http3;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.ServerEvents;
import com.s_exp.enso.core.ConnectionLimiter;
import com.s_exp.enso.core.ConnectionRegistry;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.http3.qpack.QpackFieldSection;
import com.s_exp.enso.quiche.QuicheConfig;
import com.s_exp.enso.quiche.Records;
import com.s_exp.enso.quiche.RetryToken;
import com.s_exp.enso.quiche.UdpSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Serves HTTP/3 on a UDP port.
 *
 * <p>Threading: {@code N} event loops ({@code :http3-event-loops}; by
 * default one per core on Linux, one elsewhere), each a platform thread
 * owning the connections whose ids carry its index (see
 * {@link ConnectionIds}). On Linux every loop has its own SO_REUSEPORT
 * socket and a classic BPF program steers each datagram to the socket of
 * the loop named in its destination id, so the kernel spreads the load
 * and packets never change threads; Initial and 0-RTT packets, whose id
 * the client chose, go by the kernel's 4-tuple hash and are accepted
 * where they land. Without the program (or on other systems, where one
 * socket is shared and loop 0 receives) a datagram landing on the wrong
 * loop is copied to its owner's inbox. Handlers run on virtual threads.
 *
 * <p>Admission of a client Initial: a token is verified (an expired or
 * foreign Retry token closes with INVALID_TOKEN, RFC 9000 §8.1.2);
 * without a valid one, a stateless Retry is required while
 * {@code :http3-retry-threshold} or more connections are handshaking
 * (always with {@code :http3-stateless-retry}, and with
 * {@code :max-connections-per-ip}, so per-address slots only count proven
 * addresses), so a spoofed flood can't make the server sign handshakes;
 * past {@code :http3-max-half-open} handshaking connections Initials are
 * dropped; every connection reserves its connection window of native
 * receive credit within {@code :http3-max-native-bytes} and takes a slot
 * of the server's {@link ConnectionLimiter} ({@code :max-connections},
 * {@code :max-connections-per-ip}) for its whole life, and beyond while
 * any of its handlers still runs (closing a connection doesn't free
 * handlers to pile up).
 *
 * <p>Shutdown ({@link #close}): no new connections; every connection
 * sends GOAWAY and closes once its in-flight requests completed, under
 * {@code :shutdown-timeout}; for its last part the rest are closed and
 * their interrupted handlers waited for. Each connection is also
 * registered with the server's {@link ConnectionRegistry} as
 * {@link com.s_exp.enso.core.Drainable}.
 *
 * <p>Certificates: every {@code :http3-cert-reload-interval} a virtual
 * thread compares the certificate and key files' modification time, size
 * and file key (inode) with the pair last loaded; on a change it builds a
 * new quiche configuration and new connections are accepted with it,
 * while existing ones keep theirs (each holds a reference to the
 * configuration it was accepted with, freed with its last connection). A
 * pair that fails to load (a half-written file, a key that doesn't match
 * the certificate) is logged and the current one kept; it is retried once
 * the files change again. {@link #reloadCertificates} forces a reload.
 */
public final class Http3Listener implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Listener.class.getName());
    private static final LogLimiter REFUSED = new LogLimiter(LOG, Level.FINE);
    private static final LogLimiter RELOAD_FAILURES = new LogLimiter(LOG, Level.WARNING);
    static final String PROTOCOL = "h3";
    private static final int MAX_LOOPS = 64;
    private static final long STOP_JOIN_MILLIS = 5000;
    // Past the shutdown deadline, loops still get this long to exit after
    // being stopped (a healthy loop needs a few milliseconds).
    private static final long STOP_GRACE_NANOS = 100_000_000L;
    private static final long FORCE_CLOSE_WAIT_MILLIS = 1000;

    final Service service;
    final Config config;
    final RingHandler handler;
    final Timer timer;
    private final boolean ownsService;
    final ConnectionRegistry registry;
    final ConnectionLimiter limiter;
    final ServerEvents events;
    final ThreadFactory handlerThreads = Thread.ofVirtual().factory();
    final Stats stats = new Stats();
    // Receive credit quiche may hold natively: a connection window
    // (:http3-initial-max-data-bytes) per live connection, reserved at
    // admission within :http3-max-native-bytes.
    private final MemoryBudget nativeCredit;

    /** The configuration new connections are accepted with; see {@link #acquireConfig}. */
    private volatile QuicheConfig currentConfig;
    // Every configuration built and not yet freed (diagnostics).
    private final ConcurrentLinkedQueue<QuicheConfig> configs = new ConcurrentLinkedQueue<>();
    // Certificate files as last loaded, and as last refused (not retried
    // until they change again). Certificate watcher thread only.
    private CertFiles loadedCerts;
    private CertFiles refusedCerts;
    private Thread certWatcher;
    RetryToken retryToken;
    Http3Loop[] loops = new Http3Loop[0];
    private UdpSocket[] sockets = new UdpSocket[0];
    private UdpSocket.Waker[] wakers = new UdpSocket.Waker[0];
    /** Datagrams reach the loop their destination id names (kernel steering or one shared socket). */
    boolean routeAll;
    /**
     * One socket for every loop: loop 0 receives and routes each datagram
     * by destination id, client-chosen ones (Initial, 0-RTT) included, the
     * only way handshakes spread across loops then.
     */
    boolean sharedSocket;
    private boolean gso;
    volatile boolean accepting;
    private InetSocketAddress localAddress;
    /** Encoded "server" field line, or null. */
    byte[] serverField;

    private final AtomicInteger halfOpen = new AtomicInteger();
    private final AtomicInteger live = new AtomicInteger();
    // A lock rather than a monitor: close() waits here from a virtual
    // thread, which a monitor wait would pin on JDKs before 24.
    private final ReentrantLock liveLock = new ReentrantLock();
    private final Condition noneLive = liveLock.newCondition();
    // Guards started / closed and publishes what start() set up to close();
    // a lock, not a monitor: start() binds sockets (see EnsoServer).
    private final ReentrantLock lifecycle = new ReentrantLock();
    private boolean started;
    private boolean closed;

    /** Counters for diagnostics and tests. */
    static final class Stats {
        final LongAdder truncated = new LongAdder();
        final LongAdder inboxDrops = new LongAdder();
        /** Datagrams a loop received for another loop's connection. */
        final LongAdder forwarded = new LongAdder();
        /** Times a send batch stopped on a full socket buffer (EAGAIN). */
        final LongAdder sendBlocked = new LongAdder();
        final LongAdder sendDrops = new LongAdder();
        final LongAdder retries = new LongAdder();
        final LongAdder refused = new LongAdder();
        /** Event loops restarted by their supervisor after a failure. */
        final LongAdder loopRestarts = new LongAdder();
    }

    /**
     * A standalone listener with its own timer, service and connection
     * limiter, closed with it. {@code errorHandler} may be null (a plain 500).
     */
    public Http3Listener(Config config, RingHandler handler, RingErrorHandler errorHandler) {
        this(new Service(handler, errorHandler, config,
                         new Timer("enso-h3-timer", Timer.DEFAULT_TICK_MILLIS, Timer.DEFAULT_WHEEL_SIZE)),
             true, null, null);
    }

    /**
     * A server's listener: {@code service} (handler, timer, events,
     * budget), {@code registry} and {@code limiter} are the server's
     * (connections are registered and counted there).
     */
    public Http3Listener(Service service, ConnectionRegistry registry, ConnectionLimiter limiter) {
        this(service, false, registry, limiter);
    }

    private Http3Listener(Service service, boolean ownsService, ConnectionRegistry registry,
                          ConnectionLimiter limiter) {
        this.service = service;
        this.config = service.config;
        this.handler = service.handler;
        this.timer = service.timer;
        this.ownsService = ownsService;
        this.registry = registry;
        this.limiter = limiter != null ? limiter
            : new ConnectionLimiter(config.maxConnections, config.maxConnectionsPerIp);
        this.events = service.events;
        this.nativeCredit = new MemoryBudget(nativeLimit(config, service.budget));
    }

    /**
     * {@code :http3-max-native-bytes} resolved: -1 is the
     * {@code :max-buffered-bytes} limit, but at least one connection
     * window (so a small budget still admits connections); 0 is unlimited.
     */
    private static long nativeLimit(Config config, MemoryBudget budget) {
        if (config.http3MaxNativeBytes == 0) return Long.MAX_VALUE;
        if (config.http3MaxNativeBytes > 0) return config.http3MaxNativeBytes;
        return Math.max(budget.limit(), Math.max(1, config.http3InitialMaxDataBytes));
    }

    /**
     * Bytes of request data quiche may buffer natively, off the Java heap
     * and outside {@code :max-buffered-bytes}: the connection window
     * ({@code :http3-initial-max-data-bytes}) of every live connection,
     * at most {@link #maxNativeBytes}. The server reads request streams
     * only while their pipes and the budget have room, so this much is
     * reached only under pressure, by peers that keep sending.
     */
    public long nativeCreditBytes() {
        return nativeCredit.used();
    }

    /**
     * The cap on {@link #nativeCreditBytes} ({@code :http3-max-native-bytes}
     * resolved; {@link Long#MAX_VALUE} when unlimited): a connection whose
     * window would pass it is refused.
     */
    public long maxNativeBytes() {
        return nativeCredit.limit();
    }

    /** Whether every event loop thread is alive (each is supervised: false means a fault). */
    public boolean isHealthy() {
        for (Http3Loop l : loops) {
            if (!l.thread.isAlive()) return false;
        }
        return true;
    }

    /** Binds and starts the loops. On failure everything opened is released. */
    public void start() throws IOException {
        lifecycle.lock();
        try {
            startLocked();
        } finally {
            lifecycle.unlock();
        }
    }

    private void startLocked() throws IOException {
        if (started) throw new IllegalStateException("listener already started");
        started = true;
        try {
            // Stamped before loading: a change made while loading is seen
            // by the first check.
            loadedCerts = CertFiles.read(config);
            currentConfig = track(QuicheConfig.server(config));
            retryToken = new RetryToken();
            if (config.serverHeader != null && !config.serverHeader.isEmpty()) {
                ByteBuffer b = ByteBuffer.allocate(QpackFieldSection.maxEncodedLength("server", config.serverHeader));
                QpackFieldSection.encodeField(b, "server", config.serverHeader);
                serverField = Arrays.copyOf(b.array(), b.position());
            }
            bindAndStart();
            startCertWatcher();
            accepting = true;
            LOG.fine(() -> "h3 listening on " + localAddress + " with " + loops.length
                + " event loop(s), " + sockets.length + " socket(s), steering by connection id "
                + routeAll + ", GSO " + gso + ", libquiche " + com.s_exp.enso.quiche.Quiche.libraryVersion());
        } catch (Throwable t) {
            long deadline = System.nanoTime() + STOP_JOIN_MILLIS * 1_000_000L;
            stopCertWatcher(deadline);
            // A loop that didn't stop may still use the sockets and the
            // configuration: left allocated rather than freed under it.
            releaseNative(stopLoops(deadline));
            throw t;
        }
    }

    private QuicheConfig track(QuicheConfig c) {
        // Freed ones leave as new ones come: the list stays as long as the
        // configurations still in use.
        configs.removeIf(QuicheConfig::isFreed);
        configs.add(c);
        return c;
    }

    /**
     * The configuration for a new connection, with a reference taken for
     * it: give it back with {@link QuicheConfig#release} once the
     * connection is freed (or wasn't created). Event loop threads.
     */
    QuicheConfig acquireConfig() {
        while (true) {
            QuicheConfig c = currentConfig;
            // Fails only when a reload replaced and freed it meanwhile:
            // the replacement is current by then.
            if (c.tryRetain()) return c;
        }
    }

    /** Quiche configurations alive: the current one plus replaced ones still used by connections. */
    public int liveQuicheConfigs() {
        configs.removeIf(QuicheConfig::isFreed);
        return configs.size();
    }

    /**
     * Loads the certificate and key files again for new connections, whether
     * or not they changed (existing connections keep theirs).
     *
     * @throws IOException when the pair can't be loaded; the current one stays
     * @throws IllegalStateException when the listener isn't running
     */
    public void reloadCertificates() throws IOException {
        install(QuicheConfig.server(config));
    }

    /** Makes {@code fresh} the configuration of new connections; the replaced one goes with its last connection. */
    private void install(QuicheConfig fresh) {
        QuicheConfig old;
        lifecycle.lock();
        try {
            if (!started || closed) {
                fresh.close();
                throw new IllegalStateException("listener not running");
            }
            old = currentConfig;
            currentConfig = track(fresh);
        } finally {
            lifecycle.unlock();
        }
        old.close();
    }

    private void startCertWatcher() {
        long interval = config.http3CertReloadIntervalMillis;
        if (interval <= 0) return;
        certWatcher = Thread.ofVirtual().name("enso-h3-cert-watcher").start(() -> {
            while (true) {
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException e) {
                    return;
                }
                try {
                    reloadIfChanged();
                } catch (IllegalStateException e) {
                    return;
                } catch (RuntimeException e) {
                    RELOAD_FAILURES.log("h3 certificate check failed", e);
                }
            }
        });
    }

    private void stopCertWatcher(long deadline) {
        Thread t = certWatcher;
        if (t == null) return;
        t.interrupt();
        join(t, deadline);
    }

    /** Waits for {@code t} until {@code deadline} (System.nanoTime); true when it exited. */
    private static boolean join(Thread t, long deadline) {
        try {
            long left = deadline - System.nanoTime();
            if (left > 0) t.join(java.time.Duration.ofNanos(left));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return !t.isAlive();
    }

    /** Certificate watcher: reloads when the files differ from the pair loaded (or last refused). */
    private void reloadIfChanged() {
        CertFiles now;
        try {
            now = CertFiles.read(config);
        } catch (IOException e) {
            // Mid-rotation (a file briefly missing): next round.
            return;
        }
        if (now.equals(loadedCerts) || now.equals(refusedCerts)) return;
        QuicheConfig fresh;
        try {
            fresh = QuicheConfig.server(config);
        } catch (IOException e) {
            refusedCerts = now;
            RELOAD_FAILURES.log("h3 certificate reload failed, keeping the current one: " + e.getMessage());
            return;
        }
        install(fresh);
        loadedCerts = now;
        refusedCerts = null;
        LOG.info(() -> "h3 certificate reloaded from " + config.http3CertPath);
    }

    /** What identifies a version of the certificate and key files: modification time, size, file key. */
    private record CertFiles(long certModified, long certSize, Object certKey,
                             long keyModified, long keySize, Object keyKey) {

        static CertFiles read(Config config) throws IOException {
            BasicFileAttributes c = Files.readAttributes(Path.of(config.http3CertPath), BasicFileAttributes.class);
            BasicFileAttributes k = Files.readAttributes(Path.of(config.http3KeyPath), BasicFileAttributes.class);
            return new CertFiles(c.lastModifiedTime().toMillis(), c.size(), c.fileKey(),
                                 k.lastModifiedTime().toMillis(), k.size(), k.fileKey());
        }
    }

    private void bindAndStart() throws IOException {
        InetAddress host = InetAddress.getByName(config.host);
        int port = config.http3Port > 0 ? config.http3Port : config.port;
        int n = config.http3EventLoops > 0 ? config.http3EventLoops
            : UdpSocket.reusePortBalances() ? Runtime.getRuntime().availableProcessors() : 1;
        n = Math.min(MAX_LOOPS, Math.max(1, n));
        int flags = host.isAnyLocalAddress() ? UdpSocket.OPEN_PKTINFO : 0;
        boolean perLoopSockets = n > 1 && UdpSocket.reusePortBalances();
        int socketCount = perLoopSockets ? n : 1;
        sockets = new UdpSocket[socketCount];
        for (int i = 0; i < socketCount; i++) {
            // The first bind resolves an ephemeral port; the others join it.
            sockets[i] = UdpSocket.open(host, i == 0 ? port : localPortOf(sockets[0]),
                flags | (perLoopSockets ? UdpSocket.OPEN_REUSEPORT : 0),
                config.http3SoRcvBufBytes, config.http3SoSndBufBytes);
        }
        localAddress = sockets[0].localAddress();
        logBufferSizes(sockets[0]);
        sharedSocket = !perLoopSockets;
        routeAll = !perLoopSockets || sockets[0].attachSteering(n);
        gso = sockets[0].gsoSupported();
        int sendFlags = (gso ? UdpSocket.SEND_GSO : 0)
            | (sockets[0].pktinfo() ? UdpSocket.SEND_PKTINFO : 0);
        wakers = new UdpSocket.Waker[n];
        loops = new Http3Loop[n];
        for (int i = 0; i < n; i++) {
            wakers[i] = new UdpSocket.Waker();
            UdpSocket own = perLoopSockets ? sockets[i] : (i == 0 ? sockets[0] : null);
            UdpSocket send = perLoopSockets ? sockets[i] : sockets[0];
            loops[i] = new Http3Loop(this, i, n, own, send, wakers[i], config.http3MaxUdpPayloadBytes, sendFlags);
        }
        for (Http3Loop l : loops) l.thread.start();
    }

    /**
     * Reports the socket buffer sizes the OS granted; below what was
     * requested on Linux (which reports twice the usable size) at INFO, as
     * a throughput limit to fix with net.core.rmem_max / wmem_max.
     */
    private void logBufferSizes(UdpSocket s) {
        int rcv = s.bufferSize(false);
        int snd = s.bufferSize(true);
        int usableRcv = UdpSocket.reusePortBalances() ? rcv / 2 : rcv;
        int usableSnd = UdpSocket.reusePortBalances() ? snd / 2 : snd;
        boolean belowRequested = UdpSocket.reusePortBalances()
            && (usableRcv < config.http3SoRcvBufBytes || usableSnd < config.http3SoSndBufBytes);
        Level level = belowRequested ? Level.INFO : Level.FINE;
        if (LOG.isLoggable(level)) {
            LOG.log(level, "h3 UDP socket buffers: receive " + usableRcv + " bytes (requested "
                + config.http3SoRcvBufBytes + "), send " + usableSnd + " bytes (requested "
                + config.http3SoSndBufBytes + ")" + (belowRequested ? "; raise net.core.rmem_max / wmem_max" : ""));
        }
    }

    private static int localPortOf(UdpSocket s) throws IOException {
        return s.localAddress().getPort();
    }

    public int port() {
        return localAddress != null ? localAddress.getPort() : -1;
    }

    /** Number of event loops. */
    public int eventLoops() {
        return loops.length;
    }

    /** True when the kernel steers datagrams to their loop's socket (or all share one socket). */
    public boolean steersByConnectionId() {
        return routeAll;
    }

    /** QUIC connections currently open (handshaking included), or freed with handlers still running. */
    public int connectionCount() {
        return live.get();
    }

    /** Connections still in their handshake. */
    public int halfOpenCount() {
        return halfOpen.get();
    }

    /** Times sending waited for socket buffer space. */
    public long sendBlockedCount() {
        return stats.sendBlocked.sum();
    }

    /** Datagrams received by a loop other than their connection's owner. */
    public long forwardedDatagrams() {
        return stats.forwarded.sum();
    }

    // ---- admission (event loop threads) ---------------------------------------

    /** An Initial's fate. */
    static final class Admission {
        static final int ACCEPT = 0;
        static final int DROP = 1;
        static final int RETRY = 2;
        static final int INVALID_TOKEN = 3;
        static final Admission DROPPED = new Admission(DROP, null, null);
        static final Admission RETRY_REQUIRED = new Admission(RETRY, null, null);
        static final Admission TOKEN_INVALID = new Admission(INVALID_TOKEN, null, null);

        final int verdict;
        /** The client's original destination id after a Retry, else null. */
        final byte[] odcid;
        final InetAddress remote;

        Admission(int verdict, byte[] odcid, InetAddress remote) {
            this.verdict = verdict;
            this.odcid = odcid;
            this.remote = remote;
        }
    }

    /**
     * Decides a client Initial's fate. {@code hdr} is its parsed header
     * (token included), {@code meta[peerOff]} its source address,
     * {@code dcid} its destination id. On {@link Admission#ACCEPT} a
     * limiter slot, a half-open slot and the connection window of native
     * credit are taken: give them back through
     * {@link #admissionFailed} if no connection results.
     */
    Admission admit(ByteBuffer hdr, int tokenLen, ByteBuffer meta, int peerOff, byte[] dcid) {
        InetSocketAddress peer = Records.socketAddress(meta, peerOff);
        if (peer == null) {
            // A source address the kernel reported in a family we don't
            // decode: nothing to answer or count it against.
            return Admission.DROPPED;
        }
        byte[] odcid = null;
        if (tokenLen > 0) {
            byte[] token = new byte[tokenLen];
            hdr.get(Records.HDR_TOKEN, token);
            odcid = retryToken.verify(token, 0, tokenLen, peer, dcid, dcid.length);
            // An expired token of ours, or one minted for another address:
            // the client can't get a second Retry (RFC 9000 §17.2.5.2), so
            // it is told (§8.1.2). Other tokens (NEW_TOKEN from another
            // server) count as absent (§8.1.3).
            if (odcid == null && RetryToken.looksMinted(token)) return Admission.TOKEN_INVALID;
        }
        // With a per-address limit the address is validated first: a slot
        // taken for a spoofed source would lock that address out.
        if (odcid == null && (config.http3StatelessRetry || config.maxConnectionsPerIp > 0
                              || halfOpen.get() >= config.http3RetryThreshold)) {
            stats.retries.increment();
            return Admission.RETRY_REQUIRED;
        }
        // Taken, then checked: loops admitting at once can't overshoot.
        int handshaking = halfOpen.incrementAndGet();
        if (config.http3MaxHalfOpen > 0 && handshaking > config.http3MaxHalfOpen) {
            halfOpen.decrementAndGet();
            refused("handshake-limit", "h3 Initial dropped: too many handshaking connections");
            return Admission.DROPPED;
        }
        InetAddress remote = peer.getAddress();
        if (!nativeCredit.tryReserve(config.http3InitialMaxDataBytes)) {
            halfOpen.decrementAndGet();
            refused("connection-limit", "h3 connection refused: :http3-max-native-bytes reached");
            return Admission.DROPPED;
        }
        if (!limiter.tryAcquire(remote)) {
            halfOpen.decrementAndGet();
            nativeCredit.release(config.http3InitialMaxDataBytes);
            refused("connection-limit", "h3 connection refused: connection limit reached");
            return Admission.DROPPED;
        }
        return new Admission(Admission.ACCEPT, odcid, remote);
    }

    private void refused(String kind, String message) {
        stats.refused.increment();
        protocolError(kind);
        REFUSED.log(message);
    }

    void protocolError(String kind) {
        service.protocolError(PROTOCOL, kind);
    }

    /** Undoes a successful {@link #admit} whose connection couldn't be created. */
    void admissionFailed(InetAddress remote) {
        halfOpen.decrementAndGet();
        nativeCredit.release(config.http3InitialMaxDataBytes);
        limiter.release(remote);
    }

    /** A connection was created (event loop thread). */
    void opened(Http3Connection c) {
        live.incrementAndGet();
        if (registry != null) registry.register(c);
    }

    /** A connection completed its handshake (event loop thread). */
    void established(Http3Connection c) {
        halfOpen.decrementAndGet();
    }

    /**
     * A connection was freed (event loop thread). Its limiter slot and
     * registry entry stay taken while any of its handlers still runs; the
     * last one gives them back ({@link #released}).
     */
    void closed(Http3Connection c) {
        // Once: a teardown that failed half-way may be finished by the loop.
        if (c.closedReported) return;
        c.closedReported = true;
        if (!c.wasEstablished()) halfOpen.decrementAndGet();
        if (c.liveHandlers.get() == 0) {
            released(c);
        }
    }

    /**
     * Nothing of {@code c} runs any more (freed, no handler left): its
     * limiter slot and registry entry are given back, once (the loop's
     * {@link #closed} and the last handler may both get here).
     */
    void released(Http3Connection c) {
        if (!c.release()) return;
        nativeCredit.release(config.http3InitialMaxDataBytes);
        limiter.release(c.remote);
        if (registry != null) registry.unregister(c);
        if (live.decrementAndGet() == 0) {
            liveLock.lock();
            try {
                noneLive.signalAll();
            } finally {
                liveLock.unlock();
            }
        }
    }

    // ---- shutdown ---------------------------------------------------------------

    /**
     * Stops accepting connections, drains the open ones (GOAWAY, in-flight
     * requests complete) until {@code :shutdown-timeout}, closes the rest,
     * stops the loops and frees the native state. The quiche config and
     * sockets are only freed once every loop has exited; a loop that
     * doesn't is left holding them (logged) rather than risk a
     * use-after-free.
     */
    @Override
    public void close() {
        lifecycle.lock();
        try {
            if (closed) return;
            closed = true;
        } finally {
            lifecycle.unlock();
        }
        accepting = false;
        long budget = config.shutdownTimeoutMillis * 1_000_000L;
        long deadline = System.nanoTime() + budget;
        // As the server: the last part of the budget (a quarter, at most
        // FORCE_CLOSE_WAIT_MILLIS) force-closes and waits for the handlers
        // it interrupted.
        long drainDeadline = deadline - Math.min(FORCE_CLOSE_WAIT_MILLIS * 1_000_000L, budget / 4);
        stopCertWatcher(drainDeadline);
        for (Http3Loop l : loops) l.requestDrain();
        awaitNoConnections(drainDeadline);
        if (live.get() > 0) {
            for (Http3Loop l : loops) l.requestForceClose();
            awaitNoConnections(deadline);
        }
        boolean stopped = stopLoops(Math.max(deadline, System.nanoTime()) + STOP_GRACE_NANOS);
        releaseNative(stopped);
        if (ownsService) {
            timer.close();
            service.close();
        }
    }

    private void awaitNoConnections(long deadline) {
        liveLock.lock();
        try {
            while (live.get() > 0) {
                long left = deadline - System.nanoTime();
                if (left <= 0) return;
                try {
                    noneLive.await(left, TimeUnit.NANOSECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {
            liveLock.unlock();
        }
    }

    /** Stops every loop and joins them until {@code deadline}; true when all exited. */
    private boolean stopLoops(long deadline) {
        for (Http3Loop l : loops) {
            if (l != null) l.requestStop();
        }
        boolean all = true;
        for (Http3Loop l : loops) {
            if (l == null) continue;
            if (!join(l.thread, deadline)) {
                all = false;
                LOG.warning("h3 event loop " + l.index + " did not stop; its native state is not freed");
            }
        }
        return all;
    }

    private void releaseNative(boolean loopsStopped) {
        if (!loopsStopped) return;
        for (UdpSocket s : sockets) {
            if (s != null) s.close();
        }
        for (UdpSocket.Waker w : wakers) {
            if (w != null) w.close();
        }
        // Connections gave back their references when the loops freed them.
        QuicheConfig c = currentConfig;
        if (c != null) c.close();
    }
}

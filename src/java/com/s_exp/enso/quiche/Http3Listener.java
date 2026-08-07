package com.s_exp.enso.quiche;

import com.s_exp.enso.Config;
import com.s_exp.enso.RingHandler;
import com.s_exp.enso.quiche.ffm.quiche_h;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP/3 listener. Owns:
 *
 * <ul>
 *   <li>one blocking {@link DatagramChannel} bound to the configured UDP
 *       port;
 *   <li>a shared {@link QuicheConfig} loaded from PEM cert/key;
 *   <li>a demux virtual thread that receives datagrams, parses the QUIC
 *       long header for the destination connection ID, and dispatches to
 *       the matching {@link Http3Connection} — or creates a new one via
 *       {@code quiche_accept} for unknown CIDs.
 * </ul>
 *
 * <p>Instantiated reflectively from {@link com.s_exp.enso.EnsoServer} so
 * that non-http3 users never trigger classloading of the FFM bindings.
 *
 * <p>Phase 1/2 scope: real handshake completes end-to-end with quiche-client.
 * Streams / Ring handler dispatch lands in Phase 3.
 */
public final class Http3Listener implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Listener.class.getName());

    private static final int MAX_DATAGRAM_SIZE = 1350;
    private static final int LOCAL_CID_LEN = 16;
    // Hard cap on concurrent QUIC connections per listener. Above this,
    // new Initials are dropped so a flood of unique-DCID packets can't
    // exhaust memory / thread count. Rough sizing: 10K conns × ~8 KB
    // arena footprint ≈ 80 MB.
    private static final int MAX_CONNECTIONS = 10_000;

    private final Config config;
    private final RingHandler handler;
    @SuppressWarnings("unused") // reserved for stop-signal callbacks
    private final Object server;
    private DatagramChannel channel;
    private QuicheConfig quicheConfig;
    private Thread demux;
    private volatile boolean running = true;
    private InetSocketAddress localAddr;
    private final SecureRandom rng = new SecureRandom();
    private final ConcurrentHashMap<CidKey, Http3Connection> conns = new ConcurrentHashMap<>();
    // Named platform-thread pool for per-connection drivers. Cached so
    // threads are reused as connections come and go (h3 handshake floods
    // are common). Combined with MAX_CONNECTIONS the pool size is bounded.
    private ExecutorService connExecutor;
    // Listener-lifetime arena backing the demux thread's persistent
    // quiche_header_info scratch slots. Allocated once at start(); freed
    // on close(). Avoids Arena.ofConfined() + several allocate() calls
    // per received datagram.
    private Arena demuxArena;
    private MemorySegment hVersion;
    private MemorySegment hType;
    private MemorySegment hScid, hScidLen;
    private MemorySegment hDcid, hDcidLen;
    private MemorySegment hToken, hTokenLen;

    public Http3Listener(Config config, RingHandler handler, Object server) {
        this.config = config;
        this.handler = handler;
        this.server = server;
    }

    public void start() throws IOException {
        LOG.info("Http3Listener starting, libquiche version " + Quiche.version());
        quicheConfig = new QuicheConfig(config);

        int port = config.http3Port > 0 ? config.http3Port : config.port;
        channel = DatagramChannel.open();
        channel.socket().bind(new InetSocketAddress(config.host, port));
        localAddr = (InetSocketAddress) channel.getLocalAddress();

        // Persistent header-info slots. quiche_header_info writes into
        // these each call; we reset the length outputs before every
        // dispatch. Keeps demux hot path allocation-free (aside from the
        // byte[] we enqueue).
        demuxArena = Arena.ofShared();
        int maxCid = (int) quiche_h.QUICHE_MAX_CONN_ID_LEN();
        hVersion = demuxArena.allocate(ValueLayout.JAVA_INT);
        hType = demuxArena.allocate(ValueLayout.JAVA_BYTE);
        hScid = demuxArena.allocate(maxCid);
        hScidLen = demuxArena.allocate(ValueLayout.JAVA_LONG);
        hDcid = demuxArena.allocate(maxCid);
        hDcidLen = demuxArena.allocate(ValueLayout.JAVA_LONG);
        hToken = demuxArena.allocate(2048);
        hTokenLen = demuxArena.allocate(ValueLayout.JAVA_LONG);

        // Named platform threads for per-connection drivers; reused via
        // the cached pool so accept floods don't churn thread creation.
        connExecutor = Executors.newCachedThreadPool(
            Thread.ofPlatform().name("enso-h3-conn-", 0).factory());

        demux = Thread.ofVirtual()
            .name("enso-h3-demux")
            .start(this::demuxLoop);
    }

    public int port() {
        return localAddr != null ? localAddr.getPort() : -1;
    }

    private void demuxLoop() {
        ByteBuffer buf = ByteBuffer.allocateDirect(2 * MAX_DATAGRAM_SIZE);
        while (running) {
            try {
                buf.clear();
                SocketAddress from = channel.receive(buf);
                if (from == null) continue;
                buf.flip();
                onDatagram(buf, (InetSocketAddress) from);
            } catch (java.nio.channels.AsynchronousCloseException e) {
                return;
            } catch (IOException e) {
                if (running) LOG.log(Level.WARNING, "h3 receive failed", e);
                return;
            } catch (Throwable t) {
                LOG.log(Level.WARNING, "h3 demux crash", t);
            }
        }
    }

    private void onDatagram(ByteBuffer datagram, InetSocketAddress from) {
        int length = datagram.remaining();
        // Peek the header on the direct ByteBuffer directly via
        // MemorySegment.ofBuffer — no heap byte[] allocation until we
        // actually route the datagram to a connection.
        MemorySegment in = MemorySegment.ofBuffer(datagram);
        int maxCid = (int) quiche_h.QUICHE_MAX_CONN_ID_LEN();
        try {
            hScidLen.set(ValueLayout.JAVA_LONG, 0, maxCid);
            hDcidLen.set(ValueLayout.JAVA_LONG, 0, maxCid);
            hTokenLen.set(ValueLayout.JAVA_LONG, 0, 2048);
            int rc = quiche_h.quiche_header_info(
                in, length, LOCAL_CID_LEN,
                hVersion, hType, hScid, hScidLen, hDcid, hDcidLen, hToken, hTokenLen);
            if (rc < 0) {
                // Non-QUIC or malformed. Drop.
                return;
            }
            long dLen = hDcidLen.get(ValueLayout.JAVA_LONG, 0);
            byte[] dcidBytes = hDcid.reinterpret(dLen).toArray(ValueLayout.JAVA_BYTE);
            CidKey key = new CidKey(dcidBytes);
            Http3Connection existing = conns.get(key);
            if (existing != null) {
                // Extract heap byte[] only when we're going to hand it off
                // to a connection's ingress queue. Also rewinds the buffer
                // so we read from position 0.
                datagram.rewind();
                byte[] pkt = new byte[length];
                datagram.get(pkt);
                existing.enqueue(pkt);
                return;
            }
            // New DCID — accept a new connection.
            int wireVersion = hVersion.get(ValueLayout.JAVA_INT, 0);
            if (!quiche_h.quiche_version_is_supported(wireVersion)) {
                sendVersionNegotiation(hScid, hScidLen.get(ValueLayout.JAVA_LONG, 0),
                                       hDcid, dLen, from);
                return;
            }
            long sLen = hScidLen.get(ValueLayout.JAVA_LONG, 0);
            byte[] scidBytes = hScid.reinterpret(sLen).toArray(ValueLayout.JAVA_BYTE);
            // Materialise the datagram bytes for the connection driver's
            // ingress queue (only when we're actually going to accept).
            datagram.rewind();
            byte[] pkt = new byte[length];
            datagram.get(pkt);
            acceptNew(pkt, from, scidBytes, dcidBytes);
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 onDatagram failed", t);
        }
    }

    private void sendVersionNegotiation(MemorySegment scid, long scidLen,
                                        MemorySegment dcid, long dcidLen,
                                        InetSocketAddress peer) throws IOException {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment out = scratch.allocate(MAX_DATAGRAM_SIZE);
            long len = quiche_h.quiche_negotiate_version(
                scid, scidLen, dcid, dcidLen, out, MAX_DATAGRAM_SIZE);
            if (len < 0) {
                LOG.info("h3 quiche_negotiate_version rc=" + len);
                return;
            }
            byte[] pkt = new byte[(int) len];
            MemorySegment.copy(out, ValueLayout.JAVA_BYTE, 0, pkt, 0, (int) len);
            channel.send(ByteBuffer.wrap(pkt), peer);
        }
    }

    private void acceptNew(byte[] datagram, InetSocketAddress from,
                           byte[] clientScid, byte[] clientDcid) throws IOException {
        // Cheap DoS gate. Once the map is at cap, drop new-CID datagrams
        // rather than allocate more arenas + threads. Legit peers get a
        // retryable connection error; abusers get bounced.
        if (conns.size() >= MAX_CONNECTIONS) {
            return;
        }
        // Server-generated destination CID for this connection — that's the
        // stable routing key for subsequent datagrams from the same peer.
        byte[] localCid = new byte[LOCAL_CID_LEN];
        rng.nextBytes(localCid);
        Arena connArena = Arena.ofShared();
        try {
            MemorySegment scidSeg = connArena.allocate(localCid.length);
            MemorySegment.copy(localCid, 0, scidSeg, ValueLayout.JAVA_BYTE, 0, localCid.length);
            Sockaddr.Encoded local = Sockaddr.encode(connArena, localAddr);
            Sockaddr.Encoded peer = Sockaddr.encode(connArena, from);
            // odcid = original destination CID sent by the client on this Initial.
            MemorySegment odcidSeg = connArena.allocate(clientDcid.length);
            MemorySegment.copy(clientDcid, 0, odcidSeg, ValueLayout.JAVA_BYTE, 0, clientDcid.length);
            MemorySegment conn = quiche_h.quiche_accept(
                scidSeg, localCid.length,
                odcidSeg, clientDcid.length,
                local.segment(), local.length(),
                peer.segment(), peer.length(),
                quicheConfig.segment());
            if (conn.address() == 0) {
                LOG.warning("h3 quiche_accept returned null");
                connArena.close();
                return;
            }
            CidKey key = new CidKey(localCid);
            Http3Connection h3conn = new Http3Connection(
                localCid, conn, connArena, channel, localAddr, from,
                handler,
                config.maxRequestBodyBytes,
                connExecutor,
                () -> conns.remove(key));
            Http3Connection prev = conns.putIfAbsent(key, h3conn);
            if (prev != null) {
                // Extremely unlikely collision on 128-bit random CID; keep
                // existing and abandon this one.
                h3conn.close();
                prev.enqueue(datagram);
                return;
            }
            LOG.info("h3 accepted new connection cid="
                + HexFormat.of().formatHex(localCid) + " from " + from);
            h3conn.enqueue(datagram);
        } catch (Throwable t) {
            connArena.close();
            throw t;
        }
    }

    @Override
    public void close() throws IOException {
        running = false;
        if (channel != null) {
            try { channel.close(); } catch (IOException ignored) {}
        }
        for (Http3Connection c : conns.values()) {
            try { c.close(); } catch (Throwable ignored) {}
        }
        conns.clear();
        if (quicheConfig != null) {
            try { quicheConfig.close(); } catch (Throwable ignored) {}
        }
        if (demuxArena != null) {
            try { demuxArena.close(); } catch (Throwable ignored) {}
        }
        if (connExecutor != null) {
            connExecutor.shutdown();
            try {
                connExecutor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * ByteBuffer-backed hash key for connection ID lookups. Wrapping a raw
     * byte[] in a value class lets us use it as a {@code ConcurrentHashMap}
     * key without relying on identity semantics.
     */
    private static final class CidKey {
        private final byte[] bytes;
        private final int hash;

        CidKey(byte[] bytes) {
            this.bytes = bytes;
            this.hash = Arrays.hashCode(bytes);
        }

        @Override public int hashCode() { return hash; }
        @Override public boolean equals(Object o) {
            return o instanceof CidKey k && Arrays.equals(bytes, k.bytes);
        }
    }
}

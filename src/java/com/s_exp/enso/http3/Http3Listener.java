package com.s_exp.enso.http3;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.QuicheConfig;
import com.s_exp.enso.quiche.RetryToken;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
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
 * that non-http3 users never trigger classloading of the JNI shim.
 */
public final class Http3Listener implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(Http3Listener.class.getName());

    private static final int MAX_DATAGRAM_SIZE = 1350;
    private static final int LOCAL_CID_LEN = 16;
    private static final int MAX_TOKEN_LEN = 2048;
    // Hard cap on concurrent QUIC connections per listener. Above this,
    // new Initials are dropped so a flood of unique-DCID packets can't
    // exhaust memory / thread count.
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
    private RetryToken retryToken;
    private ExecutorService connExecutor;

    public Http3Listener(Config config, RingHandler handler, Object server) {
        this.config = config;
        this.handler = handler;
        this.server = server;
    }

    public void start() throws IOException {
        LOG.info("Http3Listener starting, libquiche version " + Quiche.version());
        quicheConfig = new QuicheConfig(config);

        int port = config.http3Port > 0 ? config.http3Port : config.port;
        // Match the address family of the configured host — force IPv4
        // when the host resolves to an IPv4 address so a dual-stack
        // socket doesn't source outbound datagrams from ::ffff:x.y.z.w
        // (some middleboxes and simulated networks mishandle
        // IPv4-mapped IPv6).
        InetAddress hostAddr = InetAddress.getByName(config.host);
        StandardProtocolFamily fam = hostAddr instanceof java.net.Inet6Address
            ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET;
        channel = DatagramChannel.open(fam);
        channel.socket().bind(new InetSocketAddress(hostAddr, port));
        localAddr = (InetSocketAddress) channel.getLocalAddress();

        // Named platform threads for per-connection drivers; reused via
        // the cached pool so accept floods don't churn thread creation.
        connExecutor = Executors.newCachedThreadPool(
            Thread.ofPlatform().name("enso-h3-conn-", 0).factory());

        if (config.http3StatelessRetry) {
            retryToken = new RetryToken();
        }

        demux = Thread.ofVirtual()
            .name("enso-h3-demux")
            .start(this::demuxLoop);
    }

    public int port() {
        return localAddr != null ? localAddr.getPort() : -1;
    }

    /**
     * Owner-only scratch for {@link #onDatagram}. Kept on the demux
     * vthread so we never allocate on the hot per-datagram path — task
     * #118 restored what task #72 had removed but the JNI rewrite
     * dropped. Reset each call: the two *Len arrays get re-primed with
     * the buffer capacities that quiche is allowed to write.
     */
    private static final class DemuxScratch {
        final int[] versionOut = new int[1];
        final byte[] typeOut = new byte[1];
        final byte[] scidBuf = new byte[Quiche.QUICHE_MAX_CONN_ID_LEN];
        final long[] scidLenA = new long[1];
        final byte[] dcidBuf = new byte[Quiche.QUICHE_MAX_CONN_ID_LEN];
        final long[] dcidLenA = new long[1];
        final byte[] tokenBuf = new byte[MAX_TOKEN_LEN];
        final long[] tokenLenA = new long[1];
    }

    private void demuxLoop() {
        ByteBuffer buf = ByteBuffer.allocateDirect(2 * MAX_DATAGRAM_SIZE);
        DemuxScratch scratch = new DemuxScratch();
        while (running) {
            try {
                buf.clear();
                SocketAddress from = channel.receive(buf);
                if (from == null) continue;
                buf.flip();
                onDatagram(buf, (InetSocketAddress) from, scratch);
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

    private void onDatagram(ByteBuffer datagram, InetSocketAddress from,
                             DemuxScratch s) {
        int length = datagram.remaining();
        byte[] pkt = new byte[length];
        datagram.get(pkt);
        try {
            s.scidLenA[0] = Quiche.QUICHE_MAX_CONN_ID_LEN;
            s.dcidLenA[0] = Quiche.QUICHE_MAX_CONN_ID_LEN;
            s.tokenLenA[0] = MAX_TOKEN_LEN;
            int rc = Quiche.headerInfo(pkt, length, LOCAL_CID_LEN,
                s.versionOut, s.typeOut,
                s.scidBuf, s.scidLenA,
                s.dcidBuf, s.dcidLenA,
                s.tokenBuf, s.tokenLenA);
            if (rc < 0) {
                // Non-QUIC or malformed. Drop.
                return;
            }
            int scidLen = (int) s.scidLenA[0];
            int dcidLen = (int) s.dcidLenA[0];
            int tokenLen = (int) s.tokenLenA[0];
            // Look up existing connection via a view-based key first so
            // the common case (packet for an established conn) skips the
            // dcidBytes copy entirely.
            Http3Connection existing = conns.get(CidKey.view(s.dcidBuf, dcidLen));
            if (existing != null) {
                existing.enqueue(pkt);
                return;
            }
            // Miss → materialise the cid bytes for the accept path (we
            // hand them off to Http3Connection ctor + retryToken).
            byte[] scidBytes = Arrays.copyOf(s.scidBuf, scidLen);
            byte[] dcidBytes = Arrays.copyOf(s.dcidBuf, dcidLen);
            int wireVersion = s.versionOut[0];
            if (!Quiche.versionIsSupported(wireVersion)) {
                sendVersionNegotiation(scidBytes, dcidBytes, from);
                return;
            }
            // Stateless retry (RFC 9000 §8.1.2). Force the client to prove
            // it can receive at its claimed source address before we
            // allocate connection state. Peers that don't echo a valid
            // token get bounced with a retry challenge; peers that do get
            // their odcid restored so the handshake proceeds normally.
            //
            // retryOdcid is passed to quiche_accept — MUST be null when no
            // stateless retry was performed. Passing the client's DCID
            // here without a retry causes quiche to advertise
            // retry_source_connection_id in its transport params, which
            // spec-conformant clients reject with TRANSPORT_PARAMETER_ERROR
            // (aioquic: "retry_source_connection_id does not match").
            byte[] localCid;
            byte[] retryOdcid;
            if (retryToken != null) {
                if (tokenLen == 0) {
                    byte[] token = retryToken.mint(from, dcidBytes);
                    byte[] newScid = new byte[LOCAL_CID_LEN];
                    rng.nextBytes(newScid);
                    sendRetry(scidBytes, dcidBytes, newScid, token, wireVersion, from);
                    return;
                }
                byte[] token = Arrays.copyOf(s.tokenBuf, tokenLen);
                byte[] verifiedOdcid = retryToken.verify(token, from);
                if (verifiedOdcid == null) {
                    return;
                }
                localCid = dcidBytes;
                retryOdcid = verifiedOdcid;
            } else {
                localCid = new byte[LOCAL_CID_LEN];
                rng.nextBytes(localCid);
                retryOdcid = null;
            }
            acceptNew(pkt, from, localCid, dcidBytes, retryOdcid);
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "h3 onDatagram failed", t);
        }
    }

    private void sendRetry(byte[] scid, byte[] dcid, byte[] newScid,
                           byte[] token, int version,
                           InetSocketAddress peer) throws IOException {
        byte[] out = new byte[MAX_DATAGRAM_SIZE];
        long len = Quiche.retry(scid, dcid, newScid, token, version, out);
        if (len < 0) {
            LOG.info("h3 quiche_retry rc=" + len);
            return;
        }
        channel.send(ByteBuffer.wrap(out, 0, (int) len), peer);
    }

    private void sendVersionNegotiation(byte[] scid, byte[] dcid,
                                        InetSocketAddress peer) throws IOException {
        byte[] out = new byte[MAX_DATAGRAM_SIZE];
        long len = Quiche.negotiateVersion(scid, dcid, out);
        if (len < 0) {
            LOG.info("h3 quiche_negotiate_version rc=" + len);
            return;
        }
        channel.send(ByteBuffer.wrap(out, 0, (int) len), peer);
    }

    private void acceptNew(byte[] datagram, InetSocketAddress from,
                           byte[] localCid, byte[] clientDcid, byte[] retryOdcid) {
        // First-line DoS gate — cheap and racy, real bound enforced below
        // via putIfAbsent semantics on the connection map.
        if (conns.size() >= MAX_CONNECTIONS) {
            return;
        }
        byte[] localIp = localAddr.getAddress().getAddress();
        byte[] peerIp = from.getAddress().getAddress();
        long conn = Quiche.accept(
            localCid, retryOdcid,
            localIp, localAddr.getPort(),
            peerIp, from.getPort(),
            quicheConfig.handle());
        if (conn == 0) {
            LOG.warning("h3 quiche_accept returned null");
            return;
        }
        CidKey key = new CidKey(localCid);
        CidKey odKey = new CidKey(clientDcid);
        Http3Connection h3conn = new Http3Connection(
            localCid, conn, channel, localAddr, from,
            handler,
            config,
            connExecutor,
            () -> { conns.remove(key); conns.remove(odKey); });
        Http3Connection prev = conns.putIfAbsent(key, h3conn);
        if (prev != null) {
            // Extremely unlikely collision on 128-bit random CID; keep
            // existing and abandon this one.
            h3conn.close();
            prev.enqueue(datagram);
            return;
        }
        // Also route packets whose DCID is still the client's original
        // (odcid) to this same connection. Client's second Initial packet
        // — sent before it sees any server response — carries the same
        // client-chosen DCID; without this alias every subsequent client
        // Initial would trigger a fresh acceptNew and clobber the
        // handshake (each Server Initial would use a different SCID, so
        // the client can never latch onto ours). Aliasing is safe: quiche
        // internally consumes/emits packets by our localCid; the odcid
        // alias only matters for demux routing.
        conns.putIfAbsent(odKey, h3conn);
        LOG.info("h3 accepted new connection cid="
            + HexFormat.of().formatHex(localCid) + " from " + from);
        h3conn.enqueue(datagram);
    }

    @Override
    public void close() throws IOException {
        // Signal demux to stop accepting, but leave the channel OPEN so
        // per-connection driver threads can flush their graceful
        // CONNECTION_CLOSE datagrams to peers on the way down (RFC 9114
        // §5.1). If we close the channel here, out.send in the driver
        // finally throws AsynchronousCloseException and peers never see
        // H3_NO_ERROR — task #133.
        running = false;
        for (Http3Connection c : conns.values()) {
            try { c.close(); } catch (Throwable ignored) {}
        }
        conns.clear();
        // Drain per-connection driver threads BEFORE freeing the shared
        // quiche_config — quiche's conn objects keep no strong ref to the
        // config after quiche_accept returns, but freeing config while a
        // still-running driver might touch anything config-adjacent is a
        // pointless risk. Ordering matters (task #113).
        if (connExecutor != null) {
            connExecutor.shutdown();
            try {
                connExecutor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        // Now safe to close the channel — all conn drivers have flushed
        // their final datagrams. Closing here also unblocks the demux
        // vthread (channel.receive throws AsynchronousCloseException).
        if (channel != null) {
            try { channel.close(); } catch (IOException ignored) {}
        }
        if (quicheConfig != null) {
            try { quicheConfig.close(); } catch (Throwable ignored) {}
        }
    }

    /**
     * ByteBuffer-backed hash key for connection ID lookups. Wrapping a raw
     * byte[] in a value class lets us use it as a {@code ConcurrentHashMap}
     * key without relying on identity semantics.
     */
    private static final class CidKey {
        private final byte[] bytes;
        private final int off;
        private final int len;
        private final int hash;

        /** Owned-copy variant — used as the persisted map key. */
        CidKey(byte[] bytes) {
            this.bytes = bytes;
            this.off = 0;
            this.len = bytes.length;
            this.hash = hashBytes(bytes, 0, bytes.length);
        }

        private CidKey(byte[] bytes, int off, int len, int hash) {
            this.bytes = bytes;
            this.off = off;
            this.len = len;
            this.hash = hash;
        }

        /**
         * Lookup-only view over a scratch buffer prefix. Do NOT store this
         * in the map — the backing array is reused across datagrams.
         * Safe for {@code get}/{@code containsKey} which only invoke
         * hashCode/equals synchronously.
         */
        static CidKey view(byte[] scratch, int len) {
            return new CidKey(scratch, 0, len, hashBytes(scratch, 0, len));
        }

        private static int hashBytes(byte[] a, int off, int len) {
            int h = 1;
            for (int i = 0; i < len; i++) h = 31 * h + a[off + i];
            return h;
        }

        @Override public int hashCode() { return hash; }
        @Override public boolean equals(Object o) {
            if (!(o instanceof CidKey k) || k.len != this.len) return false;
            for (int i = 0; i < len; i++) {
                if (bytes[off + i] != k.bytes[k.off + i]) return false;
            }
            return true;
        }
    }
}

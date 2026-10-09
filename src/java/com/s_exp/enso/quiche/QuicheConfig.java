// ABOUTME: Owns a native quiche_config: built from the server Config (certificate, ALPN, transport
// ABOUTME: parameters, flow-control windows and their autotuning bounds) or for the test client.
package com.s_exp.enso.quiche;

import com.s_exp.enso.api.Config;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@code quiche_config}. Server instances come from {@link #server}:
 * certificate and key from PEM files, ALPN "h3", the transport parameters
 * of {@link Config}. {@link #client} builds the test client's.
 *
 * <p>Flow control: quiche autotunes a receive window upwards (doubling,
 * when the application drains it within two RTTs) until
 * {@code max_connection_window} / {@code max_stream_window}, 24 MiB and
 * 16 MiB by default. Those bounds are what a peer can make quiche buffer
 * for a connection whose handler doesn't read, so they are pinned to the
 * configured initial windows: {@code :http3-initial-max-data-bytes} is a
 * hard per-connection bound, the per-stream windows a hard per-stream one.
 *
 * <p>Thread-safety: configure on one thread, then hand to the event
 * loops. Lifetime is reference counted: the creator holds one reference,
 * released by {@link #close}; each connection accepted with it holds
 * another ({@link #tryRetain} before {@code quiche_accept},
 * {@link #release} once the connection is freed). The native config is
 * freed when the last reference goes, so a replaced configuration (a
 * reloaded certificate) lives exactly as long as connections use it.
 */
public final class QuicheConfig implements AutoCloseable {

    private volatile long ptr;
    private final AtomicInteger refs = new AtomicInteger(1);
    // The creator's reference was given back (close is idempotent).
    private boolean closed;

    /** Effective flow-control values, for diagnostics and tests. */
    private long connectionWindow;
    private long streamWindowBidiRemote;
    private long streamWindowBidiLocal;
    private long streamWindowUni;

    private QuicheConfig(long ptr) {
        this.ptr = ptr;
    }

    private static long allocate() throws IOException {
        // Version 1 = the current wire version. quiche_config_new(0xbabababa)
        // is for version negotiation testing; we always advertise v1.
        long p = Quiche.configNew(Quiche.QUICHE_PROTOCOL_VERSION);
        if (p == 0) throw new IOException("quiche_config_new returned null");
        return p;
    }

    /** Server configuration from {@code cfg}; frees the native config if any step fails. */
    public static QuicheConfig server(Config cfg) throws IOException {
        QuicheConfig c = new QuicheConfig(allocate());
        try {
            c.loadCertKey(cfg);
            c.setApplicationProtos();
            c.setServerKnobs(cfg);
        } catch (Throwable t) {
            c.close();
            throw t;
        }
        return c;
    }

    /**
     * Test-client configuration: ALPN h3, no certificate verification,
     * generous windows unless overridden with the setters.
     */
    public static QuicheConfig client(long idleTimeoutMillis) throws IOException {
        QuicheConfig c = new QuicheConfig(allocate());
        try {
            c.setApplicationProtos();
            long p = c.ptr;
            Quiche.configVerifyPeer(p, false);
            Quiche.configSetMaxIdleTimeout(p, idleTimeoutMillis);
            Quiche.configSetMaxRecvUdpPayloadSize(p, 65527);
            Quiche.configSetMaxSendUdpPayloadSize(p, 1350);
            c.setInitialMaxData(100_000_000L);
            c.setInitialMaxStreamDataBidiLocal(10_000_000L);
            Quiche.configSetInitialMaxStreamDataBidiRemote(p, 10_000_000L);
            Quiche.configSetInitialMaxStreamDataUni(p, 10_000_000L);
            Quiche.configSetInitialMaxStreamsBidi(p, 100);
            Quiche.configSetInitialMaxStreamsUni(p, 100);
        } catch (Throwable t) {
            c.close();
            throw t;
        }
        return c;
    }

    /** The native handle; this package only. */
    long handle() {
        long p = ptr;
        if (p == 0) throw new IllegalStateException("quiche config already freed");
        return p;
    }

    /** Connection receive window, also its autotuning bound. */
    public void setInitialMaxData(long v) {
        long p = handle();
        Quiche.configSetInitialMaxData(p, v);
        Quiche.configSetMaxConnectionWindow(p, v);
        connectionWindow = v;
    }

    /**
     * Receive window of locally initiated bidirectional streams (a client's
     * requests: the response bytes the server may send before the client
     * reads), also the stream autotuning bound.
     */
    public void setInitialMaxStreamDataBidiLocal(long v) {
        long p = handle();
        Quiche.configSetInitialMaxStreamDataBidiLocal(p, v);
        Quiche.configSetMaxStreamWindow(p, v);
        streamWindowBidiLocal = v;
    }

    /** Largest UDP payload this endpoint accepts (its max_udp_payload_size transport parameter). */
    public void setMaxRecvUdpPayloadSize(long v) {
        Quiche.configSetMaxRecvUdpPayloadSize(handle(), v);
    }

    public long connectionWindow() { return connectionWindow; }

    public long streamWindowBidiRemote() { return streamWindowBidiRemote; }

    public long streamWindowBidiLocal() { return streamWindowBidiLocal; }

    public long streamWindowUni() { return streamWindowUni; }

    private void loadCertKey(Config cfg) throws IOException {
        int rc = Quiche.configLoadCertChainFromPemFile(handle(), cfg.http3CertPath);
        if (rc < 0) {
            throw new IOException("quiche_config_load_cert_chain_from_pem_file failed rc=" + rc
                + " for " + cfg.http3CertPath);
        }
        rc = Quiche.configLoadPrivKeyFromPemFile(handle(), cfg.http3KeyPath);
        if (rc < 0) {
            throw new IOException("quiche_config_load_priv_key_from_pem_file failed rc=" + rc
                + " for " + cfg.http3KeyPath);
        }
    }

    /** ALPN list, length-prefixed: {@code [len]["h3"]}. */
    private void setApplicationProtos() throws IOException {
        byte[] h3 = "h3".getBytes(StandardCharsets.US_ASCII);
        byte[] protos = new byte[1 + h3.length];
        protos[0] = (byte) h3.length;
        System.arraycopy(h3, 0, protos, 1, h3.length);
        int rc = Quiche.configSetApplicationProtos(handle(), protos);
        if (rc < 0) {
            throw new IOException("quiche_config_set_application_protos failed rc=" + rc);
        }
    }

    private void setServerKnobs(Config cfg) {
        long p = handle();
        // :idle-timeout is the connection's idle timeout on every
        // protocol; over QUIC it is the max_idle_timeout transport
        // parameter (RFC 9000 §10.1).
        Quiche.configSetMaxIdleTimeout(p, cfg.idleTimeoutMillis);
        Quiche.configSetMaxRecvUdpPayloadSize(p, cfg.http3MaxUdpPayloadBytes);
        Quiche.configSetMaxSendUdpPayloadSize(p, cfg.http3MaxUdpPayloadBytes);
        Quiche.configSetInitialMaxData(p, cfg.http3InitialMaxDataBytes);
        Quiche.configSetMaxConnectionWindow(p, cfg.http3InitialMaxDataBytes);
        connectionWindow = cfg.http3InitialMaxDataBytes;
        // Per-stream windows: explicit config when set, otherwise derived
        // from the connection window and stream count, at least 1 MiB
        // (never above the connection window).
        long derived = Math.min(cfg.http3InitialMaxDataBytes, Math.max(1L << 20,
            cfg.http3InitialMaxDataBytes / Math.max(1, cfg.http3InitialMaxStreamsBidi)));
        streamWindowBidiLocal = cfg.http3InitialMaxStreamDataBidiLocalBytes >= 0
            ? cfg.http3InitialMaxStreamDataBidiLocalBytes : derived;
        streamWindowBidiRemote = cfg.http3InitialMaxStreamDataBidiRemoteBytes >= 0
            ? cfg.http3InitialMaxStreamDataBidiRemoteBytes : derived;
        streamWindowUni = cfg.http3InitialMaxStreamDataUniBytes >= 0
            ? cfg.http3InitialMaxStreamDataUniBytes : derived;
        Quiche.configSetInitialMaxStreamDataBidiLocal(p, streamWindowBidiLocal);
        Quiche.configSetInitialMaxStreamDataBidiRemote(p, streamWindowBidiRemote);
        Quiche.configSetInitialMaxStreamDataUni(p, streamWindowUni);
        // One autotuning bound for every stream type: the largest window
        // configured, so no stream's initial window is cut.
        Quiche.configSetMaxStreamWindow(p,
            Math.max(streamWindowBidiRemote, Math.max(streamWindowBidiLocal, streamWindowUni)));
        Quiche.configSetInitialMaxStreamsBidi(p, cfg.http3InitialMaxStreamsBidi);
        // Peer needs 3 uni streams (control + QPACK enc/dec) plus any
        // grease uni streams they may open (RFC 9114 §7.2.8). Default 8
        // leaves headroom without needing on-demand MAX_STREAMS_UNI
        // updates; validation enforces >= 3.
        Quiche.configSetInitialMaxStreamsUni(p, cfg.http3InitialMaxStreamsUni);
        if (cfg.http3AckDelayExponent >= 0) {
            Quiche.configSetAckDelayExponent(p, cfg.http3AckDelayExponent);
        }
        if (cfg.http3MaxAckDelay >= 0) {
            Quiche.configSetMaxAckDelay(p, cfg.http3MaxAckDelay);
        }
        if (cfg.http3ActiveConnectionIdLimit >= 0) {
            Quiche.configSetActiveConnectionIdLimit(p, cfg.http3ActiveConnectionIdLimit);
        }
        Quiche.configSetDisableActiveMigration(p, true);
    }

    /**
     * Takes a reference for a connection. False once the config was freed
     * (its last reference released): the caller must use another one.
     */
    public boolean tryRetain() {
        while (true) {
            int r = refs.get();
            if (r <= 0) return false;
            if (refs.compareAndSet(r, r + 1)) return true;
        }
    }

    /** Gives back a reference taken by {@link #tryRetain}; the last one frees the native config. */
    public void release() {
        if (refs.decrementAndGet() == 0) free();
    }

    /** True once the native config was freed. */
    public boolean isFreed() {
        return ptr == 0;
    }

    private synchronized void free() {
        long p = ptr;
        if (p == 0) return;
        ptr = 0;
        Quiche.configFree(p);
    }

    /**
     * Gives back the creator's reference: the native config is freed now,
     * or when the last connection using it is. Idempotent.
     */
    @Override
    public void close() {
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        release();
    }
}

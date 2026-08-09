package com.s_exp.enso.quiche;

import com.s_exp.enso.api.Config;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Thin Java wrapper over a heap-allocated {@code quiche_config} pointer.
 * Populated from Enso's {@link Config} at listener startup — cert/key
 * PEM paths, ALPN protos, idle timeout, initial flow control windows.
 * {@link #close} frees the underlying quiche config.
 */
public final class QuicheConfig implements AutoCloseable {

    private final long ptr;

    public QuicheConfig(Config cfg) throws IOException {
        // Version 1 = the current wire version. quiche_config_new(0xbabababa)
        // is for version negotiation testing; we always advertise v1.
        this.ptr = Quiche.configNew(Quiche.QUICHE_PROTOCOL_VERSION);
        if (ptr == 0) {
            throw new IOException("quiche_config_new returned null");
        }
        loadCertKey(cfg);
        setApplicationProtos();
        setKnobs(cfg);
    }

    /** Raw {@code quiche_config *} handle for {@code quiche_accept}. */
    public long handle() {
        return ptr;
    }

    private void loadCertKey(Config cfg) throws IOException {
        int rc = Quiche.configLoadCertChainFromPemFile(ptr, cfg.http3CertPath);
        if (rc < 0) {
            throw new IOException("quiche_config_load_cert_chain_from_pem_file failed rc=" + rc
                + " for " + cfg.http3CertPath);
        }
        rc = Quiche.configLoadPrivKeyFromPemFile(ptr, cfg.http3KeyPath);
        if (rc < 0) {
            throw new IOException("quiche_config_load_priv_key_from_pem_file failed rc=" + rc
                + " for " + cfg.http3KeyPath);
        }
    }

    /**
     * quiche expects the ALPN list as a length-prefixed byte string:
     * {@code [len1][proto1 bytes][len2][proto2 bytes]…}. We only advertise
     * "h3" for now; add "http/1.1" if we ever want simultaneous fallback.
     */
    private void setApplicationProtos() throws IOException {
        byte[] h3 = "h3".getBytes(StandardCharsets.US_ASCII);
        byte[] protos = new byte[1 + h3.length];
        protos[0] = (byte) h3.length;
        System.arraycopy(h3, 0, protos, 1, h3.length);
        int rc = Quiche.configSetApplicationProtos(ptr, protos);
        if (rc < 0) {
            throw new IOException("quiche_config_set_application_protos failed rc=" + rc);
        }
    }

    private void setKnobs(Config cfg) {
        Quiche.configSetMaxIdleTimeout(ptr, cfg.http3MaxIdleTimeoutMs);
        Quiche.configSetMaxRecvUdpPayloadSize(ptr, cfg.http3MaxUdpPayloadSize);
        Quiche.configSetMaxSendUdpPayloadSize(ptr, cfg.http3MaxUdpPayloadSize);
        Quiche.configSetInitialMaxData(ptr, cfg.http3InitialMaxData);
        // Per-stream windows: use explicit config when set, otherwise
        // derive from connection window / stream count.
        long derived = Math.max(1L << 20,
            cfg.http3InitialMaxData / Math.max(1, cfg.http3InitialMaxStreamsBidi));
        long bidiLocal  = cfg.http3InitialMaxStreamDataBidiLocal  >= 0 ? cfg.http3InitialMaxStreamDataBidiLocal  : derived;
        long bidiRemote = cfg.http3InitialMaxStreamDataBidiRemote >= 0 ? cfg.http3InitialMaxStreamDataBidiRemote : derived;
        long uni        = cfg.http3InitialMaxStreamDataUni        >= 0 ? cfg.http3InitialMaxStreamDataUni        : derived;
        Quiche.configSetInitialMaxStreamDataBidiLocal(ptr, bidiLocal);
        Quiche.configSetInitialMaxStreamDataBidiRemote(ptr, bidiRemote);
        Quiche.configSetInitialMaxStreamDataUni(ptr, uni);
        Quiche.configSetInitialMaxStreamsBidi(ptr, cfg.http3InitialMaxStreamsBidi);
        // Peer needs 3 uni streams (control + QPACK enc/dec) plus any
        // grease uni streams they may open (RFC 9114 §7.2.8). Default 8
        // leaves headroom without needing on-demand MAX_STREAMS_UNI
        // updates (task #142); validation enforces >= 3.
        Quiche.configSetInitialMaxStreamsUni(ptr, cfg.http3InitialMaxStreamsUni);
        if (cfg.http3AckDelayExponent >= 0) {
            Quiche.configSetAckDelayExponent(ptr, cfg.http3AckDelayExponent);
        }
        if (cfg.http3MaxAckDelay >= 0) {
            Quiche.configSetMaxAckDelay(ptr, cfg.http3MaxAckDelay);
        }
        if (cfg.http3ActiveConnectionIdLimit >= 0) {
            Quiche.configSetActiveConnectionIdLimit(ptr, cfg.http3ActiveConnectionIdLimit);
        }
        Quiche.configSetDisableActiveMigration(ptr, true);
    }

    @Override
    public void close() {
        Quiche.configFree(ptr);
    }
}

package com.s_exp.enso.quiche;

import com.s_exp.enso.Config;
import com.s_exp.enso.quiche.ffm.quiche_h;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

/**
 * Thin Java wrapper over a heap-allocated {@code quiche_config} pointer.
 * Owns an {@link Arena} that keeps the config alive for the listener's
 * lifetime; {@link #close} frees both the arena and the quiche config via
 * {@code quiche_config_free}.
 *
 * <p>Populated from Enso's {@link Config} at listener startup — cert/key
 * PEM paths, ALPN protos, idle timeout, initial flow control windows.
 */
public final class QuicheConfig implements AutoCloseable {

    private final Arena arena;
    private final MemorySegment ptr;

    public QuicheConfig(Config cfg) throws IOException {
        this.arena = Arena.ofShared();
        // Version 1 = the current wire version. quiche_config_new(0xbabababa)
        // is for version negotiation testing; we always advertise v1.
        this.ptr = quiche_h.quiche_config_new(quiche_h.QUICHE_PROTOCOL_VERSION());
        if (ptr.address() == 0) {
            throw new IOException("quiche_config_new returned null");
        }
        loadCertKey(cfg);
        setApplicationProtos();
        setKnobs(cfg);
    }

    public MemorySegment segment() {
        return ptr;
    }

    private void loadCertKey(Config cfg) throws IOException {
        MemorySegment certPath = arena.allocateFrom(cfg.http3CertPath, StandardCharsets.UTF_8);
        int rc = quiche_h.quiche_config_load_cert_chain_from_pem_file(ptr, certPath);
        if (rc < 0) {
            throw new IOException("quiche_config_load_cert_chain_from_pem_file failed rc=" + rc
                + " for " + cfg.http3CertPath);
        }
        MemorySegment keyPath = arena.allocateFrom(cfg.http3KeyPath, StandardCharsets.UTF_8);
        rc = quiche_h.quiche_config_load_priv_key_from_pem_file(ptr, keyPath);
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
        MemorySegment protos = arena.allocate(1 + h3.length);
        protos.set(ValueLayout.JAVA_BYTE, 0, (byte) h3.length);
        MemorySegment.copy(h3, 0, protos, ValueLayout.JAVA_BYTE, 1, h3.length);
        int rc = quiche_h.quiche_config_set_application_protos(ptr, protos, protos.byteSize());
        if (rc < 0) {
            throw new IOException("quiche_config_set_application_protos failed rc=" + rc);
        }
    }

    private void setKnobs(Config cfg) {
        quiche_h.quiche_config_set_max_idle_timeout(ptr, cfg.http3MaxIdleTimeoutMs);
        quiche_h.quiche_config_set_max_recv_udp_payload_size(ptr, cfg.http3MaxUdpPayloadSize);
        quiche_h.quiche_config_set_max_send_udp_payload_size(ptr, cfg.http3MaxUdpPayloadSize);
        quiche_h.quiche_config_set_initial_max_data(ptr, cfg.http3InitialMaxData);
        // Per-stream windows sized to match the connection window / streams.
        long perStream = Math.max(1L << 20,
            cfg.http3InitialMaxData / Math.max(1, cfg.http3InitialMaxStreamsBidi));
        quiche_h.quiche_config_set_initial_max_stream_data_bidi_local(ptr, perStream);
        quiche_h.quiche_config_set_initial_max_stream_data_bidi_remote(ptr, perStream);
        quiche_h.quiche_config_set_initial_max_stream_data_uni(ptr, perStream);
        quiche_h.quiche_config_set_initial_max_streams_bidi(ptr, cfg.http3InitialMaxStreamsBidi);
        quiche_h.quiche_config_set_initial_max_streams_uni(ptr, cfg.http3InitialMaxStreamsBidi);
        quiche_h.quiche_config_set_disable_active_migration(ptr, true);
    }

    @Override
    public void close() {
        try {
            quiche_h.quiche_config_free(ptr);
        } finally {
            arena.close();
        }
    }
}

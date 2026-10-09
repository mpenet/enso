// ABOUTME: Owns one native quiche_conn: packet and stream I/O through state-checked methods, so no
// ABOUTME: raw pointer escapes and nothing touches the connection after it was freed.
package com.s_exp.enso.quiche;

import java.lang.ref.Reference;

/**
 * A {@code quiche_conn}. Not thread-safe: one thread (the connection's
 * event loop, or the test client) makes every call. After {@link #free}
 * every method throws {@link IllegalStateException} instead of passing a
 * dangling pointer to quiche.
 *
 * <p>Return conventions follow quiche: a count, {@link Quiche#QUICHE_ERR_DONE}
 * or another negative error code.
 *
 * <p>Calls that pass a {@link NativeBuffer}'s address keep the buffer
 * reachable until the native call returns
 * ({@link Reference#reachabilityFence}): once its address is read, nothing
 * else would stop the collector from freeing the memory mid-call.
 */
public final class QuicheConnection {

    private long ptr;

    private QuicheConnection(long ptr) {
        this.ptr = ptr;
    }

    /**
     * Server side: a connection for a client Initial, with local id
     * {@code scid} and, after a stateless Retry, the client's original
     * destination id {@code odcid} (null otherwise). Addresses are ADDR
     * records in {@code addrs}. Null when quiche refuses.
     */
    public static QuicheConnection accept(QuicheConfig config, byte[] scid, byte[] odcid,
                                          NativeBuffer addrs, int localOff, int peerOff) {
        try {
            long p = Quiche.accept(scid, odcid, addrs.address, addrs.capacity, localOff, peerOff,
                config.handle());
            return p == 0 ? null : new QuicheConnection(p);
        } finally {
            Reference.reachabilityFence(addrs);
            Reference.reachabilityFence(config);
        }
    }

    /** Client side (the test client). Null when quiche refuses. */
    public static QuicheConnection connect(QuicheConfig config, String serverName, byte[] scid,
                                           NativeBuffer addrs, int localOff, int peerOff) {
        try {
            long p = Quiche.connect(serverName, scid, addrs.address, addrs.capacity, localOff, peerOff,
                config.handle());
            return p == 0 ? null : new QuicheConnection(p);
        } finally {
            Reference.reachabilityFence(addrs);
            Reference.reachabilityFence(config);
        }
    }

    private long p() {
        long p = ptr;
        if (p == 0) throw new IllegalStateException("quiche connection already freed");
        return p;
    }

    public boolean isFreed() { return ptr == 0; }

    /** Feeds {@code buf[off, off + len)} received from the ADDR record {@code meta[peerOff]} on {@code meta[localOff]}. */
    public long recv(NativeBuffer buf, int off, int len, NativeBuffer meta, int peerOff, int localOff) {
        try {
            return Quiche.connRecv(p(), buf.address, buf.capacity, off, len, meta.address, meta.capacity,
                peerOff, localOff);
        } finally {
            Reference.reachabilityFence(buf);
            Reference.reachabilityFence(meta);
        }
    }

    /**
     * Writes the next packet into {@code out[off, off + cap)}; the PKT
     * record at {@code meta[metaOff]} receives its destination, source and
     * pacing delay (see {@link Records}).
     */
    public long send(NativeBuffer out, int off, int cap, NativeBuffer meta, int metaOff) {
        try {
            return Quiche.connSend(p(), out.address, out.capacity, off, cap, meta.address, meta.capacity,
                metaOff);
        } finally {
            Reference.reachabilityFence(out);
            Reference.reachabilityFence(meta);
        }
    }

    public boolean isClosed() { return Quiche.connIsClosed(p()); }

    public boolean isEstablished() { return Quiche.connIsEstablished(p()); }

    public boolean isDraining() { return Quiche.connIsDraining(p()); }

    /** Nanoseconds until quiche's next timer, or -1 when none is armed. */
    public long timeoutNanos() { return Quiche.connTimeoutAsNanos(p()); }

    /** {@link #timeoutNanos} result for a closed connection. */
    public static final long CLOSED = -2;

    /** {@link #CLOSED} once {@link #isClosed}, else {@link #timeoutNanos}. */
    public long timeoutNanosOrClosed() { return Quiche.connTimeoutAsNanosOrClosed(p()); }

    public void onTimeout() { Quiche.connOnTimeout(p()); }

    /**
     * When the peer closed the connection: {@code out[0]} 1 for an
     * application close, {@code out[1]} its code; true.
     */
    public boolean peerError(long[] out) { return Quiche.connPeerError(p(), out); }

    /**
     * When we closed the connection (quiche included, after a packet it
     * refused): {@code out[0]} 1 for an application close, {@code out[1]}
     * its code; true.
     */
    public boolean localError(long[] out) { return Quiche.connLocalError(p(), out); }

    /** CONNECTION_CLOSE: application ({@code app}) or transport error {@code err}. */
    public int close(boolean app, long err, byte[] reason) {
        return Quiche.connClose(p(), app, err, reason);
    }

    /** The smoothed round-trip time estimate in nanoseconds, -1 when unknown. */
    public long rttNanos() { return Quiche.connRttNanos(p()); }

    /** DER bytes of the certificate the peer presented, or null. */
    public byte[] peerCertificate() { return Quiche.connPeerCert(p()); }

    /** Queues a PING so the next packet is ack-eliciting. */
    public long sendAckEliciting() { return Quiche.connSendAckEliciting(p()); }

    /** {@link #streamRecv} results at or below this are a peer reset; see {@link #resetCode}. */
    public static final long STREAM_RESET_BASE = -(1L << 62);

    /**
     * {@code (bytes << 1) | fin} read into {@code out[off, off + len)}; a
     * peer RESET_STREAM as a value {@code <= STREAM_RESET_BASE} (see
     * {@link #resetCode}); else a negative quiche error.
     */
    public long streamRecv(long streamId, byte[] out, int off, int len) {
        return Quiche.connStreamRecv(p(), streamId, out, off, len);
    }

    /** The peer's error code of a {@link #streamRecv} result that reports a reset, else -1. */
    public static long resetCode(long rc) {
        return rc <= STREAM_RESET_BASE ? STREAM_RESET_BASE - rc : -1;
    }

    /** Bytes of {@code buf[off, off + len)} quiche took, or a negative error. */
    public long streamSend(long streamId, byte[] buf, int off, int len, boolean fin) {
        return Quiche.connStreamSend(p(), streamId, buf, off, len, fin);
    }

    public int streamShutdown(long streamId, int direction, long err) {
        return Quiche.connStreamShutdown(p(), streamId, direction, err);
    }

    public long streamCapacity(long streamId) {
        return Quiche.connStreamCapacity(p(), streamId);
    }

    /** Next stream with data to read, -1 when none (reported once until new data arrives). */
    public long readableNext() { return Quiche.connStreamReadableNext(p()); }

    /** Next stream whose send capacity grew (or that was stopped), -1 when none. */
    public long writableNext() { return Quiche.connStreamWritableNext(p()); }

    /** Frees the native connection. Idempotent; the handle is unusable afterwards. */
    public void free() {
        long p = ptr;
        if (p == 0) return;
        ptr = 0;
        Quiche.connFree(p);
    }

    /** Parses the QUIC header of {@code buf[off, off + len)} into the HDR record at {@code out[outOff]}. */
    public static int headerInfo(NativeBuffer buf, int off, int len, int dcil, NativeBuffer out,
                                 int outOff) {
        try {
            return Quiche.headerInfo(buf.address, buf.capacity, off, len, dcil, out.address, out.capacity,
                outOff);
        } finally {
            Reference.reachabilityFence(buf);
            Reference.reachabilityFence(out);
        }
    }

    public static boolean versionIsSupported(int version) {
        return Quiche.versionIsSupported(version);
    }

    /** A Retry packet into {@code out[off, off + cap)}; its length or a negative error. */
    public static long retry(byte[] scid, byte[] dcid, byte[] newScid, byte[] token, int version,
                             NativeBuffer out, int off, int cap) {
        try {
            return Quiche.retry(scid, dcid, newScid, token, version, out.address, out.capacity, off, cap);
        } finally {
            Reference.reachabilityFence(out);
        }
    }

    /** A Version Negotiation packet into {@code out[off, off + cap)}; its length or a negative error. */
    public static long negotiateVersion(byte[] scid, byte[] dcid, NativeBuffer out, int off, int cap) {
        try {
            return Quiche.negotiateVersion(scid, dcid, out.address, out.capacity, off, cap);
        } finally {
            Reference.reachabilityFence(out);
        }
    }
}

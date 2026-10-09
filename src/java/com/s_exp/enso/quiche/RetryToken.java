// ABOUTME: Mints and verifies stateless Retry tokens: HMAC-bound to the client address and family,
// ABOUTME: the original and Retry connection ids, and a 10 s lifetime.
package com.s_exp.enso.quiche;

import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Mint + verify stateless-retry tokens for QUIC Initial packets (RFC 9000
 * §8.1.2). The listener uses these to force a round-trip before allocating
 * connection state, defeating handshake floods.
 *
 * <p>Layout: {@code HMAC(32) || magic(4) || issuedAt(8) || ipLen(1) ||
 * peerIp(4|16) || peerPort(2) || odcid_len(1) || odcid(≤20) || scid_len(1)
 * || scid(≤20)}. The keyed-HMAC(SHA-256) tag covers everything after it, so
 * an attacker who can see one valid token can't fabricate another for a
 * different peer. The address length binds the family: the bytes of an
 * IPv6 token can't be read as a valid IPv4 layout. {@code scid} is the Source Connection ID of our Retry
 * packet: the client's retried Initial MUST use it as its Destination
 * Connection ID (RFC 9000 §17.2.5.2), and the server adopts that DCID as
 * the connection's ID, so binding it stops a client from choosing its
 * own server-side CID (wrong length for short-header routing, or a
 * collision with an existing connection).
 *
 * <p>The HMAC key is generated at listener start and lives only in memory
 * — tokens don't survive server restart, which is fine because clients
 * always retry from the Initial state on failure.
 */
public final class RetryToken {

    private static final byte[] MAGIC = { 'e', 'n', '3', '0' };
    private static final int HMAC_LEN = 32; // SHA-256
    // 8-byte issued-at (seconds since epoch, big-endian) folded into the
    // token body between MAGIC and the peer address. Verify rejects
    // tokens older than TOKEN_MAX_AGE_SECONDS. Bounds replay of a stolen
    // token to a small window.
    static final int ISSUED_AT_LEN = 8;
    static final long TOKEN_MAX_AGE_SECONDS = 10;

    /** A thread's HMAC keyed for this instance, and its tag scratch. */
    private static final class Signer {
        final Mac mac;
        final byte[] tag = new byte[HMAC_LEN];

        Signer(SecretKeySpec key) {
            try {
                mac = Mac.getInstance("HmacSHA256");
                mac.init(key);
            } catch (Exception e) {
                throw new IllegalStateException("HmacSHA256 unavailable", e);
            }
        }
    }

    // One HMAC per thread (in practice per event loop): loops minting and
    // verifying under a flood never wait on each other.
    private final ThreadLocal<Signer> signers;

    public RetryToken() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        SecretKeySpec spec = new SecretKeySpec(key, "HmacSHA256");
        // Fails here, when the listener starts, if HMAC is unavailable.
        new Signer(spec);
        this.signers = ThreadLocal.withInitial(() -> new Signer(spec));
    }

    /**
     * Encode a token binding the peer address, the original destination
     * connection ID and the Retry packet's source connection ID
     * {@code retryScid}. The peer must echo the token verbatim in its
     * retried Initial; {@link #verify} then checks all three.
     */
    public byte[] mint(InetSocketAddress peer, byte[] odcid, byte[] retryScid) {
        // Body built directly into `out[HMAC_LEN..]`, HMAC over that
        // region, tag into `out[0..HMAC_LEN]`: one allocation, the
        // returned array.
        byte[] ip = peer.getAddress().getAddress();
        int addrLen = 1 + ip.length + 2; // length, ip, 2-byte port (matches verify layout)
        int bodyLen = MAGIC.length + ISSUED_AT_LEN + addrLen + 1 + odcid.length
            + 1 + retryScid.length;
        byte[] out = new byte[HMAC_LEN + bodyLen];
        int p = HMAC_LEN;
        System.arraycopy(MAGIC, 0, out, p, MAGIC.length); p += MAGIC.length;
        long issuedAt = System.currentTimeMillis() / 1000L;
        for (int i = 7; i >= 0; i--) {
            out[p++] = (byte) ((issuedAt >>> (i * 8)) & 0xFF);
        }
        out[p++] = (byte) ip.length;
        System.arraycopy(ip, 0, out, p, ip.length); p += ip.length;
        int port = peer.getPort();
        out[p++] = (byte) ((port >>> 8) & 0xFF);
        out[p++] = (byte) (port & 0xFF);
        out[p++] = (byte) odcid.length;
        System.arraycopy(odcid, 0, out, p, odcid.length); p += odcid.length;
        out[p++] = (byte) retryScid.length;
        System.arraycopy(retryScid, 0, out, p, retryScid.length);
        Mac mac = signers.get().mac;
        mac.reset();
        mac.update(out, HMAC_LEN, bodyLen);
        try {
            mac.doFinal(out, 0);
        } catch (javax.crypto.ShortBufferException e) {
            throw new IllegalStateException("HMAC output overflow", e);
        }
        return out;
    }

    /**
     * Check the token in {@code buf[off, off+len)} for a retried Initial
     * from {@code peer} whose Destination Connection ID is
     * {@code dcid[0, dcidLen)}.
     *
     * @return the original DCID when the HMAC, age, peer address and
     *   Retry SCID all match; {@code null} otherwise.
     */
    public byte[] verify(byte[] buf, int off, int len, InetSocketAddress peer,
                         byte[] dcid, int dcidLen) {
        if (buf == null || len < HMAC_LEN + MAGIC.length + ISSUED_AT_LEN + 1) return null;
        int end = off + len;
        Signer signer = signers.get();
        signer.mac.reset();
        signer.mac.update(buf, off + HMAC_LEN, len - HMAC_LEN);
        try {
            signer.mac.doFinal(signer.tag, 0);
        } catch (javax.crypto.ShortBufferException e) {
            throw new IllegalStateException("HMAC output overflow", e);
        }
        // Constant-time compare over the tag prefix without slicing.
        if (!constantTimeEquals(buf, off, signer.tag, 0, HMAC_LEN)) return null;
        int p = off + HMAC_LEN;
        for (int i = 0; i < MAGIC.length; i++) {
            if (p >= end || buf[p++] != MAGIC[i]) return null;
        }
        // 8-byte issued-at (seconds). Reject stale or future-dated tokens.
        if (p + ISSUED_AT_LEN > end) return null;
        long issuedAt = 0;
        for (int i = 0; i < 8; i++) {
            issuedAt = (issuedAt << 8) | (buf[p++] & 0xFFL);
        }
        long nowSec = System.currentTimeMillis() / 1000L;
        long age = nowSec - issuedAt;
        if (age < -1 || age > TOKEN_MAX_AGE_SECONDS) return null;
        // Peer IP: its length (4 for v4, 16 for v6), then its bytes.
        byte[] ip = peer.getAddress().getAddress();
        if (p >= end || (buf[p++] & 0xFF) != ip.length) return null;
        for (int i = 0; i < ip.length; i++) {
            if (p >= end || buf[p++] != ip[i]) return null;
        }
        // Peer port: big-endian short.
        if (p + 2 > end) return null;
        int port = ((buf[p] & 0xFF) << 8) | (buf[p + 1] & 0xFF);
        if (port != (peer.getPort() & 0xFFFF)) return null;
        p += 2;
        if (p >= end) return null;
        int odcidLen = buf[p++] & 0xFF;
        if (odcidLen > 20 || p + odcidLen >= end) return null;
        int odcidOff = p;
        p += odcidLen;
        int scidLen = buf[p++] & 0xFF;
        if (scidLen != dcidLen || p + scidLen != end) return null;
        for (int i = 0; i < scidLen; i++) {
            if (buf[p + i] != dcid[i]) return null;
        }
        byte[] odcid = new byte[odcidLen];
        System.arraycopy(buf, odcidOff, odcid, 0, odcidLen);
        return odcid;
    }

    /**
     * True when {@code token} has the shape of a token this class mints
     * (length and magic), whether or not it verifies. Distinguishes a
     * stale or misdirected Retry token of ours from a foreign one.
     */
    public static boolean looksMinted(byte[] token) {
        if (token.length < HMAC_LEN + MAGIC.length + ISSUED_AT_LEN + 2) return false;
        for (int i = 0; i < MAGIC.length; i++) {
            if (token[HMAC_LEN + i] != MAGIC[i]) return false;
        }
        return true;
    }

    private static boolean constantTimeEquals(byte[] a, int aOff,
                                              byte[] b, int bOff, int len) {
        int diff = 0;
        for (int i = 0; i < len; i++) diff |= (a[aOff + i] ^ b[bOff + i]);
        return diff == 0;
    }

}

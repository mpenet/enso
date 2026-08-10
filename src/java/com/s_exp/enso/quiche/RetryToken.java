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
 * <p>Layout: {@code magic(4) || peerAddrDigest(32) || odcid_len(1) ||
 * odcid(≤20)}. The whole blob is prefixed with a keyed-HMAC(SHA-256) tag
 * so an attacker who can see one valid token can't fabricate another for
 * a different peer.
 *
 * <p>The HMAC key is generated at listener start and lives only in memory
 * — tokens don't survive server restart, which is fine because clients
 * always retry from the Initial state on failure.
 */
public final class RetryToken {

    private static final byte[] MAGIC = { 'e', 'n', '3', '0' };
    private static final int HMAC_LEN = 32; // SHA-256

    private final Mac mac;

    public RetryToken() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        try {
            this.mac = Mac.getInstance("HmacSHA256");
            this.mac.init(new SecretKeySpec(key, "HmacSHA256"));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /**
     * Encode a token binding the peer address and the original destination
     * connection ID. The peer must echo the token verbatim in its retry
     * Initial; {@link #verify} then binds the peer to the same odcid.
     */
    public byte[] mint(InetSocketAddress peer, byte[] odcid) {
        // Build body directly into `out[HMAC_LEN..]`, then HMAC over that
        // region, then write tag into `out[0..HMAC_LEN]`. Task #145
        // dropped the alloc from verify; this drops mint from 4 allocs
        // to 1 (the returned array).
        byte[] ip = peer.getAddress().getAddress();
        int addrLen = ip.length + 2; // ip + 2-byte port (matches verify layout)
        int bodyLen = MAGIC.length + addrLen + 1 + odcid.length;
        byte[] out = new byte[HMAC_LEN + bodyLen];
        int p = HMAC_LEN;
        System.arraycopy(MAGIC, 0, out, p, MAGIC.length); p += MAGIC.length;
        System.arraycopy(ip, 0, out, p, ip.length); p += ip.length;
        int port = peer.getPort();
        out[p++] = (byte) ((port >>> 8) & 0xFF);
        out[p++] = (byte) (port & 0xFF);
        out[p++] = (byte) odcid.length;
        System.arraycopy(odcid, 0, out, p, odcid.length);
        synchronized (mac) {
            mac.reset();
            mac.update(out, HMAC_LEN, bodyLen);
            try {
                mac.doFinal(out, 0);
            } catch (javax.crypto.ShortBufferException e) {
                throw new IllegalStateException("HMAC output overflow", e);
            }
        }
        return out;
    }

    /**
     * @return the original DCID from the token when the HMAC and peer
     *   address match; {@code null} on any mismatch.
     */
    public byte[] verify(byte[] token, InetSocketAddress peer) {
        if (token == null || token.length < HMAC_LEN + MAGIC.length + 1) return null;
        // Slice-based verify — no intermediate body[] / copyOfRange
        // (task #145). HMAC over the tail via mac.update(off,len).
        byte[] tag;
        synchronized (mac) {
            mac.reset();
            mac.update(token, HMAC_LEN, token.length - HMAC_LEN);
            tag = mac.doFinal();
        }
        // Constant-time compare over the tag prefix without slicing.
        if (!constantTimeEquals(token, 0, tag, 0, HMAC_LEN)) return null;
        // Body starts at token[HMAC_LEN].
        int p = HMAC_LEN;
        int end = token.length;
        for (int i = 0; i < MAGIC.length; i++) {
            if (p >= end || token[p++] != MAGIC[i]) return null;
        }
        // Peer IP: 4 bytes v4 or 16 bytes v6.
        byte[] ip = peer.getAddress().getAddress();
        for (int i = 0; i < ip.length; i++) {
            if (p >= end || token[p++] != ip[i]) return null;
        }
        // Peer port: big-endian short.
        if (p + 2 > end) return null;
        int port = ((token[p] & 0xFF) << 8) | (token[p + 1] & 0xFF);
        if (port != (peer.getPort() & 0xFFFF)) return null;
        p += 2;
        if (p >= end) return null;
        int odcidLen = token[p++] & 0xFF;
        if (odcidLen > 20 || p + odcidLen != end) return null;
        byte[] odcid = new byte[odcidLen];
        System.arraycopy(token, p, odcid, 0, odcidLen);
        return odcid;
    }

    private static boolean constantTimeEquals(byte[] a, int aOff,
                                              byte[] b, int bOff, int len) {
        int diff = 0;
        for (int i = 0; i < len; i++) diff |= (a[aOff + i] ^ b[bOff + i]);
        return diff == 0;
    }

}

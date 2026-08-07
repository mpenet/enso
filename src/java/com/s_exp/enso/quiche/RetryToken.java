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
        byte[] addr = addressBytes(peer);
        byte[] body = new byte[MAGIC.length + addr.length + 1 + odcid.length];
        int p = 0;
        System.arraycopy(MAGIC, 0, body, p, MAGIC.length); p += MAGIC.length;
        System.arraycopy(addr, 0, body, p, addr.length); p += addr.length;
        body[p++] = (byte) odcid.length;
        System.arraycopy(odcid, 0, body, p, odcid.length);
        byte[] tag;
        synchronized (mac) {
            mac.reset();
            tag = mac.doFinal(body);
        }
        byte[] out = new byte[HMAC_LEN + body.length];
        System.arraycopy(tag, 0, out, 0, HMAC_LEN);
        System.arraycopy(body, 0, out, HMAC_LEN, body.length);
        return out;
    }

    /**
     * @return the original DCID from the token when the HMAC and peer
     *   address match; {@code null} on any mismatch.
     */
    public byte[] verify(byte[] token, InetSocketAddress peer) {
        if (token == null || token.length < HMAC_LEN + MAGIC.length + 1) return null;
        byte[] body = new byte[token.length - HMAC_LEN];
        System.arraycopy(token, HMAC_LEN, body, 0, body.length);
        byte[] tag;
        synchronized (mac) {
            mac.reset();
            tag = mac.doFinal(body);
        }
        // Constant-time compare — matters when a peer can control the
        // token body via replay/probe attempts.
        if (!MessageDigest.isEqual(java.util.Arrays.copyOfRange(token, 0, HMAC_LEN), tag)) {
            return null;
        }
        int p = 0;
        for (int i = 0; i < MAGIC.length; i++) {
            if (body[p++] != MAGIC[i]) return null;
        }
        byte[] addr = addressBytes(peer);
        for (int i = 0; i < addr.length; i++) {
            if (p >= body.length || body[p++] != addr[i]) return null;
        }
        if (p >= body.length) return null;
        int odcidLen = body[p++] & 0xFF;
        if (odcidLen > 20 || p + odcidLen != body.length) return null;
        byte[] odcid = new byte[odcidLen];
        System.arraycopy(body, p, odcid, 0, odcidLen);
        return odcid;
    }

    private static byte[] addressBytes(InetSocketAddress addr) {
        byte[] ip = addr.getAddress().getAddress();
        byte[] out = new byte[ip.length + 2];
        System.arraycopy(ip, 0, out, 0, ip.length);
        int port = addr.getPort();
        out[ip.length]     = (byte) ((port >>> 8) & 0xFF);
        out[ip.length + 1] = (byte) (port & 0xFF);
        return out;
    }
}

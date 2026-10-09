// ABOUTME: Builds a server Initial packet carrying a transport CONNECTION_CLOSE without any
// ABOUTME: connection state: Initial keys derived from the client's destination id (RFC 9001 §5).
package com.s_exp.enso.quiche;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 9000 §8.1.2: a server receiving a client Initial with an invalid
 * Retry token SHOULD close the connection with INVALID_TOKEN. A client
 * accepts one Retry per connection attempt (§17.2.5.2), so answering with
 * another Retry would leave it waiting for a timeout. This writes the
 * close statelessly, as a server Initial protected with the Initial keys
 * (RFC 9001 §5.2) derived from the destination id of the client's packet:
 * no quiche connection, no handshake work. The packet is a few dozen
 * bytes, far below the 1200-byte datagram that triggered it.
 *
 * <p>The same packet carries the error of a client Initial quiche refused
 * (e.g. TRANSPORT_PARAMETER_ERROR): quiche queues that close at the
 * Handshake level, which a client that never received our ServerHello
 * can't decrypt (RFC 9000 §10.2.3 asks for an Initial as well).
 */
public final class InitialClose {

    private static final byte[] INITIAL_SALT_V1 = {
        0x38, 0x76, 0x2c, (byte) 0xf7, (byte) 0xf5, 0x59, 0x34, (byte) 0xb3, 0x4d, 0x17,
        (byte) 0x9a, (byte) 0xe6, (byte) 0xa4, (byte) 0xc8, 0x0c, (byte) 0xad, (byte) 0xcc,
        (byte) 0xbb, 0x7f, 0x0a};
    /** RFC 9000 §20.1. */
    public static final int INVALID_TOKEN = 0x0b;
    private static final int CONNECTION_CLOSE_TRANSPORT = 0x1c;
    private static final int TAG_LEN = 16;
    // Payload: CONNECTION_CLOSE then PADDING, long enough for the header
    // protection sample (RFC 9001 §5.4.2).
    private static final int PAYLOAD_LEN = 20;

    private InitialClose() {}

    private static final byte[] INFO_SERVER_IN = labelInfo("server in", 32);
    private static final byte[] INFO_KEY = labelInfo("quic key", 16);
    private static final byte[] INFO_IV = labelInfo("quic iv", 12);
    private static final byte[] INFO_HP = labelInfo("quic hp", 16);
    private static final SecretKeySpec SALT_KEY = new SecretKeySpec(INITIAL_SALT_V1, "HmacSHA256");
    // A key and nonce no Initial derives in practice, to step the GCM
    // cipher off the previous pair (see build).
    private static final SecretKeySpec RESET_KEY = new SecretKeySpec(new byte[16], "AES");
    private static final GCMParameterSpec RESET_NONCE = new GCMParameterSpec(128, new byte[12]);

    /**
     * The MAC and ciphers, looked up once per thread (an event loop): a
     * flood of forged tokens costs key derivation and two block cipher
     * calls per reply, not provider lookups. Also the last packet built,
     * returned again for the same inputs (a retransmitted Initial): the
     * JDK refuses to encrypt twice with one GCM key and nonce.
     */
    private static final class Crypto {
        final Mac mac = Mac.getInstance("HmacSHA256");
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        final byte[] prk = new byte[32];
        final byte[] secret = new byte[32];
        final byte[] scratch = new byte[32];
        final byte[] key = new byte[16];
        final byte[] iv = new byte[12];
        final byte[] hp = new byte[16];
        final byte[] mask = new byte[16];
        final byte[] payload = new byte[PAYLOAD_LEN];
        byte[] lastPacket;
        int lastCode = -1;
        byte[] lastDcid;
        byte[] lastScid;
        // The destination id whose key and nonce the GCM cipher was last
        // initialised with.
        byte[] gcmDcid;

        Crypto() throws GeneralSecurityException {}

        boolean sameAsLast(int code, byte[] dcid, byte[] scid) {
            return lastPacket != null && code == lastCode && Arrays.equals(dcid, lastDcid)
                && Arrays.equals(scid, lastScid);
        }
    }

    private static final ThreadLocal<Crypto> CRYPTO = ThreadLocal.withInitial(() -> {
        try {
            return new Crypto();
        } catch (GeneralSecurityException e) {
            return null;
        }
    });

    /**
     * Writes into {@code out[off, off + cap)} a server Initial closing with
     * INVALID_TOKEN, answering a client Initial whose destination id was
     * {@code clientDcid} and source id {@code clientScid}. Returns its
     * length, or -1 when it doesn't fit (or the crypto is unavailable).
     */
    public static long invalidToken(byte[] clientDcid, byte[] clientScid, int version,
                                    ByteBuffer out, int off, int cap) {
        return transportClose(INVALID_TOKEN, clientDcid, clientScid, version, out, off, cap);
    }

    /**
     * Like {@link #invalidToken} with the transport error {@code code}
     * ({@code < 2^14}). Only valid as the server's first Initial: it uses
     * packet number 0.
     */
    public static long transportClose(int code, byte[] clientDcid, byte[] clientScid, int version,
                                      ByteBuffer out, int off, int cap) {
        if (version != Quiche.QUICHE_PROTOCOL_VERSION || code < 0 || code >= (1 << 14)) return -1;
        Crypto c = CRYPTO.get();
        if (c == null) return -1;
        try {
            byte[] pkt = c.sameAsLast(code, clientDcid, clientScid)
                ? c.lastPacket : build(c, code, clientDcid, clientScid, version);
            if (pkt.length > cap) return -1;
            out.put(off, pkt);
            return pkt.length;
        } catch (GeneralSecurityException e) {
            return -1;
        }
    }

    private static byte[] build(Crypto c, int code, byte[] clientDcid, byte[] clientScid, int version)
            throws GeneralSecurityException {
        // RFC 9001 §5.2: initial secret, then the server's key, iv and
        // header-protection key.
        c.mac.init(SALT_KEY);
        c.mac.update(clientDcid);
        c.mac.doFinal(c.prk, 0);
        expandLabel(c, c.prk, INFO_SERVER_IN, c.secret);
        expandLabel(c, c.secret, INFO_KEY, c.key);
        expandLabel(c, c.secret, INFO_IV, c.iv);
        expandLabel(c, c.secret, INFO_HP, c.hp);

        // Header: long, Initial, 1-byte packet number 0; our DCID is the
        // client's source id, our SCID the id it addressed.
        int pnLen = 1;
        int length = pnLen + PAYLOAD_LEN + TAG_LEN;
        int headerLen = 1 + 4 + 1 + clientScid.length + 1 + clientDcid.length + 1 + 2 + pnLen;
        byte[] pkt = new byte[headerLen + PAYLOAD_LEN + TAG_LEN];
        int p = 0;
        pkt[p++] = (byte) (0xC0 | (pnLen - 1));
        pkt[p++] = (byte) (version >>> 24);
        pkt[p++] = (byte) (version >>> 16);
        pkt[p++] = (byte) (version >>> 8);
        pkt[p++] = (byte) version;
        pkt[p++] = (byte) clientScid.length;
        System.arraycopy(clientScid, 0, pkt, p, clientScid.length);
        p += clientScid.length;
        pkt[p++] = (byte) clientDcid.length;
        System.arraycopy(clientDcid, 0, pkt, p, clientDcid.length);
        p += clientDcid.length;
        pkt[p++] = 0; // token length
        pkt[p++] = (byte) (0x40 | (length >>> 8));
        pkt[p++] = (byte) length;
        int pnOffset = p;
        pkt[p++] = 0; // packet number 0

        byte[] payload = c.payload;
        Arrays.fill(payload, (byte) 0);
        payload[0] = (byte) CONNECTION_CLOSE_TRANSPORT;
        // Error code as a 2-byte varint, frame type none, empty reason;
        // PADDING (0x00) follows.
        payload[1] = (byte) (0x40 | (code >>> 8));
        payload[2] = (byte) code;
        payload[3] = 0; // frame type: none
        payload[4] = 0; // reason length

        // Nonce: the IV XORed with the packet number (0). The JDK refuses
        // to encrypt with the key and nonce it last encrypted with: an
        // Initial to the same destination id (another source id or code)
        // first steps the cipher onto a throwaway pair.
        if (Arrays.equals(c.gcmDcid, clientDcid)) {
            c.gcm.init(Cipher.ENCRYPT_MODE, RESET_KEY, RESET_NONCE);
        }
        c.gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(c.key, "AES"), new GCMParameterSpec(128, c.iv));
        c.gcmDcid = clientDcid.clone();
        c.gcm.updateAAD(pkt, 0, headerLen);
        c.gcm.doFinal(payload, 0, payload.length, pkt, headerLen);

        // Header protection: sample 4 bytes past the packet number start.
        c.ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(c.hp, "AES"));
        c.ecb.doFinal(pkt, pnOffset + 4, 16, c.mask, 0);
        pkt[0] ^= (byte) (c.mask[0] & 0x0f);
        for (int i = 0; i < pnLen; i++) pkt[pnOffset + i] ^= c.mask[1 + i];

        c.lastPacket = pkt;
        c.lastCode = code;
        c.lastDcid = clientDcid.clone();
        c.lastScid = clientScid.clone();
        return pkt;
    }

    /** RFC 8446 §7.1 HKDF-Expand-Label (context empty, one block) of {@code secret} into {@code out}. */
    private static void expandLabel(Crypto c, byte[] secret, byte[] info, byte[] out)
            throws GeneralSecurityException {
        c.mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        c.mac.update(info);
        c.mac.doFinal(c.scratch, 0);
        System.arraycopy(c.scratch, 0, out, 0, out.length);
    }

    /** The HkdfLabel of {@code label} for an output of {@code len} bytes, the expansion counter appended. */
    private static byte[] labelInfo(String label, int len) {
        byte[] full = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[2 + 1 + full.length + 1 + 1];
        info[0] = (byte) (len >>> 8);
        info[1] = (byte) len;
        info[2] = (byte) full.length;
        System.arraycopy(full, 0, info, 3, full.length);
        info[3 + full.length] = 0; // context length
        info[4 + full.length] = 1; // HKDF-Expand counter
        return info;
    }
}

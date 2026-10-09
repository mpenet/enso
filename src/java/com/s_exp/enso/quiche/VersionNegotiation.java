// ABOUTME: Builds a QUIC Version Negotiation packet answering a long header of any version, with
// ABOUTME: connection ids of up to 255 bytes (RFC 8999 §6, RFC 9000 §17.2.1); no native call.
package com.s_exp.enso.quiche;

import java.nio.ByteBuffer;

/**
 * RFC 8999 fixes only the version-independent part of a long header:
 * the form bit, a 32-bit version, then destination and source connection
 * ids of 0 to 255 bytes each. A server answers an unsupported version
 * with Version Negotiation whatever those ids' lengths and whatever the
 * remaining bits of the first byte (they mean nothing outside the
 * version that defines them), so this reads the header itself rather
 * than through quiche, whose parser applies QUIC v1's 20-byte limit.
 * Allocation-free.
 */
public final class VersionNegotiation {

    private VersionNegotiation() {}

    /** The version of the long header at {@code pkt[off]} ({@code len >= 5}). */
    public static int version(ByteBuffer pkt, int off) {
        return (pkt.get(off + 1) & 0xFF) << 24 | (pkt.get(off + 2) & 0xFF) << 16
            | (pkt.get(off + 3) & 0xFF) << 8 | (pkt.get(off + 4) & 0xFF);
    }

    /**
     * Writes into {@code out[outOff, outOff + cap)} the Version
     * Negotiation packet answering the long header in
     * {@code pkt[off, off + len)}: its source id as destination, its
     * destination id as source, QUIC v1 as the only version.
     * {@code unused} fills the first byte's arbitrary bits (RFC 9000
     * §17.2.1; 0x40 is always set, for protocol multiplexing).
     *
     * @return the packet's length; 0 when the header is truncated or the
     *   packet doesn't fit
     */
    public static int write(ByteBuffer pkt, int off, int len, int unused, ByteBuffer out, int outOff, int cap) {
        if (len < 7) return 0;
        int dcidLen = pkt.get(off + 5) & 0xFF;
        if (6 + dcidLen + 1 > len) return 0;
        int scidLen = pkt.get(off + 6 + dcidLen) & 0xFF;
        if (7 + dcidLen + scidLen > len) return 0;
        int size = 1 + 4 + 1 + scidLen + 1 + dcidLen + 4;
        if (size > cap) return 0;
        int at = outOff;
        out.put(at++, (byte) (0xC0 | (unused & 0x3F)));
        for (int i = 0; i < 4; i++) out.put(at++, (byte) 0);
        out.put(at++, (byte) scidLen);
        out.put(at, pkt, off + 7 + dcidLen, scidLen);
        at += scidLen;
        out.put(at++, (byte) dcidLen);
        out.put(at, pkt, off + 6, dcidLen);
        at += dcidLen;
        int v = Quiche.QUICHE_PROTOCOL_VERSION;
        out.put(at++, (byte) (v >>> 24));
        out.put(at++, (byte) (v >>> 16));
        out.put(at++, (byte) (v >>> 8));
        out.put(at++, (byte) v);
        return at - outOff;
    }
}

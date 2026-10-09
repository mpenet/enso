// ABOUTME: Layouts of the fixed-size records the shim exchanges through direct buffers (socket
// ABOUTME: addresses, per-datagram receive/send metadata, parsed packet headers) and their codecs.
package com.s_exp.enso.quiche;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Record layouts shared with {@code enso_quiche.c}. Multi-byte fields are
 * in native byte order: buffers holding records must be created with
 * {@link #allocate}.
 *
 * <p>ADDR (24 bytes): family at 0 (0 none, 4, 6), port at 2 (u16), IPv6
 * scope id at 4, address at 8 (IPv4 uses 4 of the 16 bytes).
 */
public final class Records {

    private Records() {}

    public static final int ADDR_LEN = 24;
    static final int ADDR_FAMILY = 0;
    static final int ADDR_PORT = 2;
    static final int ADDR_SCOPE = 4;
    static final int ADDR_IP = 8;

    /** Receive record per datagram slot: length, flags, peer, local. */
    public static final int RECV_META_LEN = 64;
    public static final int RECV_LEN = 0;
    public static final int RECV_FLAGS = 4;
    public static final int RECV_PEER = 8;
    public static final int RECV_LOCAL = 32;
    public static final int RECV_FLAG_TRUNCATED = 1;

    /** Send batch: a status header then one record per datagram. */
    public static final int SEND_HEADER_LEN = 64;
    public static final int SEND_STATUS_DROPPED = 0;
    public static final int SEND_STATUS_ERRNO = 4;
    public static final int SEND_STATUS_FLAGS = 8;
    public static final int SEND_STATUS_GSO_DISABLED = 1;
    public static final int SEND_META_LEN = 64;
    public static final int SEND_OFF = 0;
    public static final int SEND_LEN = 4;
    public static final int SEND_TO = 8;
    public static final int SEND_FROM = 32;

    /**
     * {@link QuicheConnection#send} result, shaped like a SEND record so it
     * can be written in place into a send batch: destination, source, and
     * the pacing delay in nanoseconds (a long).
     */
    public static final int PKT_TO = SEND_TO;
    public static final int PKT_FROM = SEND_FROM;
    public static final int PKT_DELAY = 56;
    public static final int PKT_META_LEN = SEND_META_LEN;

    /** {@link QuicheConnection#headerInfo} result. */
    public static final int HDR_VERSION = 0;
    public static final int HDR_TYPE = 4;
    public static final int HDR_SCID_LEN = 5;
    public static final int HDR_DCID_LEN = 6;
    public static final int HDR_TOKEN_LEN = 8;
    public static final int HDR_SCID = 12;
    public static final int HDR_DCID = 32;
    public static final int HDR_TOKEN = 52;
    public static final int HDR_MAX_TOKEN = 1024;
    public static final int HDR_LEN = HDR_TOKEN + HDR_MAX_TOKEN;

    /** A direct buffer in native byte order, as the shim reads and writes records. */
    public static ByteBuffer allocate(int capacity) {
        return ByteBuffer.allocateDirect(capacity).order(ByteOrder.nativeOrder());
    }

    /** Writes {@code a} as an ADDR record at {@code off}. */
    public static void putAddress(ByteBuffer b, int off, InetSocketAddress a) {
        for (int i = 0; i < ADDR_LEN; i++) b.put(off + i, (byte) 0);
        InetAddress ip = a.getAddress();
        byte[] raw = ip.getAddress();
        b.put(off + ADDR_FAMILY, (byte) (raw.length == 4 ? 4 : 6));
        b.putShort(off + ADDR_PORT, (short) a.getPort());
        if (ip instanceof java.net.Inet6Address v6) b.putInt(off + ADDR_SCOPE, v6.getScopeId());
        b.put(off + ADDR_IP, raw);
    }

    /** Family of the ADDR record at {@code off}: 0 (none), 4 or 6. */
    public static int family(ByteBuffer b, int off) {
        return b.get(off + ADDR_FAMILY);
    }

    public static int port(ByteBuffer b, int off) {
        return b.getShort(off + ADDR_PORT) & 0xFFFF;
    }

    /** True when the ADDR records at {@code a} in {@code x} and {@code b} in {@code y} are equal. */
    public static boolean sameAddress(ByteBuffer x, int a, ByteBuffer y, int b) {
        return x.getLong(a) == y.getLong(b) && x.getLong(a + 8) == y.getLong(b + 8)
            && x.getLong(a + 16) == y.getLong(b + 16);
    }

    /** Copies the ADDR record at {@code from} in {@code src} to {@code to} in {@code dst}. */
    public static void copyAddress(ByteBuffer src, int from, ByteBuffer dst, int to) {
        dst.putLong(to, src.getLong(from));
        dst.putLong(to + 8, src.getLong(from + 8));
        dst.putLong(to + 16, src.getLong(from + 16));
    }

    /**
     * The IP address of the ADDR record at {@code off} (an IPv4-mapped IPv6
     * address becomes the IPv4 one), or null for an empty record. Allocates.
     */
    public static InetAddress inetAddress(ByteBuffer b, int off) {
        int family = family(b, off);
        if (family == 0) return null;
        byte[] raw = new byte[family == 4 ? 4 : 16];
        b.get(off + ADDR_IP, raw);
        try {
            if (family == 6) {
                InetAddress a = InetAddress.getByAddress(raw);
                if (a instanceof Inet4Address) return a;
                int scope = b.getInt(off + ADDR_SCOPE);
                return scope == 0 ? a : java.net.Inet6Address.getByAddress(null, raw, scope);
            }
            return InetAddress.getByAddress(raw);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("malformed address record", e);
        }
    }

    /** The ADDR record at {@code off} as a socket address, or null. Allocates. */
    public static InetSocketAddress socketAddress(ByteBuffer b, int off) {
        InetAddress a = inetAddress(b, off);
        return a == null ? null : new InetSocketAddress(a, port(b, off));
    }
}

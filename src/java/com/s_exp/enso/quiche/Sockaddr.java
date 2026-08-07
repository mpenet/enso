package com.s_exp.enso.quiche;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Build {@code struct sockaddr_in} / {@code sockaddr_in6} in native memory
 * so that quiche's C API can receive a peer / local address. The layout is
 * OS-dependent because BSD (macOS, FreeBSD) prefixes each sockaddr with a
 * one-byte length field, while Linux does not — same fields, different
 * offsets.
 *
 * <p>quiche uses these purely for path validation + return-address bookkeeping,
 * so as long as the bytes we hand in match what the OS's sendto/recvfrom
 * expect, the round-trip works.
 */
final class Sockaddr {

    private static final boolean IS_MAC =
        System.getProperty("os.name", "").toLowerCase().contains("mac");

    // AF_INET is 2 everywhere. AF_INET6 is 30 on macOS / 10 on Linux — hence
    // the platform switch below.
    private static final byte AF_INET  = 2;
    private static final byte AF_INET6 = (byte) (IS_MAC ? 30 : 10);

    private Sockaddr() {}

    /**
     * Encode {@code addr} into a fresh sockaddr_{{in,in6}} segment allocated
     * from {@code arena}. Returns a pair (segment, byte length) — quiche's
     * API takes both.
     */
    static Encoded encode(Arena arena, InetSocketAddress addr) {
        InetAddress ia = addr.getAddress();
        if (ia instanceof Inet4Address) {
            return encodeIPv4(arena, (Inet4Address) ia, addr.getPort());
        } else if (ia instanceof Inet6Address) {
            return encodeIPv6(arena, (Inet6Address) ia, addr.getPort());
        }
        throw new IllegalArgumentException("unknown address family: " + ia);
    }

    /** Non-throwing accessor for the AF_INET6 constant on the current platform. */
    static byte afInet6() {
        return AF_INET6;
    }

    private static Encoded encodeIPv4(Arena arena, Inet4Address ia, int port) {
        // Layout: (macOS) sin_len(1) sin_family(1) sin_port(2) sin_addr(4) sin_zero(8)
        //         (linux) sin_family(2) sin_port(2) sin_addr(4) sin_zero(8)
        MemorySegment s = arena.allocate(16);
        int p = 0;
        if (IS_MAC) {
            s.set(ValueLayout.JAVA_BYTE, p++, (byte) 16);   // sin_len
            s.set(ValueLayout.JAVA_BYTE, p++, AF_INET);
        } else {
            s.set(ValueLayout.JAVA_BYTE, p++, AF_INET);
            s.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
        }
        // sin_port — network byte order
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) ((port >>> 8) & 0xFF));
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) (port & 0xFF));
        // sin_addr — 4 raw bytes, already in network order from InetAddress.
        byte[] octets = ia.getAddress();
        s.set(ValueLayout.JAVA_BYTE, p++, octets[0]);
        s.set(ValueLayout.JAVA_BYTE, p++, octets[1]);
        s.set(ValueLayout.JAVA_BYTE, p++, octets[2]);
        s.set(ValueLayout.JAVA_BYTE, p++, octets[3]);
        // sin_zero — remaining 8 bytes stay at zero from allocate().
        return new Encoded(s, 16);
    }

    private static Encoded encodeIPv6(Arena arena, Inet6Address ia, int port) {
        // Layout: (macOS) sin6_len(1) sin6_family(1) sin6_port(2) sin6_flowinfo(4)
        //                 sin6_addr(16) sin6_scope_id(4) — 28 bytes
        //         (linux) sin6_family(2)      sin6_port(2) sin6_flowinfo(4)
        //                 sin6_addr(16) sin6_scope_id(4) — 28 bytes
        MemorySegment s = arena.allocate(28);
        int p = 0;
        if (IS_MAC) {
            s.set(ValueLayout.JAVA_BYTE, p++, (byte) 28);
            s.set(ValueLayout.JAVA_BYTE, p++, AF_INET6);
        } else {
            s.set(ValueLayout.JAVA_BYTE, p++, AF_INET6);
            s.set(ValueLayout.JAVA_BYTE, p++, (byte) 0);
        }
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) ((port >>> 8) & 0xFF));
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) (port & 0xFF));
        // sin6_flowinfo — zero.
        p += 4;
        byte[] octets = ia.getAddress();
        for (int i = 0; i < 16; i++) {
            s.set(ValueLayout.JAVA_BYTE, p++, octets[i]);
        }
        // sin6_scope_id.
        int scope = ia.getScopeId();
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) (scope & 0xFF));
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) ((scope >>> 8) & 0xFF));
        s.set(ValueLayout.JAVA_BYTE, p++, (byte) ((scope >>> 16) & 0xFF));
        s.set(ValueLayout.JAVA_BYTE, p, (byte) ((scope >>> 24) & 0xFF));
        return new Encoded(s, 28);
    }

    record Encoded(MemorySegment segment, int length) {}
}

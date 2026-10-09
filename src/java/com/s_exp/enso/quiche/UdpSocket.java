// ABOUTME: Non-blocking UDP socket owned through the shim: batched receive and send on direct
// ABOUTME: buffers (recvmmsg/sendmmsg/GSO on Linux), source-address pinning, reuseport steering.
package com.s_exp.enso.quiche;

import java.io.IOException;
import java.lang.ref.Reference;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * A UDP socket for the HTTP/3 event loops. Every I/O call is
 * non-blocking; {@link Waker#poll} waits for readiness. One loop thread
 * receives on a socket; any loop may send on it (sendmsg is atomic per
 * datagram). {@link #close} must only run once no thread uses the socket
 * any more (the listener closes sockets after joining its loops); calls
 * after it throw instead of reaching a recycled descriptor.
 *
 * <p>On Linux, with {@code pktinfo} set (a wildcard bind), each received
 * datagram reports the address it was sent to and replies leave from that
 * address (IP_PKTINFO / IPV6_PKTINFO), so a multi-homed host answers from
 * the address the client used. Elsewhere the local address of every
 * datagram is the bound one.
 */
public final class UdpSocket implements AutoCloseable {

    public static final int OPEN_REUSEPORT = 1;
    public static final int OPEN_PKTINFO = 2;
    public static final int SEND_GSO = 1;
    public static final int SEND_PKTINFO = 2;

    private volatile int fd;
    private final boolean pktinfo;

    private UdpSocket(int fd, boolean pktinfo) {
        this.fd = fd;
        this.pktinfo = pktinfo;
    }

    /**
     * Binds {@code address:port}. {@code rcvBuf} / {@code sndBuf}: socket
     * buffer sizes requested (best effort, the OS may grant less; 0 keeps
     * its default).
     */
    public static UdpSocket open(InetAddress address, int port, int flags, int rcvBuf, int sndBuf)
            throws IOException {
        int fd = Quiche.udpOpen(address.getAddress(), port, flags, rcvBuf, sndBuf);
        if (fd < 0) {
            throw new IOException("cannot bind UDP " + address.getHostAddress() + ":" + port
                + " (errno " + -fd + ")");
        }
        boolean pktinfo = (flags & OPEN_PKTINFO) != 0 && isLinux();
        return new UdpSocket(fd, pktinfo);
    }

    static boolean isLinux() {
        return System.getProperty("os.name").toLowerCase().contains("linux");
    }

    /** True when SO_REUSEPORT spreads datagrams across sockets (Linux). */
    public static boolean reusePortBalances() {
        return isLinux();
    }

    int fd() {
        int f = fd;
        if (f < 0) throw new IllegalStateException("UDP socket closed");
        return f;
    }

    /** True when received datagrams report their destination address. */
    public boolean pktinfo() { return pktinfo; }

    /** The bound address, written as an ADDR record at {@code b[off]}. */
    public void localAddress(NativeBuffer b, int off) throws IOException {
        int rc;
        try {
            rc = Quiche.udpLocalAddress(fd(), b.address, b.capacity, off);
        } finally {
            Reference.reachabilityFence(b);
        }
        if (rc != 0) throw new IOException("getsockname failed (" + rc + ")");
    }

    public InetSocketAddress localAddress() throws IOException {
        NativeBuffer b = NativeBuffer.allocate(Records.ADDR_LEN);
        localAddress(b, 0);
        return Records.socketAddress(b.buffer, 0);
    }

    /** Effective receive (or send) buffer size. */
    public int bufferSize(boolean send) {
        return Quiche.udpBufferSize(fd(), send);
    }

    /**
     * Steers datagrams across this socket's SO_REUSEPORT group by the first
     * byte of their destination connection id modulo {@code n} (Linux).
     * False when unsupported.
     */
    public boolean attachSteering(int n) {
        return Quiche.udpAttachSteering(fd(), n) == 0;
    }

    /** True when the kernel can segment (UDP GSO). */
    public boolean gsoSupported() {
        return Quiche.udpGsoSupported(fd());
    }

    /**
     * Receives up to {@code maxSlots} queued datagrams without blocking into
     * {@code slab} slots of {@code slotSize} bytes, with a RECV record per
     * datagram in {@code meta}; the record after the last slot holds the
     * local ADDR template. Returns the count, or a negative errno.
     */
    public int recvBatch(NativeBuffer slab, int slotSize, int maxSlots, NativeBuffer meta) {
        try {
            return Quiche.udpRecvBatch(fd(), slab.address, slab.capacity, slotSize, maxSlots,
                meta.address, meta.capacity);
        } finally {
            Reference.reachabilityFence(slab);
            Reference.reachabilityFence(meta);
        }
    }

    /**
     * Sends {@code count} SEND records of {@code meta} (after its status
     * header) from {@code slab}. Returns the records consumed (sent, or
     * dropped as lost: see the status header); fewer than {@code count}
     * when the socket buffer is full. Negative errno on a socket failure.
     */
    public int sendBatch(NativeBuffer slab, NativeBuffer meta, int count, int flags) {
        try {
            return Quiche.udpSendBatch(fd(), slab.address, slab.capacity, meta.address, meta.capacity,
                count, flags);
        } finally {
            Reference.reachabilityFence(slab);
            Reference.reachabilityFence(meta);
        }
    }

    /** Closes the descriptor. Idempotent. */
    @Override
    public synchronized void close() {
        int f = fd;
        if (f < 0) return;
        fd = -1;
        Quiche.udpClose(f);
    }

    /**
     * A wake-up channel for a loop blocked in {@link #poll} (an eventfd on
     * Linux, a pipe elsewhere). {@link #signal} may be called from any
     * thread; callers coalesce so it is only signalled while the loop parks.
     */
    public static final class Waker implements AutoCloseable {
        private final int readFd;
        private final int writeFd;
        // Guarded by this: a signal racing close must not write to a
        // descriptor number the OS may already have handed out again.
        private boolean closed;

        public Waker() throws IOException {
            long h = Quiche.wakeOpen();
            if (h < 0) throw new IOException("cannot open wake-up channel (errno " + -h + ")");
            this.readFd = (int) (h >> 32);
            this.writeFd = (int) h;
        }

        public synchronized void signal() {
            if (!closed) Quiche.wakeSignal(writeFd);
        }

        /**
         * Waits until {@code recv} is readable, {@code send} writable (when
         * {@code wantWrite}), this waker signalled, or {@code timeoutNanos}
         * (negative: forever). Null sockets are ignored. Returns
         * {@link #READABLE} / {@link #WAKE} / {@link #WRITABLE} bits. Only
         * the thread that will {@link #close} this waker polls it.
         */
        public int poll(UdpSocket recv, UdpSocket send, boolean wantWrite, long timeoutNanos) {
            return Quiche.poll(recv == null ? -1 : recv.fd(), send == null ? -1 : send.fd(),
                readFd, wantWrite, timeoutNanos);
        }

        public static final int READABLE = 1;
        public static final int WAKE = 2;
        public static final int WRITABLE = 4;

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            Quiche.wakeClose(((long) readFd << 32) | (writeFd & 0xFFFFFFFFL));
        }
    }
}

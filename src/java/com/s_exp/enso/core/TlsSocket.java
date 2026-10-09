// ABOUTME: Blocking TLS over a SocketChannel with an SSLEngine: handshake deadline, record I/O,
// ABOUTME: close_notify / half-close, abortable close, idle buffer release, renegotiation refusal.
package com.s_exp.enso.core;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

/**
 * Thin blocking TLS wrapper: {@link SocketChannel} + {@link SSLEngine}. Every
 * TLS connection (HTTP/1.1 and HTTP/2) goes through it rather than
 * {@code SSLSocket}, for direct control of the record boundary (gathering
 * writes, clean {@code close_notify} shutdown), an abortable close, and a
 * wall-clock handshake deadline.
 *
 * <p>The underlying channel stays in blocking mode; Loom parks virtual
 * threads that block on its reads (through the socket adaptor stream, so
 * SO_TIMEOUT applies) / writes via the JDK poller with no carrier pin.
 *
 * <p>Thread model — read and write use disjoint buffers and disjoint SSLEngine
 * directions, so a framer vthread can call {@link RecordInputStream#read}
 * concurrently with a writer vthread calling
 * {@link RecordOutputStream#write}. Handshake / close_notify go through
 * {@link #handshakeLock}. The read path never writes: a TLS 1.3 KeyUpdate
 * that asks for ours leaves it queued in the engine for the next record
 * written (see RecordInputStream#postHandshake).
 */
public final class TlsSocket implements AutoCloseable {

    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    // Record buffers of an idle connection (releaseIdleBuffers): enough
    // for a record header and a close_notify; they grow back to the
    // session's sizes through the BUFFER_UNDERFLOW / BUFFER_OVERFLOW paths.
    private static final int IDLE_BUFFER_BYTES = 512;

    private final SocketChannel channel;
    private final SSLEngine engine;

    // Cached at construction: `channel.getRemoteAddress()` /
    // `getLocalAddress()` each cost a getsockname/getpeername syscall,
    // and callers (HTTP/1.1 handler map build in HttpConnection) hit them
    // per request. The values don't change over the connection lifetime.
    private final InetAddress remoteAddress;
    private final int localPort;

    // Ciphertext from peer → plaintext to consumer.
    private ByteBuffer peerNetData;
    private ByteBuffer peerAppData;

    // Plaintext from producer → ciphertext to peer. Producer supplies its
    // own source buffer per write; we only own the network staging buffer.
    private ByteBuffer myNetData;

    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();
    // Serialises anything that can advance the handshake state (both
    // directions may see NEED_WRAP/NEED_UNWRAP during renegotiation).
    private final ReentrantLock handshakeLock = new ReentrantLock();

    private volatile boolean handshakeDone = false;
    // Set when the peer tried to renegotiate after the initial handshake.
    private volatile boolean renegotiationRefused;
    private final java.util.concurrent.atomic.AtomicBoolean closed =
        new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicBoolean outputShut =
        new java.util.concurrent.atomic.AtomicBoolean(false);

    private final InputStream in;
    private final OutputStream out;
    // Ciphertext source. SocketChannel.read ignores SO_TIMEOUT; the socket
    // adaptor's stream reads the same channel but honours it, which is what
    // makes the idle / request timeouts apply to TLS connections.
    private final InputStream netIn;
    // Non-zero only while handshake(int) runs: wall-clock limit for the
    // whole handshake, so a peer dripping bytes under SO_TIMEOUT can't
    // hold it open indefinitely.
    private long handshakeDeadlineNanos;
    // Wall-clock limit (System.nanoTime) of a plaintext read, 0 = none;
    // see setReadDeadline. Reading thread only.
    private long readDeadlineNanos;
    // The session's packet size, fixed once the handshake is done (TLS 1.3
    // has no renegotiation; earlier versions' is refused); 0 before.
    private volatile int packetSize;

    public TlsSocket(SocketChannel channel, SSLEngine engine) throws IOException {
        this.channel = channel;
        this.engine = engine;
        this.netIn = channel.socket().getInputStream();
        engine.setUseClientMode(false);
        SSLSession session = engine.getSession();
        int netSize = session.getPacketBufferSize();
        int appSize = session.getApplicationBufferSize();
        this.peerNetData = ByteBuffer.allocate(netSize);
        this.peerAppData = ByteBuffer.allocate(appSize);
        this.peerAppData.flip(); // start empty
        this.myNetData = ByteBuffer.allocate(netSize);
        this.in = new RecordInputStream();
        this.out = new RecordOutputStream();
        // Snapshot connection-scoped addresses once.
        this.remoteAddress = ((java.net.InetSocketAddress) channel.getRemoteAddress()).getAddress();
        this.localPort = ((java.net.InetSocketAddress) channel.getLocalAddress()).getPort();
    }

    /**
     * Force the initial TLS handshake to run to completion within
     * {@code timeoutMillis} (0 = no overall limit; each read is still bound
     * by the socket's SO_TIMEOUT). Throws {@link SocketTimeoutException} when
     * the limit passes. SO_TIMEOUT is restored afterwards.
     */
    public void handshake(int timeoutMillis) throws IOException {
        handshakeLock.lock();
        java.net.Socket raw = channel.socket();
        int soTimeout = raw.getSoTimeout();
        try {
            if (handshakeDone) return;
            if (timeoutMillis > 0) {
                handshakeDeadlineNanos = System.nanoTime() + timeoutMillis * 1_000_000L;
            }
            engine.beginHandshake();
            HandshakeStatus hs = engine.getHandshakeStatus();
            while (hs != HandshakeStatus.FINISHED && hs != HandshakeStatus.NOT_HANDSHAKING) {
                hs = stepHandshake(hs);
            }
            packetSize = engine.getSession().getPacketBufferSize();
            handshakeDone = true;
        } finally {
            if (handshakeDeadlineNanos != 0) {
                handshakeDeadlineNanos = 0;
                raw.setSoTimeout(soTimeout);
            }
            handshakeLock.unlock();
        }
    }

    /**
     * One handshake step. Buffer modes, on entry and on return: peerNetData
     * in write mode (ciphertext not yet unwrapped sits in [0, position)),
     * peerAppData in read mode (plaintext not yet consumed sits in
     * [position, limit)).
     */
    private HandshakeStatus stepHandshake(HandshakeStatus hs) throws IOException {
        switch (hs) {
            case NEED_UNWRAP -> {
                // Only fetch more ciphertext if the staging buffer is empty.
                // Client's Finished may share a TCP segment with early
                // application data (TLS 1.3 sends Finished then app data
                // immediately), so we may already have plaintext bytes queued
                // that unwrap can consume without another read.
                if (peerNetData.position() == 0) {
                    fillPeerNet();
                }
                peerNetData.flip();
                peerAppData.compact();
                SSLEngineResult r = engine.unwrap(peerNetData, peerAppData);
                peerNetData.compact();
                // enlarge() expects (and returns) a write-mode buffer, so
                // grow before flipping back to read mode.
                if (r.getStatus() == Status.BUFFER_OVERFLOW) {
                    peerAppData = enlarge(peerAppData, engine.getSession().getApplicationBufferSize());
                }
                peerAppData.flip();
                if (r.getStatus() == Status.CLOSED) {
                    throw new EOFException("peer closed during handshake");
                }
                if (r.getStatus() == Status.BUFFER_UNDERFLOW) {
                    if (peerNetData.capacity() < engine.getSession().getPacketBufferSize()) {
                        peerNetData = enlarge(peerNetData, engine.getSession().getPacketBufferSize());
                    }
                    fillPeerNet();
                }
                return r.getHandshakeStatus();
            }
            case NEED_WRAP -> {
                myNetData.clear();
                SSLEngineResult r = engine.wrap(EMPTY, myNetData);
                myNetData.flip();
                writeFully(myNetData);
                if (r.getStatus() == Status.BUFFER_OVERFLOW) {
                    myNetData = ByteBuffer.allocate(Math.max(myNetData.capacity() * 2,
                                                             engine.getSession().getPacketBufferSize()));
                    return hs;
                }
                return r.getHandshakeStatus();
            }
            case NEED_TASK -> {
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
                return engine.getHandshakeStatus();
            }
            default -> {
                return hs;
            }
        }
    }

    /** Refill peerNetData from the channel — buffer left in write-mode. */
    private void fillPeerNet() throws IOException {
        long deadline = handshakeDeadlineNanos;
        if (deadline != 0) {
            long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
            if (remainingMs <= 0) {
                throw new SocketTimeoutException("TLS handshake timed out");
            }
            java.net.Socket raw = channel.socket();
            int soTimeout = raw.getSoTimeout();
            if (soTimeout == 0 || soTimeout > remainingMs) {
                raw.setSoTimeout((int) Math.min(remainingMs, Integer.MAX_VALUE));
            }
        }
        int n = readNet();
        if (n < 0) throw new EOFException("peer closed");
    }

    /**
     * Bounds the plaintext reads that follow by wall clock: a read with no
     * plaintext to return by {@code deadlineNanos} ({@link System#nanoTime})
     * fails with {@link SocketTimeoutException}, as SO_TIMEOUT fails one
     * silent wait. SO_TIMEOUT alone restarts with every ciphertext byte, so
     * a peer trickling one record a byte at a time would hold a read for as
     * long as it likes. 0 = none (SO_TIMEOUT only). Set by the reading
     * thread, for the reads it makes next.
     */
    public void setReadDeadline(long deadlineNanos) {
        readDeadlineNanos = deadlineNanos;
    }

    /**
     * Whether input is waiting unread: plaintext or ciphertext held here,
     * or bytes the socket received. Closing now would make the kernel
     * answer them with a reset.
     */
    public boolean inputPending() {
        readLock.lock();
        try {
            if (peerAppData.hasRemaining() || peerNetData.position() > 0) {
                return true;
            }
        } finally {
            readLock.unlock();
        }
        try {
            return netIn.available() > 0;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * {@link #readNet} within the read deadline (see
     * {@link #setReadDeadline}): SO_TIMEOUT is lowered to what is left of it
     * for this one wait, then restored.
     */
    private int readNetWithinDeadline() throws IOException {
        long deadline = readDeadlineNanos;
        if (deadline == 0) {
            return readNet();
        }
        long remainingNs = deadline - System.nanoTime();
        if (remainingNs <= 0) {
            throw new SocketTimeoutException("TLS read deadline passed");
        }
        long remainingMs = (remainingNs + 999_999L) / 1_000_000L;
        java.net.Socket raw = channel.socket();
        int soTimeout = raw.getSoTimeout();
        if (soTimeout != 0 && soTimeout <= remainingMs) {
            return readNet();
        }
        raw.setSoTimeout((int) Math.min(remainingMs, Integer.MAX_VALUE));
        try {
            return readNet();
        } finally {
            raw.setSoTimeout(soTimeout);
        }
    }

    /**
     * Reads ciphertext into peerNetData (write-mode, heap-backed) through
     * {@link #netIn} so SO_TIMEOUT applies. Returns the byte count or -1.
     */
    private int readNet() throws IOException {
        ByteBuffer b = peerNetData;
        int n = netIn.read(b.array(), b.arrayOffset() + b.position(), b.remaining());
        if (n > 0) {
            b.position(b.position() + n);
        }
        return n;
    }

    private void writeFully(ByteBuffer src) throws IOException {
        while (src.hasRemaining()) {
            int n = channel.write(src);
            if (n < 0) throw new IOException("channel write returned -1");
        }
    }

    private static ByteBuffer enlarge(ByteBuffer src, int minCap) {
        int cap = Math.max(src.capacity() * 2, minCap);
        ByteBuffer bigger = ByteBuffer.allocate(cap);
        src.flip();
        bigger.put(src);
        return bigger;
    }

    /**
     * Swaps the record buffers (about 16 KiB each) for small ones while the
     * connection is idle, when they hold nothing: no ciphertext pending,
     * no plaintext unread. Called by the reading thread between requests.
     */
    public void releaseIdleBuffers() {
        releaseIdleInputBuffers();
        releaseOutputBuffer();
    }

    /**
     * The input half of {@link #releaseIdleBuffers}, for a reader that must
     * not wait for a writer (the HTTP/2 framer): only takes the read lock.
     */
    public void releaseIdleInputBuffers() {
        readLock.lock();
        try {
            if (peerNetData.position() == 0 && !peerAppData.hasRemaining()
                && peerNetData.capacity() > IDLE_BUFFER_BYTES) {
                peerNetData = ByteBuffer.allocate(IDLE_BUFFER_BYTES);
                peerAppData = ByteBuffer.allocate(IDLE_BUFFER_BYTES);
                peerAppData.flip();
            }
        } finally {
            readLock.unlock();
        }
    }

    /**
     * The output half of {@link #releaseIdleBuffers}: the output record
     * buffer becomes a small one (it grows back on the next write). A
     * driver writing through {@link #writeRecords} with its own buffers
     * calls it once, so the connection only keeps room for a close_notify.
     */
    public void releaseOutputBuffer() {
        writeLock.lock();
        try {
            if (myNetData.capacity() > IDLE_BUFFER_BYTES) {
                myNetData = ByteBuffer.allocate(IDLE_BUFFER_BYTES);
            }
            ((RecordOutputStream) out).forgetWrapped();
        } finally {
            writeLock.unlock();
        }
    }

    /** Whether the peer tried to renegotiate after the initial handshake (refused, connection failed). */
    public boolean renegotiationRefused() {
        return renegotiationRefused;
    }

    /** The TLS session, for the peer's certificates. */
    public SSLSession session() {
        return engine.getSession();
    }

    public String getApplicationProtocol() {
        return engine.getApplicationProtocol();
    }

    public InputStream getInputStream() {
        return in;
    }

    public OutputStream getOutputStream() {
        return out;
    }

    public InetAddress getInetAddress() {
        return remoteAddress;
    }

    public int getLocalPort() {
        return localPort;
    }

    @Override
    public void close() throws IOException {
        // CAS keeps double-close (framer + shutdown hook, or two workers on
        // the same reset) from both sending close_notify and shutting the
        // socket twice — the second call would throw on an already-closed
        // channel.
        if (!closed.compareAndSet(false, true)) return;
        // §7.2.1 — send close_notify then FIN. Ordering matters here: if we
        // close the socket before the close_notify record hits the wire the
        // peer sees a bare TCP RST/FIN and can't tell our clean GOAWAY apart
        // from an abrupt drop (h2spec §6.9.1).
        try {
            shutdownOutput();
        } catch (IOException ignored) {
            // socket may be already dead — the finally block still closes it
        } finally {
            channel.close();
        }
    }

    /**
     * Sends close_notify, then FIN; the input side stays open, so the
     * peer's remaining bytes can still be read (a lingering close) rather
     * than answered with a TCP reset that could discard data the peer hasn't
     * read yet (a final response or GOAWAY). Idempotent; {@link #close}
     * afterwards closes the channel.
     */
    public void shutdownOutput() throws IOException {
        if (!outputShut.compareAndSet(false, true)) return;
        // writeLock must be held — myNetData is shared with the regular
        // write path and racing wrap() calls corrupt its buffer state.
        writeLock.lock();
        try {
            handshakeLock.lock();
            try {
                engine.closeOutbound();
                while (!engine.isOutboundDone()) {
                    myNetData.clear();
                    SSLEngineResult r = engine.wrap(EMPTY, myNetData);
                    myNetData.flip();
                    writeFully(myNetData);
                    if (r.getStatus() == Status.CLOSED) break;
                    if (r.getStatus() == Status.BUFFER_OVERFLOW) {
                        myNetData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                    }
                }
                // Half-close outbound (send FIN) after the close_notify
                // record is on the wire. Reads may still drain any
                // trailing bytes from the peer.
                try {
                    channel.shutdownOutput();
                } catch (IOException ignored) {
                }
            } finally {
                handshakeLock.unlock();
            }
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Writes {@code src[off, off+len)} as TLS records encrypted into
     * {@code net}, a caller-owned buffer of at least one packet
     * ({@code getPacketBufferSize}), with as many records per channel write
     * as {@code net} holds: one syscall per several records, where the
     * output stream makes one per record. Callers can pool {@code net}
     * across connections; it holds nothing once this returns.
     */
    public void writeRecords(byte[] src, int off, int len, ByteBuffer net) throws IOException {
        if (len == 0) return;
        writeRecords(ByteBuffer.wrap(src, off, len), net);
    }

    /**
     * {@link #writeRecords(byte[], int, int, ByteBuffer)} of {@code app}'s
     * remaining bytes, consumed: a caller that keeps a wrapper per buffer
     * allocates nothing per call.
     */
    public void writeRecords(ByteBuffer app, ByteBuffer net) throws IOException {
        if (!app.hasRemaining()) return;
        writeLock.lock();
        try {
            int packet = packetSize;
            if (packet == 0) {
                packet = engine.getSession().getPacketBufferSize();
            }
            if (net.capacity() < packet) {
                throw new IllegalArgumentException("net buffer smaller than a TLS packet");
            }
            net.clear();
            while (app.hasRemaining()) {
                if (net.remaining() < packet) {
                    net.flip();
                    writeFully(net);
                    net.clear();
                }
                SSLEngineResult r = engine.wrap(app, net);
                if (r.getStatus() == Status.CLOSED) {
                    throw new IOException("SSL engine outbound closed");
                }
            }
            net.flip();
            writeFully(net);
        } finally {
            net.clear();
            writeLock.unlock();
        }
    }

    /**
     * Closes the channel at once, without close_notify. For forced teardown:
     * {@link #close} waits for the write lock, which a writer stalled on a
     * peer that stopped reading can hold indefinitely. Closing the channel
     * unblocks such a writer (and a close() waiting behind it).
     */
    public void abort() throws IOException {
        closed.set(true);
        channel.close();
    }

    /**
     * Closes {@code socket} at once, for forced teardown. A TLS close waits
     * to send close_notify behind any writer stalled on a peer that stopped
     * reading, so a {@link AdapterSocket} is aborted instead.
     */
    public static void forceClose(java.net.Socket socket) throws IOException {
        if (socket instanceof AdapterSocket adapter) {
            adapter.tls().abort();
        } else {
            socket.close();
        }
    }

    /**
     * Wrap this TlsSocket in a {@link java.net.Socket} shim so it can be
     * passed to callers that expect the classic API. Only the accessors and
     * lifecycle methods the connection drivers actually use are overridden;
     * the underlying {@link java.net.Socket} instance is unconnected and inert.
     */
    public java.net.Socket asSocket() {
        return new AdapterSocket(this);
    }

    public static final class AdapterSocket extends java.net.Socket {

        private final TlsSocket tls;

        AdapterSocket(TlsSocket tls) {
            this.tls = tls;
        }

        public TlsSocket tls() { return tls; }

        // Overrides limited to methods actually called by HttpConnection /
        // Http2Connection / EnsoServer accept path. Adding more here without
        // a call site invites subtle default-Socket-impl behavior on an
        // unconnected shim.

        @Override public InputStream getInputStream() { return tls.getInputStream(); }
        @Override public OutputStream getOutputStream() { return tls.getOutputStream(); }
        @Override public void close() throws IOException { tls.close(); }
        @Override public void shutdownOutput() throws IOException { tls.shutdownOutput(); }
        @Override public InetAddress getInetAddress() { return tls.getInetAddress(); }
        @Override public int getLocalPort() { return tls.getLocalPort(); }
        @Override public SocketAddress getLocalSocketAddress() {
            try {
                return tls.channel.getLocalAddress();
            } catch (IOException e) {
                return null;
            }
        }
        // The adapter has no SocketImpl of its own: socket options go to
        // the socket underneath the SocketChannel.
        @Override public void setSoLinger(boolean on, int linger) throws java.net.SocketException {
            tls.channel.socket().setSoLinger(on, linger);
        }
        @Override public void setTcpNoDelay(boolean on) throws java.net.SocketException {
            tls.channel.socket().setTcpNoDelay(on);
        }
        // Per-request slowloris deadline from HttpConnection. Forward to the
        // SocketChannel's underlying Socket — ciphertext is read through its
        // adaptor stream, which honours SO_TIMEOUT and unparks the vthread
        // with SocketTimeoutException.
        // Without this override the HTTP/1.1 fallback path on the http2 TLS
        // listener loses its per-request timeout.
        @Override public void setSoTimeout(int t) throws java.net.SocketException {
            tls.channel.socket().setSoTimeout(t);
        }
        // AcceptLoop applies socket buffer sizes to whatever socket the
        // listener produced. The default Socket impl has no backing fd on
        // AdapterSocket and throws SocketException; forward to the real
        // socket underneath the SocketChannel.
        @Override public void setSendBufferSize(int size) throws java.net.SocketException {
            tls.channel.socket().setSendBufferSize(size);
        }
        @Override public void setReceiveBufferSize(int size) throws java.net.SocketException {
            tls.channel.socket().setReceiveBufferSize(size);
        }
    }

    // ---- Input stream --------------------------------------------------

    private final class RecordInputStream extends InputStream {

        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] dst, int off, int len) throws IOException {
            if (len == 0) return 0;
            readLock.lock();
            try {
                while (!peerAppData.hasRemaining()) {
                    if (!fillPlaintext()) return -1;
                }
                int n = Math.min(len, peerAppData.remaining());
                peerAppData.get(dst, off, n);
                return n;
            } finally {
                readLock.unlock();
            }
        }

        /**
         * Pulls ciphertext from the channel and unwraps until peerAppData
         * has at least one byte of plaintext, or the channel signals EOF.
         */
        private boolean fillPlaintext() throws IOException {
            peerAppData.compact();
            try {
                return unwrapUntilPlaintext();
            } catch (IOException | RuntimeException | Error e) {
                // A failed read (e.g. SO_TIMEOUT) must leave peerAppData in
                // read mode holding only what was decrypted, never the
                // compacted buffer's stale capacity as fresh plaintext.
                peerAppData.flip();
                throw e;
            }
        }

        private boolean unwrapUntilPlaintext() throws IOException {
            while (true) {
                if (peerNetData.position() == 0) {
                    int n = readNetWithinDeadline();
                    if (n < 0) {
                        peerAppData.flip();
                        return false;
                    }
                } else {
                    // Some ciphertext leftover from a previous partial record.
                    // Try to unwrap what we have; if it needs more, we'll read
                    // additional bytes.
                }
                peerNetData.flip();
                SSLEngineResult r = engine.unwrap(peerNetData, peerAppData);
                peerNetData.compact();
                switch (r.getStatus()) {
                    case OK -> {
                        HandshakeStatus hs = r.getHandshakeStatus();
                        if (hs != HandshakeStatus.NOT_HANDSHAKING && hs != HandshakeStatus.FINISHED) {
                            // Back in write mode whatever postHandshake
                            // throws: fillPlaintext's failure path flips it.
                            peerAppData.flip();
                            try {
                                postHandshake(hs);
                            } finally {
                                peerAppData.compact();
                            }
                        }
                        if (peerAppData.position() > 0) {
                            peerAppData.flip();
                            return true;
                        }
                    }
                    case BUFFER_UNDERFLOW -> {
                        int need = engine.getSession().getPacketBufferSize();
                        if (peerNetData.capacity() < need) {
                            peerNetData = enlarge(peerNetData, need);
                        }
                        int n = readNetWithinDeadline();
                        if (n < 0) {
                            peerAppData.flip();
                            return false;
                        }
                    }
                    case BUFFER_OVERFLOW -> {
                        peerAppData = enlarge(peerAppData,
                            engine.getSession().getApplicationBufferSize());
                    }
                    case CLOSED -> {
                        peerAppData.flip();
                        return false;
                    }
                }
            }
        }

        /**
         * Handshake messages after the initial handshake. Below TLS 1.3 it
         * is a client-initiated renegotiation, which is refused: it costs
         * the server a full handshake per request a client chooses to send
         * (a CPU amplification) and has a history of attacks. TLS 1.3 has
         * no renegotiation: what arrives is a KeyUpdate. One asking for
         * ours in return leaves the engine with it queued (NEED_WRAP); it is
         * not written from here but goes out ahead of the next record any
         * writer wraps (RFC 8446 §4.6.3 asks for it before our next
         * application data, not sooner), so a read never waits for the
         * write lock, which a writer blocked on a peer that doesn't read
         * may hold for a whole write timeout (the reader would stop
         * reading every stream of an HTTP/2 connection meanwhile). Called
         * with peerAppData in read mode.
         */
        private void postHandshake(HandshakeStatus hs) throws IOException {
            if (!"TLSv1.3".equals(engine.getSession().getProtocol())) {
                renegotiationRefused = true;
                throw new SSLHandshakeException("TLS renegotiation refused");
            }
            if (hs == HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
            }
        }
    }

    // ---- Output stream -------------------------------------------------

    private final class RecordOutputStream extends OutputStream {

        // Callers (a BufferedOutputStream, the h2 writer's scratch) pass the
        // same array on every write, so its wrapper is kept and re-pointed
        // instead of allocated per call. Only buffer-sized arrays are kept:
        // caching a large one-off body array would pin it in memory, and a
        // per-call wrap is noise next to encrypting that much. Guarded by
        // writeLock.
        private static final int MAX_CACHED_ARRAY = 64 * 1024;
        private byte[] wrappedArray;
        private ByteBuffer wrapped;

        // write(int) scratch, used under writeLock.
        private final byte[] one = new byte[1];

        @Override
        public void write(int b) throws IOException {
            writeLock.lock();
            try {
                one[0] = (byte) b;
                write(one, 0, 1);
            } finally {
                writeLock.unlock();
            }
        }

        @Override
        public void write(byte[] src, int off, int len) throws IOException {
            if (len == 0) return;
            writeLock.lock();
            try {
                ByteBuffer app;
                if (src == wrappedArray) {
                    app = wrapped;
                    app.limit(off + len).position(off);
                } else if (src.length <= MAX_CACHED_ARRAY) {
                    app = ByteBuffer.wrap(src, off, len);
                    wrapped = app;
                    wrappedArray = src;
                } else {
                    app = ByteBuffer.wrap(src, off, len);
                }
                while (app.hasRemaining()) {
                    myNetData.clear();
                    SSLEngineResult r = engine.wrap(app, myNetData);
                    myNetData.flip();
                    writeFully(myNetData);
                    if (r.getStatus() == Status.CLOSED) {
                        throw new IOException("SSL engine outbound closed");
                    }
                    if (r.getStatus() == Status.BUFFER_OVERFLOW) {
                        myNetData = ByteBuffer.allocate(
                            Math.max(myNetData.capacity() * 2,
                                     engine.getSession().getPacketBufferSize()));
                    }
                }
            } finally {
                writeLock.unlock();
            }
        }

        @Override
        public void flush() {
            // SSLEngine emits per wrap(); channel writes are synchronous.
            // Nothing else buffers past this point.
        }

        /** Drops the cached wrapper (and the caller's array it pins). Under writeLock. */
        void forgetWrapped() {
            wrapped = null;
            wrappedArray = null;
        }
    }
}

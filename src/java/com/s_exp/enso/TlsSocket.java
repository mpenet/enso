package com.s_exp.enso;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLSession;

/**
 * Thin blocking TLS wrapper: {@link SocketChannel} + {@link SSLEngine}. Used
 * in place of {@code SSLSocket} when the HTTP/2 path wants direct control of
 * the record boundary (gathering writes, clean {@code close_notify}
 * shutdown).
 *
 * <p>The underlying channel stays in blocking mode; Loom parks virtual
 * threads that block inside {@link SocketChannel#read} / {@code write} via
 * the JDK poller with no carrier pin.
 *
 * <p>Thread model — read and write use disjoint buffers and disjoint SSLEngine
 * directions, so a framer vthread can call {@link RecordInputStream#read}
 * concurrently with a writer vthread calling
 * {@link RecordOutputStream#write}. Handshake / close_notify go through
 * {@link #handshakeLock}, which both directions acquire when they see
 * {@code NEED_TASK} or a pending renegotiation status.
 */
public final class TlsSocket implements AutoCloseable {

    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

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
    private final java.util.concurrent.atomic.AtomicBoolean closed =
        new java.util.concurrent.atomic.AtomicBoolean(false);

    private final InputStream in;
    private final OutputStream out;

    public TlsSocket(SocketChannel channel, SSLEngine engine) throws IOException {
        this.channel = channel;
        this.engine = engine;
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

    /** Force the initial TLS handshake to run to completion. */
    public void handshake() throws IOException {
        handshakeLock.lock();
        try {
            if (handshakeDone) return;
            engine.beginHandshake();
            HandshakeStatus hs = engine.getHandshakeStatus();
            while (hs != HandshakeStatus.FINISHED && hs != HandshakeStatus.NOT_HANDSHAKING) {
                hs = stepHandshake(hs);
            }
            handshakeDone = true;
        } finally {
            handshakeLock.unlock();
        }
    }

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
                peerAppData.flip();
                if (r.getStatus() == Status.CLOSED) {
                    throw new EOFException("peer closed during handshake");
                }
                if (r.getStatus() == Status.BUFFER_OVERFLOW) {
                    peerAppData = enlarge(peerAppData, engine.getSession().getApplicationBufferSize());
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
        int n = channel.read(peerNetData);
        if (n < 0) throw new EOFException("peer closed");
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
        // from an abrupt drop (h2spec §6.9.1). writeLock must also be held —
        // myNetData is shared with the regular write path and racing wrap()
        // calls corrupt its buffer state.
        try {
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
        } catch (IOException ignored) {
            // socket may be already dead — the finally block still closes it
        } finally {
            channel.close();
        }
    }

    /**
     * Wrap this TlsSocket in a {@link java.net.Socket} shim so it can be
     * passed to callers that expect the classic API. Only the accessors and
     * lifecycle methods the connection drivers actually use are overridden;
     * the underlying {@link Socket} instance is unconnected and inert.
     */
    public java.net.Socket asSocket() {
        return new AdapterSocket(this);
    }

    static final class AdapterSocket extends java.net.Socket {

        private final TlsSocket tls;

        AdapterSocket(TlsSocket tls) {
            this.tls = tls;
        }

        TlsSocket tls() { return tls; }

        // Overrides limited to methods actually called by HttpConnection /
        // Http2Connection / EnsoServer accept path. Adding more here without
        // a call site invites subtle default-Socket-impl behavior on an
        // unconnected shim.

        @Override public InputStream getInputStream() { return tls.getInputStream(); }
        @Override public OutputStream getOutputStream() { return tls.getOutputStream(); }
        @Override public void close() throws IOException { tls.close(); }
        @Override public InetAddress getInetAddress() { return tls.getInetAddress(); }
        @Override public int getLocalPort() { return tls.getLocalPort(); }
        @Override public SocketAddress getLocalSocketAddress() {
            try {
                return tls.channel.getLocalAddress();
            } catch (IOException e) {
                return null;
            }
        }
        // close_notify replaces SO_LINGER as the way to make sure a final
        // GOAWAY reaches the peer, so keep this a no-op.
        @Override public void setSoLinger(boolean on, int linger) { }
        // TCP_NODELAY was set on the underlying SocketChannel at accept time.
        // The AdapterSocket has no SocketImpl to forward to; no-op.
        @Override public void setTcpNoDelay(boolean on) { }
        // Per-request slowloris deadline from HttpConnection. Forward to the
        // SocketChannel's underlying Socket — Loom's blocking-read implementation
        // honours SO_TIMEOUT and unparks the vthread with SocketTimeoutException.
        // Without this override the HTTP/1.1 fallback path on the http2 TLS
        // listener loses its per-request timeout.
        @Override public void setSoTimeout(int t) throws java.net.SocketException {
            tls.channel.socket().setSoTimeout(t);
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
            while (true) {
                if (peerNetData.position() == 0) {
                    int n = channel.read(peerNetData);
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
                        if (peerAppData.position() > 0) {
                            peerAppData.flip();
                            HandshakeStatus hs = r.getHandshakeStatus();
                            if (hs != HandshakeStatus.NOT_HANDSHAKING
                                && hs != HandshakeStatus.FINISHED) {
                                driveHandshake(hs);
                            }
                            return true;
                        }
                    }
                    case BUFFER_UNDERFLOW -> {
                        int need = engine.getSession().getPacketBufferSize();
                        if (peerNetData.capacity() < need) {
                            peerNetData = enlarge(peerNetData, need);
                        }
                        int n = channel.read(peerNetData);
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
                HandshakeStatus hs = r.getHandshakeStatus();
                if (hs != HandshakeStatus.NOT_HANDSHAKING
                    && hs != HandshakeStatus.FINISHED
                    && r.getStatus() == Status.OK) {
                    driveHandshake(hs);
                }
            }
        }

        private void driveHandshake(HandshakeStatus start) throws IOException {
            // Renegotiation triggered from the read path can transition to
            // NEED_WRAP, which mutates myNetData — the same buffer the writer
            // vthread uses under writeLock. Grab writeLock first (matching
            // close()'s order) so a concurrent RecordOutputStream.write can
            // never race with stepHandshake's wrap(). TLS 1.3 never
            // renegotiates so this is dormant in practice, but the ordering
            // must be right for older peers.
            writeLock.lock();
            try {
                handshakeLock.lock();
                try {
                    HandshakeStatus hs = start;
                    while (hs != HandshakeStatus.FINISHED
                        && hs != HandshakeStatus.NOT_HANDSHAKING) {
                        hs = stepHandshake(hs);
                    }
                } finally {
                    handshakeLock.unlock();
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    // ---- Output stream -------------------------------------------------

    private final class RecordOutputStream extends OutputStream {

        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override
        public void write(byte[] src, int off, int len) throws IOException {
            if (len == 0) return;
            writeLock.lock();
            try {
                ByteBuffer app = ByteBuffer.wrap(src, off, len);
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
    }
}

package com.s_exp.enso;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.http1.HttpConnection;
import com.s_exp.enso.http2.Http2Connection;
import com.s_exp.enso.websocket.WebSocketConnection;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public final class EnsoServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(EnsoServer.class.getName());
    private static final long ACCEPT_FAILURE_BACKOFF_MILLIS = 50;
    private static final long SHUTDOWN_POLL_MILLIS = 10;

    private final Listener listener;
    private final RingHandler handler;
    private final RingErrorHandler errorHandler;
    private final ExecutorService executor;
    // Where request-handler tasks actually run. == executor when the user
    // did not supply Config.workerExecutor, else the user's Executor (its
    // lifecycle is theirs — we don't shutdown() external executors).
    private final java.util.concurrent.Executor dispatchExecutor;
    private final Thread acceptor;
    private final Config config;
    private final Set<HttpConnection> connections = ConcurrentHashMap.newKeySet();
    private final Set<Http2Connection> http2Connections = ConcurrentHashMap.newKeySet();
    // HTTP/3 listener kept as Object to avoid a static reference from
    // EnsoServer to the quiche FFM classes; loaded reflectively when the
    // http3 flag is set. Users with http3 disabled never trigger the FFM
    // classloader.
    private final AutoCloseable http3Listener;
    private volatile boolean running = true;

    public EnsoServer(RingHandler handler, Config config) throws IOException {
        this(handler, null, config);
    }

    public EnsoServer(RingHandler handler, RingErrorHandler errorHandler, Config config)
            throws IOException {
        this.handler = handler;
        this.errorHandler = errorHandler;
        this.config = config;
        this.listener = config.sslContext != null
            ? (config.http2
                ? new TlsChannelListener(config)
                : new SslListener(config))
            : new PlainListener(config);
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        this.dispatchExecutor = config.workerExecutor != null
            ? config.workerExecutor : this.executor;
        this.acceptor = Thread.ofPlatform()
            .name("enso-acceptor")
            .daemon(true)
            .unstarted(this::acceptLoop);
        this.http3Listener = createHttp3Listener();
    }

    /**
     * Reflective probe for the optional HTTP/3 listener. Keeping the
     * dependency behind {@link Class#forName} means users with
     * {@code :http3 false} never trigger classloading of the quiche FFM
     * bindings and never touch libquiche.
     */
    private AutoCloseable createHttp3Listener() throws IOException {
        if (!config.http3) return null;
        try {
            Class<?> cls = Class.forName("com.s_exp.enso.http3.Http3Listener");
            AutoCloseable l = (AutoCloseable) cls
                .getConstructor(Config.class, RingHandler.class, RingErrorHandler.class)
                .newInstance(config, handler, errorHandler);
            cls.getMethod("start").invoke(l);
            return l;
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new IllegalStateException(
                "HTTP/3 support requires the com.s_exp.enso.quiche package "
                + "(shipped with the main jar) plus libquiche installed. "
                + "See README.", e);
        } catch (Throwable t) {
            Throwable root = t.getCause() != null ? t.getCause() : t;
            throw new IllegalStateException(
                "HTTP/3 listener failed to start: " + root.getMessage(), root);
        }
    }

    public void start() {
        acceptor.start();
    }

    public int port() {
        return listener.port();
    }

    public Config config() {
        return config;
    }

    public RingErrorHandler errorHandler() {
        return errorHandler;
    }

    public boolean isRunning() {
        return running;
    }

    public void register(HttpConnection conn) {
        connections.add(conn);
    }

    public void unregister(HttpConnection conn) {
        connections.remove(conn);
    }

    public void register(Http2Connection conn) {
        http2Connections.add(conn);
    }

    public void unregister(Http2Connection conn) {
        http2Connections.remove(conn);
    }

    /**
     * Failures are contained per iteration so one bad connection never stops
     * the acceptor: a socket that can't be set up or dispatched is closed
     * rather than leaked, and accept errors (e.g. EMFILE) back off briefly
     * instead of spinning on a condition that persists.
     */
    private void acceptLoop() {
        while (running) {
            Socket socket;
            try {
                socket = listener.accept();
            } catch (IOException e) {
                if (running) {
                    LOG.log(Level.WARNING, "accept failed", e);
                    backOffAfterAcceptFailure();
                }
                continue;
            } catch (RuntimeException e) {
                // e.g. sslContextProvider threw; the listener already
                // closed the accepted channel.
                LOG.log(Level.WARNING, "connection setup failed", e);
                continue;
            }
            try {
                applySocketOptions(socket);
                if (config.idleTimeoutMillis > 0) {
                    socket.setSoTimeout(config.idleTimeoutMillis);
                }
                dispatchExecutor.execute(() -> dispatch(socket));
            } catch (IOException | RuntimeException e) {
                LOG.log(Level.WARNING, "connection dispatch failed", e);
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private static void backOffAfterAcceptFailure() {
        try {
            Thread.sleep(ACCEPT_FAILURE_BACKOFF_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * User-supplied ALPN list wins. Otherwise: advertise h2 + http/1.1 when
     * http2 is enabled; null (JVM default = single protocol per cipher) when
     * not. Explicit empty array means "clear ALPN".
     */
    private static String[] resolveAlpn(Config config) {
        if (config.alpnProtocols != null) return config.alpnProtocols;
        return config.http2 ? new String[] {"h2", "http/1.1"} : null;
    }

    private void applySocketOptions(Socket s) throws IOException {
        s.setTcpNoDelay(config.soNodelay);
        if (config.soLinger >= 0) {
            s.setSoLinger(true, config.soLinger);
        }
        if (config.soRcvBuf > 0) {
            s.setReceiveBufferSize(config.soRcvBuf);
        }
        if (config.soSndBuf > 0) {
            s.setSendBufferSize(config.soSndBuf);
        }
    }

    /**
     * Routes the accepted socket to the right protocol driver. Runs on the
     * virtual thread that will own the connection so the TLS handshake and
     * ALPN inspection happen off the acceptor. When the listener produced a
     * {@link TlsSocket.AdapterSocket}, drives the handshake and dispatches
     * to {@link Http2Connection} for "h2" or falls through to
     * {@link HttpConnection} for "http/1.1" (or when the peer sent no ALPN).
     */
    private void dispatch(Socket socket) {
        if (socket instanceof TlsSocket.AdapterSocket adapter) {
            try {
                TlsSocket tls = adapter.tls();
                // The handshake is the first part of reading a request, so
                // the request budget bounds it (each read also stays under
                // the idle timeout set at accept).
                tls.handshake(config.requestTimeoutMillis);
                String proto = tls.getApplicationProtocol();
                if ("h2".equals(proto)) {
                    // The idle timeout set at accept keeps bounding reads
                    // until the preface and SETTINGS exchange completes;
                    // Http2Connection then switches to its stream-aware
                    // idle timer.
                    new Http2Connection(socket, handler, this).run();
                    return;
                }
                // ALPN negotiated http/1.1 or the peer sent no ALPN — fall
                // through to HttpConnection.
            } catch (java.io.IOException e) {
                try {
                    socket.close();
                } catch (java.io.IOException ignored) {
                }
                return;
            }
        }
        new HttpConnection(socket, handler, this).run();
    }

    /**
     * Graceful shutdown: stops accepting new connections, lets in-flight requests
     * finish for up to shutdownTimeoutMillis, then force-closes remaining sockets.
     * Idle keep-alive connections exit as soon as they check {@link #isRunning()}
     * between requests, which happens after every response.
     */
    @Override
    public void close() throws IOException {
        running = false;
        listener.close();
        // Kick off h3 shutdown in parallel with h1/h2. h3 drains graceful
        // CONNECTION_CLOSE per conn (task #180 does this in parallel too);
        // waiting on h1/h2 executor termination first would leave h3 conns
        // no time to send their close frames before hard shutdown.
        Thread h3CloseThread = null;
        if (http3Listener != null) {
            h3CloseThread = Thread.ofVirtual().name("enso-h3-close").start(() -> {
                try {
                    http3Listener.close();
                } catch (Exception e) {
                    LOG.log(Level.WARNING, "http3 listener close failed", e);
                }
            });
        }
        closeIdleConnections();
        closeWebSockets();
        goAwayHttp2Connections();
        executor.shutdown();
        boolean clean = false;
        if (config.shutdownTimeoutMillis > 0) {
            // Connections are waited on directly: with a user-supplied
            // workerExecutor the internal executor runs no tasks, so its
            // termination says nothing about in-flight requests.
            long deadline = System.nanoTime() + config.shutdownTimeoutMillis * 1_000_000L;
            try {
                clean = awaitConnectionsDrained(deadline)
                    && executor.awaitTermination(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (!clean) {
            forEachConnection(c -> forceClose(c.socketRef()));
            for (Http2Connection c : http2Connections) {
                forceClose(c.socketRef());
            }
            executor.shutdownNow();
        }
        connections.clear();
        http2Connections.clear();
        if (h3CloseThread != null) {
            try {
                h3CloseThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** {@link TlsSocket#forceClose}, ignoring failures: teardown proceeds regardless. */
    public static void forceClose(Socket socket) {
        try {
            TlsSocket.forceClose(socket);
        } catch (IOException ignored) {
        }
    }

    /** Polls until every HTTP/1 and HTTP/2 connection has unregistered or the deadline passes. */
    private boolean awaitConnectionsDrained(long deadlineNanos) throws InterruptedException {
        while (!(connections.isEmpty() && http2Connections.isEmpty())
               && System.nanoTime() < deadlineNanos) {
            Thread.sleep(SHUTDOWN_POLL_MILLIS);
        }
        return connections.isEmpty() && http2Connections.isEmpty();
    }

    /**
     * GOAWAY(NO_ERROR) to every HTTP/2 connection: no new streams, close once
     * in-flight ones finish. Each runs on its own virtual thread since
     * goAway() may block behind a peer that stopped reading.
     */
    private void goAwayHttp2Connections() {
        for (Http2Connection c : http2Connections) {
            Thread.ofVirtual().name("enso-h2-goaway").start(c::goAway);
        }
    }

    /**
     * CLOSE 1001 to every open WebSocket so it finishes the closing
     * handshake within the shutdown timeout. Each runs on its own virtual
     * thread since the CLOSE may queue behind a writer stalled on a peer
     * that stopped reading.
     */
    private void closeWebSockets() {
        for (HttpConnection c : connections) {
            WebSocketConnection ws = c.webSocket();
            if (ws != null) {
                Thread.ofVirtual().name("enso-ws-close").start(ws::shutdown);
            }
        }
    }

    private void closeIdleConnections() {
        for (HttpConnection c : connections) {
            if (c.idle) {
                try {
                    c.socketRef().close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private void forEachConnection(Consumer<HttpConnection> action) {
        for (HttpConnection c : connections) {
            action.accept(c);
        }
    }

    private sealed interface Listener extends Closeable
            permits PlainListener, SslListener, TlsChannelListener {
        Socket accept() throws IOException;
        int port();
    }

    /**
     * Plain HTTP listener over {@link ServerSocketChannel}, so that accepted
     * sockets expose a {@link SocketChannel} for zero-copy file transfer.
     */
    private static final class PlainListener implements Listener {

        private final ServerSocketChannel channel;

        PlainListener(Config config) throws IOException {
            this.channel = ServerSocketChannel.open();
            this.channel.socket().setReuseAddress(config.soReuseAddr);
            this.channel.bind(new InetSocketAddress(config.host, config.port), config.backlog);
        }

        @Override
        public Socket accept() throws IOException {
            SocketChannel sc = channel.accept();
            return sc.socket();
        }

        @Override
        public int port() {
            return ((InetSocketAddress) channel.socket().getLocalSocketAddress()).getPort();
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    /** Applies {@code :ssl-session-cache-size}; 0 keeps the JVM default. */
    private static void applySessionCacheSize(Config config, SSLContext ctx) {
        if (config.sslSessionCacheSize > 0 && ctx != null) {
            ctx.getServerSessionContext().setSessionCacheSize(config.sslSessionCacheSize);
        }
    }

    /**
     * TLS listener over {@link SSLServerSocket}. Sockets have no
     * {@link SocketChannel}; file bodies use the user-space transfer fallback.
     */
    private static final class SslListener implements Listener {

        private final SSLServerSocket serverSocket;

        SslListener(Config config) throws IOException {
            applySessionCacheSize(config, config.sslContext);
            SSLServerSocketFactory factory = config.sslContext.getServerSocketFactory();
            this.serverSocket = (SSLServerSocket) factory.createServerSocket(
                config.port, config.backlog, InetAddress.getByName(config.host));
            serverSocket.setReuseAddress(config.soReuseAddr);
            if (config.sslNeedClientAuth) {
                this.serverSocket.setNeedClientAuth(true);
            } else if (config.sslWantClientAuth) {
                this.serverSocket.setWantClientAuth(true);
            }
            javax.net.ssl.SSLParameters params = serverSocket.getSSLParameters();
            String[] alpn = resolveAlpn(config);
            if (alpn != null) params.setApplicationProtocols(alpn);
            if (config.enabledCipherSuites != null) {
                params.setCipherSuites(config.enabledCipherSuites);
            }
            if (config.enabledTlsProtocols != null) {
                params.setProtocols(config.enabledTlsProtocols);
            }
            serverSocket.setSSLParameters(params);
        }

        @Override
        public Socket accept() throws IOException {
            return serverSocket.accept();
        }

        @Override
        public int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    /**
     * TLS listener over {@link ServerSocketChannel} + {@link SSLEngine}.
     * Each accepted connection is wrapped in a {@link TlsSocket}; the
     * handshake and ALPN inspection happen in the connection's virtual
     * thread (see {@link EnsoServer#dispatch}). Enables gathering writes,
     * clean {@code close_notify} shutdown, and a {@link SocketChannel} for
     * zero-copy file transfer.
     */
    private static final class TlsChannelListener implements Listener {

        private final ServerSocketChannel channel;
        private final Config config;
        // Acceptor-thread only: the context last configured, so a provider
        // returning the same one isn't reconfigured per accept.
        private SSLContext configured;

        TlsChannelListener(Config config) throws IOException {
            this.config = config;
            applySessionCacheSize(config, config.sslContext);
            this.configured = config.sslContext;
            this.channel = ServerSocketChannel.open();
            this.channel.socket().setReuseAddress(config.soReuseAddr);
            this.channel.bind(new InetSocketAddress(config.host, config.port), config.backlog);
        }

        @Override
        public Socket accept() throws IOException {
            SocketChannel sc = channel.accept();
            try {
                // Reloadable SSL: read the live context per accept so cert
                // rotation lands on new connections without restart.
                SSLContext current = config.sslContextProvider != null
                    ? config.sslContextProvider.get()
                    : config.sslContext;
                if (current == null) {
                    throw new IOException("SSLContext provider returned null");
                }
                if (current != configured) {
                    applySessionCacheSize(config, current);
                    configured = current;
                }
                SSLEngine engine = current.createSSLEngine();
                engine.setUseClientMode(false);
                if (config.sslNeedClientAuth) engine.setNeedClientAuth(true);
                else if (config.sslWantClientAuth) engine.setWantClientAuth(true);
                javax.net.ssl.SSLParameters params = engine.getSSLParameters();
                String[] alpn = resolveAlpn(config);
                if (alpn != null) params.setApplicationProtocols(alpn);
                if (config.enabledCipherSuites != null) {
                    params.setCipherSuites(config.enabledCipherSuites);
                }
                if (config.enabledTlsProtocols != null) {
                    params.setProtocols(config.enabledTlsProtocols);
                }
                engine.setSSLParameters(params);
                return new TlsSocket(sc, engine).asSocket();
            } catch (Throwable t) {
                // Any failure between accept and TlsSocket construction
                // (cipher/protocol misconfig, alloc, engine ctor) would
                // leak sc's file descriptor. Close before rethrowing.
                try { sc.close(); } catch (IOException ignored) {}
                if (t instanceof IOException io) throw io;
                if (t instanceof RuntimeException re) throw re;
                if (t instanceof Error er) throw er;
                throw new IOException("TLS engine setup failed", t);
            }
        }

        @Override
        public int port() {
            try {
                return ((InetSocketAddress) channel.getLocalAddress()).getPort();
            } catch (IOException e) {
                return -1;
            }
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }
}

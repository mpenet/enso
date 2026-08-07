package com.s_exp.enso;

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
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public final class EnsoServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(EnsoServer.class.getName());

    private final Listener listener;
    private final RingHandler handler;
    private final RingErrorHandler errorHandler;
    private final ExecutorService executor;
    private final Thread acceptor;
    private final Config config;
    private final Set<HttpConnection> connections = ConcurrentHashMap.newKeySet();
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
        this.acceptor = Thread.ofPlatform()
            .name("enso-acceptor")
            .daemon(true)
            .unstarted(this::acceptLoop);
    }

    public void start() {
        acceptor.start();
    }

    public int port() {
        return listener.port();
    }

    Config config() {
        return config;
    }

    RingErrorHandler errorHandler() {
        return errorHandler;
    }

    boolean isRunning() {
        return running;
    }

    void register(HttpConnection conn) {
        connections.add(conn);
    }

    void unregister(HttpConnection conn) {
        connections.remove(conn);
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = listener.accept();
                socket.setTcpNoDelay(true);
                if (config.idleTimeoutMillis > 0) {
                    socket.setSoTimeout(config.idleTimeoutMillis);
                }
                executor.execute(() -> dispatch(socket));
            } catch (IOException e) {
                if (running) {
                    LOG.log(Level.WARNING, "accept failed", e);
                }
            }
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
                tls.handshake();
                String proto = tls.getApplicationProtocol();
                if ("h2".equals(proto)) {
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
        closeIdleConnections();
        executor.shutdown();
        boolean clean = false;
        if (config.shutdownTimeoutMillis > 0) {
            try {
                clean = executor.awaitTermination(config.shutdownTimeoutMillis, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (!clean) {
            forEachConnection(c -> {
                try {
                    c.socketRef().close();
                } catch (IOException ignored) {
                }
            });
            executor.shutdownNow();
        }
        connections.clear();
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

    /**
     * TLS listener over {@link SSLServerSocket}. Sockets have no
     * {@link SocketChannel}; file bodies use the user-space transfer fallback.
     */
    private static final class SslListener implements Listener {

        private final SSLServerSocket serverSocket;

        SslListener(Config config) throws IOException {
            SSLServerSocketFactory factory = config.sslContext.getServerSocketFactory();
            this.serverSocket = (SSLServerSocket) factory.createServerSocket(
                config.port, config.backlog, InetAddress.getByName(config.host));
            if (config.sslNeedClientAuth) {
                this.serverSocket.setNeedClientAuth(true);
            } else if (config.sslWantClientAuth) {
                this.serverSocket.setWantClientAuth(true);
            }
            if (config.http2) {
                // Advertise both application protocols; "h2" first so ALPN-aware
                // clients prefer HTTP/2 while HTTP/1.1-only clients still work.
                javax.net.ssl.SSLParameters params = serverSocket.getSSLParameters();
                params.setApplicationProtocols(new String[] {"h2", "http/1.1"});
                serverSocket.setSSLParameters(params);
            }
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
        private final javax.net.ssl.SSLContext sslContext;
        private final Config config;

        TlsChannelListener(Config config) throws IOException {
            this.config = config;
            this.sslContext = config.sslContext;
            this.channel = ServerSocketChannel.open();
            this.channel.bind(new InetSocketAddress(config.host, config.port), config.backlog);
        }

        @Override
        public Socket accept() throws IOException {
            SocketChannel sc = channel.accept();
            sc.socket().setTcpNoDelay(true);
            SSLEngine engine = sslContext.createSSLEngine();
            engine.setUseClientMode(false);
            if (config.sslNeedClientAuth) engine.setNeedClientAuth(true);
            else if (config.sslWantClientAuth) engine.setWantClientAuth(true);
            javax.net.ssl.SSLParameters params = engine.getSSLParameters();
            params.setApplicationProtocols(new String[] {"h2", "http/1.1"});
            engine.setSSLParameters(params);
            return new TlsSocket(sc, engine).asSocket();
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

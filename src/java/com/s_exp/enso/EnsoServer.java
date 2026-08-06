package com.s_exp.enso;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
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
        this.listener = config.sslContext != null ? new SslListener(config) : new PlainListener(config);
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
                executor.execute(new HttpConnection(socket, handler, this));
            } catch (IOException e) {
                if (running) {
                    LOG.log(Level.WARNING, "accept failed", e);
                }
            }
        }
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

    private sealed interface Listener extends Closeable permits PlainListener, SslListener {
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
}

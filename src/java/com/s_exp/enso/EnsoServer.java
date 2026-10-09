// ABOUTME: The server: binds the TCP (and optional QUIC) listeners, admits connections through the
// ABOUTME: limiter, hands each to a protocol driver on a virtual thread, and drives shutdown.
package com.s_exp.enso;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.api.ServerEvents;
import com.s_exp.enso.core.ConnectionLimiter;
import com.s_exp.enso.core.ConnectionRegistry;
import com.s_exp.enso.core.Drainable;
import com.s_exp.enso.core.Jfr;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.http1.HttpConnection;
import com.s_exp.enso.http2.Http2Connection;
import com.s_exp.enso.http3.Http3Listener;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardSocketOptions;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/**
 * Lifecycle: the constructor only records its arguments; {@link #start}
 * binds every listener, starts the shared {@link Timer} and the acceptor,
 * and releases everything again if any step fails; {@link #close} drains
 * every connection under one {@code :shutdown-timeout} deadline, then
 * force-closes what is left.
 *
 * <p>One TCP listener serves plain HTTP/1.1 or TLS (SSLEngine over a
 * SocketChannel, so a plain listener keeps zero-copy file transfer). Each
 * accepted connection passes the {@link ConnectionLimiter} on the
 * acceptor, then runs on its own virtual thread: TLS handshake and ALPN
 * there (or, on a plain listener with {@code :http2c}, a look at the first
 * bytes for the HTTP/2 preface), then the HTTP/1.1 or HTTP/2 driver. It is
 * registered as {@link Drainable} from accept to close.
 */
public final class EnsoServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(EnsoServer.class.getName());
    private static final LogLimiter ACCEPT_FAILURES = new LogLimiter(LOG, Level.WARNING);
    private static final LogLimiter CONNECTION_FAILURES = new LogLimiter(LOG, Level.FINE);
    private static final long ACCEPT_FAILURE_BACKOFF_MILLIS = 50;
    // Longest part of :shutdown-timeout kept for force-closing what didn't
    // drain and joining its threads (a quarter of the timeout when shorter).
    private static final long FORCE_WINDOW_MAX_NANOS = 1_000_000_000L;

    public static final String HTTP_1_1 = "http/1.1";
    public static final String H2 = "h2";
    /** Cleartext HTTP/2 (prior knowledge, {@code :http2c}). */
    public static final String H2C = "h2c";

    private final RingHandler handler;
    private final RingErrorHandler errorHandler;
    private final Config config;
    private final ConnectionRegistry registry = new ConnectionRegistry();
    private final ConnectionLimiter limiter;

    private ServerSocketChannel channel;
    private ExecutorService executor;
    private Timer timer;
    private Service service;
    private Thread acceptor;
    // HTTP/3 listener; servers without :http3 never load the JNI shim.
    private AutoCloseable http3Listener;
    private volatile boolean running;
    // Guards started / closed and publishes what start() set up to close().
    // A lock rather than a monitor: start() binds sockets, and blocking
    // under a monitor pins a virtual thread's carrier on JDKs before 24.
    private final ReentrantLock lifecycle = new ReentrantLock();
    private boolean started;
    private boolean closed;
    // The TLS context last configured (session cache size), so a provider
    // returning the same context isn't reconfigured per connection.
    private volatile SSLContext configuredContext;

    public EnsoServer(RingHandler handler, Config config) {
        this(handler, null, config);
    }

    public EnsoServer(RingHandler handler, RingErrorHandler errorHandler, Config config) {
        this.handler = handler;
        this.errorHandler = errorHandler;
        this.config = config;
        this.limiter = new ConnectionLimiter(config.maxConnections, config.maxConnectionsPerIp);
    }

    /**
     * Binds and starts serving. On failure (port in use, bad TLS or HTTP/3
     * setup) everything already started is released before the exception
     * propagates; the server can't be started again.
     */
    public void start() throws IOException {
        lifecycle.lock();
        try {
            startLocked();
        } finally {
            lifecycle.unlock();
        }
    }

    private void startLocked() throws IOException {
        if (started) throw new IllegalStateException("server already started");
        started = true;
        try {
            timer = new Timer();
            service = new Service(handler, errorHandler, config, timer);
            executor = Executors.newVirtualThreadPerTaskExecutor();
            if (config.sslContext != null) {
                configureContext(config.sslContext);
            }
            channel = bind();
            running = true;
            http3Listener = createHttp3Listener();
            acceptor = Thread.ofPlatform().name("enso-acceptor").daemon(true).unstarted(this::acceptLoop);
            acceptor.start();
        } catch (Throwable t) {
            running = false;
            releaseResources();
            throw t;
        }
    }

    private ServerSocketChannel bind() throws IOException {
        ServerSocketChannel ch = ServerSocketChannel.open();
        try {
            // Options that must precede bind: address reuse, and the receive
            // buffer (accepted sockets inherit it, and a window scale is
            // only negotiated for buffers set before the handshake).
            ch.setOption(StandardSocketOptions.SO_REUSEADDR, config.soReuseAddr);
            if (config.soRcvBufBytes > 0) {
                ch.setOption(StandardSocketOptions.SO_RCVBUF, config.soRcvBufBytes);
            }
            ch.bind(new InetSocketAddress(config.host, config.port), config.backlog);
            return ch;
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
    }

    /**
     * The HTTP/3 listener, when {@code :http3}. Referencing it loads no
     * native code: the JNI shim loads with the quiche bindings, which only
     * {@code start()} touches.
     */
    private AutoCloseable createHttp3Listener() throws IOException {
        if (!config.http3) return null;
        Http3Listener l = new Http3Listener(service, registry, limiter);
        try {
            l.start();
        } catch (IOException | RuntimeException | LinkageError e) {
            l.close();
            throw new IllegalStateException("HTTP/3 listener failed to start: " + e.getMessage(), e);
        }
        return l;
    }

    public int port() {
        ServerSocketChannel ch = channel;
        if (ch == null) return -1;
        try {
            return ((InetSocketAddress) ch.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    public Config config() {
        return config;
    }

    public RingErrorHandler errorHandler() {
        return errorHandler;
    }

    /** The server's shared timer; null before {@link #start}. */
    public Timer timer() {
        return timer;
    }

    /** {@code :server-events} listener (guarded), or null (also before {@link #start}). */
    public ServerEvents events() {
        Service s = service;
        return s == null ? null : s.events;
    }

    /** Server events dropped because the {@code :server-events} listener fell behind. */
    public long droppedEvents() {
        Service s = service;
        return s == null ? 0 : s.droppedEvents();
    }

    /** What the drivers serve (handler, config, events, budget); null before {@link #start}. */
    public Service service() {
        return service;
    }

    public boolean isRunning() {
        return running;
    }

    /** Connections currently open, from accept to close. */
    public int connectionCount() {
        return registry.size();
    }

    /**
     * Accept errors (e.g. EMFILE) back off briefly instead of spinning on
     * a condition that persists; one failing connection never stops the
     * acceptor, whatever it throws.
     */
    private void acceptLoop() {
        while (running) {
            SocketChannel sc;
            try {
                sc = channel.accept();
            } catch (Throwable e) {
                if (running) {
                    ACCEPT_FAILURES.log("accept failed", e);
                    backOffAfterAcceptFailure();
                }
                continue;
            }
            try {
                admit(sc);
            } catch (Throwable t) {
                closeQuietly(sc);
                if (running) {
                    ACCEPT_FAILURES.log("connection admission failed", t);
                    backOffAfterAcceptFailure();
                }
            }
        }
    }

    /** Admits {@code sc} through the limiter and dispatches it; closes it when refused. */
    private void admit(SocketChannel sc) {
        InetAddress remote = sc.socket().getInetAddress();
        if (remote == null || !limiter.tryAcquire(remote)) {
            closeQuietly(sc);
            service.protocolError("tcp", "connection-limit");
            CONNECTION_FAILURES.log("connection refused: connection limit reached");
            return;
        }
        try {
            executor.execute(new Accepted(sc, remote));
        } catch (Throwable t) {
            limiter.release(remote);
            closeQuietly(sc);
            if (running) ACCEPT_FAILURES.log("connection dispatch failed", t);
        }
    }

    /**
     * Whether the server is running with its acceptor and timer threads
     * alive (and, with {@code :http3}, every HTTP/3 event loop): both are
     * supervised, so false means a fault worth alerting on.
     */
    public boolean isHealthy() {
        Thread a = acceptor;
        Timer t = timer;
        return running && a != null && a.isAlive() && t != null && t.isAlive()
            && (!(http3Listener instanceof Http3Listener h3) || h3.isHealthy());
    }

    private static void backOffAfterAcceptFailure() {
        try {
            Thread.sleep(ACCEPT_FAILURE_BACKOFF_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void closeQuietly(SocketChannel sc) {
        try {
            sc.close();
        } catch (IOException ignored) {
        }
    }

    private void applySocketOptions(SocketChannel sc) throws IOException {
        sc.setOption(StandardSocketOptions.TCP_NODELAY, config.soNodelay);
        if (config.soLinger >= 0) {
            sc.setOption(StandardSocketOptions.SO_LINGER, config.soLinger);
        }
        if (config.soSndBufBytes > 0) {
            sc.setOption(StandardSocketOptions.SO_SNDBUF, config.soSndBufBytes);
        }
    }

    /**
     * ALPN offered: the configured list, else h2 + http/1.1 with
     * {@code :http2}, else http/1.1 (so an h2-capable client that
     * negotiates gets a definite answer).
     */
    private String[] alpnProtocols() {
        if (config.sslAlpnProtocols != null) return config.sslAlpnProtocols;
        return config.http2 ? new String[] {H2, HTTP_1_1} : new String[] {HTTP_1_1};
    }

    private void configureContext(SSLContext ctx) {
        if (config.sslSessionCacheSize > 0) {
            ctx.getServerSessionContext().setSessionCacheSize(config.sslSessionCacheSize);
        }
        configuredContext = ctx;
    }

    /** A fresh server-side engine from the live context (rotation via the provider). */
    private SSLEngine newEngine() throws IOException {
        SSLContext ctx = config.sslContextProvider != null
            ? config.sslContextProvider.get()
            : config.sslContext;
        if (ctx == null) {
            throw new IOException("SSLContext provider returned null");
        }
        if (ctx != configuredContext) {
            configureContext(ctx);
        }
        SSLEngine engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        if (config.sslNeedClientAuth) {
            engine.setNeedClientAuth(true);
        } else if (config.sslWantClientAuth) {
            engine.setWantClientAuth(true);
        }
        SSLParameters params = engine.getSSLParameters();
        params.setApplicationProtocols(alpnProtocols());
        if (config.sslCipherSuites != null) {
            params.setCipherSuites(config.sslCipherSuites);
        }
        if (config.sslProtocols != null) {
            params.setProtocols(config.sslProtocols);
        }
        engine.setSSLParameters(params);
        return engine;
    }

    /**
     * One accepted connection, from accept to close: socket setup, TLS
     * handshake and ALPN, then the protocol driver, all on its virtual
     * thread. Registered for shutdown before anything can block, and
     * closed whatever happens.
     */
    private final class Accepted implements Runnable, Drainable {

        private final SocketChannel channel;
        private final InetAddress remote;
        private volatile Socket socket;
        private volatile Drainable driver;

        Accepted(SocketChannel channel, InetAddress remote) {
            this.channel = channel;
            this.remote = remote;
        }

        @Override
        public void run() {
            registry.register(this);
            long openedAt = 0;
            String protocol = null;
            Jfr.ConnectionEvent jfr = null;
            TlsSocket tls = null;
            // Bytes a plain :http2c listener read to tell HTTP/2 from HTTP/1.1.
            byte[] prefix = null;
            int prefixLen = 0;
            try {
                if (!running) return;
                applySocketOptions(channel);
                Socket s;
                long handshakeDeadline = 0;
                if (config.sslContext != null) {
                    tls = new TlsSocket(channel, newEngine());
                    s = tls.asSocket();
                    socket = s;
                    if (config.handshakeTimeoutMillis > 0) {
                        handshakeDeadline = System.nanoTime() + config.handshakeTimeoutMillis * 1_000_000L;
                    }
                    // A silent peer is still bounded with the handshake
                    // timeout disabled.
                    s.setSoTimeout(config.idleTimeoutMillis);
                    tls.handshake(config.handshakeTimeoutMillis);
                    protocol = H2.equals(tls.getApplicationProtocol()) ? H2 : HTTP_1_1;
                } else {
                    s = channel.socket();
                    socket = s;
                    protocol = HTTP_1_1;
                    if (config.http2c) {
                        if (config.handshakeTimeoutMillis > 0) {
                            handshakeDeadline = System.nanoTime() + config.handshakeTimeoutMillis * 1_000_000L;
                        }
                        prefix = new byte[Http2Connection.PREFACE_LENGTH];
                        prefixLen = readPrefix(s, prefix);
                        if (prefixLen < 0) return;
                        if (Http2Connection.isPreface(prefix, prefixLen)) {
                            protocol = H2C;
                            // Until its first SETTINGS the HTTP/2 driver
                            // relies on this bound for a silent peer.
                            s.setSoTimeout(config.idleTimeoutMillis);
                        }
                    }
                }
                if (service.events != null || Jfr.connections()) {
                    openedAt = System.nanoTime();
                    service.connectionOpened(protocol, remote);
                    if (Jfr.connections()) {
                        jfr = new Jfr.ConnectionEvent();
                        jfr.begin();
                    }
                }
                if (H2.equals(protocol) || H2C.equals(protocol)) {
                    Http2Connection c = new Http2Connection(s, handler, EnsoServer.this, handshakeDeadline,
                                                            H2C.equals(protocol));
                    driver = c;
                    c.run();
                } else {
                    HttpConnection c = new HttpConnection(s, handler, EnsoServer.this, prefix, prefixLen);
                    driver = c;
                    c.run();
                }
            } catch (Throwable t) {
                if (protocol == null && config.sslContext != null) {
                    // A silent or drip-feeding peer runs out the handshake
                    // deadline (or the idle timeout bounding each read).
                    tlsError(t instanceof java.net.SocketTimeoutException ? "handshake-timeout" : "handshake");
                }
                if (!(t instanceof IOException) && running) {
                    CONNECTION_FAILURES.log("connection failed", t);
                }
            } finally {
                forceClose();
                if (tls != null && tls.renegotiationRefused()) {
                    tlsError("renegotiation");
                }
                registry.unregister(this);
                limiter.release(remote);
                if (openedAt != 0) {
                    service.connectionClosed(protocol, remote, System.nanoTime() - openedAt);
                }
                if (jfr != null) {
                    jfr.protocol = protocol;
                    jfr.remoteAddress = remote.getHostAddress();
                    jfr.commit();
                }
            }
        }

        private void tlsError(String kind) {
            service.protocolError("tls", kind);
        }

        /**
         * Reads the first bytes of a plain connection into {@code buf} (the
         * preface's length) until they can't be the HTTP/2 preface or all
         * of it arrived: a mismatch shows within the first bytes of any
         * HTTP/1.1 request, which may be shorter than the preface. Returns
         * how many were read, or -1 when the peer closed or stayed silent
         * for :idle-timeout before sending anything. Once bytes arrived,
         * the rest is bounded by :header-timeout as an HTTP/1.1 head is.
         * The socket's timeout is left at 0, as the drivers expect it.
         */
        private int readPrefix(Socket s, byte[] buf) throws IOException {
            java.io.InputStream in = s.getInputStream();
            int n = 0;
            long deadline = 0;
            try {
                s.setSoTimeout(config.idleTimeoutMillis);
                while (n < buf.length) {
                    int r;
                    try {
                        r = in.read(buf, n, buf.length - n);
                    } catch (java.net.SocketTimeoutException e) {
                        if (n == 0) return -1;
                        throw e;
                    }
                    if (r < 0) return n == 0 ? -1 : n;
                    n += r;
                    if (!Http2Connection.isPreface(buf, n)) break;
                    if (deadline == 0 && config.headerTimeoutMillis > 0) {
                        deadline = System.nanoTime() + config.headerTimeoutMillis * 1_000_000L;
                    }
                    if (deadline != 0) {
                        long left = (deadline - System.nanoTime()) / 1_000_000L;
                        if (left <= 0) throw new java.net.SocketTimeoutException("preface not completed in time");
                        s.setSoTimeout((int) Math.min(left, Integer.MAX_VALUE));
                    }
                }
                return n;
            } finally {
                s.setSoTimeout(0);
            }
        }

        @Override
        public void beginDrain() {
            Drainable d = driver;
            if (d != null) {
                d.beginDrain();
            } else {
                // Still setting up or handshaking: no request in flight.
                forceClose();
            }
        }

        @Override
        public void forceClose() {
            Drainable d = driver;
            if (d != null) {
                d.forceClose();
            }
            Socket s = socket;
            if (s != null) {
                EnsoServer.forceClose(s);
            } else {
                closeQuietly(channel);
            }
        }
    }

    /**
     * Graceful shutdown within {@code :shutdown-timeout}: stop accepting,
     * ask every connection to drain (idle HTTP/1.1 connections close at
     * once, HTTP/2 sends GOAWAY, WebSockets CLOSE 1001) and wait for them;
     * for the last part of the timeout (a quarter, at most a second)
     * force-close what is left, which interrupts every handler still
     * running, and wait for those threads to exit. A connection leaves the
     * registry only once its handlers are done, so an empty registry means
     * every handler thread was joined. HTTP/3 drains in parallel under the
     * same budget. Handlers that ignore their interrupt past the deadline
     * are logged and left behind.
     */
    @Override
    public void close() throws IOException {
        lifecycle.lock();
        try {
            if (closed) return;
            closed = true;
        } finally {
            lifecycle.unlock();
        }
        running = false;
        long start = System.nanoTime();
        long budget = config.shutdownTimeoutMillis * 1_000_000L;
        long deadline = start + budget;
        long drainDeadline = deadline - Math.min(FORCE_WINDOW_MAX_NANOS, budget / 4);
        if (channel != null) {
            channel.close();
        }
        Thread h3Close = null;
        if (http3Listener != null) {
            AutoCloseable h3 = http3Listener;
            h3Close = Thread.ofVirtual().name("enso-h3-close").start(() -> {
                try {
                    h3.close();
                } catch (Exception e) {
                    LOG.log(Level.WARNING, "http3 listener close failed", e);
                }
            });
        }
        registry.beginDrainAll();
        boolean clean = registry.awaitEmpty(drainDeadline);
        if (!clean) {
            // Closing interrupts the drivers' handler threads (HTTP/2 and
            // HTTP/3 on their teardown); shutdownNow interrupts the
            // connection threads, which run the HTTP/1.1 handlers.
            registry.forceCloseAll();
            if (executor != null) {
                executor.shutdownNow();
            }
            clean = registry.awaitEmpty(deadline);
            if (!clean) {
                LOG.warning(registry.size() + " connection(s) still running handlers at the "
                            + ":shutdown-timeout deadline; their threads ignore interrupts");
            }
        }
        if (executor != null) {
            executor.shutdown();
            if (clean) {
                // Every connection left the registry; their threads only
                // have their last bookkeeping to run. Joining them means
                // close() returns with no connection thread still alive.
                awaitExecutor(deadline);
            }
        }
        if (h3Close != null) {
            try {
                h3Close.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        releaseResources();
    }

    private void awaitExecutor(long deadlineNanos) {
        try {
            executor.awaitTermination(Math.max(0, deadlineNanos - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void releaseResources() {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
            }
        }
        if (http3Listener != null && !closed) {
            try {
                http3Listener.close();
            } catch (Exception ignored) {
            }
        }
        if (executor != null) {
            executor.shutdown();
            try {
                executor.awaitTermination(100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (timer != null) {
            timer.close();
        }
        if (service != null) {
            service.close();
        }
    }

    /** {@link TlsSocket#forceClose}, ignoring failures: teardown proceeds regardless. */
    public static void forceClose(Socket socket) {
        try {
            TlsSocket.forceClose(socket);
        } catch (IOException ignored) {
        }
    }
}

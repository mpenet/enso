// ABOUTME: HTTP/1.1 connection driver: parses requests off a blocking socket on the connection's
// ABOUTME: virtual thread, runs the Ring handler, writes responses (pipelined, keep-alive, upgrade).
package com.s_exp.enso.http1;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingHandler;
import com.s_exp.enso.core.Drainable;
import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.HttpError;
import com.s_exp.enso.core.HttpFields;
import com.s_exp.enso.core.HttpStatus;
import com.s_exp.enso.core.LogLimiter;
import com.s_exp.enso.core.RequestBodyException;
import com.s_exp.enso.core.RequestBodyTimeoutException;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.WatchedOutputStream;
import com.s_exp.enso.core.WriteWatchdog;
import com.s_exp.enso.websocket.PerMessageDeflate;
import com.s_exp.enso.websocket.WebSocketConnection;
import com.s_exp.enso.websocket.WebSocketHandshake;

/**
 * One HTTP/1.1 connection, run on its own virtual thread.
 *
 * <p>Timeouts are socket read timeouts set per phase, so the common path
 * costs no timer operation: {@code :idle-timeout} while waiting for the
 * first byte of a request, the remaining {@code :header-timeout} budget
 * (wall clock from that byte) while the head is incomplete, and
 * {@code :read-timeout} for body reads. Writes go through a
 * {@link WatchedOutputStream} ({@code :write-timeout}); the opt-in
 * {@code :handler-timeout} uses the server's {@link Timer}.
 *
 * <p>Requests are read by a {@link RequestReader}, responses written by a
 * {@link ResponseWriter}; this class runs the request loop: handler,
 * keep-alive, handler timeout, WebSocket upgrade, drain and tracing.
 */
public final class HttpConnection implements Runnable, Drainable {

    private static final Logger LOG = Logger.getLogger(HttpConnection.class.getName());
    static final LogLimiter INVALID_RESPONSES = new LogLimiter(LOG, Level.WARNING);
    static final LogLimiter BODY_FAILURES = new LogLimiter(LOG, Level.FINE);

    private static final byte[] SEC_WEBSOCKET_VERSION_13 =
        "Sec-WebSocket-Version: 13\r\n".getBytes(StandardCharsets.ISO_8859_1);
    // Largest unread request body drained to keep the connection; above
    // it the connection is closed instead.
    private static final int MAX_DRAIN_BYTES = 65_536;
    private static final String WEBSOCKET = "websocket";

    private final Socket socket;
    private final RingHandler handler;
    private final EnsoServer server;
    private final Service service;
    private final Config config;
    private final Timer timer;
    // :write-timeout, null when disabled.
    private final Watchdog watchdog;
    private final ResponseWriter writer;
    private final RequestReader reader;
    // The exchange of the request in flight, reused for every request; also
    // the :handler-timeout timer node.
    private final Call call = new Call();

    /**
     * True while this connection is between requests: keep-alive completed the
     * previous response, no bytes for the next request have been buffered or
     * observed on the socket yet. Read by {@link #beginDrain} to tell sockets
     * that can be closed without dropping an in-flight request from those
     * still handling one. Cleared by {@link RequestReader#socketRead} on the
     * first byte received of a new request, closing the shutdown race to the
     * kernel-read latency window.
     */
    public volatile boolean idle;
    /**
     * The WebSocket this connection was upgraded to, once its handshake is
     * written. Read by {@link #beginDrain} to close it gracefully.
     */
    private volatile WebSocketConnection webSocket;
    private int servedRequests;
    // The connection ends with input possibly still arriving (an error
    // response, an unread body, a close the client didn't ask for): close
    // it lingering.
    private boolean linger;
    // Orders the writes that can come from two threads during a handler:
    // the 100 Continue (connection thread) and the handler-timeout 503.
    // Both block on the socket: a ReentrantLock, which doesn't pin the
    // virtual thread's carrier on JDKs before 24 as a monitor would.
    private final ReentrantLock handlerWriteLock = new ReentrantLock();
    // The handler-timeout 503 is written and the handler interrupted.
    private volatile boolean timeoutResponded;
    private boolean timerUsed;
    private Thread connectionThread;
    private final byte[] prefix;
    private final int prefixLen;

    public HttpConnection(Socket socket, RingHandler handler, EnsoServer server) {
        this(socket, handler, server, null, 0);
    }

    /**
     * {@code prefix[0, prefixLen)}: the first bytes of the connection,
     * already read by the listener (to rule out the HTTP/2 preface); they
     * are parsed before anything read from the socket.
     */
    public HttpConnection(Socket socket, RingHandler handler, EnsoServer server, byte[] prefix, int prefixLen) {
        this.prefix = prefix;
        this.prefixLen = prefixLen;
        this.socket = socket;
        this.handler = handler;
        this.server = server;
        this.service = server.service();
        this.config = service.config;
        this.timer = service.timer;
        this.watchdog = config.writeTimeoutMillis > 0 ? new Watchdog() : null;
        this.writer = new ResponseWriter(socket, service, watchdog);
        this.reader = new RequestReader(this, writer, socket, config);
    }

    public Socket socketRef() {
        return socket;
    }

    public WebSocketConnection webSocket() {
        return webSocket;
    }

    @Override
    public void run() {
        connectionThread = Thread.currentThread();
        try (Socket s = socket) {
            reader.start(s.getInputStream(), prefix, prefixLen);
            OutputStream t = s.getOutputStream();
            if (watchdog != null) {
                t = new WatchedOutputStream(t, watchdog);
            }
            writer.start(t, connectionThread);
            while (server.isRunning() && handleOne()) {
                servedRequests++;
            }
            writer.flush();
            // Closing with unread input makes the kernel answer it with a
            // reset, which can destroy responses the client hasn't read yet.
            if (linger || reader.inputPending()) {
                reader.lingeringClose();
            }
        } catch (IOException e) {
            // client went away or timed out
        } finally {
            // A cancelled node stays in the wheel until its slot comes
            // around, keeping this connection reachable: retire unlinks it
            // on the next tick.
            if (watchdog != null) timer.retire(watchdog);
            if (timerUsed) timer.retire(call);
            writer.retireTimers();
        }
    }

    /**
     * Stops after the request in flight: an idle connection closes now, a
     * busy one announces Connection: close on its response (the loop checks
     * {@link EnsoServer#isRunning}), a WebSocket starts its closing
     * handshake.
     */
    @Override
    public void beginDrain() {
        WebSocketConnection ws = webSocket;
        if (ws != null) {
            Thread.ofVirtual().name("enso-ws-close").start(ws::shutdown);
        } else if (idle) {
            Thread.ofVirtual().name("enso-h1-close").start(this::closeIdle);
        }
    }

    /**
     * Closes an idle connection for a drain. Over TLS that writes a
     * close_notify, which blocks if the peer stopped reading with the send
     * buffer full: the write watchdog bounds it, so the drain doesn't wait
     * for the shutdown deadline (that deadline's force close still bounds
     * it when :write-timeout is off).
     */
    private void closeIdle() {
        Watchdog wd = watchdog;
        if (wd != null) wd.enter();
        try {
            socket.close();
        } catch (IOException ignored) {
        } finally {
            if (wd != null) wd.exit();
        }
    }

    @Override
    public void forceClose() {
        EnsoServer.forceClose(socket);
    }

    private boolean handleOne() throws IOException {
        reader.compact();
        if (reader.hasBuffered()) {
            // Pipelined bytes already buffered: the request has started.
            reader.startHead();
        } else {
            // About to wait for the next request: whatever was written must
            // be on the wire before the connection counts as idle, or a
            // drain closing an idle connection could cut it off.
            writer.flush();
            reader.startIdle();
            idle = true;
            // A drain that began while this connection was busy didn't see
            // it idle; it would otherwise wait out the idle timeout.
            if (!server.isRunning()) {
                return false;
            }
            try {
                if (!reader.awaitRequest()) {
                    return false;
                }
            } catch (IOException e) {
                if (!server.isRunning() && idle) {
                    return false;
                }
                throw e;
            }
        }
        Request request;
        try {
            request = reader.parseRequest();
        } catch (HttpError e) {
            idle = false;
            headError(e.status);
            writeError(e.status, e.getMessage());
            return false;
        } catch (IOException e) {
            if (!server.isRunning() && idle) {
                return false;
            }
            throw e;
        }
        idle = false;
        if (request == null) {
            return false;
        }
        reader.startBody();
        Call c = call;
        c.reset();
        c.request = request;
        c.begin();
        boolean timed = config.handlerTimeoutMillis > 0;
        if (writer.hasPending()) {
            if (timed) {
                // The 503 is written from another thread: nothing may be
                // held when it can be.
                writer.flush();
            } else {
                writer.holdOutput();
            }
        }
        if (timed) {
            // hbuf is empty here (flushed above), so a 503 written from
            // another thread can't overtake a pipelined response.
            timeoutResponded = false;
            timerUsed = true;
            c.handlerThread = connectionThread;
            timer.schedule(c, config.handlerTimeoutMillis);
        }
        Response response = c.serve(handler);
        writer.reclaimOutput();
        if (timed) {
            timer.cancel(c);
            c.handlerThread = null;
            if (response == null) {
                // The 503 went out in its place.
                awaitTimeoutResponse();
                linger = true;
                c.status = 503;
                c.responseBytes = HttpStatus.reason(503).length();
                c.complete();
                return false;
            }
        }
        if (c.outcome != Exchange.RESPONSE) {
            // A client error (the body failed) or a handler failure with no
            // error handler response: answered, then the connection ends.
            writeError(request, response.status, HttpStatus.reason(response.status));
            return false;
        }

        if (response.webSocketListener != null) {
            handleWebSocketUpgrade(request, response);
            return false;
        }

        // Decided before the head is written, so a connection that won't
        // survive the unread body says Connection: close (RFC 9112 §9.6).
        boolean bodyAllowsReuse = settleBody();
        if (!writer.prepare(response, request.method.equals("HEAD"))) {
            Exchange.closeBody(response.body);
            writeError(request, 500, HttpStatus.reason(500));
            return false;
        }
        writer.bodyBytesWritten = 0;
        int status = writer.head.status();
        boolean keepAlive = writeResponse(request, bodyAllowsReuse);
        complete(status);
        if (!bodyAllowsReuse) {
            linger = true;
            return false;
        }
        boolean reuse;
        try {
            reuse = drainBody() && keepAlive;
        } catch (RequestBodyException e) {
            // The response is already written; an unreadable leftover body
            // only means the connection can't be reused.
            service.protocolError(EnsoServer.HTTP_1_1, Exchange.clientErrorKind(e.status));
            linger = true;
            return false;
        } catch (RequestBodyTimeoutException e) {
            service.protocolError(EnsoServer.HTTP_1_1, Exchange.clientErrorKind(408));
            linger = true;
            return false;
        }
        if (!reuse && clientExpectsReuse(request)) {
            // The server ends a connection the client meant to keep (the
            // keep-alive cap, a drain, the handler's Connection: close): it
            // may already be sending its next request.
            linger = true;
        }
        return reuse;
    }

    /** Whether the client planned to send more requests on this connection. */
    private static boolean clientExpectsReuse(Request request) {
        if (!request.protocol.equals("HTTP/1.1")) return false;
        String connection = request.header("connection");
        return connection == null || !HttpFields.containsToken(connection, "close");
    }

    /**
     * Whether the connection can outlive the request's body, decided
     * before the response head is written. The handler read it all, or
     * what's left is already buffered, or it is a known length small
     * enough to drain after the response. Not when the client still waits
     * for a 100 Continue (it may never send the body) or the rest of a
     * chunked body is still to come.
     */
    private boolean settleBody() throws IOException {
        RequestReader.RequestBody body = reader.body();
        if (body == null || body.isFinished()) {
            return true;
        }
        if (body.continuePending) {
            return false;
        }
        try {
            if (body.drainBuffered()) {
                return true;
            }
        } catch (RequestBodyException e) {
            service.protocolError(EnsoServer.HTTP_1_1, Exchange.clientErrorKind(e.status));
            return false;
        } catch (EOFException e) {
            return false;
        }
        long remaining = body.remaining();
        return remaining >= 0 && remaining <= MAX_DRAIN_BYTES;
    }

    /**
     * Writes the response prepared in the writer's head. Returns whether
     * the connection stays open.
     */
    private boolean writeResponse(Request request, boolean bodyAllowsReuse) throws IOException {
        String requestConnection = request.header("connection");
        // The last response this connection will carry (keep-alive cap
        // reached, server stopping) must say so: RFC 9112 §9.6. The cap on
        // keep-alive reuse per connection bounds resource hold time
        // (RFC-agnostic mitigation; nginx defaults to 1000).
        boolean http11 = request.protocol.equals("HTTP/1.1");
        boolean keepAlive = http11
            && (requestConnection == null || !HttpFields.containsToken(requestConnection, "close"))
            && server.isRunning()
            && (config.maxKeepAliveRequests <= 0 || servedRequests + 1 < config.maxKeepAliveRequests)
            && !writer.head.closeRequested()
            && bodyAllowsReuse;
        return writer.writeResponse(http11, keepAlive, reader.hasBuffered());
    }

    private boolean drainBody() throws IOException {
        RequestReader.RequestBody body = reader.takeBody();
        if (body == null || body.isFinished()) {
            return true;
        }
        return body.drain(MAX_DRAIN_BYTES);
    }

    /** The first read of a body whose request said Expect: 100-continue. */
    void sendContinue() throws IOException {
        handlerWriteLock.lock();
        try {
            if (call.claimed() != Exchange.OPEN) {
                // The handler timed out: its 503 is (being) sent.
                return;
            }
            writer.writeContinue();
        } finally {
            handlerWriteLock.unlock();
        }
    }

    private void writeError(int status, String message) {
        writeError(status, message, null);
    }

    /** An error answering a parsed request: also reported as that request's completion. */
    private void writeError(Request request, int status, String message) {
        writeError(request, status, message, null);
    }

    private void writeError(Request request, int status, String message, byte[] extraHeaders) {
        writeError(status, message, extraHeaders);
        complete(status);
    }

    /** {@code extraHeaders}: preformatted field lines (each ending CRLF), or null. */
    private void writeError(int status, String message, byte[] extraHeaders) {
        linger = true;
        writer.writeError(status, message, extraHeaders);
    }

    /** The response with {@code status} is written: reported once. */
    private void complete(int status) {
        Call c = call;
        c.status = status;
        c.responseBytes = writer.bodyBytesWritten;
        c.complete();
    }

    // ---- :handler-timeout --------------------------------------------------

    /**
     * The timeout claimed the response while the handler ran: waits until
     * the 503 is written (closing the connection must not cut it short),
     * then clears the interrupt that was meant for the handler.
     */
    private void awaitTimeoutResponse() {
        while (!timeoutResponded) {
            LockSupport.parkNanos(this, 10_000_000L);
        }
        // Issued before timeoutResponded was published, so it is set by
        // now: clearing it here means it can't hit the lingering close.
        Thread.interrupted();
    }

    /**
     * Nothing of the response was written (it is only written once the
     * handler returns), so the 503 owns the connection: written in one
     * piece, then the handler is interrupted and the connection ends.
     */
    private void respondHandlerTimeout() {
        try {
            byte[] bytes = ResponseWriter.handlerTimeoutResponse();
            // Straight to the transport: hbuf belongs to the connection
            // thread.
            handlerWriteLock.lock();
            try {
                writer.writeDirect(bytes);
            } finally {
                handlerWriteLock.unlock();
            }
        } catch (IOException ignored) {
        }
        // Interrupt first, publish second: the connection thread clears
        // its interrupt only once it sees the 503 written.
        call.interruptHandler();
        timeoutResponded = true;
    }

    /** The request in flight, as the shared exchange sees it. */
    private final class Call extends Exchange {
        @Override
        protected Service service() {
            return service;
        }

        @Override
        protected String protocol() {
            return EnsoServer.HTTP_1_1;
        }

        @Override
        protected Throwable bodyFailure() {
            RequestReader.RequestBody body = reader.body();
            return body != null ? body.failure : null;
        }

        @Override
        protected long requestBytes() {
            RequestReader.RequestBody body = reader.body();
            return body != null ? body.received : 0;
        }

        @Override
        protected void handlerTimedOut() {
            Thread.ofVirtual().name("enso-h1-handler-timeout").start(HttpConnection.this::respondHandlerTimeout);
        }
    }

    // ---- Events ---------------------------------------------------------------

    /** A request head the server refused before any handler ran. */
    private void headError(int status) {
        String kind = status == 408
            ? (reader.inBody() ? "read-timeout" : "header-timeout")
            : Exchange.clientErrorKind(status);
        service.protocolError(EnsoServer.HTTP_1_1, kind);
    }

    private final class Watchdog extends WriteWatchdog {
        Watchdog() {
            super(timer, config.writeTimeoutMillis);
        }

        @Override
        protected void onStall() {
            Thread.ofVirtual().name("enso-h1-write-timeout").start(() -> {
                service.protocolError(EnsoServer.HTTP_1_1, "write-timeout");
                forceClose();
            });
        }
    }

    // ---- WebSocket upgrade --------------------------------------------------

    /**
     * Validates the WebSocket handshake, writes the 101 Switching Protocols
     * response, then runs the WebSocket read loop on the current virtual
     * thread. On return the underlying socket is closed.
     */
    private void handleWebSocketUpgrade(Request request, Response response) throws IOException {
        String upgrade = request.header("upgrade");
        String connection = request.header("connection");
        String key = request.header("sec-websocket-key");
        String version = request.header("sec-websocket-version");
        // RFC 6455 §4.1 / §4.2.1: a GET over HTTP/1.1 whose key is the
        // base64 of 16 bytes.
        if (!request.method.equals("GET") || !request.protocol.equals("HTTP/1.1")
            || upgrade == null || !upgrade.equalsIgnoreCase("websocket")
            || connection == null || !HttpFields.containsToken(connection, "upgrade")
            || !isWebSocketKey(key)
            || version == null) {
            writeError(request, 400, "Invalid WebSocket handshake");
            return;
        }
        // §4.4: an unsupported version gets 426 naming the one we speak.
        if (!version.equals("13")) {
            writeError(request, 426, "Unsupported WebSocket version", SEC_WEBSOCKET_VERSION_13);
            return;
        }
        // Reject upgrade requests carrying a body — RFC 6455 §4.1
        // doesn't forbid it, but any bytes past the request headers
        // would be misinterpreted as the first WebSocket frame after
        // upgrade → framing error / disconnect.
        if (reader.body() != null) {
            writeError(request, 400, "WebSocket upgrade cannot carry a request body");
            return;
        }
        // §4.1: the client fails the connection if the server selects a
        // subprotocol it didn't offer, so that's a handler error.
        String protocol = response.webSocketProtocol;
        String offered = request.header("sec-websocket-protocol");
        if (protocol != null && (offered == null || !HttpFields.containsToken(offered, protocol))) {
            INVALID_RESPONSES.log("WebSocket subprotocol not offered by the client: " + protocol);
            writeError(request, 500, HttpStatus.reason(500));
            return;
        }
        if (!WebSocketHandshake.originAllowed(request.header("origin"), request.header("host"),
                                              config.wsAllowedOrigins)) {
            writeError(request, 403, "Forbidden");
            return;
        }
        PerMessageDeflate deflate = config.wsCompression
            ? PerMessageDeflate.negotiate(request.header("sec-websocket-extensions"))
            : null;
        if (!writer.writeSwitchingProtocols(response, key, protocol, deflate)) {
            writeError(request, 500, HttpStatus.reason(500));
            return;
        }
        writer.flush();
        complete(101);

        WebSocketConnection ws = new WebSocketConnection(socket, reader.upgradeInput(), writer.output(),
                                                         response.webSocketListener, config, deflate, timer,
                                                         service.budget);
        webSocket = ws;
        // A shutdown that began before the field was set didn't see this
        // WebSocket, so it closes itself.
        if (!server.isRunning()) {
            ws.shutdown();
        }
        InetAddress remote = socket.getInetAddress();
        long openedAt = 0;
        if (service.events != null) {
            openedAt = System.nanoTime();
            service.connectionOpened(WEBSOCKET, remote);
        }
        try {
            ws.run();
        } finally {
            if (openedAt != 0) {
                service.connectionClosed(WEBSOCKET, remote, System.nanoTime() - openedAt);
            }
        }
    }

    private static boolean isWebSocketKey(String key) {
        if (key == null) {
            return false;
        }
        try {
            return Base64.getDecoder().decode(key).length == 16;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}

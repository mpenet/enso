// ABOUTME: One request/response exchange as every protocol driver runs it: the handler call, the response
// ABOUTME: claim raced by the handler timeout and cancels, client-error mapping, logging and reporting.
package com.s_exp.enso.core;

import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.RingErrorHandler;
import com.s_exp.enso.api.RingHandler;
import java.io.Closeable;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The protocol-neutral part of serving a request. Drivers extend it with
 * the object they already have per exchange (HTTP/1.1: one per connection,
 * reused; HTTP/2: the stream; HTTP/3: the request stream), so it costs no
 * extra object; they parse heads and frame bytes, this decides what to
 * send and reports it.
 *
 * <p><b>Claim.</b> Exactly one of the handler ({@link #HANDLER}), the
 * {@code :handler-timeout} ({@link #TIMED_OUT}) or a cancel
 * ({@link #CANCELLED}: stream reset, connection gone) owns the response.
 * {@link #serve} claims for the handler when it returns; the exchange is
 * its own timer node and {@link #onTimeout} claims for the timeout, then
 * calls the driver's {@link #handlerTimedOut} (timer thread: must not
 * block); {@link #cancel} claims for nobody and interrupts the handler.
 *
 * <p><b>Outcome</b> of {@link #serve} ({@link #outcome}):
 * <ul>
 *   <li>{@link #RESPONSE}: the handler's response, or the error handler's
 *       for a handler failure;
 *   <li>{@link #CLIENT_ERROR}: the request body failed
 *       ({@link RequestBodyException} 400 / 413,
 *       {@link RequestBodyTimeoutException} 408), or the handler threw an
 *       {@link HttpError}. Answered with that status
 *       ({@link HttpStatus#error}) whether the handler rethrew, wrapped
 *       or swallowed the exception; the error handler is not called;
 *       reported as a protocol error, logged at FINE;
 *   <li>{@link #SERVER_ERROR}: the handler failed and there is no error
 *       handler response: a plain 500 (logged by
 *       {@link RingErrorHandler#respond}).
 * </ul>
 *
 * <p><b>Reporting</b>: {@link #begin} when the request head is complete
 * (a timestamp and a JFR event only while traced), {@link #complete} once
 * the response is finished.
 */
public abstract class Exchange extends Timer.Task {

    private static final Logger LOG = Logger.getLogger(Exchange.class.getName());
    private static final LogLimiter CLIENT_FAILURES = new LogLimiter(LOG, Level.FINE);

    // Claim states.
    public static final int OPEN = 0;
    public static final int HANDLER = 1;
    public static final int TIMED_OUT = 2;
    public static final int CANCELLED = 3;

    // Outcomes of serve().
    public static final int RESPONSE = 0;
    public static final int CLIENT_ERROR = 1;
    public static final int SERVER_ERROR = 2;

    private static final VarHandle CLAIM;

    static {
        try {
            CLAIM = MethodHandles.lookup().findVarHandle(Exchange.class, "claim", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @SuppressWarnings("unused") // accessed through CLAIM
    private volatile int claim;
    /**
     * The thread running the handler while it does (on HTTP/2 and HTTP/3
     * also while it produces a streamed body), for interrupts. HTTP/1.1
     * sets it only with {@code :handler-timeout}.
     */
    public volatile Thread handlerThread;
    /** The request being served; set before the handler runs. */
    public Request request;
    /** System.nanoTime of the complete request head while traced, else 0. */
    public long startNanos;
    /** The JFR request event while a recording wants one. */
    public Jfr.RequestEvent jfr;
    /** Status of the response sent, 0 until there is one. */
    public int status;
    /** Response body bytes written. */
    public long responseBytes;
    /** What {@link #serve} decided. */
    public byte outcome;

    /** The server's service (handler, events, config). */
    protected abstract Service service();

    /** Protocol name for events ("http/1.1", "h2", "h3"). */
    protected abstract String protocol();

    /** The first failure the request body raised to its reader, or null. */
    protected abstract Throwable bodyFailure();

    /** Request body bytes received so far, for events. */
    protected abstract long requestBytes();

    /**
     * {@code :handler-timeout} claimed the response: send the 503
     * ({@link HttpStatus#error}) and interrupt the handler. Runs on the
     * timer thread: must not block (start a virtual thread, or signal).
     */
    protected abstract void handlerTimedOut();

    // ---- claim ---------------------------------------------------------------------

    /** Ready for the next request (exchanges reused per connection). */
    public final void reset() {
        CLAIM.setVolatile(this, OPEN);
        request = null;
        startNanos = 0;
        jfr = null;
        status = 0;
        responseBytes = 0;
        outcome = RESPONSE;
    }

    /** Who owns the response: {@link #OPEN}, {@link #HANDLER}, {@link #TIMED_OUT}, {@link #CANCELLED}. */
    public final int claimed() {
        return (int) CLAIM.getVolatile(this);
    }

    /** Claims the response for {@code by}; false when someone else has it. */
    public final boolean claim(int by) {
        return CLAIM.compareAndSet(this, OPEN, by);
    }

    /**
     * Nobody will receive a response (stream reset, connection gone): the
     * exchange is claimed for no one, and the handler (or the producer of
     * its streamed body) is interrupted. Any thread; idempotent.
     */
    public final void cancel() {
        claim(CANCELLED);
        interruptHandler();
    }

    /** Interrupts the handler thread, unless that is the calling thread. */
    public final void interruptHandler() {
        Thread t = handlerThread;
        if (t != null && t != Thread.currentThread()) {
            interrupt(t);
        }
    }

    /**
     * Delivers an interrupt to handler thread {@code t}. A driver whose
     * handler threads also write for the whole connection overrides it:
     * an interrupt landing during a blocking socket write closes the
     * socket (interruptible channels, and virtual threads on sockets).
     */
    protected void interrupt(Thread t) {
        t.interrupt();
    }

    /** {@code :handler-timeout} expired (timer thread). */
    @Override
    protected final void onTimeout() {
        if (claim(TIMED_OUT)) {
            service().protocolError(protocol(), "handler-timeout");
            handlerTimedOut();
        }
    }

    // ---- serving --------------------------------------------------------------------

    /**
     * Runs {@code handler} on the calling thread and decides the response (see
     * the class doc); {@link #outcome} tells which kind it is. Returns null
     * when the timeout or a cancel claimed the exchange first: nothing is to
     * be sent, and whatever the handler returned was closed.
     */
    public final Response serve(RingHandler handler) {
        Service s = service();
        Response response = null;
        Throwable thrown = null;
        try {
            response = handler.handle(request);
            if (response == null) {
                throw new NullPointerException("handler returned null response");
            }
        } catch (Throwable t) {
            response = null;
            thrown = t;
        }
        Response decided = decide(s, response, thrown);
        if (decided != response && response != null) {
            closeBody(response.body);
        }
        if (!claim(HANDLER)) {
            closeBody(decided.body);
            return null;
        }
        return decided;
    }

    private Response decide(Service s, Response response, Throwable thrown) {
        // A broken body is the client's error, answered as such whatever
        // the handler made of it (rethrown, wrapped, swallowed).
        Throwable failure = bodyFailure();
        int clientStatus = clientErrorStatus(failure);
        if (clientStatus == 0 && thrown != null) {
            failure = thrown;
            clientStatus = clientErrorStatus(thrown);
        }
        if (clientStatus != 0) {
            outcome = CLIENT_ERROR;
            s.protocolError(protocol(), clientErrorKind(failure, clientStatus));
            CLIENT_FAILURES.log(protocol() + " request failed with " + clientStatus, failure);
            return HttpStatus.error(clientStatus);
        }
        if (thrown != null) {
            Response r = RingErrorHandler.respond(s.errorHandler, request, thrown);
            if (r != null) {
                outcome = RESPONSE;
                return r;
            }
            outcome = SERVER_ERROR;
            return HttpStatus.error(500);
        }
        outcome = RESPONSE;
        return response;
    }

    /** The status of a client error in {@code t}'s cause chain (body failure, {@link HttpError}), else 0. */
    public static int clientErrorStatus(Throwable t) {
        if (t == null) return 0;
        Throwable c = t;
        for (int i = 0; c != null && i < Causes.MAX_DEPTH; i++) {
            if (c instanceof RequestBodyException e) return e.status;
            if (c instanceof RequestBodyTimeoutException) return 408;
            if (c instanceof HttpError e) return e.status;
            Throwable next = c.getCause();
            if (next == c) return 0;
            c = next;
        }
        return 0;
    }

    /**
     * The protocol-error kind for client error {@code status} found in
     * {@code t}: a body below {@code :min-data-rate-bytes} has its own.
     */
    public static String clientErrorKind(Throwable t, int status) {
        Throwable c = t;
        for (int i = 0; c != null && i < Causes.MAX_DEPTH; i++) {
            if (c instanceof RequestBodyTimeoutException e) return e.kind();
            Throwable next = c.getCause();
            if (next == c) break;
            c = next;
        }
        return clientErrorKind(status);
    }

    /** The protocol-error kind reported for a client error status. */
    public static String clientErrorKind(int status) {
        return switch (status) {
            case 408 -> "read-timeout";
            case 413 -> "body-too-large";
            case 414 -> "uri-too-long";
            case 431 -> "header-too-large";
            case 501 -> "not-implemented";
            case 505 -> "unsupported-version";
            default -> "bad-request";
        };
    }

    // ---- reporting --------------------------------------------------------------------

    /** The request head is complete: starts the trace when anyone listens. */
    public final void begin() {
        if (service().tracing()) {
            startNanos = System.nanoTime();
            if (Jfr.requests()) {
                Jfr.RequestEvent e = new Jfr.RequestEvent();
                e.begin();
                jfr = e;
            }
        }
    }

    /** The response with {@link #status} is finished: one event, one JFR commit. Once per request. */
    public final void complete() {
        if (startNanos == 0) return;
        Service s = service();
        String method = request != null ? request.method : null;
        if (s.events != null) {
            s.events.requestCompleted(protocol(), method, status, requestBytes(), responseBytes,
                                      System.nanoTime() - startNanos);
        }
        Jfr.RequestEvent e = jfr;
        if (e != null) {
            jfr = null;
            e.protocol = protocol();
            e.method = method;
            e.status = status;
            e.requestBytes = requestBytes();
            e.bytes = responseBytes;
            e.commit();
        }
        startNanos = 0;
    }

    /** Releases a response body that will never be written. */
    public static void closeBody(Object body) {
        if (body instanceof Closeable c) {
            try {
                c.close();
            } catch (IOException ignored) {
            }
        }
    }
}

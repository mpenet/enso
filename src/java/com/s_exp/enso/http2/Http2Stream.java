// ABOUTME: One HTTP/2 stream: its state machine (send and receive halves, closed reason), the
// ABOUTME: request it carries, and the response output the connection's writer schedules.
package com.s_exp.enso.http2;

import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.core.Service;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Per-stream state for the HTTP/2 driver.
 *
 * <p>State machine (RFC 9113 §5.1, from the server's side; a stream only
 * exists once its request HEADERS arrived): {@link #OPEN} →
 * {@link #HALF_CLOSED_REMOTE} (peer sent END_STREAM) or
 * {@link #HALF_CLOSED_LOCAL} (we sent END_STREAM) → closed, or straight
 * to closed by a reset from either side. Transitions are CAS on one int,
 * so the framer, the writer and the handler can each move it without a
 * lock. A closed state carries why it closed ({@link #CLOSED} plus the
 * reason), so the CAS that closes the stream publishes the reason with
 * it; that thread then tells the connection.
 *
 * <p>The stream is also its handler's {@link Runnable} and, as an
 * {@link Exchange}, its {@code :handler-timeout} timer node and response
 * claim, so serving a request costs no extra objects for either.
 *
 * <p>Response output fields (from {@link #sendWindow} down) are guarded by
 * the connection writer's lock; see {@link Http2Writer}.
 */
final class Http2Stream extends Exchange implements Runnable {

    static final int OPEN = 0;
    static final int HALF_CLOSED_REMOTE = 1;
    static final int HALF_CLOSED_LOCAL = 2;
    // Closed states are CLOSED + reason, never CLOSED itself.
    static final int CLOSED = 3;

    /** Both sides sent END_STREAM. Later frames from the peer are a connection error. */
    static final int ENDED = 1;
    /** The peer reset the stream. Later frames are a stream error STREAM_CLOSED. */
    static final int PEER_RESET = 2;
    /** We reset the stream. Later frames were possibly in flight: ignored. */
    static final int WE_RESET = 3;

    private static final VarHandle STATE;
    private static final VarHandle SLOT;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            STATE = l.findVarHandle(Http2Stream.class, "state", int.class);
            SLOT = l.findVarHandle(Http2Stream.class, "slot", int.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    final Http2Connection conn;
    final int id;
    @SuppressWarnings("unused") // accessed through STATE
    private volatile int state;

    // Request body, or null when the request had none (END_STREAM on HEADERS).
    RequestBody body;
    // Declared request Content-Length, or -1 (framer only).
    long declaredContentLength = -1;
    // Request body bytes received: written by the framer, read for events.
    volatile long receivedBodyBytes;
    // Consecutive empty non-final DATA frames (framer only).
    int emptyDataFrames;
    // The request is answered without running the handler: 413 for a
    // declared body over max-request-body-bytes, 431 for a header section
    // over the limits, 417 for an unknown expectation. Set by the framer
    // before the handler starts.
    int earlyStatus;
    // Expect: 100-continue on a request with a body: the 100 goes out on
    // the body's first read.
    volatile boolean continuePending;
    // 1 once the stream gave back its admission slot (its response is
    // complete or its handler is gone), which happens once.
    @SuppressWarnings("unused") // accessed through SLOT
    private volatile int slot;
    // Next stream on the connection's retired stack (lock-free push).
    Http2Stream nextRetired;

    // ---- Response output: guarded by the writer's lock ----

    // Send window (RFC 9113 §6.9): bytes we may still send on this stream.
    long sendWindow;
    // Response head waiting to be HPACK-encoded by the writer.
    ResponseHead head;
    // The exchange was handed over whole (fixed body): the writer releases
    // the head and finishes the exchange; the handler thread has gone.
    boolean detached;
    // A detached exchange was finished (sent or aborted); exactly once.
    boolean finished;
    // Next stream on the writer's lock-free inbox of handed-over exchanges.
    Http2Stream nextInbox;
    boolean headersSent;
    // A 100 (Continue) interim head is to go out before anything else.
    boolean continueQueued;
    // Fixed body handed over as-is (the producer waits until it's consumed):
    // bytes, or ASCII text written one byte per char, [srcPos, srcEnd).
    byte[] srcBytes;
    String srcText;
    int srcPos;
    int srcEnd;
    // Streamed body bytes, copied in by the producer: ring[ringHead..+ringCount).
    byte[] ring;
    int ringHead;
    int ringCount;
    // The producer is reading into the ring's free region outside the lock:
    // the array must not be replaced meanwhile.
    boolean filling;
    // The producer has queued everything; END_STREAM goes with the last byte.
    boolean endQueued;
    boolean endSent;
    // The writer can no longer send on this stream (reset, connection gone).
    boolean outputClosed;
    // Producer parked waiting on this stream (room, consumption, flush).
    Thread waiter;
    // Scheduler membership: ready to send, blocked on flow control, or neither.
    int sched;
    Http2Stream schedPrev;
    Http2Stream schedNext;
    // Flow-control stall tracking (System.nanoTime, 0 = none): since when
    // the stream has had pending bytes without sending a full frame's worth,
    // and how much it sent since; since when it waits for credit (reset when
    // it sends). Credit below a useful size is pooled until dribbleDue.
    long stalledSince;
    long sentSinceStall;
    long blockedAt;
    boolean dribbleDue;
    // Batch that last carried this stream's frames; flush waits for it.
    long packedSeq;
    // In the writer's list of streams packed into the current batch.
    boolean inBatch;

    Http2Stream(Http2Connection conn, int id, long initialSendWindow) {
        this.conn = conn;
        this.id = id;
        this.sendWindow = initialSendWindow;
    }

    int state() {
        return (int) STATE.getVolatile(this);
    }

    boolean isClosed() {
        return state() > CLOSED;
    }

    /** Why the stream closed ({@link #ENDED}, {@link #PEER_RESET}, {@link #WE_RESET}), 0 while open. */
    int closedReason() {
        int s = state();
        return s > CLOSED ? s - CLOSED : 0;
    }

    /** The peer sent END_STREAM (or the stream is closed). */
    boolean remoteEnded() {
        int s = state();
        return s == HALF_CLOSED_REMOTE || s > CLOSED;
    }

    /** Peer END_STREAM: open → half-closed (remote), half-closed (local) → closed. */
    void receiveEnd() {
        while (true) {
            int s = state();
            if (s == OPEN) {
                if (STATE.compareAndSet(this, OPEN, HALF_CLOSED_REMOTE)) return;
            } else if (s == HALF_CLOSED_LOCAL) {
                if (close(HALF_CLOSED_LOCAL, ENDED)) return;
            } else {
                return;
            }
        }
    }

    /** Our END_STREAM is out: open → half-closed (local), half-closed (remote) → closed. */
    void sendEnd() {
        while (true) {
            int s = state();
            if (s == OPEN) {
                if (STATE.compareAndSet(this, OPEN, HALF_CLOSED_LOCAL)) return;
            } else if (s == HALF_CLOSED_REMOTE) {
                if (close(HALF_CLOSED_REMOTE, ENDED)) return;
            } else {
                return;
            }
        }
    }

    /** Closes the stream for {@code reason} unless already closed; true when this call closed it. */
    boolean reset(int reason) {
        while (true) {
            int s = state();
            if (s > CLOSED) return false;
            if (close(s, reason)) return true;
        }
    }

    private boolean close(int from, int reason) {
        if (!STATE.compareAndSet(this, from, CLOSED + reason)) return false;
        conn.onStreamClosed(this, reason);
        return true;
    }

    /** True for the first caller only: the stream's admission slot is given back once. */
    boolean releaseSlot() {
        return SLOT.compareAndSet(this, 0, 1);
    }

    /** Pending response body bytes the writer hasn't taken yet. */
    int pendingBytes() {
        return ringCount + (srcEnd - srcPos);
    }

    /** {@code :handler-timeout} claimed the response; runs on the timer thread. */
    @Override
    protected void handlerTimedOut() {
        conn.onHandlerTimeout(this);
    }

    /** Past any socket write the handler thread is doing for the connection (see Http2Writer#interrupt). */
    @Override
    protected void interrupt(Thread t) {
        conn.writer().interrupt(t);
    }

    @Override
    protected Service service() {
        return conn.service();
    }

    @Override
    protected String protocol() {
        return conn.protocol;
    }

    @Override
    protected Throwable bodyFailure() {
        RequestBody b = body;
        return b != null ? b.failure() : null;
    }

    @Override
    protected long requestBytes() {
        return receivedBodyBytes;
    }

    /** The handler thread's body. */
    @Override
    public void run() {
        conn.serve(this);
    }
}

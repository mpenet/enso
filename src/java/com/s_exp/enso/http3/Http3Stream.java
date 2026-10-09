// ABOUTME: A QUIC stream the server sends on: its outbound bytes that flow control hasn't accepted
// ABOUTME: yet, kept in order, plus write-progress time for the write timeout.
package com.s_exp.enso.http3;

import com.s_exp.enso.core.Exchange;
import com.s_exp.enso.core.Service;

/**
 * Send-side state of one stream, owned by the connection's event loop.
 * Bytes quiche didn't take (flow or congestion control) wait in
 * {@link #pendingHead} in order; nothing may be handed to quiche for the
 * stream while any wait, so frames never reorder. Request streams extend
 * this as {@link Http3Exchange}; the shared {@link Exchange} base is theirs
 * (handler, response claim, timeout node), it only sits here because Java
 * has one superclass. The server's control and QPACK streams are
 * {@link Control}s, which never serve a request.
 */
abstract class Http3Stream extends Exchange {

    /** A deferred write. {@code buf} is owned (copied) or a response body array. */
    static final class Pending {
        final byte[] buf;
        int off;
        int len;
        final boolean fin;
        Pending next;

        Pending(byte[] buf, int off, int len, boolean fin) {
            this.buf = buf;
            this.off = off;
            this.len = len;
            this.fin = fin;
        }
    }

    final long id;
    Pending pendingHead;
    Pending pendingTail;
    /** Deferred bytes, for diagnostics and the write timeout. */
    long pendingBytes;
    /**
     * System.nanoTime of the last write progress while bytes were waiting:
     * when the stream blocked, or since then each time quiche's taking
     * bytes moved a byte count across a {@link #MIN_PROGRESS} boundary.
     */
    long writeProgressNanos;
    /** The send side ended: FIN accepted, reset, or the peer stopped it. */
    boolean sendClosed;
    /** Waiting for send capacity (deferred bytes or a body slice); counted by the connection. */
    boolean blocked;

    /**
     * Bytes that count as write progress, as on HTTP/2: a peer granting
     * credit a few bytes at a time makes none, so {@code :write-timeout}
     * holds a waiting stream to at least this much per period.
     */
    static final int MIN_PROGRESS = 16 * 1024;

    Http3Stream(long id) {
        this.id = id;
    }

    /**
     * quiche took bytes of this stream at {@code now}, moving a byte count
     * the stream keeps anyway (response bytes sent, deferred bytes left)
     * from {@code before} to {@code after}: progress whenever that crosses
     * a {@link #MIN_PROGRESS} boundary, so after the first, every progress
     * mark takes that many bytes (no field of its own per request).
     */
    final void sent(long before, long after, long now) {
        if (before / MIN_PROGRESS != after / MIN_PROGRESS) {
            writeProgressNanos = now;
        }
    }

    final boolean hasPending() {
        return pendingHead != null;
    }

    final void enqueue(Pending p) {
        if (pendingTail == null) {
            pendingHead = p;
        } else {
            pendingTail.next = p;
        }
        pendingTail = p;
        pendingBytes += p.len;
    }

    final void clearPending() {
        pendingHead = null;
        pendingTail = null;
        pendingBytes = 0;
    }

    /** A control or QPACK stream of the server: send state only, no exchange. */
    static final class Control extends Http3Stream {
        Control(long id) {
            super(id);
        }

        @Override
        protected Service service() {
            throw new UnsupportedOperationException("control stream");
        }

        @Override
        protected String protocol() {
            return Http3Listener.PROTOCOL;
        }

        @Override
        protected Throwable bodyFailure() {
            return null;
        }

        @Override
        protected long requestBytes() {
            return 0;
        }

        @Override
        protected void handlerTimedOut() {
        }
    }
}

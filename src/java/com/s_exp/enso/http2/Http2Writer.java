// ABOUTME: Outbound side of one HTTP/2 connection: control-frame lane, per-stream response output,
// ABOUTME: send flow control and round-robin scheduling, written out by whichever thread combines.
package com.s_exp.enso.http2;

import com.s_exp.enso.api.Config;
import com.s_exp.enso.core.HttpDates;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.ResponseHead;
import com.s_exp.enso.core.Service;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.TlsSocket;
import com.s_exp.enso.core.WriteWatchdog;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Pull scheduling with a combining writer.
 *
 * <pre>
 *  handler threads (producers)                          framer
 *   │ handOver: head + fixed body ──► inbox             │ SETTINGS ACK, PING ACK,
 *   │   (lock-free push; the handler is done)           │ WINDOW_UPDATE, RST, GOAWAY
 *   │ begin / write / readInto / flush / finish         ▼
 *   │   (streamed bodies; block on their own stream) control lane (serialised frames,
 *   ▼                                                 count-capped: flood → ENHANCE_YOUR_CALM)
 *  Http2Stream output                                   │
 *   head (HPACK-encoded at pack time)                   │
 *   borrowed byte[] / ASCII String, or ring (≤ 64 KiB)  │
 *   │                                                   │
 *   └──► ready ring (round robin) ◄── credit ── blocked lists (own window / connection
 *              │                                 window; dribble pool, stall deadline →
 *              │                                 RST CANCEL / GOAWAY)
 *              ▼
 *        fill(): inbox → ready, control lane first, then one frame per ready
 *        stream per turn, packed into a 64 KiB batch (four TLS records), under the lock
 *              │
 *              ▼
 *        exchanges whose END_STREAM is in the batch are finished (stream state,
 *        events, accounting), then out.write(batch) by the combining thread,
 *        both outside the lock (WriteWatchdog)
 * </pre>
 *
 * <p>Whoever has something to send and finds no writer active becomes the
 * writer ({@link #drain}): usually the handler thread that just queued its
 * response, so a lone response goes out with no thread hand-over. Others
 * queue and return: a response with a fixed body is handed over whole
 * through a lock-free inbox and its handler thread ends without taking
 * the lock or parking; a streamed body blocks only on its own stream's
 * room. Once the connection is open the framer never writes:
 * when it queues a control frame or grants credit with no writer active it
 * hands the writer role to a parked producer or starts a short-lived
 * flusher thread. A producer whose own output is done hands the role on
 * after a few more batches, so it can't be held hostage by a busy
 * neighbour.
 *
 * <p>Memory is bounded in bytes: a stream holds at most {@link #RING_MAX}
 * copied bytes, and no more than its send window lets go (at least one
 * frame, see {@link #ringLimit}), so a peer that grants little credit or
 * reads slowly pins little. Copied bytes are charged to the
 * connection's share of the memory budget until sent or dropped; while
 * the connection is throttled (the budget exhausted, or under pressure
 * with this connection over its fair share) a stream
 * buffers one frame. A body array that already existed is sent in place.
 * The batch is {@link #BATCH_SIZE}, and the control lane is count-capped. A reset
 * purges the stream's output at once. HPACK encoding happens while
 * packing, so header blocks reach the wire in encoding order and no block
 * is encoded for a stream once a reset purged its output.
 *
 * <p>Lock discipline: {@link #lock} guards everything here, including the
 * output fields of {@link Http2Stream} and the HPACK encoder. It is never
 * held across a socket write, a park, or a user callback.
 */
final class Http2Writer {

    /** Most bytes packed per socket write: four full TLS records. */
    static final int BATCH_SIZE = 64 * 1024;
    // Encrypted batch: four records of at most 16 KiB + 256 bytes each
    // (RFC 8446 §5.2, TLS 1.2 similar), what TlsSocket.writeRecords needs to
    // send a whole batch in one channel write.
    private static final int NET_BUFFER_SIZE = 4 * (16 * 1024 + 256) + 1024;
    /**
     * Outbound DATA payload cap. Every peer accepts 16 KiB frames; a peer
     * advertising a larger SETTINGS_MAX_FRAME_SIZE (up to 16 MiB) must not
     * dictate our buffer sizes and copy granularity.
     */
    static final int DATA_FRAME_MAX = Http2.DEFAULT_MAX_FRAME_SIZE;
    /** Most bytes a streamed response may have copied in and not yet sent. */
    static final int RING_MAX = 64 * 1024;
    private static final int RING_INITIAL = 4096;
    /**
     * Credit below this (and below what the stream has pending) is pooled
     * for {@link #DRIBBLE_NANOS} rather than sent as tiny frames
     * (CVE-2019-9511, data dribble).
     */
    static final int MIN_DATA_CHUNK = 1024;
    static final long DRIBBLE_NANOS = 20_000_000L;
    /**
     * A stream (or the connection) with bytes pending must send at least
     * this much per write timeout, the same rate a stalled socket write is
     * held to.
     */
    static final int MIN_PROGRESS = DATA_FRAME_MAX;
    // Batches a producer keeps writing for others once its own output is
    // out, before handing the writer role on.
    private static final int HANDOFF_BATCHES = 4;
    // Longest GOAWAY debug data sent, so a control frame always fits a batch.
    private static final int GOAWAY_DEBUG_MAX = 256;
    // Teardown waits this long for another writer when there is no write
    // timeout to cut a stalled one.
    private static final long SHUTDOWN_WAIT_NANOS = 10_000_000_000L;
    private static final long IDLE_WAIT_NANOS = 10_000_000L;

    private static final int CONTROL_INITIAL = 128;
    private static final int LIST_INITIAL = 4;

    private static final int SCHED_NONE = 0;
    private static final int SCHED_READY = 1;
    // Waiting for credit on its own window (a stream WINDOW_UPDATE or
    // SETTINGS can help), or with its own window open, on the connection's.
    private static final int SCHED_BLOCKED = 2;
    private static final int SCHED_CONN_BLOCKED = 3;

    private static final int UNTIL_ROOM = 0;
    private static final int UNTIL_ENDED = 1;
    private static final int UNTIL_WRITTEN = 2;

    private final Http2Connection conn;
    private final OutputStream out;
    // Plain connections on a channel: batches are written from their
    // pooled wrapper straight to it (the stream would wrap each write).
    private final SocketChannel channel;
    // Set for TLS connections: batches go out through writeRecords.
    private final TlsSocket tls;
    private final Watchdog watchdog;
    private final long writeTimeoutNanos;
    private final Service service;
    // The connection's share of the memory budget, charged with ring bytes.
    private final MemoryBudget.Account budget;
    private final int controlCap;
    private final ReentrantLock lock = new ReentrantLock();
    // Held around every socket write, so interrupts for handler threads
    // never land inside one (see interrupt); uncontended for writes, which
    // are already one at a time.
    private final ReentrantLock ioLock = new ReentrantLock();
    // Interrupts that found a write in progress; delivered by the writer.
    private final java.util.concurrent.ConcurrentLinkedQueue<Thread> deferredInterrupts =
        new java.util.concurrent.ConcurrentLinkedQueue<>();
    private final Hpack.Encoder encoder = new Hpack.Encoder(Hpack.DEFAULT_MAX_TABLE_SIZE);
    private final Runnable flusher = () -> drain(null);

    private static final VarHandle WRITING;
    private static final VarHandle INBOX;

    static {
        try {
            MethodHandles.Lookup l = MethodHandles.lookup();
            WRITING = l.findVarHandle(Http2Writer.class, "writing", int.class);
            INBOX = l.findVarHandle(Http2Writer.class, "inbox", Http2Stream.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // 1 while a thread is writing (owns the batch and the socket); taken
    // by CAS, so a producer can claim it without the lock.
    @SuppressWarnings("unused") // accessed through WRITING
    private volatile int writing;
    // Lock-free stack of exchanges handed over whole, for the writer to schedule.
    @SuppressWarnings("unused") // accessed through INBOX
    private volatile Http2Stream inbox;

    // ---- Guarded by lock ----

    private byte[] control = new byte[CONTROL_INITIAL];
    private int controlLen;
    private int controlFrames;
    // Only control frames go out from now on (connection error, closing).
    private boolean controlOnly;

    private Http2Stream readyHead;
    private Http2Stream readyTail;
    private Http2Stream blockedHead;
    private Http2Stream blockedTail;
    private Http2Stream connBlockedHead;
    private Http2Stream connBlockedTail;

    // Ring bytes sent since the last batch was filled: released from the
    // memory budget once the lock is let go, so it stays short.
    private long ringFreed;

    private long connSendWindow = Http2.DEFAULT_INITIAL_WINDOW_SIZE;
    private int peerMaxFrameSize = Http2.DEFAULT_MAX_FRAME_SIZE;
    // Connection-level stall: since when streams wait on the connection
    // window, and how much was sent since.
    private long connStalledSince;
    private long connSentSinceStall;

    // The writer role handed to this parked producer.
    private Thread handoff;
    // The socket failed or the connection shut output down: nothing more is written.
    private boolean failed;
    private Thread idleWaiter;
    private long batchSeq;
    private long writtenSeq;
    private Http2Stream[] batchStreams = new Http2Stream[LIST_INITIAL];
    private int batchStreamCount;
    // The batch, grown past BATCH_SIZE for a header block that can't fit
    // one (see packStream); written in place of the scratch buffer.
    private byte[] oversized;
    // Set by packStream when the stream at the front of the ready ring
    // needs the next batch: the current one closes.
    private boolean batchFull;
    // The stream whose header block didn't fit the rest of the last batch
    // and opens the next one. If it still doesn't fit behind that batch's
    // control frames, the batch grows for it (oversized): a steady flow of
    // control frames can't starve it, and control frames still lead.
    private Http2Stream deferredHeaders;
    // Streams whose END_STREAM is in the current batch, and handed-over
    // exchanges that were aborted: finished by the writer before the batch
    // is written.
    private Http2Stream[] finished = new Http2Stream[LIST_INITIAL];
    private int finishedCount;
    // The other list, swapped in while one is being finished outside the lock.
    private Http2Stream[] spareFinished = new Http2Stream[LIST_INITIAL];

    Http2Writer(Http2Connection conn, java.net.Socket socket, Config config, Timer timer,
                int maxConcurrentStreams) throws IOException {
        this.conn = conn;
        this.out = socket.getOutputStream();
        this.channel = socket instanceof TlsSocket.AdapterSocket ? null : socket.getChannel();
        this.tls = socket instanceof TlsSocket.AdapterSocket a ? a.tls() : null;
        this.writeTimeoutNanos = config.writeTimeoutMillis * 1_000_000L;
        this.watchdog = config.writeTimeoutMillis > 0 ? new Watchdog(timer, config.writeTimeoutMillis) : null;
        this.service = conn.service();
        this.budget = conn.account();
        // Legitimate control traffic is a few frames per stream; a peer
        // making us queue more (PING / SETTINGS floods, induced resets)
        // without reading is cut off (nghttp2's outbound flood rule).
        this.controlCap = 1000 + 4 * maxConcurrentStreams;
    }

    private boolean tryWrite() {
        return (int) WRITING.getVolatile(this) == 0 && WRITING.compareAndSet(this, 0, 1);
    }

    private boolean isWriting() {
        return (int) WRITING.getVolatile(this) == 1;
    }

    private void releaseWriting() {
        WRITING.setVolatile(this, 0);
    }

    /**
     * Connection idle (framer): gives back what bursts grew (control lane,
     * encoder buffer, batch lists) when not in use. Takes the lock briefly
     * like any control frame; never waits for a write.
     */
    void releaseIdle() {
        lock.lock();
        try {
            if (controlLen == 0 && control.length > CONTROL_INITIAL) {
                control = new byte[CONTROL_INITIAL];
            }
            encoder.releaseBuffer();
            if (batchStreamCount == 0 && batchStreams.length > LIST_INITIAL) {
                batchStreams = new Http2Stream[LIST_INITIAL];
            }
            if (finishedCount == 0 && finished.length > LIST_INITIAL) {
                finished = new Http2Stream[LIST_INITIAL];
            }
            if (spareFinished != null && spareFinished.length > LIST_INITIAL) {
                spareFinished = new Http2Stream[LIST_INITIAL];
            }
        } finally {
            lock.unlock();
        }
    }

    // ---- Settings from the peer (framer) -------------------------------------------

    /**
     * Applies the peer's SETTINGS values that shape our output and queues
     * the SETTINGS ACK, in one lock section: control frames lead every
     * batch and header blocks are encoded while packing, so the dynamic
     * table size update follows the acknowledgment, in the first header
     * block after it (RFC 7541 §4.2). -1: the value wasn't in the frame.
     * {@code minTableSize}: the smallest HEADER_TABLE_SIZE the frame
     * carried, signalled before the last when smaller.
     */
    void applySettingsAndAck(int minTableSize, int tableSize, int maxFrameSize) throws IOException {
        boolean flusher;
        lock.lock();
        try {
            if (tableSize >= 0) {
                if (minTableSize < tableSize) {
                    encoder.setMaxTableSize(minTableSize);
                }
                encoder.setMaxTableSize(tableSize);
            }
            if (maxFrameSize >= 0) {
                peerMaxFrameSize = maxFrameSize;
            }
            appendControl(Http2.TYPE_SETTINGS, Http2.FLAG_ACK, 0, null, 0, 0, 0, true);
            flusher = kickFromFramer(null);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
    }

    /**
     * SETTINGS_INITIAL_WINDOW_SIZE changed by {@code delta}: adjust every
     * live stream (§6.9.2). {@code maxDelta}: the largest change a value of
     * the same frame made on the way, which must not overflow a window either.
     */
    void adjustInitialWindow(long delta, long maxDelta, Http2StreamTable streams) throws Http2.ConnectionError {
        boolean flusher;
        lock.lock();
        try {
            for (int i = 0, n = streams.capacity(); i < n; i++) {
                Http2Stream s = streams.slot(i);
                if (s == null) continue;
                long peak = s.sendWindow + maxDelta;
                s.sendWindow += delta;
                if (s.sendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE || peak > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                    throw new Http2.ConnectionError(
                        Http2.ERROR_FLOW_CONTROL_ERROR, "stream window overflow via SETTINGS delta");
                }
                if (delta > 0 && s.sched == SCHED_BLOCKED) {
                    schedule(s);
                }
            }
            flusher = kickFromFramer(null);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
    }

    /**
     * WINDOW_UPDATE on stream 0. Only streams waiting on the connection
     * window are rescheduled, and only once it opens (from zero or less)
     * or reaches a useful size ({@link #MIN_DATA_CHUNK}): a stream whose
     * own window is shut can't use it, and credit in between is pooled
     * anyway (dribble), so a peer's tiny updates cost constant work, not a
     * pass over every waiting stream.
     */
    void connectionWindowUpdate(int increment) throws Http2.ConnectionError {
        boolean flusher;
        lock.lock();
        try {
            long before = connSendWindow;
            connSendWindow += increment;
            if (connSendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                throw new Http2.ConnectionError(
                    Http2.ERROR_FLOW_CONTROL_ERROR, "connection window overflow");
            }
            Http2Stream preferred = null;
            if (before <= 0 || connSendWindow >= MIN_DATA_CHUNK) {
                Http2Stream s = connBlockedHead;
                while (s != null) {
                    Http2Stream next = s.schedNext;
                    schedule(s);
                    if (preferred == null && s.waiter != null) preferred = s;
                    s = next;
                }
            }
            flusher = kickFromFramer(preferred);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
    }

    /** WINDOW_UPDATE on a live stream; false when it overflows the window (a stream error). */
    boolean streamWindowUpdate(Http2Stream s, int increment) {
        boolean flusher = false;
        lock.lock();
        try {
            s.sendWindow += increment;
            if (s.sendWindow > Http2.MAX_ALLOWED_WINDOW_SIZE) {
                return false;
            }
            if (s.sched == SCHED_BLOCKED) {
                schedule(s);
                flusher = kickFromFramer(s);
            }
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
        return true;
    }

    // ---- Control lane --------------------------------------------------------------

    /**
     * Our SETTINGS and the connection window growth, written by the
     * calling framer before it reads anything: the only time the framer
     * writes, with nothing else to send and an empty socket buffer.
     */
    void initialSettings(byte[] payload, int len, int connWindowIncrement) throws IOException {
        lock.lock();
        try {
            int p = reserveControl(len);
            int base = p;
            p = frameHeader(control, p, len, Http2.TYPE_SETTINGS, 0, 0);
            System.arraycopy(payload, 0, control, p, len);
            controlLen = base + Http2.FRAME_HEADER_SIZE + len;
            controlFrames++;
            WRITING.setVolatile(this, 1);
        } finally {
            lock.unlock();
        }
        if (connWindowIncrement > 0) {
            windowUpdate(0, connWindowIncrement);
        }
        drain(null);
    }

    void ping(byte[] payload, int off, boolean ack) throws IOException {
        control(Http2.TYPE_PING, ack ? Http2.FLAG_ACK : 0, 0, payload, off, 8, 0, ack, false);
    }

    /** WINDOW_UPDATE from us; never fails (credit is bounded by the windows). */
    void windowUpdate(int streamId, int increment) {
        boolean flusher;
        lock.lock();
        try {
            // RFC 9113 §6.9: reserved (high) bit of the increment must be 0.
            appendControl(Http2.TYPE_WINDOW_UPDATE, 0, streamId, null, 0, 4, increment & 0x7FFFFFFF, false);
            flusher = kickFromFramer(null);
        } catch (Http2.ConnectionError impossible) {
            // Only induced frames are capped.
            throw new IllegalStateException(impossible);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
    }

    /**
     * RST_STREAM. {@code induced}: caused by the peer's frames, so it counts
     * toward the flood cap. {@code mayWrite}: the calling thread may become
     * the writer (it is a producer that owns its response).
     */
    void rstStream(int streamId, int code, boolean induced, boolean mayWrite) throws IOException {
        control(Http2.TYPE_RST_STREAM, 0, streamId, null, 0, 4, code, induced, mayWrite);
    }

    void goaway(int lastStreamId, int errorCode, String debugData) {
        byte[] debug = debugData == null ? null : debugData.getBytes(StandardCharsets.UTF_8);
        int debugLen = debug == null ? 0 : Math.min(debug.length, GOAWAY_DEBUG_MAX);
        boolean flusher;
        lock.lock();
        try {
            int p = reserveControl(8 + debugLen);
            int base = p;
            p = frameHeader(control, p, 8 + debugLen, Http2.TYPE_GOAWAY, 0, 0);
            // RFC 9113 §6.8: high bit of stream identifiers is a reserved bit;
            // the sender MUST set it to 0 on transmission.
            control[p] = (byte) ((lastStreamId >>> 24) & 0x7F);
            control[p + 1] = (byte) (lastStreamId >>> 16);
            control[p + 2] = (byte) (lastStreamId >>> 8);
            control[p + 3] = (byte) lastStreamId;
            control[p + 4] = (byte) (errorCode >>> 24);
            control[p + 5] = (byte) (errorCode >>> 16);
            control[p + 6] = (byte) (errorCode >>> 8);
            control[p + 7] = (byte) errorCode;
            if (debugLen > 0) {
                System.arraycopy(debug, 0, control, p + 8, debugLen);
            }
            controlLen = base + Http2.FRAME_HEADER_SIZE + 8 + debugLen;
            controlFrames++;
            flusher = kickFromFramer(null);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
    }

    /** No stream data is sent from now on: only what the control lane holds (e.g. a final GOAWAY). */
    void controlOnly() {
        lock.lock();
        try {
            controlOnly = true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Queues a control frame whose payload is {@code payload[off, off+len)},
     * or, when {@code payload} is null and {@code len} is 4, the 32-bit
     * {@code word} (no array per frame).
     */
    private void control(int type, int flags, int streamId, byte[] payload, int off, int len, int word,
                         boolean induced, boolean mayWrite) throws IOException {
        boolean write = false;
        boolean flusher = false;
        lock.lock();
        try {
            appendControl(type, flags, streamId, payload, off, len, word, induced);
            if (mayWrite && !failed && tryWrite()) {
                write = true;
            } else {
                flusher = kickFromFramer(null);
            }
        } finally {
            lock.unlock();
        }
        if (write) {
            drain(null);
        } else if (flusher) {
            startFlusher();
        }
    }

    /**
     * Lock held: appends one control frame to the lane (payload as for
     * {@link #control}). {@code induced}: caused by the peer's frames, so a
     * lane already holding {@link #controlCap} frames is a connection error.
     */
    private void appendControl(int type, int flags, int streamId, byte[] payload, int off, int len, int word,
                               boolean induced) throws Http2.ConnectionError {
        if (induced && controlFrames >= controlCap) {
            throw new Http2.ConnectionError(
                Http2.ERROR_ENHANCE_YOUR_CALM, "peer is not reading its control frames");
        }
        int p = reserveControl(len);
        int base = p;
        p = frameHeader(control, p, len, type, flags, streamId);
        if (payload != null) {
            System.arraycopy(payload, off, control, p, len);
        } else if (len == 4) {
            control[p] = (byte) (word >>> 24);
            control[p + 1] = (byte) (word >>> 16);
            control[p + 2] = (byte) (word >>> 8);
            control[p + 3] = (byte) word;
        }
        controlLen = base + Http2.FRAME_HEADER_SIZE + len;
        controlFrames++;
    }

    /** Room for one control frame with a {@code payloadLen} payload; returns where it starts. */
    private int reserveControl(int payloadLen) {
        int need = controlLen + Http2.FRAME_HEADER_SIZE + payloadLen;
        if (need > control.length) {
            control = java.util.Arrays.copyOf(control, Math.max(need, control.length * 2));
        }
        return controlLen;
    }

    private static int frameHeader(byte[] b, int p, int len, int type, int flags, int streamId) {
        b[p] = (byte) (len >>> 16);
        b[p + 1] = (byte) (len >>> 8);
        b[p + 2] = (byte) len;
        b[p + 3] = (byte) type;
        b[p + 4] = (byte) flags;
        b[p + 5] = (byte) ((streamId >>> 24) & 0x7F);
        b[p + 6] = (byte) (streamId >>> 16);
        b[p + 7] = (byte) (streamId >>> 8);
        b[p + 8] = (byte) streamId;
        return p + Http2.FRAME_HEADER_SIZE;
    }

    // ---- Response output (handler threads) -----------------------------------------

    /**
     * Hands a whole response over: {@code head} and its fixed body,
     * {@code bytes} or {@code text} (ASCII, one byte per char), or none.
     * The writer owns the exchange from here: it releases the head once
     * encoded and finishes the exchange ({@link Http2Connection#exchangeFinished})
     * once END_STREAM is out or the stream is reset. No lock, no wait: the
     * calling handler thread writes only if no one else is writing. The
     * fields written here are published by the inbox and only touched by
     * the writer once it took the exchange ({@link #takeInbox}); a reset
     * meanwhile leaves them alone ({@link #purge}).
     */
    void handOver(Http2Stream s, ResponseHead head, byte[] bytes, String text, int len) {
        s.head = head;
        s.srcBytes = bytes;
        s.srcText = text;
        s.srcPos = 0;
        s.srcEnd = len;
        s.endQueued = true;
        Http2Stream top;
        do {
            top = (Http2Stream) INBOX.getVolatile(this);
            s.nextInbox = top;
        } while (!INBOX.compareAndSet(this, top, s));
        if (tryWrite()) {
            drain(s);
        }
    }

    /** Lock held: schedules the exchanges handed over since the last batch, oldest first. */
    private void takeInbox() {
        if (INBOX.getVolatile(this) == null) return;
        Http2Stream s = (Http2Stream) INBOX.getAndSet(this, null);
        // The stack is newest first: reverse it so responses keep their order.
        Http2Stream reversed = null;
        while (s != null) {
            Http2Stream next = s.nextInbox;
            s.nextInbox = reversed;
            reversed = s;
            s = next;
        }
        for (s = reversed; s != null; ) {
            Http2Stream next = s.nextInbox;
            s.nextInbox = null;
            s.detached = true;
            if (s.outputClosed || failed) {
                // Reset before the writer saw it.
                abortDetached(s);
            } else {
                schedule(s);
            }
            s = next;
        }
    }

    /**
     * Queues the response head of {@code s}. {@code endStream}: there is no
     * body. {@code flushNow}: send the head right away rather than with the
     * first body bytes (a body whose bytes may be slow to come).
     */
    void begin(Http2Stream s, ResponseHead head, boolean endStream, boolean flushNow) throws IOException {
        boolean write = false;
        lock.lock();
        try {
            ensureOpen(s);
            s.head = head;
            if (endStream) {
                s.endQueued = true;
            }
            schedule(s);
            if (flushNow && tryWrite()) {
                write = true;
            }
        } finally {
            lock.unlock();
        }
        if (write) {
            drain(s);
        }
    }

    /**
     * Queues a 100 (Continue) interim response on {@code s} and sends it
     * now: the handler is about to wait for a body the client only sends
     * once it sees it. Dropped when the final head is already queued or the
     * stream can't send any more.
     */
    void interimContinue(Http2Stream s) {
        boolean write = false;
        lock.lock();
        try {
            if (s.outputClosed || s.headersSent || s.head != null || failed) return;
            s.continueQueued = true;
            schedule(s);
            write = tryWrite();
        } finally {
            lock.unlock();
        }
        if (write) {
            drain(s);
        }
    }

    /**
     * Copies body bytes into the stream's ring, waiting for room. The
     * bytes go out from a flusher thread, so the producer keeps producing
     * while they are encrypted and written.
     */
    void write(Http2Stream s, byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            boolean flusher;
            lock.lock();
            try {
                ensureOpen(s);
                int limit = ringLimit(s);
                if (s.ringCount >= limit) {
                    awaitLocked(s, UNTIL_ROOM);
                    continue;
                }
                int n = Math.min(len, limit - s.ringCount);
                ensureRing(s, s.ringCount + n);
                byte[] ring = s.ring;
                int tail = (s.ringHead + s.ringCount) % ring.length;
                int first = Math.min(n, ring.length - tail);
                System.arraycopy(b, off, ring, tail, first);
                if (first < n) {
                    System.arraycopy(b, off + first, ring, 0, n - first);
                }
                s.ringCount += n;
                budget.charge(n);
                off += n;
                len -= n;
                if (s.sched == SCHED_NONE) {
                    schedule(s);
                }
                flusher = kickAsync();
            } finally {
                lock.unlock();
            }
            if (flusher) startFlusher();
        }
    }

    /**
     * Reads the next body bytes from {@code in} straight into the stream's
     * ring (no intermediate buffer), at most {@code max}. Returns the count
     * read, or -1 at the end of {@code in}. Reading all of {@code max} means
     * the body is complete: nothing is kicked, the producer's
     * {@link #finish} sends it with END_STREAM in the same batch.
     */
    int readInto(Http2Stream s, InputStream in, long max) throws IOException {
        return transferInto(s, in, null, max);
    }

    /** {@link #readInto} from a file channel. */
    int readInto(Http2Stream s, FileChannel ch, long max) throws IOException {
        return transferInto(s, null, ch, max);
    }

    private int transferInto(Http2Stream s, InputStream in, FileChannel ch, long max) throws IOException {
        byte[] ring;
        int pos;
        int room;
        lock.lock();
        try {
            int limit;
            while (true) {
                ensureOpen(s);
                limit = ringLimit(s);
                if (s.ringCount < limit) break;
                awaitLocked(s, UNTIL_ROOM);
            }
            // What the ring holds after this read at most (within the
            // limit): what is left of a body of known length at once, rather
            // than growing through every size; a frame's worth more for one
            // of unknown length (its producer passes a huge max) or past
            // 2 GiB. Not whatever a larger pooled array offers: each read is
            // a step the limit is checked between (it shrinks to a frame
            // while the connection is throttled).
            long upTo = max > Integer.MAX_VALUE ? DATA_FRAME_MAX : max;
            int target = (int) Math.min(limit, s.ringCount + upTo);
            if (s.ring == null && max < RING_INITIAL) {
                // What is left of the body is known and small: a ring of its size.
                s.ring = new byte[(int) max];
                s.ringHead = 0;
            } else {
                ensureRing(s, target);
            }
            ring = s.ring;
            pos = (s.ringHead + s.ringCount) % ring.length;
            // Contiguous free space from the tail, up to the target.
            room = (int) Math.min(max, Math.min(target - s.ringCount, ring.length - pos));
            s.filling = true;
        } finally {
            lock.unlock();
        }
        // Outside the lock: only this producer writes the ring's free region
        // or replaces the array, and the writer only reads the filled part.
        int r;
        try {
            r = ch != null ? ch.read(ByteBuffer.wrap(ring, pos, room)) : in.read(ring, pos, room);
        } finally {
            lock.lock();
            s.filling = false;
            lock.unlock();
        }
        if (r <= 0) {
            return r;
        }
        boolean flusher = false;
        lock.lock();
        try {
            ensureOpen(s);
            s.ringCount += r;
            budget.charge(r);
            if (s.sched == SCHED_NONE) {
                schedule(s);
            }
            // A short read means the source is slower than the socket:
            // send now. Otherwise let half a batch build up first.
            if (r != max && (r < room || s.ringCount >= BATCH_SIZE / 2)) {
                flusher = kickAsync();
            }
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
        return r;
    }

    /**
     * Lock held: streamed bytes were queued; a flusher writes them unless a
     * writer is active. True when the caller, once it released the lock,
     * must {@link #startFlusher} (it holds the writer role for it).
     */
    private boolean kickAsync() {
        return !failed && tryWrite();
    }

    /**
     * Starts a flusher for the writer role the caller took. Outside the
     * lock: starting a thread may wake a carrier (a system call), which
     * must not hold up the framer or producers waiting for the lock.
     */
    private void startFlusher() {
        Thread.startVirtualThread(flusher);
    }

    /**
     * Most bytes {@code s} may hold copied: what its send window lets go,
     * at least one frame and at most {@link #RING_MAX}; one frame while the
     * connection is throttled by the memory budget. Lock held.
     */
    private int ringLimit(Http2Stream s) {
        if (budget.throttled()) return DATA_FRAME_MAX;
        return (int) Math.max(DATA_FRAME_MAX, Math.min(RING_MAX, s.sendWindow));
    }

    private void ensureRing(Http2Stream s, int need) {
        byte[] ring = s.ring;
        if (ring != null && ring.length >= need) return;
        int cap = ring == null ? RING_INITIAL : ring.length;
        while (cap < need) cap <<= 1;
        // A ring past its first size tends to reach the largest: a pooled
        // one of that size, if any, saves the copies through every size in
        // between and the allocation.
        byte[] bigger = cap > RING_INITIAL ? take(RING_POOL) : null;
        if (bigger == null) {
            bigger = new byte[Math.min(cap, RING_MAX)];
        }
        if (s.ringCount > 0) {
            int first = Math.min(s.ringCount, ring.length - s.ringHead);
            System.arraycopy(ring, s.ringHead, bigger, 0, first);
            System.arraycopy(ring, 0, bigger, first, s.ringCount - first);
        }
        s.ring = bigger;
        s.ringHead = 0;
    }

    /** Waits until everything queued on {@code s} so far is on the socket (user flush). */
    void flush(Http2Stream s) throws IOException {
        lock.lock();
        try {
            ensureOpen(s);
            awaitLocked(s, UNTIL_WRITTEN);
        } finally {
            lock.unlock();
        }
    }

    /** The body is complete: queue END_STREAM and wait until the writer took it. */
    void finish(Http2Stream s) throws IOException {
        lock.lock();
        try {
            ensureOpen(s);
            s.endQueued = true;
            if (s.sched == SCHED_NONE) {
                schedule(s);
            }
            awaitLocked(s, UNTIL_ENDED);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The stream is closed: drop its pending output and fail its producer,
     * or finish its handed-over exchange as aborted. An exchange still in
     * the inbox is left to {@link #takeInbox}, which aborts it: its fields
     * may still be being written by the handler handing it over. A
     * producer's head is its own (it releases it on failing). Any thread.
     */
    void purge(Http2Stream s) {
        boolean finish = false;
        int dropped;
        lock.lock();
        try {
            s.outputClosed = true;
            unschedule(s);
            dropped = s.ringCount;
            if (!s.filling) {
                // Else its producer is reading into it outside the lock.
                recycleRing(s.ring);
            }
            s.ring = null;
            s.ringCount = 0;
            Thread t = s.waiter;
            if (t != null) {
                LockSupport.unpark(t);
            }
            if (s.detached) {
                s.srcBytes = null;
                s.srcText = null;
                s.srcPos = 0;
                s.srcEnd = 0;
                if (!s.finished) {
                    finish = true;
                    s.finished = true;
                    releaseHead(s);
                }
            }
        } finally {
            lock.unlock();
        }
        budget.release(dropped);
        if (finish) {
            conn.exchangeFinished(s, false);
        }
    }

    /** Lock held: a handed-over exchange can't be sent; the writer finishes it. */
    private void abortDetached(Http2Stream s) {
        if (s.finished) return;
        s.finished = true;
        releaseHead(s);
        s.srcBytes = null;
        s.srcText = null;
        addFinished(s);
    }

    private void releaseHead(Http2Stream s) {
        ResponseHead h = s.head;
        if (h != null) {
            s.head = null;
            // Fixed bodies only: release just drops references.
            h.release();
            Http2Exchange.giveBack(s, h);
        }
    }

    private void addFinished(Http2Stream s) {
        if (finishedCount == finished.length) {
            finished = java.util.Arrays.copyOf(finished, finishedCount * 2);
        }
        finished[finishedCount++] = s;
    }

    private void ensureOpen(Http2Stream s) throws IOException {
        if (s.outputClosed) {
            throw new IOException("HTTP/2 stream " + s.id + " closed");
        }
        if (failed) {
            throw new IOException("HTTP/2 connection closed");
        }
    }

    private boolean satisfied(Http2Stream s, int until) {
        return switch (until) {
            case UNTIL_ROOM -> s.ringCount < ringLimit(s);
            case UNTIL_ENDED -> s.endSent;
            default -> s.pendingBytes() == 0 && (s.head == null || s.headersSent)
                && s.packedSeq <= writtenSeq;
        };
    }

    /**
     * Caller holds the lock. Waits on {@code s} until {@code until} holds,
     * writing for everyone whenever there is work and no writer.
     */
    private void awaitLocked(Http2Stream s, int until) throws IOException {
        Thread me = Thread.currentThread();
        while (true) {
            if (handoff == me) {
                handoff = null;
                drainUnlocked(s);
                continue;
            }
            if (satisfied(s, until)) return;
            ensureOpen(s);
            if (!isWriting() && hasWork() && tryWrite()) {
                drainUnlocked(s);
                continue;
            }
            s.waiter = me;
            lock.unlock();
            LockSupport.park(this);
            lock.lock();
            s.waiter = null;
            if (handoff != me && Thread.interrupted()) {
                me.interrupt();
                throw new InterruptedIOException("interrupted waiting on HTTP/2 stream " + s.id);
            }
        }
    }

    private void drainUnlocked(Http2Stream own) {
        lock.unlock();
        try {
            drain(own);
        } finally {
            lock.lock();
        }
    }

    private boolean hasWork() {
        return controlLen > 0 || (!controlOnly && (readyHead != null || INBOX.getVolatile(this) != null));
    }

    // ---- Combining writer ----------------------------------------------------------

    /**
     * The framer (or another thread that must not write) added work: make
     * sure someone writes it. Hands the role to a parked producer (one
     * whose stream just became sendable when given), else returns true:
     * the caller starts a flusher ({@link #startFlusher}) once it released
     * the lock. Caller holds the lock.
     */
    private boolean kickFromFramer(Http2Stream preferred) {
        if (failed || isWriting() || !hasWork() || !tryWrite()) return false;
        Thread t = preferred != null ? preferred.waiter : null;
        if (t != null) {
            handoff = t;
            LockSupport.unpark(t);
            return false;
        }
        return true;
    }

    /**
     * Writes batches until there is nothing sendable left. The caller
     * holds the writer role ({@link #tryWrite}). {@code own}: the stream
     * the calling producer works for, null for a flusher. Whatever it
     * throws fails the connection ({@link #fail}), so the role can't be
     * left taken with nobody writing.
     */
    private void drain(Http2Stream own) {
        ByteBuffer scratchBuf = borrowScratch();
        byte[] scratch = scratchBuf.array();
        ByteBuffer net = tls != null ? borrowNet() : null;
        int extra = 0;
        try {
            while (true) {
                byte[] batch = null;
                Http2Stream[] done;
                int doneCount;
                int n;
                long freed;
                boolean flusher = false;
                lock.lock();
                try {
                    if (failed) {
                        // Exchanges handed over since: aborted.
                        takeInbox();
                        releaseWriting();
                        wakeIdleWaiter();
                        n = -1;
                    } else {
                        takeInbox();
                        if (own != null && extra >= HANDOFF_BATCHES && ownDone(own) && hasWork()) {
                            flusher = passOn();
                            n = -1;
                        } else {
                            n = fill(scratch);
                            if (n == 0) {
                                releaseWriting();
                                wakeIdleWaiter();
                            } else {
                                batchSeq++;
                                batch = oversized != null ? oversized : scratch;
                                oversized = null;
                                if (own != null && ownDone(own)) {
                                    extra++;
                                }
                            }
                        }
                    }
                    doneCount = finishedCount;
                    done = doneCount > 0 ? takeFinished() : null;
                    freed = ringFreed;
                    ringFreed = 0;
                } finally {
                    lock.unlock();
                }
                budget.release(freed);
                if (flusher) {
                    startFlusher();
                }
                // Before the batch leaves, so a peer reacting to an
                // END_STREAM finds the exchange's slot free.
                if (done != null) {
                    finish(done, doneCount);
                }
                if (n > 0) {
                    boolean ok = writeOut(batch == scratch ? scratchBuf : ByteBuffer.wrap(batch), n, net);
                    lock.lock();
                    try {
                        if (ok) {
                            batchWritten();
                        }
                        recycleFinished(done);
                    } finally {
                        lock.unlock();
                    }
                    if (!ok) return;
                    continue;
                }
                if (done != null) {
                    lock.lock();
                    try {
                        recycleFinished(done);
                    } finally {
                        lock.unlock();
                    }
                }
                // Handed over after the last batch was filled (or after the
                // connection failed): take it on.
                if (n <= 0 && INBOX.getVolatile(this) != null && tryWrite()) {
                    continue;
                }
                return;
            }
        } catch (Throwable t) {
            fail(t);
        } finally {
            releaseScratch(scratchBuf);
            if (net != null) {
                releaseNet(net);
            }
        }
    }

    /** Lock held: hands out the finished list, leaving an empty one in its place. */
    private Http2Stream[] takeFinished() {
        Http2Stream[] list = finished;
        Http2Stream[] spare = spareFinished;
        finished = spare != null && spare.length >= list.length ? spare : new Http2Stream[list.length];
        spareFinished = null;
        finishedCount = 0;
        return list;
    }

    private void recycleFinished(Http2Stream[] list) {
        if (list != null && spareFinished == null) {
            spareFinished = list;
        }
    }

    /**
     * Outside the lock: finishes the exchanges in {@code list[0, n)} and
     * clears it. A stream whose END_STREAM is packed moves on in its state
     * machine here rather than while packing: closing it may close the
     * connection, which takes locks the writer's must not be held under.
     */
    private void finish(Http2Stream[] list, int n) {
        for (int i = 0; i < n; i++) {
            Http2Stream s = list[i];
            list[i] = null;
            if (s.endSent) {
                s.sendEnd();
            }
            conn.exchangeFinished(s, s.endSent);
        }
    }

    /** {@link #finish} whatever is on the finished list, from any thread. */
    private void finishExchanges() {
        Http2Stream[] list;
        int n;
        lock.lock();
        try {
            n = finishedCount;
            if (n == 0) return;
            list = takeFinished();
        } finally {
            lock.unlock();
        }
        finish(list, n);
        lock.lock();
        try {
            recycleFinished(list);
        } finally {
            lock.unlock();
        }
    }

    private static boolean ownDone(Http2Stream s) {
        return s.outputClosed || s.pendingBytes() == 0 && (s.head == null || s.headersSent);
    }

    /**
     * Hands the writer role (still held) to a parked producer; true when
     * there is none and the caller must start a flusher after unlocking.
     * Lock held.
     */
    private boolean passOn() {
        Thread t = findWaiter(readyHead);
        if (t == null) t = findWaiter(blockedHead);
        if (t == null) t = findWaiter(connBlockedHead);
        if (t != null) {
            handoff = t;
            LockSupport.unpark(t);
            return false;
        }
        return true;
    }

    private static Thread findWaiter(Http2Stream s) {
        for (; s != null; s = s.schedNext) {
            if (s.waiter != null) return s.waiter;
        }
        return null;
    }

    /** Writes {@code batch[0, n)} (its backing array). */
    private boolean writeOut(ByteBuffer batch, int n, ByteBuffer net) {
        // A pending interrupt would close the channel under the write
        // (InterruptibleChannel); it is restored once the batch is out.
        // Interrupts sent meanwhile wait for the write too (interrupt).
        // The lock first: one delivered (by interrupt) before it is taken
        // is pending and cleared here; none is delivered after.
        ioLock.lock();
        boolean interrupted = Thread.interrupted();
        try {
            if (watchdog != null) watchdog.enter();
            try {
                batch.clear().limit(n);
                if (net != null) {
                    tls.writeRecords(batch, net);
                } else if (channel != null) {
                    while (batch.hasRemaining()) {
                        channel.write(batch);
                    }
                } else {
                    out.write(batch.array(), 0, n);
                    out.flush();
                }
            } finally {
                if (watchdog != null) watchdog.exit();
            }
            return true;
        } catch (IOException | RuntimeException e) {
            fail(e);
            return false;
        } finally {
            interrupted |= deliverDeferredLocked();
            ioLock.unlock();
            deliverDeferred();
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    /**
     * Interrupts handler thread {@code t} (a cancelled stream, a timed-out
     * handler) without ever landing in a socket write: handler threads are
     * also the connection's writers, and an interrupt during a blocking
     * write closes the socket for every stream. Delivered at once when no
     * write is in progress, else by the writing thread right after its
     * write (to itself: as a pending interrupt). Any thread; never blocks.
     */
    void interrupt(Thread t) {
        if (ioLock.tryLock()) {
            try {
                t.interrupt();
            } finally {
                ioLock.unlock();
            }
            return;
        }
        deferredInterrupts.add(t);
        // The write may have ended in between: deliver if nobody writes now.
        deliverDeferred();
    }

    /** Delivers deferred interrupts if no write is in progress. */
    private void deliverDeferred() {
        while (!deferredInterrupts.isEmpty() && ioLock.tryLock()) {
            boolean self;
            try {
                self = deliverDeferredLocked();
            } finally {
                ioLock.unlock();
            }
            if (self) Thread.currentThread().interrupt();
        }
    }

    /** ioLock held: interrupts the deferred threads; true when the caller was one of them. */
    private boolean deliverDeferredLocked() {
        boolean self = false;
        Thread t;
        while ((t = deferredInterrupts.poll()) != null) {
            if (t == Thread.currentThread()) {
                self = true;
            } else {
                t.interrupt();
            }
        }
        return self;
    }

    /** The batch is on the socket: wake producers waiting for their bytes to be written. */
    private void batchWritten() {
        writtenSeq = batchSeq;
        for (int i = 0; i < batchStreamCount; i++) {
            Http2Stream s = batchStreams[i];
            batchStreams[i] = null;
            s.inBatch = false;
            Thread t = s.waiter;
            if (t != null) {
                LockSupport.unpark(t);
            }
        }
        batchStreamCount = 0;
    }

    private void fail(Throwable e) {
        lock.lock();
        try {
            failed = true;
            releaseWriting();
            controlLen = 0;
            controlFrames = 0;
            wakeAll(readyHead);
            wakeAll(blockedHead);
            wakeAll(connBlockedHead);
            for (int i = 0; i < batchStreamCount; i++) {
                wakeAll(batchStreams[i]);
            }
            wakeIdleWaiter();
        } finally {
            lock.unlock();
        }
        conn.onWriteFailure(e);
    }

    private static void wakeAll(Http2Stream s) {
        for (; s != null; s = s.schedNext) {
            Thread t = s.waiter;
            if (t != null) LockSupport.unpark(t);
        }
    }

    private void wakeIdleWaiter() {
        Thread t = idleWaiter;
        if (t != null) LockSupport.unpark(t);
    }

    /**
     * Connection teardown: waits for the active writer, writes what can
     * still be sent (the control lane first: a final GOAWAY), then stops
     * all writing. Waiting for another writer is bounded by twice the
     * write timeout (a stalled socket write is cut by the write watchdog
     * within that), or {@link #SHUTDOWN_WAIT_NANOS} without one: past it
     * the socket is closed and nothing more is written. Several threads
     * may call it; all return once writing has stopped.
     */
    void shutdown() {
        long deadline = System.nanoTime()
            + (writeTimeoutNanos > 0 ? 2 * writeTimeoutNanos : SHUTDOWN_WAIT_NANOS);
        boolean write = false;
        boolean stuck = false;
        lock.lock();
        try {
            while (!failed) {
                if (tryWrite()) {
                    write = true;
                    break;
                }
                if (System.nanoTime() - deadline >= 0) {
                    // The writer never finished: whatever it does now fails.
                    failed = true;
                    stuck = true;
                    break;
                }
                idleWaiter = Thread.currentThread();
                lock.unlock();
                // Timed: another closing thread may have taken the wake-up.
                LockSupport.parkNanos(this, IDLE_WAIT_NANOS);
                lock.lock();
                if (idleWaiter == Thread.currentThread()) {
                    idleWaiter = null;
                }
            }
        } finally {
            lock.unlock();
        }
        if (stuck) {
            conn.onWriteFailure(new IOException("HTTP/2 writer did not finish"));
        }
        if (write) {
            drain(null);
        }
        lock.lock();
        try {
            failed = true;
            // Nothing more will be written: handed-over exchanges still
            // waiting are finished as aborted, producers fail.
            takeInbox();
            for (Http2Stream s = readyHead; s != null; s = s.schedNext) {
                if (s.detached) abortDetached(s);
            }
            for (Http2Stream s = blockedHead; s != null; s = s.schedNext) {
                if (s.detached) abortDetached(s);
            }
            for (Http2Stream s = connBlockedHead; s != null; s = s.schedNext) {
                if (s.detached) abortDetached(s);
            }
            wakeAll(readyHead);
            wakeAll(blockedHead);
            wakeAll(connBlockedHead);
        } finally {
            lock.unlock();
        }
        finishExchanges();
    }

    // ---- Packing (lock held) -------------------------------------------------------

    /** Packs the next batch into {@code buf} (or {@link #oversized}); returns its length. */
    private int fill(byte[] buf) {
        int p = packControl(buf, 0);
        if (controlOnly) {
            return p;
        }
        Http2Stream s;
        while ((s = readyHead) != null && buf.length - p > Http2.FRAME_HEADER_SIZE) {
            unschedule(s);
            p = packStream(s, buf, p);
            if (oversized != null) {
                // The batch grew for a header block: it ends with it.
                return p;
            }
            if (batchFull) {
                // s is back at the front for the next batch.
                batchFull = false;
                return p;
            }
        }
        return p;
    }

    private int packControl(byte[] buf, int p) {
        int i = 0;
        while (i < controlLen) {
            int len = Http2.FRAME_HEADER_SIZE + (((control[i] & 0xFF) << 16)
                                                 | ((control[i + 1] & 0xFF) << 8)
                                                 | (control[i + 2] & 0xFF));
            if (len > buf.length - p) break;
            System.arraycopy(control, i, buf, p, len);
            p += len;
            i += len;
            controlFrames--;
        }
        if (i > 0) {
            System.arraycopy(control, i, control, 0, controlLen - i);
            controlLen -= i;
        }
        return p;
    }

    /**
     * One turn of {@code s} (just taken off the ready ring): its header
     * block if not sent yet, then at most one DATA frame. Returns the
     * position after what was packed. When s needs room the batch no
     * longer has, s is requeued at the front and {@link #batchFull} set;
     * a header block that can't fit a batch (or, the second time, what is
     * left of one behind its control frames) is packed with the batch so
     * far into {@link #oversized} instead and that length returned.
     */
    private int packStream(Http2Stream s, byte[] buf, int p) {
        if (s.outputClosed) {
            if (s.detached) abortDetached(s);
            return p;
        }
        if (s.continueQueued) {
            if (buf.length - p < Http2.FRAME_HEADER_SIZE + 8) {
                return full(s, p);
            }
            p = packContinue(s, buf, p);
        }
        if (s.head != null && !s.headersSent) {
            int bound = headerBound(s.head);
            int frames = bound / peerMaxFrameSize + 1;
            int need = bound + frames * Http2.FRAME_HEADER_SIZE;
            if (need > buf.length - p) {
                if (p > 0 && deferredHeaders != s) {
                    // It opens the next batch instead.
                    deferredHeaders = s;
                    return full(s, p);
                }
                // Larger than a batch, or than what one has left behind its
                // control frames even when it opens with this block: the
                // batch grows for it.
                byte[] big = new byte[p + need];
                System.arraycopy(buf, 0, big, 0, p);
                int n = packHeaders(s, big, p);
                oversized = big;
                if (s.pendingBytes() > 0 || (s.endQueued && !s.endSent)) {
                    schedule(s);
                }
                return n;
            }
            // The block is packed even when its DATA must wait for the
            // next batch: it was encoded, so it has to go out now.
            p = packHeaders(s, buf, p);
        }
        int pending = s.pendingBytes();
        if (pending > 0) {
            long credit = Math.min(s.sendWindow, connSendWindow);
            if (credit <= 0
                || (credit < pending && credit < MIN_DATA_CHUNK && !s.dribbleDue)) {
                block(s);
                return p;
            }
            int room = buf.length - p - Http2.FRAME_HEADER_SIZE;
            int n = (int) Math.min(Math.min(pending, credit), Math.min(DATA_FRAME_MAX, room));
            if (n < Math.min(Math.min(pending, credit), MIN_DATA_CHUNK)) {
                // Too little room left: a full frame opens the next batch.
                return full(s, p);
            }
            p = packData(s, buf, p, n);
            if (s.pendingBytes() > 0 || (s.endQueued && !s.endSent)) {
                schedule(s);
            }
        } else if (s.endQueued && !s.endSent) {
            if (buf.length - p < Http2.FRAME_HEADER_SIZE) {
                return full(s, p);
            }
            // Empty DATA with END_STREAM: no flow-control credit needed (§6.9.1).
            p = frameHeader(buf, p, 0, Http2.TYPE_DATA, Http2.FLAG_END_STREAM, s.id);
            ended(s);
            inBatch(s);
        }
        return p;
    }

    /** The 100 (Continue) interim head: its own header block, never END_STREAM (RFC 9113 §8.1). */
    private int packContinue(Http2Stream s, byte[] buf, int p) {
        s.continueQueued = false;
        Hpack.Encoder e = encoder;
        e.beginBlock();
        e.status(100);
        int len = e.length();
        p = frameHeader(buf, p, len, Http2.TYPE_HEADERS, Http2.FLAG_END_HEADERS, s.id);
        System.arraycopy(e.buffer(), 0, buf, p, len);
        inBatch(s);
        return p + len;
    }

    /** {@code s} needs the next batch: back at the front, and this batch closes at {@code p}. */
    private int full(Http2Stream s, int p) {
        pushFront(s);
        batchFull = true;
        return p;
    }

    private int packHeaders(Http2Stream s, byte[] buf, int p) {
        ResponseHead h = s.head;
        Hpack.Encoder e = encoder;
        e.beginBlock();
        e.status(h.status());
        for (int i = 0, n = h.fieldCount(); i < n; i++) {
            Object v = h.value(i);
            if (v instanceof String str) {
                e.field(h.name(i), str);
            } else {
                e.field(h.name(i), ((Number) v).longValue());
            }
        }
        long contentLength = h.contentLength();
        if (contentLength >= 0) {
            e.field("content-length", contentLength);
        }
        if (Service.addsDate(h)) {
            e.field("date", HttpDates.now());
        }
        String altSvc = service.altSvcField(h);
        if (altSvc != null) {
            e.field("alt-svc", altSvc);
        }
        String server = service.serverField(h);
        if (server != null) {
            e.field("server", server);
        }
        byte[] block = e.buffer();
        int len = e.length();
        boolean endStream = s.endQueued && s.pendingBytes() == 0;
        int max = peerMaxFrameSize;
        // §4.3: HEADERS + CONTINUATIONs are contiguous: all packed here.
        int off = 0;
        int type = Http2.TYPE_HEADERS;
        int flags = endStream ? Http2.FLAG_END_STREAM : 0;
        do {
            int n = Math.min(max, len - off);
            int f = flags | (off + n == len ? Http2.FLAG_END_HEADERS : 0);
            p = frameHeader(buf, p, n, type, f, s.id);
            System.arraycopy(block, off, buf, p, n);
            p += n;
            off += n;
            type = Http2.TYPE_CONTINUATION;
            flags = 0;
        } while (off < len);
        s.headersSent = true;
        if (deferredHeaders == s) {
            deferredHeaders = null;
        }
        if (s.detached) {
            releaseHead(s);
        }
        inBatch(s);
        if (endStream) {
            ended(s);
        }
        return p;
    }

    /** Upper bound of the encoded header block of {@code h}, as {@link #packHeaders} writes it. */
    private int headerBound(ResponseHead h) {
        int n = 10 + 5 + 3; // size updates, :status
        for (int i = 0, c = h.fieldCount(); i < c; i++) {
            Object v = h.value(i);
            n += 15 + h.name(i).length() + (v instanceof String str ? str.length() : 20);
        }
        n += 15 + 14 + 20;  // content-length
        n += 15 + 4 + 29;   // date
        n += service.addedFieldsBound();
        return n;
    }

    @SuppressWarnings("deprecation") // String.getBytes(int, int, byte[], int): exact for ASCII text
    private int packData(Http2Stream s, byte[] buf, int p, int n) {
        boolean last = s.endQueued && n == s.pendingBytes();
        p = frameHeader(buf, p, n, Http2.TYPE_DATA, last ? Http2.FLAG_END_STREAM : 0, s.id);
        if (s.srcEnd > s.srcPos) {
            if (s.srcBytes != null) {
                System.arraycopy(s.srcBytes, s.srcPos, buf, p, n);
            } else {
                s.srcText.getBytes(s.srcPos, s.srcPos + n, buf, p);
            }
            s.srcPos += n;
            if (s.srcPos == s.srcEnd) {
                s.srcBytes = null;
                s.srcText = null;
            }
        } else {
            byte[] ring = s.ring;
            int first = Math.min(n, ring.length - s.ringHead);
            System.arraycopy(ring, s.ringHead, buf, p, first);
            if (first < n) {
                System.arraycopy(ring, 0, buf, p + first, n - first);
            }
            s.ringHead = (s.ringHead + n) % ring.length;
            s.ringCount -= n;
            ringFreed += n;
        }
        p += n;
        s.sendWindow -= n;
        connSendWindow -= n;
        // DATA payload taken by the writer: the response bytes reported.
        s.responseBytes += n;
        s.blockedAt = 0;
        s.dribbleDue = false;
        if (s.stalledSince != 0) {
            s.sentSinceStall += n;
            if (s.sentSinceStall >= MIN_PROGRESS) {
                s.stalledSince = 0;
                s.sentSinceStall = 0;
            }
        }
        if (connStalledSince != 0) {
            connSentSinceStall += n;
            if (connSentSinceStall >= MIN_PROGRESS) {
                connStalledSince = 0;
                connSentSinceStall = 0;
            }
        }
        inBatch(s);
        if (last) {
            ended(s);
        }
        // Room in the ring, or the borrowed body consumed: let the producer on.
        Thread t = s.waiter;
        if (t != null) {
            LockSupport.unpark(t);
        }
        return p;
    }

    /** END_STREAM is packed; the stream's state moves on in {@link #finish}, before the batch leaves. */
    private void ended(Http2Stream s) {
        s.endSent = true;
        s.stalledSince = 0;
        // END_STREAM goes with the last byte: the ring is empty for good,
        // its bytes copied into the batch, so it can serve another stream
        // before this batch is even written.
        recycleRing(s.ring);
        s.ring = null;
        s.ringHead = 0;
        if (!s.finished) {
            s.finished = true;
            addFinished(s);
        }
    }

    private void inBatch(Http2Stream s) {
        s.packedSeq = batchSeq + 1;
        if (s.inBatch) return;
        s.inBatch = true;
        if (batchStreamCount == batchStreams.length) {
            batchStreams = java.util.Arrays.copyOf(batchStreams, batchStreamCount * 2);
        }
        batchStreams[batchStreamCount++] = s;
    }

    // ---- Flow-control waits --------------------------------------------------------

    /**
     * {@code s} has bytes but too little credit: park it on the blocked list
     * and watch it. A ring grown while credit flowed is cut down to what it
     * holds (its producer may now only fill it to {@link #ringLimit}).
     */
    private void block(Http2Stream s) {
        byte[] ring = s.ring;
        if (ring != null && !s.filling && ring.length > RING_INITIAL && s.ringCount <= ringLimit(s)) {
            int size = Math.max(RING_INITIAL, Integer.highestOneBit(Math.max(1, s.ringCount - 1)) << 1);
            if (size < ring.length) {
                byte[] smaller = new byte[size];
                int first = Math.min(s.ringCount, ring.length - s.ringHead);
                System.arraycopy(ring, s.ringHead, smaller, 0, first);
                System.arraycopy(ring, 0, smaller, first, s.ringCount - first);
                s.ring = smaller;
                s.ringHead = 0;
                recycleRing(ring);
            }
        }
        unschedule(s);
        int pending = s.pendingBytes();
        // Waiting on its own window, or (that one open enough) on the connection's.
        boolean own = s.sendWindow < Math.min(pending, MIN_DATA_CHUNK);
        s.schedNext = null;
        if (own) {
            s.sched = SCHED_BLOCKED;
            s.schedPrev = blockedTail;
            if (blockedTail == null) blockedHead = s; else blockedTail.schedNext = s;
            blockedTail = s;
        } else {
            s.sched = SCHED_CONN_BLOCKED;
            s.schedPrev = connBlockedTail;
            if (connBlockedTail == null) connBlockedHead = s; else connBlockedTail.schedNext = s;
            connBlockedTail = s;
        }
        long now = System.nanoTime();
        if (s.blockedAt == 0) s.blockedAt = now;
        long deadline = Long.MAX_VALUE;
        long credit = Math.min(s.sendWindow, connSendWindow);
        if (credit > 0) {
            deadline = s.blockedAt + DRIBBLE_NANOS;
        }
        if (writeTimeoutNanos > 0) {
            if (own) {
                if (s.stalledSince == 0) {
                    s.stalledSince = now;
                    s.sentSinceStall = 0;
                }
                deadline = Math.min(deadline, s.stalledSince + writeTimeoutNanos);
            } else {
                if (connStalledSince == 0) {
                    connStalledSince = now;
                    connSentSinceStall = 0;
                }
                deadline = Math.min(deadline, connStalledSince + writeTimeoutNanos);
            }
        }
        if (deadline != Long.MAX_VALUE) {
            conn.armFlowDeadline(deadline);
        }
    }

    /**
     * Flow deadline expiry (a virtual thread off the timer): pooled small
     * credit is released, streams stuck on their own window past the write
     * timeout are reset with CANCEL, and a connection window stuck that
     * long ends the connection. Returns the next deadline, or 0.
     */
    long checkFlow(long now) {
        Http2Stream[] cancel = null;
        int cancelCount = 0;
        boolean connStalled = false;
        boolean flusher;
        long next = Long.MAX_VALUE;
        lock.lock();
        try {
            boolean connBlocking = false;
            // Both blocked lists, the streams waiting on their own window first.
            boolean connList = blockedHead == null;
            Http2Stream s = connList ? connBlockedHead : blockedHead;
            while (s != null) {
                Http2Stream nextBlocked = s.schedNext;
                if (nextBlocked == null && !connList) {
                    connList = true;
                    nextBlocked = connBlockedHead;
                }
                int pending = s.pendingBytes();
                long credit = Math.min(s.sendWindow, connSendWindow);
                if (credit > 0 && !s.dribbleDue) {
                    if (now - (s.blockedAt + DRIBBLE_NANOS) >= 0) {
                        s.dribbleDue = true;
                        schedule(s);
                        s = nextBlocked;
                        continue;
                    }
                    next = Math.min(next, s.blockedAt + DRIBBLE_NANOS);
                }
                if (writeTimeoutNanos > 0) {
                    if (s.sendWindow < Math.min(pending, MIN_DATA_CHUNK)) {
                        if (s.stalledSince != 0 && now - (s.stalledSince + writeTimeoutNanos) >= 0) {
                            if (cancel == null) cancel = new Http2Stream[4];
                            if (cancelCount == cancel.length) cancel = java.util.Arrays.copyOf(cancel, cancelCount * 2);
                            cancel[cancelCount++] = s;
                        } else if (s.stalledSince != 0) {
                            next = Math.min(next, s.stalledSince + writeTimeoutNanos);
                        }
                    } else {
                        connBlocking = true;
                    }
                }
                s = nextBlocked;
            }
            if (connBlocking && connStalledSince != 0) {
                if (now - (connStalledSince + writeTimeoutNanos) >= 0) {
                    connStalled = true;
                } else {
                    next = Math.min(next, connStalledSince + writeTimeoutNanos);
                }
            } else if (!connBlocking) {
                connStalledSince = 0;
            }
            flusher = kickFromFramer(readyHead);
        } finally {
            lock.unlock();
        }
        if (flusher) startFlusher();
        for (int i = 0; i < cancelCount; i++) {
            conn.cancelStalledStream(cancel[i]);
        }
        if (connStalled) {
            conn.connectionWindowStalled();
        }
        return next == Long.MAX_VALUE ? 0 : next;
    }

    // ---- Scheduler lists (lock held) -----------------------------------------------

    private void schedule(Http2Stream s) {
        if (s.sched == SCHED_READY) return;
        unschedule(s);
        s.sched = SCHED_READY;
        s.schedPrev = readyTail;
        s.schedNext = null;
        if (readyTail == null) readyHead = s; else readyTail.schedNext = s;
        readyTail = s;
    }

    private void pushFront(Http2Stream s) {
        unschedule(s);
        s.sched = SCHED_READY;
        s.schedPrev = null;
        s.schedNext = readyHead;
        if (readyHead == null) readyTail = s; else readyHead.schedPrev = s;
        readyHead = s;
    }

    private void unschedule(Http2Stream s) {
        if (s.sched == SCHED_NONE) return;
        Http2Stream prev = s.schedPrev;
        Http2Stream next = s.schedNext;
        if (s.sched == SCHED_READY) {
            if (prev == null) readyHead = next; else prev.schedNext = next;
            if (next == null) readyTail = prev; else next.schedPrev = prev;
        } else if (s.sched == SCHED_BLOCKED) {
            if (prev == null) blockedHead = next; else prev.schedNext = next;
            if (next == null) blockedTail = prev; else next.schedPrev = prev;
        } else {
            if (prev == null) connBlockedHead = next; else prev.schedNext = next;
            if (next == null) connBlockedTail = prev; else next.schedPrev = prev;
        }
        s.schedPrev = null;
        s.schedNext = null;
        s.sched = SCHED_NONE;
    }

    // ---- Batch buffers and rings -----------------------------------------------------

    // Batch buffers (plain and encrypted) are only needed while a
    // connection writes: an idle connection holds none. Shared
    // server-wide, at most POOL_SLOTS of each kept.
    private static final int POOL_SLOTS = 64;
    // Batches are kept with their ByteBuffer wrapper, so writing one wraps nothing.
    private static final AtomicReferenceArray<ByteBuffer> POOL = new AtomicReferenceArray<>(POOL_SLOTS);
    private static final AtomicReferenceArray<ByteBuffer> NET_POOL = new AtomicReferenceArray<>(POOL_SLOTS);
    // Streamed-body rings of the largest size, given back once their last
    // bytes are packed (or dropped): a ring is only held while its stream
    // has bytes to send. Fewer kept than batches: a ring is held longer.
    private static final int RING_POOL_SLOTS = 32;
    private static final AtomicReferenceArray<byte[]> RING_POOL = new AtomicReferenceArray<>(RING_POOL_SLOTS);

    private static ByteBuffer borrowNet() {
        ByteBuffer b = take(NET_POOL);
        return b != null ? b : ByteBuffer.allocate(NET_BUFFER_SIZE);
    }

    private static void releaseNet(ByteBuffer b) {
        give(NET_POOL, b);
    }

    private static ByteBuffer borrowScratch() {
        ByteBuffer b = take(POOL);
        return b != null ? b : ByteBuffer.allocate(BATCH_SIZE);
    }

    private static void releaseScratch(ByteBuffer b) {
        give(POOL, b);
    }

    /** Keeps {@code ring} for another stream if it has the largest size. */
    private static void recycleRing(byte[] ring) {
        if (ring != null && ring.length == RING_MAX) {
            give(RING_POOL, ring);
        }
    }

    /** A pooled item, or null: probes every slot from one spread by the calling thread. */
    private static <T> T take(AtomicReferenceArray<T> pool) {
        int n = pool.length();
        int start = (int) Thread.currentThread().threadId();
        for (int i = 0; i < n; i++) {
            int idx = (start + i) & (n - 1);
            T b = pool.get(idx);
            if (b != null && pool.compareAndSet(idx, b, null)) {
                return b;
            }
        }
        return null;
    }

    /** Pools {@code b} in the first free slot, or drops it when there is none. */
    private static <T> void give(AtomicReferenceArray<T> pool, T b) {
        int n = pool.length();
        int start = (int) Thread.currentThread().threadId();
        for (int i = 0; i < n; i++) {
            int idx = (start + i) & (n - 1);
            if (pool.get(idx) == null && pool.compareAndSet(idx, null, b)) {
                return;
            }
        }
    }

    /** Stalled socket write: the peer stopped reading. */
    private final class Watchdog extends WriteWatchdog {
        Watchdog(Timer timer, long timeoutMillis) {
            super(timer, timeoutMillis);
        }

        @Override
        protected void onStall() {
            conn.onWriteStall();
        }
    }

    /** Retires the watchdog's timer node at connection close. */
    void retire(Timer timer) {
        if (watchdog != null) {
            timer.retire(watchdog);
        }
    }
}

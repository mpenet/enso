// ABOUTME: RFC 6455 WebSocket driver over an upgraded HTTP/1.1 connection: frame reading and
// ABOUTME: reassembly, listener dispatch, server sends (sync and queued), and the closing handshake.
package com.s_exp.enso.websocket;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import com.s_exp.enso.api.Config;
import com.s_exp.enso.api.WebSocketException;
import com.s_exp.enso.api.WebSocketListener;
import com.s_exp.enso.api.WebSocketSocket;
import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.Timer;
import com.s_exp.enso.core.TlsSocket;

/**
 * RFC 6455 WebSocket connection driver. Reads frames, dispatches events to a
 * {@link WebSocketListener}, and exposes a {@link WebSocketSocket} for
 * server-initiated sends. Continuation frames are reassembled into a single
 * text or binary message (bounded by {@code :ws-max-message-bytes}, and by
 * {@code :read-timeout} from its first frame); pings are auto-responded by
 * the default listener implementation. Protocol violations fail the
 * connection with the matching CLOSE status (§7.1.7); a closing handshake
 * the server starts waits for the peer's CLOSE (up to
 * {@code :ws-close-timeout}) before dropping TCP. permessage-deflate
 * (RFC 7692) is used when negotiated at the upgrade.
 *
 * <p>Threads: {@link #run} is the read loop and dispatches every listener
 * event. Sends come from any thread. A synchronous send writes on the
 * caller's thread under {@link #writeLock}; asynchronous sends, and control
 * frames that find a write in progress, are queued and written in order by
 * a writer virtual thread started on first use. Whoever holds the lock
 * writes what is queued before its own frame, so frames leave in call
 * order. The read loop never waits on a writer: its pongs queue, and the
 * CLOSE it sends waits for the lock at most {@code :ws-close-timeout}.
 */
public final class WebSocketConnection {

    private static final String ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    static final int OP_CONTINUATION = 0x0;
    static final int OP_TEXT = 0x1;
    static final int OP_BINARY = 0x2;
    static final int OP_CLOSE = 0x8;
    static final int OP_PING = 0x9;
    static final int OP_PONG = 0xA;

    // FIN: the last frame of a message.
    private static final int FIN = 0x80;
    // RSV1: the message is compressed (RFC 7692 §6).
    private static final int RSV1 = 0x40;

    static final int CLOSE_NORMAL = 1000;
    static final int CLOSE_GOING_AWAY = 1001;
    static final int CLOSE_PROTOCOL_ERROR = 1002;
    static final int CLOSE_UNSUPPORTED_DATA = 1003;
    static final int CLOSE_NO_STATUS = 1005;
    static final int CLOSE_ABNORMAL = 1006;
    static final int CLOSE_INVALID_UTF8 = 1007;
    static final int CLOSE_POLICY_VIOLATION = 1008;
    static final int CLOSE_MESSAGE_TOO_BIG = 1009;
    static final int CLOSE_INTERNAL_ERROR = 1011;

    // RFC 6455 §5.5: control frame payloads are at most 125 bytes, so a
    // CLOSE reason is at most 123 bytes after the 2-byte code.
    static final int MAX_CONTROL_PAYLOAD = 125;
    static final int MAX_CLOSE_REASON = MAX_CONTROL_PAYLOAD - 2;

    // Messages shorter than this go out uncompressed even when
    // permessage-deflate is on: the deflate block overhead eats the gain.
    static final int COMPRESSION_THRESHOLD = 256;

    // Frame headers and small payloads are read through this buffer so a
    // frame costs one read() call, not one per header byte.
    private static final int READ_BUFFER_SIZE = 8192;
    // A connection without frames for this long gives back its grown
    // buffers (see releaseIdleBuffers); the next message regrows them.
    private static final int IDLE_RELEASE_MILLIS = 1000;
    // The read buffer while idle: enough for a frame header and a small
    // control frame.
    private static final int IDLE_READ_BUFFER_SIZE = 512;
    // A frame's claimed length is only trusted as bytes arrive: payloads
    // are read in steps of at most this many bytes, and the message buffer
    // grows per step rather than up-front from the header.
    private static final int READ_STEP = 64 * 1024;
    // Assembly buffers up to this many bytes are kept for the next
    // message; larger ones are released after each message.
    private static final int RETAIN_MAX = 256 * 1024;
    // Message bytes past this many are charged to the memory budget while
    // the message is assembled: up to it a connection's buffers are its
    // own (bounded by :max-connections), and small messages cost no
    // shared atomic.
    private static final int UNCHARGED_MESSAGE_BYTES = READ_STEP;
    // Compressed output is sent in frames of at most this many bytes, so a
    // large message is compressed through a bounded buffer.
    private static final int DEFLATE_CHUNK = 64 * 1024;
    // Payloads from this size on are written with their frame header in
    // one write: the connection's output stream sends writes this large
    // straight to the transport (HTTP/1.1 ResponseWriter's direct-write
    // threshold), which would leave the header in a write of its own.
    private static final int GATHER_MIN = 8192;
    // Staging for such a write: the header and the start of the payload,
    // one full TLS record.
    private static final int GATHER_BYTES = 16 * 1024;
    // After this long without anything to do the writer thread ends (the
    // next asynchronous send starts another).
    private static final long WRITER_LINGER_NANOS = TimeUnit.SECONDS.toNanos(1);
    // What a queued frame costs besides its payload (the queue node, the
    // frame header), counted against :ws-max-queued-bytes and the memory
    // budget so empty frames can't queue without bound.
    private static final int QUEUED_FRAME_OVERHEAD = 64;

    private static final byte[] EMPTY = new byte[0];
    private static final String IDLE_TIMEOUT = "idle timeout";
    private static final byte[] IDLE_TIMEOUT_REASON = IDLE_TIMEOUT.getBytes(StandardCharsets.UTF_8);
    // A listener failure is answered with 1011 and this reason: its
    // exception text stays on the server.
    private static final String INTERNAL_ERROR = "internal error";
    private static final String CLOSED = "WebSocket closed";
    private static final String QUEUE_FULL = "WebSocket send queue full";
    private static final String BUDGET_EXHAUSTED = "server buffer budget (:max-buffered-bytes) exhausted";
    // RFC 7692 §7.2.2: appended to a message's payload before inflating,
    // and removed from a compressed message's end before sending.
    private static final byte[] DEFLATE_TAIL = {0, 0, (byte) 0xFF, (byte) 0xFF};

    private static final VarHandle LONGS =
        MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    public static String computeAccept(String key) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update((key + ACCEPT_GUID).getBytes(StandardCharsets.ISO_8859_1));
            return Base64.getEncoder().encodeToString(sha1.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * True for status codes an endpoint may put on the wire (RFC 6455 §7.4
     * and the IANA registry): 1000-1003, 1007-1014, 3000-4999. 1004 is
     * reserved; 1005, 1006 and 1015 are local-only; 1016-2999 are reserved
     * for future protocol revisions.
     */
    static boolean isValidCloseCode(int code) {
        return (code >= 1000 && code <= 1003)
            || (code >= 1007 && code <= 1014)
            || (code >= 3000 && code <= 4999);
    }

    /**
     * {@code reason} as UTF-8, cut at a character boundary to fit a CLOSE
     * frame (123 bytes).
     */
    static byte[] closeReasonBytes(String reason) {
        byte[] b = reason.getBytes(StandardCharsets.UTF_8);
        if (b.length <= MAX_CLOSE_REASON) {
            return b;
        }
        // b[end] is the first byte left out: while it continues a
        // character, that character would be split, so leave it out whole.
        int end = MAX_CLOSE_REASON;
        while (end > 0 && (b[end] & 0xC0) == 0x80) {
            end--;
        }
        return Arrays.copyOf(b, end);
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final WebSocketListener listener;
    private final int idleTimeoutMillis;
    private final int messageTimeoutMillis;
    private final int closeTimeoutMillis;
    private final int pingIntervalMillis;
    private final int maxQueuedBytes;
    // Negotiated permessage-deflate, or null.
    private final PerMessageDeflate deflate;
    private final Timer timer;
    // :max-buffered-bytes, charged for queued sends and large incoming
    // messages.
    private final MemoryBudget budget;
    // Drops TCP if the peer never answers a CLOSE the server sent.
    private final Timer.Task closeTimer = new Timer.Task() {
        @Override
        protected void onTimeout() {
            // Closing may block (SO_LINGER): off the timer thread.
            Thread.ofVirtual().name("enso-ws-close-timeout").start(WebSocketConnection.this::forceClose);
        }
    };
    private final WebSocketSocket socketApi;

    // ---- Send state ----
    // ReentrantLock rather than synchronized: writes block on the socket
    // and must not pin the carrier of a virtual thread.
    private final ReentrantLock writeLock = new ReentrantLock();
    // True until a CLOSE has been sent (or TCP dropped); gates every send.
    // Cleared under queueLock by sendClose, so nothing is queued after the
    // queue was flushed ahead of the CLOSE.
    private volatile boolean open = true;
    // Written under writeLock; at most one CLOSE frame is ever sent.
    // Volatile so the read loop can check it without the lock, which a
    // stalled writer may hold.
    private volatile boolean closeSent;
    // Guarded by writeLock: frame header, control payload and compression
    // scratch.
    private final byte[] headerOut = new byte[10];
    private final byte[] controlOut = new byte[MAX_CONTROL_PAYLOAD];
    // Staging for a large frame's header and first payload bytes, and for
    // direct ByteBuffer payloads; allocated on first use.
    private byte[] gatherOut;
    private byte[] deflateOut = EMPTY;

    // ---- Send queue, guarded by queueLock (never held across I/O) ----
    private final ReentrantLock queueLock = new ReentrantLock();
    // Volatile so a sender can see an empty queue without the lock.
    private volatile Outgoing queueHead;
    private Outgoing queueTail;
    private long queuedBytes;
    // The queued PONG not taken by a writer yet: a later one replaces its
    // payload (RFC 6455 §5.5.3), so a ping flood leaves one pending pong.
    private Outgoing pendingPong;
    // Set when the connection ended: nothing is queued any more.
    private volatile boolean terminated;
    // Writes queued frames; started on demand, ends once idle a while.
    private Thread writer;
    private boolean writerIdle;

    // ---- Read state, owned by the read loop ----
    // Close state updated by CLOSE frames received in either the top-level
    // dispatch or interleaved between message fragments (RFC 6455 §5.4).
    private int closeCode = CLOSE_ABNORMAL;
    private String closeReason = "";
    private boolean closeReceived;
    // The server failed the connection: onClose reports its code, not the
    // peer's answer.
    private boolean failed;
    // Bytes of the current frame still unread when a failure was raised
    // with the frame stream intact, -1 when it can't be resumed. Skipped
    // before reading on, so the loop can wait for the peer's CLOSE.
    private long resyncSkip = -1;
    private long pendingSkip;
    // Buffered input. Bytes rbuf[rpos..rlim) have been read off the stream
    // but not consumed. Small while idle.
    private byte[] rbuf = new byte[READ_BUFFER_SIZE];
    private int rpos;
    private int rlim;
    // Unmasked payload of the current control frame (≤ 125 bytes).
    // Overwritten by every control frame.
    private final byte[] controlIn = new byte[MAX_CONTROL_PAYLOAD];
    // Reusable Frame instance returned by readFrame. Fields overwritten
    // per call; consumers use fields inline and don't retain references
    // to the Frame past the current dispatch.
    private final Frame currentFrame = new Frame();
    private final MessageReader reader;
    // A data message is being assembled: reads are bounded by the message
    // deadline rather than the idle timeout.
    private boolean inMessage;
    // Wall-clock end (System.nanoTime) of the frame or message being read,
    // started by its first read that had to wait for the socket.
    private boolean deadlineStarted;
    private long deadlineNanos;
    // SO_TIMEOUT last set on the socket, -1 before the first read.
    private int soTimeout = -1;
    // run() returned: the close timer must stay retired.
    private volatile boolean finished;
    // TCP was dropped (forceClose); ends a read loop's wait for budget.
    private volatile boolean socketClosed;
    // The read loop's thread, unparked by budgetWaiter and forceClose.
    private volatile Thread readThread;
    // Wakes the read loop when the memory budget has room; created on
    // first use.
    private MemoryBudget.Waiter budgetWaiter;

    public WebSocketConnection(Socket socket, InputStream in, OutputStream out,
                               WebSocketListener listener, Config config,
                               PerMessageDeflate deflate, Timer timer, MemoryBudget budget) {
        this.timer = timer;
        this.budget = budget;
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.listener = listener;
        this.idleTimeoutMillis = config.idleTimeoutMillis;
        this.messageTimeoutMillis = config.readTimeoutMillis;
        this.closeTimeoutMillis = config.wsCloseTimeoutMillis;
        this.pingIntervalMillis = config.wsPingIntervalMillis;
        this.maxQueuedBytes = config.wsMaxQueuedBytes;
        this.deflate = deflate;
        this.reader = new MessageReader(config.wsMaxMessageBytes);
        this.socketApi = new SocketImpl();
    }

    public WebSocketSocket socket() {
        return socketApi;
    }

    /**
     * Starts the closing handshake with 1001 "server shutting down"; the
     * read loop ends once the peer answers or the close timer fires.
     * No-op when a CLOSE was already sent.
     */
    public void shutdown() {
        try {
            socketApi.close(CLOSE_GOING_AWAY, "server shutting down");
        } catch (IOException ignored) {
        }
    }

    /**
     * Blocks the calling (virtual) thread reading frames until the connection
     * closes. On return the socket is guaranteed to be closed and either
     * {@link WebSocketListener#onClose} or {@link WebSocketListener#onError}
     * followed by {@code onClose} has been invoked exactly once.
     */
    public void run() {
        readThread = Thread.currentThread();
        try {
            try {
                listener.onOpen(socketApi);
            } catch (Throwable t) {
                // Nothing was read yet: the frame stream is intact, so the
                // peer's CLOSE can still be awaited.
                failConnection(CLOSE_INTERNAL_ERROR, INTERNAL_ERROR, t);
                resyncSkip = 0;
                resync();
            }
            readUntilClosed();
        } finally {
            finish();
        }
    }

    /**
     * Reads frames until the peer's CLOSE, EOF, or a failure. A failure
     * sends its CLOSE, then keeps reading (discarding) until the peer
     * answers when the frame stream is intact, or drains raw bytes after
     * half-closing when it isn't, so the CLOSE isn't lost to a TCP reset.
     */
    private void readUntilClosed() {
        while (true) {
            try {
                readFrames();
                return;
            } catch (WebSocketException e) {
                if (failed) {
                    return;
                }
                failConnection(e.code(), e.getMessage(), e);
                if (!resync()) {
                    linger();
                    return;
                }
            } catch (SocketTimeoutException e) {
                // Mid-frame or mid-message: the message deadline passed.
                if (failed || closeSent) {
                    return;
                }
                failConnection(CLOSE_POLICY_VIOLATION, "message timeout", e);
                linger();
                return;
            } catch (IOException e) {
                // After our CLOSE the peer may drop TCP instead of answering,
                // or the close timer fires: an expected end, not an error.
                if (!failed && !closeSent) {
                    notifyError(e);
                    closeCode = CLOSE_ABNORMAL;
                    closeReason = e.getMessage() == null ? "" : e.getMessage();
                }
                return;
            } catch (Throwable t) {
                // A failure of the server itself while reading (listener
                // failures are handled where they are called): the frame
                // stream's state is unknown.
                if (!failed) {
                    failConnection(CLOSE_INTERNAL_ERROR, INTERNAL_ERROR, t);
                }
                linger();
                return;
            }
        }
    }

    private void readFrames() throws IOException {
        while (!closeReceived) {
            if (pendingSkip > 0) {
                long n = pendingSkip;
                pendingSkip = 0;
                skipPayload(n);
            }
            Frame frame = readFrame();
            if (frame == null) {
                return;
            }
            if (frame == IDLE) {
                if (!closeOnIdle()) {
                    return;
                }
                continue;
            }
            if ((frame.opcode & 0x8) != 0) {
                handleControlFrame(frame);
                continue;
            }
            if (!open) {
                // Our CLOSE is out: data frames are read and dropped until
                // the peer's CLOSE arrives.
                if (inMessage) {
                    inMessage = false;
                    reader.abandon();
                }
                skipPayload(frame.length);
                continue;
            }
            if (frame.opcode == OP_CONTINUATION) {
                if (!inMessage) {
                    throw protocolError("unexpected CONTINUATION with no in-flight message");
                }
            } else {
                if (inMessage) {
                    throw protocolError("expected continuation frame, got opcode " + frame.opcode);
                }
                reader.start(frame.opcode, frame.fin, frame.length, frame.compressed);
                inMessage = true;
            }
            reader.readPayload(frame.length, frame.mask, frame.fin);
            if (frame.fin) {
                inMessage = false;
                Object message = reader.finish();
                // Messages completed after our CLOSE are dropped: the
                // server has already asked to close.
                if (open) {
                    try {
                        listener.onMessage(socketApi, message);
                    } catch (Throwable t) {
                        listenerFailed(t);
                    }
                }
                // The message is held until the listener returned.
                reader.releaseBudget();
            }
        }
    }

    /**
     * The idle timeout passed with no frame: start the closing handshake
     * with 1001. False when the server's CLOSE was already out, which ends
     * the read loop.
     */
    private boolean closeOnIdle() {
        if (closeSent) {
            return false;
        }
        closeCode = CLOSE_GOING_AWAY;
        closeReason = IDLE_TIMEOUT;
        if (sendClose(CLOSE_GOING_AWAY, IDLE_TIMEOUT_REASON)) {
            startCloseTimer();
        }
        return true;
    }

    private void handleControlFrame(Frame frame) throws IOException {
        int len = frame.controlLength;
        switch (frame.opcode) {
            case OP_PING, OP_PONG -> {
                // After our CLOSE nothing can be answered.
                if (!open) {
                    return;
                }
                // Copy so the listener can retain the buffer past the
                // next readFrame (which overwrites controlIn).
                byte[] copy = new byte[len];
                System.arraycopy(controlIn, 0, copy, 0, len);
                ByteBuffer bb = ByteBuffer.wrap(copy);
                try {
                    if (frame.opcode == OP_PING) listener.onPing(socketApi, bb);
                    else listener.onPong(socketApi, bb);
                } catch (Throwable t) {
                    listenerFailed(t);
                }
            }
            case OP_CLOSE -> {
                // The peer sends nothing after its CLOSE, whatever comes of
                // it: even a malformed one ends the read loop.
                closeReceived = true;
                resyncSkip = 0;
                int code = CLOSE_NO_STATUS;
                String reason = "";
                // RFC 6455 §5.5.1: CLOSE payload MUST be either 0 bytes
                // (no status) or ≥ 2 bytes (2-byte code + optional
                // reason). A 1-byte payload is a protocol error.
                if (len == 1) {
                    throw protocolError("CLOSE frame with 1-byte payload");
                }
                if (len >= 2) {
                    code = ((controlIn[0] & 0xFF) << 8) | (controlIn[1] & 0xFF);
                    if (!isValidCloseCode(code)) {
                        throw protocolError("invalid close code " + code);
                    }
                    if (len > 2) {
                        reason = decodeCloseReason(len - 2);
                    }
                }
                resyncSkip = -1;
                if (!failed) {
                    closeCode = code;
                    closeReason = reason;
                }
                // RFC 6455 §5.5.1: echo the received status code. An empty
                // CLOSE is answered with an empty CLOSE since 1005 MUST NOT
                // be sent on the wire (§7.4.1). No-op when this CLOSE
                // answers our own.
                sendClose(len == 0 ? -1 : code, EMPTY);
            }
            default -> throw protocolError("unknown control opcode: " + frame.opcode);
        }
    }

    private String decodeCloseReason(int len) throws WebSocketException {
        // RFC 6455 §7.1.6: CLOSE reason MUST be UTF-8.
        if (Utf8.validate(controlIn, 2, 2 + len, Utf8.ACCEPT) != Utf8.ACCEPT) {
            throw new WebSocketException(CLOSE_INVALID_UTF8, "invalid UTF-8 in CLOSE reason");
        }
        return new String(controlIn, 2, len, StandardCharsets.UTF_8);
    }

    /**
     * Fails the connection (RFC 6455 §7.1.7): sends CLOSE {@code code}
     * with {@code reason} (no-op when a CLOSE is already out), arms the
     * close timer and reports {@code cause} to the listener.
     */
    private void failConnection(int code, String reason, Throwable cause) {
        failed = true;
        closeCode = code;
        closeReason = reason;
        if (sendClose(code, closeReasonBytes(reason))) {
            startCloseTimer();
        }
        notifyError(cause);
    }

    /**
     * A listener callback threw, whatever its type: an IOException of the
     * listener's own I/O is not this connection's. Frames were consumed
     * whole, so the stream is intact: fail with 1011, drop a message in
     * progress and keep reading (discarding) until the peer's CLOSE.
     */
    private void listenerFailed(Throwable t) {
        if (failed) {
            return;
        }
        failConnection(CLOSE_INTERNAL_ERROR, INTERNAL_ERROR, t);
        if (inMessage) {
            inMessage = false;
            reader.abandon();
        }
    }

    /**
     * After a failure: true when the frame stream is intact, with the rest
     * of the failed frame scheduled to be skipped; the partial message is
     * dropped.
     */
    private boolean resync() {
        long skip = resyncSkip;
        resyncSkip = -1;
        if (skip < 0) {
            return false;
        }
        pendingSkip = skip;
        if (inMessage) {
            inMessage = false;
            reader.abandon();
        }
        return true;
    }

    /**
     * Lingering close for a broken frame stream: half-close so the peer
     * reads our CLOSE then EOF, and discard what it still sends until it
     * closes or the close timer drops the connection. Closing with unread
     * input would reset the connection and could destroy the CLOSE.
     */
    private void linger() {
        try {
            // Over TLS (TlsSocket.AdapterSocket) this sends close_notify,
            // then FIN, once any write in progress has released the lock.
            socket.shutdownOutput();
        } catch (IOException | RuntimeException ignored) {
            // Already closed (writing the CLOSE failed and force-closed the
            // socket): the reads below end at once.
        }
        try {
            rpos = 0;
            rlim = 0;
            while (fill(rbuf, 0, rbuf.length, idleTimeoutMillis) >= 0) {
                // discard
            }
        } catch (IOException ignored) {
        }
    }

    private void notifyError(Throwable t) {
        try {
            listener.onError(socketApi, t);
        } catch (Throwable ignored) {
        }
    }

    /** The read loop ended: release everything and report the close. */
    private void finish() {
        finished = true;
        forceClose();
        reader.releaseBudget();
        // retire: the wheel drops this connection on the next tick.
        timer.retire(closeTimer);
        Outgoing left;
        Thread w;
        long dropped;
        queueLock.lock();
        try {
            terminated = true;
            left = queueHead;
            queueHead = null;
            queueTail = null;
            pendingPong = null;
            dropped = queuedBytes;
            queuedBytes = 0;
            w = writer;
        } finally {
            queueLock.unlock();
        }
        // Outside the lock: a release may run budget waiters.
        budget.release(dropped);
        if (left != null) {
            IOException closed = new SendRejected(CLOSED);
            for (Outgoing o = left; o != null; o = o.next) {
                o.failure = closed;
            }
            complete(left);
        }
        if (w != null) {
            LockSupport.unpark(w);
        }
        if (deflate != null) {
            deflate.releaseInflater();
            // A writer may still be compressing; the socket is closed, so it
            // gives the lock up promptly. If not, the Deflater's cleaner
            // frees it once unreachable.
            if (tryLockWrites()) {
                try {
                    deflate.releaseDeflater();
                } finally {
                    writeLock.unlock();
                }
            }
        }
        try {
            listener.onClose(socketApi, closeCode, closeReason);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Drops TCP without a closing handshake. Doesn't take the write lock:
     * a writer blocked on a peer that stopped reading holds it, and closing
     * the socket is what unblocks that writer. A TLS socket is aborted
     * without close_notify, which would wait on that writer too.
     */
    private void forceClose() {
        open = false;
        socketClosed = true;
        try {
            TlsSocket.forceClose(socket);
        } catch (IOException ignored) {
        }
        Thread t = readThread;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    /**
     * Waits, between reads of a large message, while the memory budget is
     * exhausted: not reading lets TCP push back on the peer. Bounded by the
     * message deadline (a SocketTimeoutException, like a read).
     */
    private void awaitBudget() throws IOException {
        MemoryBudget.Waiter w = budgetWaiter;
        if (w == null) {
            w = new MemoryBudget.Waiter() {
                @Override
                protected void budgetAvailable() {
                    Thread t = readThread;
                    if (t != null) {
                        LockSupport.unpark(t);
                    }
                }
            };
            budgetWaiter = w;
        }
        while (budget.exhausted()) {
            if (socketClosed) {
                throw new EOFException("connection closed");
            }
            int timeout = messageReadTimeout();
            budget.await(w);
            if (!budget.exhausted()) {
                return;
            }
            if (timeout == 0) {
                LockSupport.park(this);
            } else {
                LockSupport.parkNanos(this, timeout * 1_000_000L);
            }
        }
    }

    // ---- Reading ----------------------------------------------------------

    // Returned by readFrame when the idle timeout passed between frames.
    private static final Frame IDLE = new Frame();

    /**
     * Reads the next frame header. For control frames the unmasked payload
     * is left in {@link #controlIn}; for data frames the caller reads the
     * payload with {@link MessageReader#readPayload}. Returns null on a
     * clean EOF between messages and {@link #IDLE} when the idle timeout
     * passed before a frame began.
     */
    private Frame readFrame() throws IOException {
        if (!inMessage) {
            deadlineStarted = false;
        }
        if (rpos == rlim) {
            rpos = 0;
            rlim = 0;
            int n;
            if (inMessage) {
                n = fill(rbuf, 0, rbuf.length, messageReadTimeout());
                if (n < 0) {
                    throw new EOFException("connection closed mid-message");
                }
            } else {
                n = awaitFrame();
                if (n == 0) {
                    return IDLE;
                }
                if (n < 0) {
                    return null;
                }
            }
            rlim = n;
        }
        require(2);
        int b0 = rbuf[rpos] & 0xFF;
        int b1 = rbuf[rpos + 1] & 0xFF;
        boolean fin = (b0 & 0x80) != 0;
        int opcode = b0 & 0x0F;
        boolean control = (opcode & 0x8) != 0;
        // RFC 6455 §5.2: RSV1/2/3 MUST be 0 unless an extension defines
        // them. permessage-deflate (RFC 7692 §6) gives RSV1 to the first
        // frame of a compressed data message.
        int rsv = b0 & 0x70;
        if (rsv != 0 && (rsv != RSV1 || deflate == null || control || opcode == OP_CONTINUATION)) {
            throw protocolError(deflate == null
                                ? "reserved bits set (no extensions negotiated)"
                                : "reserved bits set");
        }
        // RFC 6455 §5.2: opcodes 0x3-0x7 and 0xB-0xF are reserved.
        if (opcode > OP_BINARY && opcode != OP_CLOSE && opcode != OP_PING && opcode != OP_PONG) {
            throw protocolError("reserved opcode: " + opcode);
        }
        if ((b1 & 0x80) == 0) {
            // per RFC 6455, all client → server frames must be masked
            throw protocolError("unmasked client frame");
        }
        int lenCode = b1 & 0x7F;
        // RFC 6455 §5.5: control frames (opcode >= 0x8) MUST have payload
        // length ≤ 125 AND MUST NOT be fragmented (FIN=1).
        if (control) {
            if (lenCode > MAX_CONTROL_PAYLOAD) {
                throw protocolError("control frame payload > 125 bytes");
            }
            if (!fin) {
                throw protocolError("fragmented control frame");
            }
        }
        int extLen = lenCode == 126 ? 2 : lenCode == 127 ? 8 : 0;
        require(2 + extLen + 4);
        int p = rpos + 2;
        long payloadLen;
        if (lenCode == 126) {
            payloadLen = ((rbuf[p] & 0xFF) << 8) | (rbuf[p + 1] & 0xFF);
        } else if (lenCode == 127) {
            long len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | (rbuf[p + i] & 0xFF);
            }
            payloadLen = len;
        } else {
            payloadLen = lenCode;
        }
        p += extLen;
        // RFC 6455 §5.2: the most significant bit of a 64-bit length
        // MUST be 0.
        if (payloadLen < 0) {
            throw protocolError("64-bit payload length with MSB set");
        }
        // Mask bytes packed little-endian so byte k of the int masks
        // payload byte k (mod 4).
        int mask = (rbuf[p] & 0xFF) | (rbuf[p + 1] & 0xFF) << 8
            | (rbuf[p + 2] & 0xFF) << 16 | (rbuf[p + 3] & 0xFF) << 24;
        rpos = p + 4;
        Frame f = currentFrame;
        f.fin = fin;
        f.opcode = opcode;
        f.compressed = rsv != 0;
        f.length = payloadLen;
        f.mask = mask;
        if (control) {
            int plen = (int) payloadLen;
            readFully(controlIn, 0, plen);
            unmask(controlIn, 0, plen, mask, 0);
            f.controlLength = plen;
        }
        return f;
    }

    /**
     * Waits between messages for the next frame's first bytes, read into
     * rbuf: their count, -1 on EOF, 0 once {@code :idle-timeout} passed.
     * The wait is cut at what happens along it: after
     * {@link #IDLE_RELEASE_MILLIS} the connection gives back its grown
     * buffers, every {@code :ws-ping-interval} it pings the client. Times
     * are counted from the expired socket timeouts, which never fire
     * early, so the wait takes no clock reads.
     */
    private int awaitFrame() throws IOException {
        int idle = idleTimeoutMillis;
        int ping = pingIntervalMillis;
        boolean released = false;
        long waited = 0;
        long nextPing = ping;
        while (true) {
            long until = idle == 0 ? Long.MAX_VALUE : idle;
            if (!released) {
                until = Math.min(until, IDLE_RELEASE_MILLIS);
            }
            if (ping > 0) {
                until = Math.min(until, nextPing);
            }
            int n;
            try {
                n = fill(rbuf, 0, rbuf.length, until == Long.MAX_VALUE ? 0 : (int) (until - waited));
            } catch (SocketTimeoutException e) {
                waited = until;
                if (idle != 0 && waited >= idle) {
                    return 0;
                }
                if (!released && waited >= IDLE_RELEASE_MILLIS) {
                    releaseIdleBuffers();
                    released = true;
                }
                if (ping > 0 && waited >= nextPing) {
                    keepalivePing();
                    nextPing += ping;
                }
                continue;
            }
            if (n > 0 && rbuf.length < READ_BUFFER_SIZE) {
                byte[] full = new byte[READ_BUFFER_SIZE];
                System.arraycopy(rbuf, 0, full, 0, n);
                rbuf = full;
            }
            return n;
        }
    }

    /**
     * {@code :ws-ping-interval} passed without a frame: an empty PING,
     * which never waits for a stalled writer. Once our CLOSE is out there
     * is nothing to ping.
     */
    private void keepalivePing() {
        if (!open) {
            return;
        }
        try {
            sendControl(OP_PING, null);
        } catch (IOException ignored) {
            // Closed meanwhile: the read loop sees it.
        }
    }

    /**
     * An idle connection keeps only small buffers: the read buffer shrinks,
     * message assembly, compression and staging buffers and the TLS record
     * buffers are dropped (allocated again by the next message that needs
     * them). The send side is only touched when no write is in progress: a
     * writer stalled on the peer holds the lock.
     */
    private void releaseIdleBuffers() {
        if (rbuf.length > IDLE_READ_BUFFER_SIZE) {
            rbuf = new byte[IDLE_READ_BUFFER_SIZE];
        }
        reader.releaseIdle();
        if (writeLock.tryLock()) {
            try {
                gatherOut = null;
                deflateOut = EMPTY;
                if (socket instanceof TlsSocket.AdapterSocket tls) {
                    tls.tls().releaseIdleBuffers();
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    /**
     * Reads from the stream into {@code dst} with SO_TIMEOUT
     * {@code timeout}: the idle wait between messages; inside a frame or
     * message the message deadline ({@link #messageReadTimeout}), so a
     * peer trickling bytes can't hold a buffer longer than
     * {@code :read-timeout}.
     */
    private int fill(byte[] dst, int off, int len, int timeout) throws IOException {
        if (timeout != soTimeout) {
            socket.setSoTimeout(timeout);
            soTimeout = timeout;
        }
        return in.read(dst, off, len);
    }

    /** SO_TIMEOUT for a read inside a frame or message. */
    private int messageReadTimeout() throws SocketTimeoutException {
        if (messageTimeoutMillis == 0) {
            return idleTimeoutMillis;
        }
        long now = System.nanoTime();
        if (!deadlineStarted) {
            deadlineStarted = true;
            deadlineNanos = now + messageTimeoutMillis * 1_000_000L;
            return messageTimeoutMillis;
        }
        long left = deadlineNanos - now;
        if (left <= 0) {
            throw new SocketTimeoutException("message timeout");
        }
        return (int) Math.max(1, Math.min(left / 1_000_000L, Integer.MAX_VALUE));
    }

    /** Ensures at least {@code n} (≤ buffer size) unconsumed buffered bytes. */
    private void require(int n) throws IOException {
        if (rlim - rpos >= n) {
            return;
        }
        if (rpos + n > rbuf.length) {
            int avail = rlim - rpos;
            System.arraycopy(rbuf, rpos, rbuf, 0, avail);
            rpos = 0;
            rlim = avail;
        }
        while (rlim - rpos < n) {
            int r = fill(rbuf, rlim, rbuf.length - rlim, messageReadTimeout());
            if (r < 0) {
                throw new EOFException("truncated frame header");
            }
            rlim += r;
        }
    }

    /**
     * Reads between 1 and {@code max} payload bytes into {@code dst},
     * draining buffered bytes first. Large reads with an empty buffer go
     * straight from the stream into {@code dst} to skip a copy.
     */
    private int readSome(byte[] dst, int off, int max) throws IOException {
        int avail = rlim - rpos;
        if (avail == 0) {
            if (max >= rbuf.length) {
                int n = fill(dst, off, max, messageReadTimeout());
                if (n < 0) {
                    throw new EOFException("truncated frame payload");
                }
                return n;
            }
            rpos = 0;
            rlim = 0;
            int n = fill(rbuf, 0, rbuf.length, messageReadTimeout());
            if (n < 0) {
                throw new EOFException("truncated frame payload");
            }
            rlim = n;
            avail = n;
        }
        int n = Math.min(avail, max);
        System.arraycopy(rbuf, rpos, dst, off, n);
        rpos += n;
        return n;
    }

    private void readFully(byte[] dst, int off, int len) throws IOException {
        while (len > 0) {
            int n = readSome(dst, off, len);
            off += n;
            len -= n;
        }
    }

    /** Reads and drops {@code n} payload bytes. */
    private void skipPayload(long n) throws IOException {
        while (n > 0) {
            int avail = rlim - rpos;
            if (avail == 0) {
                rpos = 0;
                rlim = 0;
                int r = fill(rbuf, 0, rbuf.length, messageReadTimeout());
                if (r < 0) {
                    throw new EOFException("truncated frame payload");
                }
                rlim = r;
                avail = r;
            }
            int k = (int) Math.min(avail, n);
            rpos += k;
            n -= k;
        }
    }

    /**
     * XORs {@code data[off..off+n)} with the frame mask in place, 8 bytes at
     * a time. {@code phase} is the number of payload bytes of this frame
     * already unmasked, so a payload read in several steps stays aligned
     * with the 4-byte mask.
     */
    static void unmask(byte[] data, int off, int n, int mask, long phase) {
        int m = Integer.rotateRight(mask, (int) (phase & 3) << 3);
        long m64 = (m & 0xFFFFFFFFL) | ((long) m << 32);
        int i = off;
        int end = off + n;
        for (; i + 8 <= end; i += 8) {
            LONGS.set(data, i, (long) LONGS.get(data, i) ^ m64);
        }
        for (; i < end; i++) {
            data[i] ^= (byte) (m >>> (((i - off) & 3) << 3));
        }
    }

    // ---- Writing ----------------------------------------------------------

    /** A frame queued for the writer thread. */
    private static final class Outgoing {
        final int opcode;
        // Payload: array[offset..offset+length), or a direct buffer's
        // remaining bytes. A pending PONG's array and length are replaced
        // under queueLock until a writer takes it.
        byte[] array;
        final int offset;
        int length;
        final ByteBuffer direct;
        final WebSocketSocket.SendCallback callback;
        Throwable failure;
        Outgoing next;

        Outgoing(int opcode, byte[] array, int offset, int length, ByteBuffer direct,
                 WebSocketSocket.SendCallback callback) {
            this.opcode = opcode;
            this.array = array;
            this.offset = offset;
            this.length = length;
            this.direct = direct;
            this.callback = callback;
        }

        /**
         * Bytes charged while queued. A PONG is charged its largest size,
         * so replacing its payload changes nothing.
         */
        long cost() {
            return (opcode == OP_PONG ? MAX_CONTROL_PAYLOAD : length) + QUEUED_FRAME_OVERHEAD;
        }
    }

    /**
     * A send refused before it was queued (closed, queue full, budget).
     * Refusals are routine under back-pressure, so no stack trace is taken.
     */
    private static final class SendRejected extends IOException {
        SendRejected(String message) {
            super(message);
        }

        @Override
        public synchronized Throwable fillInStackTrace() {
            return this;
        }
    }

    /** {@code firstByte}: FIN, RSV1 and the opcode. */
    private void writeHeader(int firstByte, int len) throws IOException {
        out.write(headerOut, 0, putHeader(headerOut, firstByte, len));
    }

    /** Puts a frame header at the start of {@code header}; returns its length. */
    private static int putHeader(byte[] header, int firstByte, int len) {
        int hi = 0;
        header[hi++] = (byte) firstByte;
        if (len < 126) {
            header[hi++] = (byte) len;
        } else if (len <= 0xFFFF) {
            header[hi++] = 126;
            header[hi++] = (byte) ((len >>> 8) & 0xFF);
            header[hi++] = (byte) (len & 0xFF);
        } else {
            header[hi++] = 127;
            for (int i = 7; i >= 0; i--) {
                header[hi++] = (byte) ((((long) len) >>> (i * 8)) & 0xFF);
            }
        }
        return hi;
    }

    /**
     * Writes one frame (not flushed). The payload is {@code a[off..off+len)}
     * or, when {@code direct} is non-null, its remaining bytes, read
     * without moving its position. Data messages are compressed when
     * permessage-deflate is on and they are long enough. Caller holds
     * {@link #writeLock}.
     */
    private void writeFrameLocked(int opcode, byte[] a, int off, int len, ByteBuffer direct)
        throws IOException {
        if (deflate != null && (opcode == OP_TEXT || opcode == OP_BINARY)
            && deflate.compresses(len, COMPRESSION_THRESHOLD)) {
            writeCompressed(opcode, a, off, len, direct);
            return;
        }
        if (len < GATHER_MIN && direct == null) {
            // Header and payload join the output stream's buffer.
            writeHeader(FIN | opcode, len);
            if (len > 0) {
                out.write(a, off, len);
            }
            return;
        }
        byte[] staging = gatherOut;
        if (staging == null) {
            staging = new byte[GATHER_BYTES];
            gatherOut = staging;
        }
        int h = putHeader(staging, FIN | opcode, len);
        int first = Math.min(len, staging.length - h);
        if (direct != null) {
            direct.get(direct.position(), staging, h, first);
        } else {
            System.arraycopy(a, off, staging, h, first);
        }
        out.write(staging, 0, h + first);
        if (direct != null) {
            int pos = direct.position() + first;
            int end = direct.position() + len;
            while (pos < end) {
                int n = Math.min(staging.length, end - pos);
                direct.get(pos, staging, 0, n);
                out.write(staging, 0, n);
                pos += n;
            }
        } else if (first < len) {
            out.write(a, off + first, len - first);
        }
    }

    /**
     * Compresses one message (RFC 7692 §7.2.1: raw deflate, sync flush, the
     * trailing 00 00 FF FF left off) and writes it: one frame when the
     * output fits {@link #DEFLATE_CHUNK}, else a frame per chunk (RSV1 on
     * the first only, §6.1). The last 4 bytes of output are always held
     * back, since they may be the start of the tail to drop. Caller holds
     * {@link #writeLock}: consecutive messages share the Deflater's
     * window, so they compress in wire order.
     */
    private void writeCompressed(int opcode, byte[] a, int off, int len, ByteBuffer direct)
        throws IOException {
        Deflater d = deflate.deflater();
        if (direct != null) {
            d.setInput(direct.duplicate());
        } else {
            d.setInput(a, off, len);
        }
        byte[] buf = deflateOut;
        if (buf.length == 0) {
            buf = new byte[Math.min(DEFLATE_CHUNK, Math.max(1024, len >>> 1))];
        }
        int tail = DEFLATE_TAIL.length;
        int firstByte = RSV1 | opcode;
        try {
            int pos = 0;
            while (true) {
                pos += d.deflate(buf, pos, buf.length - pos, Deflater.SYNC_FLUSH);
                if (pos < buf.length) {
                    // Input consumed and flushed.
                    break;
                }
                if (buf.length < DEFLATE_CHUNK) {
                    buf = Arrays.copyOf(buf, Math.min(DEFLATE_CHUNK, buf.length * 2));
                    deflateOut = buf;
                    continue;
                }
                int n = pos - tail;
                writeHeader(firstByte, n);
                out.write(buf, 0, n);
                System.arraycopy(buf, n, buf, 0, tail);
                pos = tail;
                firstByte = OP_CONTINUATION;
            }
            writeHeader(FIN | firstByte, pos - tail);
            out.write(buf, 0, pos - tail);
        } finally {
            deflateOut = buf;
            // The Deflater outlives the message: let go of the caller's
            // array or buffer.
            d.setInput(EMPTY);
            deflate.deflated();
        }
    }

    /**
     * Takes every queued frame and writes it, in order, then flushes.
     * Caller holds {@link #writeLock}. Returns the chain for
     * {@link #complete} (to run after unlocking), or null when nothing was
     * queued. A write failure fails every frame of the chain and drops the
     * connection. {@code markIdle}: an empty queue parks the writer thread.
     */
    private Outgoing writeQueued(boolean markIdle) {
        if (queueHead == null && !markIdle) {
            return null;
        }
        Outgoing chain;
        long taken;
        queueLock.lock();
        try {
            chain = queueHead;
            if (chain == null) {
                if (markIdle) {
                    writerIdle = true;
                }
                return null;
            }
            queueHead = null;
            queueTail = null;
            pendingPong = null;
            taken = queuedBytes;
            queuedBytes = 0;
        } finally {
            queueLock.unlock();
        }
        try {
            for (Outgoing o = chain; o != null; o = o.next) {
                writeFrameLocked(o.opcode, o.array, o.offset, o.length, o.direct);
            }
            out.flush();
        } catch (IOException | RuntimeException e) {
            forceClose();
            for (Outgoing o = chain; o != null; o = o.next) {
                o.failure = e;
            }
        } finally {
            budget.release(taken);
        }
        return chain;
    }

    /** Runs the callbacks of a written chain. */
    private static void complete(Outgoing chain) {
        for (Outgoing o = chain; o != null; o = o.next) {
            WebSocketSocket.SendCallback cb = o.callback;
            if (cb == null) {
                continue;
            }
            try {
                if (o.failure == null) {
                    cb.onSuccess();
                } else {
                    cb.onFailure(o.failure);
                }
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * Synchronous send of one data frame: writes what is queued, then this
     * frame, on the caller's thread. Bounded by {@code :write-timeout}
     * through the connection's write watchdog.
     */
    private void send(int opcode, byte[] a, int off, int len, ByteBuffer direct) throws IOException {
        Outgoing written = null;
        writeLock.lock();
        try {
            if (!open) {
                throw new IOException(CLOSED);
            }
            written = writeQueued(false);
            if (!open) {
                throw new IOException(CLOSED);
            }
            try {
                writeFrameLocked(opcode, a, off, len, direct);
                out.flush();
            } catch (IOException | RuntimeException e) {
                // A partial frame can't be followed by anything.
                forceClose();
                throw e;
            }
        } finally {
            writeLock.unlock();
            complete(written);
        }
    }

    /**
     * PING / PONG: written at once when no write is in progress, otherwise
     * queued behind it, so neither the read loop's automatic pong nor a
     * keep-alive ping ever waits for a stalled writer.
     */
    private void sendControl(int opcode, ByteBuffer data) throws IOException {
        int len = data == null ? 0 : data.remaining();
        if (len > MAX_CONTROL_PAYLOAD) {
            throw new IllegalArgumentException(
                "control frame payload exceeds " + MAX_CONTROL_PAYLOAD + " bytes");
        }
        if (writeLock.tryLock()) {
            Outgoing written = null;
            try {
                if (!open) {
                    throw new IOException(CLOSED);
                }
                written = writeQueued(false);
                if (!open) {
                    throw new IOException(CLOSED);
                }
                try {
                    if (len > 0) {
                        data.get(data.position(), controlOut, 0, len);
                    }
                    writeHeader(FIN | opcode, len);
                    out.write(controlOut, 0, len);
                    out.flush();
                } catch (IOException | RuntimeException e) {
                    forceClose();
                    throw e;
                }
            } finally {
                writeLock.unlock();
                complete(written);
            }
            return;
        }
        byte[] copy = len == 0 ? EMPTY : new byte[len];
        if (len > 0) {
            data.get(data.position(), copy, 0, len);
        }
        String rejected = enqueue(new Outgoing(opcode, copy, 0, len, null, null));
        if (rejected != null) {
            throw new SendRejected(rejected);
        }
    }

    private void sendAsync(Outgoing o) {
        String rejected = enqueue(o);
        if (rejected != null) {
            try {
                o.callback.onFailure(new SendRejected(rejected));
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * Queues {@code o} for the writer thread, starting or waking it, or
     * gives its payload to the PONG already pending. Returns why it was
     * refused (closed, over {@code :ws-max-queued-bytes} with something
     * already queued, the memory budget), or null.
     */
    private String enqueue(Outgoing o) {
        Thread start = null;
        Thread wake = null;
        long cost = o.cost();
        queueLock.lock();
        try {
            if (!open || terminated) {
                return CLOSED;
            }
            if (o.opcode == OP_PONG && pendingPong != null) {
                pendingPong.array = o.array;
                pendingPong.length = o.length;
                return null;
            }
            if (maxQueuedBytes > 0 && queuedBytes > 0 && queuedBytes + cost > maxQueuedBytes) {
                return QUEUE_FULL;
            }
            // Server-wide: what every connection queues counts against
            // :max-buffered-bytes; past it sends are refused, not buffered.
            if (!budget.tryReserve(cost)) {
                return BUDGET_EXHAUSTED;
            }
            if (queueTail == null) {
                queueHead = o;
            } else {
                queueTail.next = o;
            }
            queueTail = o;
            queuedBytes += cost;
            if (o.opcode == OP_PONG) {
                pendingPong = o;
            }
            if (writer == null) {
                writer = Thread.ofVirtual().name("enso-ws-writer").unstarted(this::drainQueue);
                start = writer;
            } else if (writerIdle) {
                writerIdle = false;
                wake = writer;
            }
        } finally {
            queueLock.unlock();
        }
        if (start != null) {
            start.start();
        } else if (wake != null) {
            LockSupport.unpark(wake);
        }
        return null;
    }

    /**
     * The writer thread: writes queued frames, parks when there are none
     * and ends after {@link #WRITER_LINGER_NANOS} without any, so an idle
     * connection keeps no thread besides its read loop. It clears
     * {@link #writer} under queueLock only while the queue is empty, so a
     * send either finds it running (and wakes it) or starts another.
     */
    private void drainQueue() {
        boolean lingered = false;
        while (true) {
            Outgoing written;
            writeLock.lock();
            try {
                written = writeQueued(true);
            } finally {
                writeLock.unlock();
            }
            if (written != null) {
                complete(written);
                lingered = false;
                continue;
            }
            if (terminated) {
                return;
            }
            if (lingered) {
                queueLock.lock();
                try {
                    if (queueHead == null) {
                        writer = null;
                        writerIdle = false;
                        return;
                    }
                } finally {
                    queueLock.unlock();
                }
                lingered = false;
                continue;
            }
            LockSupport.parkNanos(this, WRITER_LINGER_NANOS);
            lingered = true;
        }
    }

    private boolean tryLockWrites() {
        try {
            return writeLock.tryLock(closeTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Sends this endpoint's single CLOSE frame: {@code code} plus
     * {@code reason}, or an empty payload when {@code code} is negative.
     * Stops all further sends; frames queued before it go out first.
     * Waits for a writer in progress at most {@code :ws-close-timeout}.
     * Returns true if this call put the CLOSE on the wire; false if one was
     * already sent or it couldn't be written, in which case TCP is dropped.
     */
    private boolean sendClose(int code, byte[] reason) {
        queueLock.lock();
        try {
            open = false;
        } finally {
            queueLock.unlock();
        }
        if (!tryLockWrites()) {
            forceClose();
            return false;
        }
        Outgoing written = null;
        try {
            if (closeSent) {
                return false;
            }
            closeSent = true;
            written = writeQueued(false);
            int len = 0;
            if (code >= 0) {
                controlOut[0] = (byte) ((code >>> 8) & 0xFF);
                controlOut[1] = (byte) (code & 0xFF);
                System.arraycopy(reason, 0, controlOut, 2, reason.length);
                len = 2 + reason.length;
            }
            writeHeader(FIN | OP_CLOSE, len);
            out.write(controlOut, 0, len);
            out.flush();
            return true;
        } catch (IOException e) {
            forceClose();
            return false;
        } finally {
            writeLock.unlock();
            complete(written);
        }
    }

    /**
     * Arms the timer that drops TCP if the peer never answers our CLOSE.
     * A close sent from another thread can race the read loop's end: if the
     * loop already finished (and retired the timer), retire it again.
     */
    private void startCloseTimer() {
        timer.schedule(closeTimer, closeTimeoutMillis);
        if (finished) {
            timer.retire(closeTimer);
        }
    }

    /**
     * Reusable frame descriptor. Fields are overwritten by every
     * {@link #readFrame} call — consumers must finish using them before
     * the next read. A control frame's payload lives in
     * {@link #controlIn}; retain by copying, never by reference.
     */
    private static final class Frame {
        boolean fin;
        int opcode;
        boolean compressed;
        long length;
        int mask;
        int controlLength;
    }

    /**
     * Reassembles one data message from its frames. Payload bytes are read
     * from the connection straight into the message buffer and unmasked in
     * place; compressed messages are inflated into it as their frames
     * arrive, bounded by the message limit. Text is validated as UTF-8 as
     * it arrives, so an invalid message fails at the frame holding the
     * first invalid byte (Autobahn §6.4), and decoded into the message
     * String once, at its end.
     */
    private final class MessageReader {
        private static final int INITIAL = 4 * 1024;
        // A retained buffer is released after this many messages in a row
        // that used under a quarter of it.
        private static final int SHRINK_AFTER = 8;

        private final int limit;
        // permessage-deflate messages may not be larger compressed than
        // the limit plus deflate's worst-case stored-block overhead.
        private final long compressedLimit;
        private int opcode;
        private boolean compressed;
        // Compressed bytes read so far.
        private long compressedSize;
        // The message so far (decompressed): buf[0..len). buf is scratch,
        // or an exact-size array for a single-frame binary message, handed
        // to the listener without a copy.
        private byte[] scratch = EMPTY;
        private byte[] buf = EMPTY;
        private int len;
        private int smallMessages;
        // Text: the UTF-8 validation state after buf[0..len).
        private int utf8State;
        // Bytes of this message charged to the memory budget.
        private long charged;
        // Compressed payload read off the wire, before inflating.
        private byte[] inflateIn;

        MessageReader(int limit) {
            this.limit = limit;
            this.compressedLimit = limit + (limit >>> 10) + 1024L;
        }

        void start(int opcode, boolean fin, long firstFrameLength, boolean compressed) {
            this.opcode = opcode;
            this.compressed = compressed;
            this.compressedSize = 0;
            this.len = 0;
            this.utf8State = Utf8.ACCEPT;
            if (opcode == OP_BINARY && !compressed && fin
                && firstFrameLength <= READ_STEP && firstFrameLength <= limit) {
                // A single-frame binary message of trusted size gets its
                // own exact array so finish() can hand it over without
                // copying.
                buf = firstFrameLength == 0 ? EMPTY : new byte[(int) firstFrameLength];
            } else {
                buf = scratch;
            }
        }

        void readPayload(long frameLength, int mask, boolean fin) throws IOException {
            if (compressed) {
                readCompressed(frameLength, mask, fin);
                return;
            }
            // Written as a subtraction so len + frameLength can't overflow.
            if (frameLength > limit - len) {
                throw tooBig(frameLength);
            }
            long remaining = frameLength;
            long done = 0;
            while (remaining > 0) {
                int step = (int) Math.min(remaining, READ_STEP);
                if (len + step > UNCHARGED_MESSAGE_BYTES && budget.exhausted()) {
                    awaitBudget();
                }
                ensureCapacity(len + step);
                int from = len;
                int n = readSome(buf, from, step);
                unmask(buf, from, n, mask, done);
                len += n;
                done += n;
                remaining -= n;
                chargeGrowth();
                if (opcode == OP_TEXT) {
                    validate(from, remaining);
                }
            }
        }

        /** Charges what the message holds past the uncharged allowance. */
        private void chargeGrowth() {
            long over = len - (long) UNCHARGED_MESSAGE_BYTES;
            if (over > charged) {
                budget.charge(over - charged);
                charged = over;
            }
        }

        /** Gives back what this message charged (delivered or dropped). */
        void releaseBudget() {
            if (charged > 0) {
                budget.release(charged);
                charged = 0;
            }
        }

        private WebSocketException tooBig(long unreadFrameBytes) {
            resyncSkip = unreadFrameBytes;
            return new WebSocketException(CLOSE_MESSAGE_TOO_BIG, "message exceeds " + limit + " bytes");
        }

        /**
         * RFC 6455 §5.6 + §8.1: text messages MUST be valid UTF-8; invalid
         * → CLOSE(1007), detected at the offending frame.
         */
        private void validate(int from, long unreadFrameBytes) throws WebSocketException {
            utf8State = Utf8.validate(buf, from, len, utf8State);
            if (utf8State == Utf8.REJECT) {
                resyncSkip = unreadFrameBytes;
                throw new WebSocketException(CLOSE_INVALID_UTF8, "invalid UTF-8 in text message");
            }
        }

        private void readCompressed(long frameLength, int mask, boolean fin) throws IOException {
            if (frameLength > compressedLimit - compressedSize) {
                throw tooBig(frameLength);
            }
            compressedSize += frameLength;
            Inflater inflater = deflate.inflater();
            byte[] cin = inflateIn;
            if (cin == null) {
                cin = new byte[READ_BUFFER_SIZE];
                inflateIn = cin;
            }
            long remaining = frameLength;
            long done = 0;
            while (remaining > 0) {
                if (len > UNCHARGED_MESSAGE_BYTES && budget.exhausted()) {
                    awaitBudget();
                }
                int n = readSome(cin, 0, (int) Math.min(remaining, cin.length));
                unmask(cin, 0, n, mask, done);
                done += n;
                remaining -= n;
                inflater.setInput(cin, 0, n);
                inflate(inflater, cin, n, true, remaining);
            }
            if (fin) {
                inflater.setInput(DEFLATE_TAIL);
                inflate(inflater, DEFLATE_TAIL, DEFLATE_TAIL.length, false, 0);
            }
        }

        /**
         * Inflates {@code input[0..inputLength)}, already set as the
         * inflater's input, into the message, stopping with 1009 as soon
         * as the output passes the limit, so a small compressed message
         * can't expand without bound.
         *
         * <p>A block with BFINAL set ends java.util.zip's stream, but not
         * the message (RFC 7692 §7.2.3.1: the next block follows): the
         * inflater starts over and inflates the rest of the input when
         * {@code inputContinues}. The appended tail is a flush marker, so
         * what is left of it is dropped.
         */
        private void inflate(Inflater inflater, byte[] input, int inputLength, boolean inputContinues,
                             long unreadFrameBytes) throws IOException {
            while (true) {
                if (len == buf.length) {
                    growForInflate();
                }
                int from = len;
                int n;
                try {
                    n = inflater.inflate(buf, from, buf.length - from);
                } catch (DataFormatException e) {
                    resyncSkip = unreadFrameBytes;
                    throw new WebSocketException(CLOSE_INVALID_UTF8, "invalid compressed data");
                }
                len += n;
                if (len > limit) {
                    throw tooBig(unreadFrameBytes);
                }
                chargeGrowth();
                if (n == 0) {
                    if (!inflater.finished()) {
                        break;
                    }
                    int rest = inflater.getRemaining();
                    restartAfterFinalBlock(inflater);
                    if (rest == 0 || !inputContinues) {
                        break;
                    }
                    inflater.setInput(input, inputLength - rest, rest);
                    continue;
                }
                if (opcode == OP_TEXT) {
                    validate(from, unreadFrameBytes);
                }
            }
            if (inflater.needsDictionary()) {
                resyncSkip = unreadFrameBytes;
                throw new WebSocketException(CLOSE_INVALID_UTF8, "invalid compressed data");
            }
        }

        /**
         * A new stream after a final block. Context takeover keeps the
         * LZ77 window across it (RFC 7692 §7.2.3.4), so the window is
         * restored as a preset dictionary from this message's output: up
         * to 32 KiB, which covers back-references into this message;
         * java.util.zip can't hand over what the window held of earlier
         * messages.
         */
        private void restartAfterFinalBlock(Inflater inflater) {
            inflater.reset();
            int window = Math.min(len, 32 * 1024);
            if (window > 0) {
                inflater.setDictionary(buf, len - window, window);
            }
        }

        /** Room for inflated output, up to one byte past the limit. */
        private void growForInflate() {
            int cap = (int) Math.min((long) limit + 1, Integer.MAX_VALUE);
            int newLen = (int) Math.min(cap, Math.max(INITIAL, 2L * buf.length));
            byte[] bigger = new byte[newLen];
            System.arraycopy(buf, 0, bigger, 0, len);
            buf = bigger;
            scratch = bigger;
        }

        private void ensureCapacity(int needed) {
            if (needed <= buf.length) {
                return;
            }
            int newLen = (int) Math.min(limit, Math.max(needed, Math.max(INITIAL, 2L * buf.length)));
            byte[] bigger = new byte[newLen];
            System.arraycopy(buf, 0, bigger, 0, len);
            buf = bigger;
            scratch = bigger;
        }

        Object finish() throws IOException {
            if (opcode == OP_TEXT) {
                if (utf8State != Utf8.ACCEPT) {
                    resyncSkip = 0;
                    throw new WebSocketException(CLOSE_INVALID_UTF8, "truncated UTF-8 sequence at message end");
                }
                String s = len == 0 ? "" : new String(buf, 0, len, StandardCharsets.UTF_8);
                recycle(len);
                return s;
            }
            byte[] data = buf;
            if (data != scratch && data.length == len) {
                buf = scratch;
                return ByteBuffer.wrap(data);
            }
            ByteBuffer message = ByteBuffer.wrap(Arrays.copyOf(data, len));
            recycle(len);
            return message;
        }


        /** Between messages, idle: drops the retained buffers. */
        void releaseIdle() {
            scratch = EMPTY;
            buf = EMPTY;
            len = 0;
            smallMessages = 0;
            inflateIn = null;
        }

        /** Drops a message cut short by a failure or our CLOSE. */
        void abandon() {
            buf = scratch;
            len = 0;
            releaseBudget();
        }

        // Keeps the assembly buffer for messages of a similar size, so a
        // stream of 100 KiB messages doesn't regrow it from a few KiB each
        // time; releases one that is too large, or that recent messages
        // stopped needing.
        private void recycle(int used) {
            int cap = scratch.length;
            if (cap > RETAIN_MAX) {
                scratch = EMPTY;
                smallMessages = 0;
            } else if (cap > INITIAL && used <= cap >>> 2) {
                if (++smallMessages >= SHRINK_AFTER) {
                    scratch = EMPTY;
                    smallMessages = 0;
                }
            } else {
                smallMessages = 0;
            }
            buf = scratch;
        }
    }

    private static WebSocketException protocolError(String msg) {
        return new WebSocketException(CLOSE_PROTOCOL_ERROR, msg);
    }

    private final class SocketImpl implements WebSocketSocket {

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void sendText(CharSequence message) throws IOException {
            // String.getBytes is a single intrinsic copy for ASCII/Latin-1
            // strings; encoding into a reused buffer would be slower.
            byte[] bytes = message.toString().getBytes(StandardCharsets.UTF_8);
            send(OP_TEXT, bytes, 0, bytes.length, null);
        }

        @Override
        public void sendBinary(ByteBuffer message) throws IOException {
            if (message == null) {
                send(OP_BINARY, EMPTY, 0, 0, null);
            } else if (message.hasArray()) {
                send(OP_BINARY, message.array(), message.arrayOffset() + message.position(),
                     message.remaining(), null);
            } else {
                send(OP_BINARY, EMPTY, 0, message.remaining(), message);
            }
        }

        @Override
        public void sendTextAsync(CharSequence message, SendCallback callback) {
            byte[] bytes = message.toString().getBytes(StandardCharsets.UTF_8);
            sendAsync(new Outgoing(OP_TEXT, bytes, 0, bytes.length, null, callback));
        }

        @Override
        public void sendBinaryAsync(ByteBuffer message, SendCallback callback) {
            if (message == null) {
                sendAsync(new Outgoing(OP_BINARY, EMPTY, 0, 0, null, callback));
            } else if (message.hasArray()) {
                sendAsync(new Outgoing(OP_BINARY, message.array(), message.arrayOffset() + message.position(),
                                       message.remaining(), null, callback));
            } else {
                sendAsync(new Outgoing(OP_BINARY, EMPTY, 0, message.remaining(), message, callback));
            }
        }

        @Override
        public void sendPing(ByteBuffer data) throws IOException {
            sendControl(OP_PING, data);
        }

        @Override
        public void sendPong(ByteBuffer data) throws IOException {
            sendControl(OP_PONG, data);
        }

        @Override
        public void close(int code, String reason) throws IOException {
            if (!isValidCloseCode(code)) {
                throw new IllegalArgumentException("invalid close code " + code);
            }
            byte[] reasonBytes = reason == null ? EMPTY : reason.getBytes(StandardCharsets.UTF_8);
            if (reasonBytes.length > MAX_CLOSE_REASON) {
                throw new IllegalArgumentException(
                    "close reason exceeds " + MAX_CLOSE_REASON + " UTF-8 bytes");
            }
            if (!open) {
                return;
            }
            // RFC 6455 §7.1.2: after sending CLOSE, keep reading until the
            // peer's CLOSE arrives; the read loop then drops TCP. The
            // timer bounds the wait for a peer that never answers.
            if (sendClose(code, reasonBytes)) {
                startCloseTimer();
            }
        }
    }
}

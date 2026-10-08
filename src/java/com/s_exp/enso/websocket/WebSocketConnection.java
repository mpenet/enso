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
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import com.s_exp.enso.core.TlsSocket;

/**
 * RFC 6455 WebSocket connection driver. Reads frames, dispatches events to a
 * {@link WebSocketListener}, and exposes a {@link WebSocketSocket} for
 * server-initiated sends. Continuation frames are reassembled into a single
 * text or binary message (bounded by {@code maxMessageBytes}); pings are
 * auto-responded by the default listener implementation. Protocol
 * violations fail the connection with the matching CLOSE status (§7.1.7);
 * a server-initiated close waits for the peer's CLOSE before dropping TCP.
 */
public final class WebSocketConnection {

    private static final String ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    static final int OP_CONTINUATION = 0x0;
    static final int OP_TEXT = 0x1;
    static final int OP_BINARY = 0x2;
    static final int OP_CLOSE = 0x8;
    static final int OP_PING = 0x9;
    static final int OP_PONG = 0xA;

    static final int CLOSE_NORMAL = 1000;
    static final int CLOSE_GOING_AWAY = 1001;
    static final int CLOSE_PROTOCOL_ERROR = 1002;
    static final int CLOSE_UNSUPPORTED_DATA = 1003;
    static final int CLOSE_NO_STATUS = 1005;
    static final int CLOSE_ABNORMAL = 1006;
    static final int CLOSE_INVALID_UTF8 = 1007;
    static final int CLOSE_MESSAGE_TOO_BIG = 1009;
    static final int CLOSE_INTERNAL_ERROR = 1011;

    // RFC 6455 §5.5: control frame payloads are at most 125 bytes, so a
    // CLOSE reason is at most 123 bytes after the 2-byte code.
    static final int MAX_CONTROL_PAYLOAD = 125;
    static final int MAX_CLOSE_REASON = MAX_CONTROL_PAYLOAD - 2;

    // How long a server-initiated close waits for the peer's CLOSE before
    // dropping TCP. Also bounds the wait for the write lock when a CLOSE
    // queues behind a writer stalled on a peer that stopped reading.
    static final long CLOSE_TIMEOUT_MILLIS = 5000;

    // Frame headers and small payloads are read through this buffer so a
    // frame costs one read() call, not one per header byte.
    private static final int READ_BUFFER_SIZE = 8192;
    // A frame's claimed length is only trusted as bytes arrive: payloads
    // are read in steps of at most this many bytes, and the message buffer
    // grows per step rather than up-front from the header.
    private static final int READ_STEP = 64 * 1024;

    private static final byte[] EMPTY = new byte[0];
    private static final byte[] IDLE_TIMEOUT_REASON = "idle timeout".getBytes(StandardCharsets.UTF_8);

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

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final WebSocketListener listener;
    private final int maxMessageBytes;
    // ReentrantLock rather than synchronized: writes block on the socket
    // and must not pin the carrier of a virtual thread.
    private final ReentrantLock writeLock = new ReentrantLock();
    // True until a CLOSE has been sent; gates every send.
    private volatile boolean open = true;
    // Written under writeLock; at most one CLOSE frame is ever sent.
    // Volatile so the read loop can check it without the lock, which a
    // stalled writer may hold.
    private volatile boolean closeSent;
    // Guarded by writeLock: frame header and control payload scratch.
    private final byte[] headerOut = new byte[10];
    private final byte[] controlOut = new byte[MAX_CONTROL_PAYLOAD];
    // Guarded by writeLock: staging for direct ByteBuffer payloads,
    // allocated on first use.
    private byte[] directOut;
    // Drops TCP if the peer never answers a server-initiated CLOSE.
    private volatile Thread closeTimer;
    private final WebSocketSocket socketApi;
    // Close state updated by CLOSE frames received in either the top-level
    // dispatch or interleaved between message fragments (RFC 6455 §5.4).
    private int closeCode = CLOSE_ABNORMAL;
    private String closeReason = "";
    private boolean closeReceived;
    // Buffered input, owned by the read vthread — no locking. Bytes
    // rbuf[rpos..rlim) have been read off the stream but not consumed.
    private final byte[] rbuf = new byte[READ_BUFFER_SIZE];
    private int rpos;
    private int rlim;
    // Unmasked payload of the current control frame (≤ 125 bytes).
    // Overwritten by every control frame; owned by the read vthread.
    private final byte[] controlIn = new byte[MAX_CONTROL_PAYLOAD];
    // Reusable Frame instance returned by readFrame. Fields overwritten
    // per call; consumers use fields inline and don't retain references
    // to the Frame past the current dispatch.
    private final Frame currentFrame = new Frame();

    public WebSocketConnection(Socket socket, InputStream in, OutputStream out,
                        WebSocketListener listener, int maxMessageBytes) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.listener = listener;
        this.maxMessageBytes = maxMessageBytes;
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
        closeCode = CLOSE_ABNORMAL;
        closeReason = "";
        try {
            listener.onOpen(socketApi);
        } catch (Throwable t) {
            try {
                listener.onError(socketApi, t);
            } catch (Throwable ignored) {
            }
            sendClose(CLOSE_INTERNAL_ERROR, EMPTY);
            forceClose();
            try {
                listener.onClose(socketApi, CLOSE_INTERNAL_ERROR, "");
            } catch (Throwable ignored) {
            }
            return;
        }

        try {
            MessageAccumulator accumulator = new MessageAccumulator(maxMessageBytes);
            while (!closeReceived) {
                Frame frame = readFrame();
                if (frame == null) {
                    break;
                }
                if ((frame.opcode & 0x8) != 0) {
                    handleControlFrame(frame);
                    continue;
                }
                switch (frame.opcode) {
                    case OP_TEXT, OP_BINARY -> {
                        accumulator.reset(frame.opcode, frame.fin, frame.length);
                        accumulator.readPayload(frame.length, frame.mask);
                        // Track the DATA-fragmentation fin locally.
                        // `frame` and `next` share the reusable Frame
                        // instance, so a control frame's own fin (always
                        // 1 for PING/PONG) would falsely satisfy
                        // `!frame.fin` and exit the loop mid-message.
                        boolean dataFin = frame.fin;
                        while (!dataFin) {
                            Frame next = readFrame();
                            if (next == null) {
                                throw new EOFException("connection closed mid-fragment");
                            }
                            // RFC 6455 §5.4: control frames MAY be
                            // interjected between fragments of a data
                            // message. Process inline; keep waiting for
                            // the continuation frame.
                            if ((next.opcode & 0x8) != 0) {
                                handleControlFrame(next);
                                if (closeReceived) break;
                                continue;
                            }
                            if (next.opcode != OP_CONTINUATION) {
                                throw protocolError("expected continuation frame, got opcode " + next.opcode);
                            }
                            accumulator.readPayload(next.length, next.mask);
                            dataFin = next.fin;
                        }
                        // Messages arriving after our CLOSE are dropped:
                        // the listener has already asked to close.
                        if (dataFin && open) {
                            Object message = accumulator.finish();
                            listener.onMessage(socketApi, message);
                        }
                    }
                    case OP_CONTINUATION -> throw protocolError("unexpected CONTINUATION with no in-flight message");
                    default -> throw protocolError("unknown opcode: " + frame.opcode);
                }
            }
        } catch (ConnectionFailure e) {
            // RFC 6455 §7.1.7 Fail the WebSocket Connection: send CLOSE
            // with the matching status, then drop TCP. sendClose is a
            // no-op if a CLOSE already went out, so the peer never sees
            // two CLOSE frames.
            sendClose(e.code, EMPTY);
            try {
                listener.onError(socketApi, e);
            } catch (Throwable ignored) {
            }
            closeCode = e.code;
            closeReason = e.getMessage();
        } catch (IOException e) {
            if (e instanceof SocketTimeoutException && !closeSent) {
                // The idle timeout passed without a frame: close as going
                // away rather than dropping TCP.
                sendClose(CLOSE_GOING_AWAY, IDLE_TIMEOUT_REASON);
                closeCode = CLOSE_GOING_AWAY;
                closeReason = "idle timeout";
            } else {
                // After our CLOSE the peer may drop TCP instead of answering,
                // or the close timer fires: an expected end, not an error.
                if (!closeSent) {
                    try {
                        listener.onError(socketApi, e);
                    } catch (Throwable ignored) {
                    }
                }
                closeCode = CLOSE_ABNORMAL;
                closeReason = e.getMessage() == null ? "" : e.getMessage();
            }
        } catch (Throwable t) {
            sendClose(CLOSE_INTERNAL_ERROR, EMPTY);
            try {
                listener.onError(socketApi, t);
            } catch (Throwable ignored) {
            }
            closeCode = CLOSE_INTERNAL_ERROR;
            closeReason = "";
        } finally {
            forceClose();
            Thread timer = closeTimer;
            if (timer != null) {
                timer.interrupt();
            }
            try {
                listener.onClose(socketApi, closeCode, closeReason);
            } catch (Throwable ignored) {
            }
        }
    }

    private void handleControlFrame(Frame frame) throws IOException {
        int len = frame.controlLength;
        switch (frame.opcode) {
            case OP_PING, OP_PONG -> {
                // Copy so the listener can retain the buffer past the
                // next readFrame (which overwrites controlIn).
                byte[] copy = new byte[len];
                System.arraycopy(controlIn, 0, copy, 0, len);
                ByteBuffer bb = ByteBuffer.wrap(copy);
                if (frame.opcode == OP_PING) listener.onPing(socketApi, bb);
                else listener.onPong(socketApi, bb);
            }
            case OP_CLOSE -> {
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
                closeReceived = true;
                closeCode = code;
                closeReason = reason;
                // RFC 6455 §5.5.1: echo the received status code. An empty
                // CLOSE is answered with an empty CLOSE since 1005 MUST NOT
                // be sent on the wire (§7.4.1). No-op when this CLOSE
                // answers our own.
                sendClose(len == 0 ? -1 : code, EMPTY);
            }
            default -> throw protocolError("unknown control opcode: " + frame.opcode);
        }
    }

    private String decodeCloseReason(int len) throws ConnectionFailure {
        // RFC 6455 §7.1.6: CLOSE reason MUST be UTF-8. Decoded with a
        // reporting decoder so validation and decoding are one pass.
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(controlIn, 2, len))
                .toString();
        } catch (CharacterCodingException e) {
            throw new ConnectionFailure(CLOSE_INVALID_UTF8, "invalid UTF-8 in CLOSE reason");
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
        try {
            TlsSocket.forceClose(socket);
        } catch (IOException ignored) {
        }
    }

    // ---- Reading ----------------------------------------------------------

    /**
     * Reads the next frame header. For control frames the unmasked payload
     * is left in {@link #controlIn}; for data frames the caller reads the
     * payload with {@link MessageAccumulator#readPayload}. Returns null on
     * a clean EOF between frames.
     */
    private Frame readFrame() throws IOException {
        if (rpos == rlim) {
            rpos = 0;
            int n = in.read(rbuf, 0, rbuf.length);
            if (n < 0) {
                return null;
            }
            rlim = n;
        }
        require(2);
        int b0 = rbuf[rpos] & 0xFF;
        int b1 = rbuf[rpos + 1] & 0xFF;
        boolean fin = (b0 & 0x80) != 0;
        // RFC 6455 §5.2: RSV1/2/3 MUST be 0 unless an extension was
        // negotiated. We negotiate none, so any set bit is a protocol
        // error and forces CLOSE(1002).
        if ((b0 & 0x70) != 0) {
            throw protocolError("reserved bits set (no extensions negotiated)");
        }
        int opcode = b0 & 0x0F;
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
        boolean control = (opcode & 0x8) != 0;
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
            int r = in.read(rbuf, rlim, rbuf.length - rlim);
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
                int n = in.read(dst, off, max);
                if (n < 0) {
                    throw new EOFException("truncated frame payload");
                }
                return n;
            }
            rpos = 0;
            rlim = 0;
            int n = in.read(rbuf, 0, rbuf.length);
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

    /**
     * XORs {@code data[off..off+n)} with the frame mask in place, 8 bytes at
     * a time. {@code phase} is the number of payload bytes of this frame
     * already unmasked, so a payload read in several steps stays aligned
     * with the 4-byte mask.
     */
    static void unmask(byte[] data, int off, int n, int mask, int phase) {
        int m = Integer.rotateRight(mask, (phase & 3) << 3);
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

    private void writeHeader(int opcode, int len) throws IOException {
        byte[] header = headerOut;
        int hi = 0;
        header[hi++] = (byte) (0x80 | opcode);
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
        out.write(header, 0, hi);
    }

    private void writeFrame(int opcode, byte[] payload, int off, int len) throws IOException {
        writeLock.lock();
        try {
            if (!open) {
                return;
            }
            writeHeader(opcode, len);
            if (len > 0) {
                out.write(payload, off, len);
            }
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Writes the remaining bytes of {@code data} as one frame without
     * copying heap buffers and without moving the caller's position. The
     * write completes before this returns, so aliasing the caller's array
     * is safe.
     */
    private void writeFrame(int opcode, ByteBuffer data) throws IOException {
        int len = data == null ? 0 : data.remaining();
        if (len == 0 || data.hasArray()) {
            writeFrame(opcode, len == 0 ? EMPTY : data.array(),
                       len == 0 ? 0 : data.arrayOffset() + data.position(), len);
            return;
        }
        writeLock.lock();
        try {
            if (!open) {
                return;
            }
            writeHeader(opcode, len);
            byte[] staging = directOut;
            if (staging == null) {
                staging = new byte[READ_BUFFER_SIZE];
                directOut = staging;
            }
            int pos = data.position();
            int end = pos + len;
            while (pos < end) {
                int n = Math.min(staging.length, end - pos);
                data.get(pos, staging, 0, n);
                out.write(staging, 0, n);
                pos += n;
            }
            out.flush();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Sends this endpoint's single CLOSE frame: {@code code} plus
     * {@code reason}, or an empty payload when {@code code} is negative.
     * Stops all further sends. Returns true if this call put the CLOSE on
     * the wire; false if one was already sent or it couldn't be written,
     * in which case TCP is dropped.
     */
    private boolean sendClose(int code, byte[] reason) {
        open = false;
        boolean locked;
        try {
            locked = writeLock.tryLock(CLOSE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            locked = false;
        }
        if (!locked) {
            forceClose();
            return false;
        }
        try {
            if (closeSent) {
                return false;
            }
            closeSent = true;
            int len = 0;
            if (code >= 0) {
                controlOut[0] = (byte) ((code >>> 8) & 0xFF);
                controlOut[1] = (byte) (code & 0xFF);
                System.arraycopy(reason, 0, controlOut, 2, reason.length);
                len = 2 + reason.length;
            }
            writeHeader(OP_CLOSE, len);
            out.write(controlOut, 0, len);
            out.flush();
            return true;
        } catch (IOException e) {
            forceClose();
            return false;
        } finally {
            writeLock.unlock();
        }
    }

    private void startCloseTimer() {
        closeTimer = Thread.ofVirtual().start(() -> {
            try {
                Thread.sleep(CLOSE_TIMEOUT_MILLIS);
                forceClose();
            } catch (InterruptedException ignored) {
            }
        });
    }

    private static ByteBuffer checkControlPayload(ByteBuffer data) {
        if (data != null && data.remaining() > MAX_CONTROL_PAYLOAD) {
            throw new IllegalArgumentException(
                "control frame payload exceeds " + MAX_CONTROL_PAYLOAD + " bytes");
        }
        return data;
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
        long length;
        int mask;
        int controlLength;
    }

    /**
     * Reassembles one data message from its frames. Payload bytes are read
     * from the connection straight into the message buffer and unmasked in
     * place; text is validated as it arrives.
     */
    private final class MessageAccumulator {
        // Ceiling on retained scratch across messages. Above this,
        // finish() shrinks back to the floor so a one-off large message
        // doesn't pin memory for the connection's lifetime.
        private static final int SHRINK_CEILING = 64 * 1024;
        private static final int SHRINK_FLOOR = 4 * 1024;

        private final int limit;
        // Reused across messages.
        private byte[] scratch = EMPTY;
        // Buffer of the message in progress: scratch, or an exact-size
        // array handed to the listener without a copy.
        private byte[] buf = EMPTY;
        private int len;
        private int opcode;
        // Text only: buf[0..validated) is valid UTF-8; buf[validated..len)
        // is an incomplete trailing sequence awaiting more bytes.
        private int validated;
        private final Utf8Validator utf8 = new Utf8Validator();

        MessageAccumulator(int limit) {
            this.limit = limit;
        }

        void reset(int opcode, boolean fin, long firstFrameLength) {
            this.opcode = opcode;
            this.len = 0;
            this.validated = 0;
            utf8.reset();
            // A single-frame binary message of trusted size gets its own
            // exact array so finish() can hand it over without copying.
            if (opcode == OP_BINARY && fin && firstFrameLength <= READ_STEP
                && firstFrameLength <= limit) {
                buf = firstFrameLength == 0 ? EMPTY : new byte[(int) firstFrameLength];
            } else {
                buf = scratch;
            }
        }

        void readPayload(long frameLength, int mask) throws IOException {
            // Written as a subtraction so len + frameLength can't overflow.
            if (frameLength > limit - len) {
                throw new ConnectionFailure(CLOSE_MESSAGE_TOO_BIG, "message exceeds " + limit + " bytes");
            }
            int remaining = (int) frameLength;
            int done = 0;
            while (remaining > 0) {
                int step = Math.min(remaining, READ_STEP);
                ensureCapacity(len + step);
                int n = readSome(buf, len, step);
                unmask(buf, len, n, mask, done);
                len += n;
                done += n;
                remaining -= n;
                // RFC 6455 §5.6 + §8.1: text messages MUST be valid UTF-8;
                // invalid → CLOSE(1007). Validate incrementally so we fail
                // fast on the offending fragment (Autobahn §6.4) instead of
                // waiting for message end.
                if (opcode == OP_TEXT) {
                    validated = utf8.validate(buf, validated, len);
                    if (validated < 0) {
                        throw new ConnectionFailure(CLOSE_INVALID_UTF8, "invalid UTF-8 in text message");
                    }
                }
            }
        }

        private void ensureCapacity(int needed) {
            if (needed <= buf.length) {
                return;
            }
            int newLen = (int) Math.min(limit, Math.max((long) needed, 2L * buf.length));
            byte[] bigger = new byte[newLen];
            System.arraycopy(buf, 0, bigger, 0, len);
            buf = bigger;
            scratch = bigger;
        }

        Object finish() throws IOException {
            byte[] data = buf;
            buf = scratch;
            // Shrink scratch after a one-off large message so we don't
            // retain a fat buffer for the connection's lifetime.
            if (scratch.length > SHRINK_CEILING) {
                scratch = new byte[SHRINK_FLOOR];
                buf = scratch;
            }
            if (opcode == OP_TEXT) {
                if (validated != len) {
                    throw new ConnectionFailure(CLOSE_INVALID_UTF8, "truncated UTF-8 sequence at message end");
                }
                return new String(data, 0, len, StandardCharsets.UTF_8);
            }
            if (data != scratch && data.length == len) {
                return ByteBuffer.wrap(data);
            }
            byte[] payload = new byte[len];
            System.arraycopy(data, 0, payload, 0, len);
            return ByteBuffer.wrap(payload);
        }
    }

    /**
     * Incremental UTF-8 validator backed by {@link CharsetDecoder} in
     * REPORT mode for both malformed and unmappable. A codepoint split
     * across WebSocket fragments is left unconsumed by
     * {@link #validate} and presented again once more bytes arrive, so it
     * validates end-to-end without copying. Slightly heavier than a
     * hand-rolled DFA but bulletproof — the JDK's decoder has decades of
     * correctness fixes behind it.
     */
    static final class Utf8Validator {
        private final CharsetDecoder decoder;
        // Throwaway decode output; only the validation verdict matters.
        private final CharBuffer out;
        // Wrapper around the array being validated, rebuilt only when
        // the caller's array changes.
        private ByteBuffer wrapped;

        Utf8Validator() {
            decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
            out = CharBuffer.allocate(1024);
        }

        /**
         * Validates {@code data[off..end)}. Returns the offset of the first
         * byte not consumed — the start of an incomplete trailing sequence,
         * or {@code end} — or -1 if the bytes are not valid UTF-8.
         */
        int validate(byte[] data, int off, int end) {
            ByteBuffer in = wrapped;
            if (in == null || in.array() != data) {
                in = ByteBuffer.wrap(data);
                wrapped = in;
            }
            in.limit(end).position(off);
            while (true) {
                out.clear();
                CoderResult cr = decoder.decode(in, out, false);
                if (cr.isError()) {
                    return -1;
                }
                if (cr.isUnderflow()) {
                    return in.position();
                }
                // Overflow: out buffer full, keep decoding.
            }
        }

        void reset() {
            decoder.reset();
        }
    }

    private static ConnectionFailure protocolError(String msg) {
        return new ConnectionFailure(CLOSE_PROTOCOL_ERROR, msg);
    }

    /**
     * Signals that the connection must be failed (RFC 6455 §7.1.7) with
     * {@link #code} as the CLOSE status: 1002 protocol error, 1007 invalid
     * UTF-8, 1009 message too big.
     */
    private static final class ConnectionFailure extends IOException {
        final int code;

        ConnectionFailure(int code, String msg) {
            super(msg);
            this.code = code;
        }
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
            writeFrame(OP_TEXT, bytes, 0, bytes.length);
        }

        @Override
        public void sendBinary(ByteBuffer message) throws IOException {
            writeFrame(OP_BINARY, message);
        }

        @Override
        public void sendPing(ByteBuffer data) throws IOException {
            writeFrame(OP_PING, checkControlPayload(data));
        }

        @Override
        public void sendPong(ByteBuffer data) throws IOException {
            writeFrame(OP_PONG, checkControlPayload(data));
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

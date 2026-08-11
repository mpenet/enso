package com.s_exp.enso.websocket;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * RFC 6455 WebSocket connection driver. Reads frames, dispatches events to a
 * {@link WebSocketListener}, and exposes a {@link WebSocketSocket} for
 * server-initiated sends. Continuation frames are reassembled into a single
 * text or binary message (bounded by {@code maxMessageBytes}); pings are
 * auto-responded by the default listener implementation.
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

    public static String computeAccept(String key) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update((key + ACCEPT_GUID).getBytes(StandardCharsets.ISO_8859_1));
            return Base64.getEncoder().encodeToString(sha1.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final WebSocketListener listener;
    private final int maxMessageBytes;
    private final Object writeLock = new Object();
    private volatile boolean open = true;
    private final WebSocketSocket socketApi;
    // Close state updated by CLOSE frames received in either the top-level
    // dispatch or interleaved between message fragments (RFC 6455 §5.4).
    private int closeCode = CLOSE_ABNORMAL;
    private String closeReason = "";
    // Reusable read scratch for mask (4 bytes) + payload. Grows on demand.
    // Reset per frame; consumers must copy any bytes they retain past the
    // readFrame return. Owned by the read vthread — no locking.
    private byte[] readScratch = new byte[4 + 512];
    // Reusable Frame instance returned by readFrame. Fields overwritten
    // per call; consumers use fields inline and don't retain references
    // to the Frame or its payload buffer past the current dispatch.
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
            listener.onError(socketApi, t);
            forceClose(CLOSE_INTERNAL_ERROR);
            listener.onClose(socketApi, CLOSE_INTERNAL_ERROR, "");
            return;
        }

        try {
            MessageAccumulator accumulator = new MessageAccumulator(maxMessageBytes);
            while (open) {
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
                        accumulator.reset(frame.opcode);
                        accumulator.append(frame.payload, frame.off, frame.len);
                        while (!frame.fin) {
                            Frame next = readFrame();
                            if (next == null) {
                                throw new IOException("connection closed mid-fragment");
                            }
                            // RFC 6455 §5.4: control frames MAY be
                            // interjected between fragments of a data
                            // message. Process inline; keep waiting for
                            // the continuation frame.
                            if ((next.opcode & 0x8) != 0) {
                                handleControlFrame(next);
                                if (!open) break;
                                continue;
                            }
                            if (next.opcode != OP_CONTINUATION) {
                                throw new IOException("expected continuation frame, got opcode " + next.opcode);
                            }
                            accumulator.append(next.payload, next.off, next.len);
                            // `frame` and `next` are the same reusable
                            // instance; `while (!frame.fin)` on the outer
                            // iteration re-checks the freshly-read fin.
                        }
                        if (open) {
                            Object message = accumulator.finish();
                            listener.onMessage(socketApi, message);
                        }
                    }
                    case OP_CONTINUATION -> throw new IOException("unexpected CONTINUATION with no in-flight message");
                    default -> throw new IOException("unknown opcode: " + frame.opcode);
                }
            }
        } catch (Utf8Exception e) {
            // Only send our CLOSE(1007) if we haven't already echoed a
            // peer CLOSE. Otherwise the peer sees two CLOSE frames.
            if (open) {
                try {
                    sendCloseFrame(CLOSE_INVALID_UTF8, "invalid UTF-8");
                } catch (IOException ignored) {
                }
            }
            try {
                listener.onError(socketApi, e);
            } catch (Throwable ignored) {
            }
            closeCode = CLOSE_INVALID_UTF8;
            closeReason = "invalid UTF-8";
        } catch (IOException e) {
            try {
                listener.onError(socketApi, e);
            } catch (Throwable ignored) {
            }
            closeCode = CLOSE_ABNORMAL;
            closeReason = e.getMessage() == null ? "" : e.getMessage();
        } catch (Throwable t) {
            try {
                listener.onError(socketApi, t);
            } catch (Throwable ignored) {
            }
            closeCode = CLOSE_INTERNAL_ERROR;
            closeReason = "";
        } finally {
            forceClose(closeCode);
            try {
                listener.onClose(socketApi, closeCode, closeReason);
            } catch (Throwable ignored) {
            }
        }
    }

    private void handleControlFrame(Frame frame) throws IOException {
        switch (frame.opcode) {
            case OP_PING, OP_PONG -> {
                // Copy so the listener can retain the buffer past the
                // next readFrame (which mutates the shared scratch).
                byte[] copy = new byte[frame.len];
                System.arraycopy(frame.payload, frame.off, copy, 0, frame.len);
                ByteBuffer bb = ByteBuffer.wrap(copy);
                if (frame.opcode == OP_PING) listener.onPing(socketApi, bb);
                else listener.onPong(socketApi, bb);
            }
            case OP_CLOSE -> {
                int code = CLOSE_NO_STATUS;
                String reason = "";
                int off = frame.off;
                int len = frame.len;
                // RFC 6455 §5.5.1: CLOSE payload MUST be either 0 bytes
                // (no status) or ≥ 2 bytes (2-byte code + optional
                // reason). A 1-byte payload is a protocol error.
                if (len == 1) {
                    throw new IOException("CLOSE frame with 1-byte payload");
                }
                if (len >= 2) {
                    code = ((frame.payload[off] & 0xFF) << 8)
                        | (frame.payload[off + 1] & 0xFF);
                    if (len > 2) {
                        // RFC 6455 §7.1.6: CLOSE reason MUST be UTF-8.
                        Utf8Validator v = new Utf8Validator();
                        if (!v.feed(frame.payload, off + 2, len - 2)
                            || !v.isComplete()) {
                            throw new Utf8Exception("invalid UTF-8 in CLOSE reason");
                        }
                        reason = new String(frame.payload, off + 2, len - 2,
                                            StandardCharsets.UTF_8);
                    }
                }
                if (open) {
                    try {
                        sendCloseFrame(code, reason);
                    } catch (IOException ignored) {
                    }
                }
                closeCode = code;
                closeReason = reason;
                open = false;
            }
            default -> throw new IOException("unknown control opcode: " + frame.opcode);
        }
    }

    private void forceClose(int code) {
        // Hold the write lock so that any in-flight sendText/sendBinary/etc
        // completes before the socket is torn down. Prevents a race where a
        // sender sees `open=true`, starts writing, and then the socket closes
        // mid-write, leaving a half-written frame on the wire.
        synchronized (writeLock) {
            open = false;
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private Frame readFrame() throws IOException {
        int b0 = in.read();
        if (b0 < 0) {
            return null;
        }
        boolean fin = (b0 & 0x80) != 0;
        // RFC 6455 §5.2: RSV1/2/3 MUST be 0 unless an extension was
        // negotiated. We negotiate none, so any set bit is a protocol
        // error and forces CLOSE(1002).
        if ((b0 & 0x70) != 0) {
            throw new IOException("reserved bits set (no extensions negotiated)");
        }
        int opcode = b0 & 0x0F;
        int b1 = in.read();
        if (b1 < 0) {
            throw new EOFException("truncated frame header");
        }
        boolean masked = (b1 & 0x80) != 0;
        long payloadLen = b1 & 0x7F;
        if (payloadLen == 126) {
            payloadLen = ((readByte() << 8) | readByte()) & 0xFFFFL;
        } else if (payloadLen == 127) {
            long len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | readByte();
            }
            payloadLen = len;
        }
        if (!masked) {
            // per RFC 6455, all client → server frames must be masked
            throw new IOException("unmasked client frame");
        }
        if (payloadLen < 0 || payloadLen > maxMessageBytes || payloadLen > Integer.MAX_VALUE) {
            throw new IOException("payload too large");
        }
        // RFC 6455 §5.5: control frames (opcode >= 0x8) MUST have payload
        // length ≤ 125 AND MUST NOT be fragmented (FIN=1).
        boolean control = (opcode & 0x8) != 0;
        if (control) {
            if (payloadLen > 125) {
                throw new IOException("control frame payload > 125 bytes");
            }
            if (!fin) {
                throw new IOException("fragmented control frame");
            }
        }
        int plen = (int) payloadLen;
        int need = 4 + plen;
        if (readScratch.length < need) {
            int cap = readScratch.length;
            while (cap < need) cap <<= 1;
            readScratch = new byte[cap];
        }
        readFully(readScratch, 0, 4);
        readFully(readScratch, 4, plen);
        // In-place unmask against the four leading mask bytes.
        byte m0 = readScratch[0], m1 = readScratch[1],
             m2 = readScratch[2], m3 = readScratch[3];
        for (int i = 0; i < plen; i++) {
            byte m = switch (i & 3) {
                case 0 -> m0; case 1 -> m1; case 2 -> m2; default -> m3;
            };
            readScratch[4 + i] ^= m;
        }
        currentFrame.fin = fin;
        currentFrame.opcode = opcode;
        currentFrame.payload = readScratch;
        currentFrame.off = 4;
        currentFrame.len = plen;
        return currentFrame;
    }

    private int readByte() throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new EOFException("truncated frame");
        }
        return b;
    }

    private void readFully(byte[] dst, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(dst, off, len);
            if (n < 0) {
                throw new EOFException("truncated frame payload");
            }
            off += n;
            len -= n;
        }
    }

    private void writeFrame(int opcode, byte[] payload, int off, int len) throws IOException {
        synchronized (writeLock) {
            if (!open) {
                return;
            }
            byte[] header = new byte[10];
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
                    header[hi++] = (byte) ((len >>> (i * 8)) & 0xFF);
                }
            }
            out.write(header, 0, hi);
            if (len > 0) {
                out.write(payload, off, len);
            }
            out.flush();
        }
    }

    private void sendCloseFrame(int code, String reason) throws IOException {
        byte[] reasonBytes = reason == null ? new byte[0] : reason.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[2 + reasonBytes.length];
        payload[0] = (byte) ((code >>> 8) & 0xFF);
        payload[1] = (byte) (code & 0xFF);
        System.arraycopy(reasonBytes, 0, payload, 2, reasonBytes.length);
        writeFrame(OP_CLOSE, payload, 0, payload.length);
    }

    private static byte[] toArray(ByteBuffer buf) {
        if (buf == null) {
            return new byte[0];
        }
        // Always copy — never alias the caller's backing array. Sends
        // happen on the writer thread; a caller mutating the buffer
        // after handing it off would corrupt an in-flight frame.
        byte[] arr = new byte[buf.remaining()];
        buf.duplicate().get(arr);
        return arr;
    }

    /**
     * Reusable frame descriptor. Fields are overwritten by every
     * {@link #readFrame} call — consumers must finish using them before
     * the next read. {@link #payload} points into the shared read
     * scratch; retain by copying, never by reference.
     */
    private static final class Frame {
        boolean fin;
        int opcode;
        byte[] payload;
        int off;
        int len;
    }

    private static final class MessageAccumulator {
        // Ceiling on retained scratch across messages. Above this,
        // finish() shrinks back to the floor so a one-off large message
        // doesn't pin memory for the connection's lifetime.
        private static final int SHRINK_CEILING = 64 * 1024;
        private static final int SHRINK_FLOOR = 4 * 1024;

        private final int limit;
        private byte[] buf = new byte[0];
        private int len;
        private int opcode;
        private final Utf8Validator utf8 = new Utf8Validator();

        MessageAccumulator(int limit) {
            this.limit = limit;
        }

        void reset(int opcode) {
            this.opcode = opcode;
            this.len = 0;
            utf8.reset();
        }

        void append(byte[] data, int off, int nBytes) throws IOException {
            if (len + nBytes > limit) {
                throw new IOException("message exceeds " + limit + " bytes");
            }
            if (len + nBytes > buf.length) {
                int newLen = Math.max(buf.length * 2, len + nBytes);
                byte[] bigger = new byte[newLen];
                System.arraycopy(buf, 0, bigger, 0, len);
                buf = bigger;
            }
            System.arraycopy(data, off, buf, len, nBytes);
            len += nBytes;
            // RFC 6455 §5.6 + §8.1: text messages MUST be valid UTF-8;
            // invalid → CLOSE(1007). Validate incrementally so we fail
            // fast on the offending fragment (Autobahn §6.4) instead of
            // waiting for message end.
            if (opcode == OP_TEXT) {
                if (!utf8.feed(data, off, nBytes)) {
                    throw new Utf8Exception("invalid UTF-8 in text message");
                }
            }
        }

        Object finish() throws IOException {
            byte[] payload = new byte[len];
            System.arraycopy(buf, 0, payload, 0, len);
            // Shrink scratch after a one-off large message so we don't
            // retain a fat buffer for the connection's lifetime.
            if (buf.length > SHRINK_CEILING) {
                buf = new byte[SHRINK_FLOOR];
            }
            if (opcode == OP_TEXT) {
                if (!utf8.isComplete()) {
                    throw new Utf8Exception("truncated UTF-8 sequence at message end");
                }
                return new String(payload, StandardCharsets.UTF_8);
            }
            return ByteBuffer.wrap(payload);
        }
    }

    /**
     * Incremental UTF-8 validator based on Björn Höhrmann's public-domain
     * DFA (<a href="https://bjoern.hoehrmann.de/utf-8/decoder/dfa/">source</a>).
     * State survives across {@link #feed} calls so callers can validate
     * a stream of bytes split across arbitrary fragment boundaries. We
     * skip codepoint reconstruction — validation only.
     */
    static final class Utf8Validator {
        private static final byte[] TABLE = new byte[] {
            // byte → character class (0..11)
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
            7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
            8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
            10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
            // (state, class) → next state, indexed as [256 + state + class]
            0,12,24,36,60,96,84,12,12,12,48,72,
            12, 0,12,12,12,12,12, 0,12, 0,12,12,
            12,24,12,12,12,12,12,24,12,24,12,12,
            12,12,12,12,12,12,12,24,12,12,12,12,
            12,24,12,12,12,12,12,12,12,24,12,12,
            12,12,12,12,12,12,12,36,12,36,12,12,
            12,36,12,12,12,12,12,36,12,36,12,12,
            12,36,12,12,12,12,12,12,12,12,12,12,
        };
        private static final int ACCEPT = 0;
        private static final int REJECT = 12;

        private int state = ACCEPT;

        boolean feed(byte[] data, int off, int len) {
            int s = state;
            for (int i = 0; i < len; i++) {
                int type = TABLE[data[off + i] & 0xFF] & 0xFF;
                s = TABLE[256 + s + type] & 0xFF;
                if (s == REJECT) {
                    state = REJECT;
                    return false;
                }
            }
            state = s;
            return true;
        }

        boolean isComplete() {
            return state == ACCEPT;
        }

        void reset() {
            state = ACCEPT;
        }
    }

    /** Signals invalid UTF-8 so the close-code mapper can emit CLOSE(1007). */
    private static final class Utf8Exception extends IOException {
        Utf8Exception(String msg) { super(msg); }
    }

    private final class SocketImpl implements WebSocketSocket {

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void sendText(CharSequence message) throws IOException {
            byte[] bytes = message.toString().getBytes(StandardCharsets.UTF_8);
            writeFrame(OP_TEXT, bytes, 0, bytes.length);
        }

        @Override
        public void sendBinary(ByteBuffer message) throws IOException {
            byte[] bytes = toArray(message);
            writeFrame(OP_BINARY, bytes, 0, bytes.length);
        }

        @Override
        public void sendPing(ByteBuffer data) throws IOException {
            byte[] bytes = toArray(data);
            writeFrame(OP_PING, bytes, 0, bytes.length);
        }

        @Override
        public void sendPong(ByteBuffer data) throws IOException {
            byte[] bytes = toArray(data);
            writeFrame(OP_PONG, bytes, 0, bytes.length);
        }

        @Override
        public void close(int code, String reason) throws IOException {
            if (!open) {
                return;
            }
            try {
                sendCloseFrame(code, reason);
            } finally {
                forceClose(code);
            }
        }
    }
}

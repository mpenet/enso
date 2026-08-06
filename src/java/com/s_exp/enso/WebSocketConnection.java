package com.s_exp.enso;

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

    static String computeAccept(String key) {
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

    WebSocketConnection(Socket socket, InputStream in, OutputStream out,
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
        int closeCode = CLOSE_ABNORMAL;
        String closeReason = "";
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
                switch (frame.opcode) {
                    case OP_PING -> listener.onPing(socketApi, ByteBuffer.wrap(frame.payload));
                    case OP_PONG -> listener.onPong(socketApi, ByteBuffer.wrap(frame.payload));
                    case OP_CLOSE -> {
                        int code = CLOSE_NO_STATUS;
                        String reason = "";
                        if (frame.payload.length >= 2) {
                            code = ((frame.payload[0] & 0xFF) << 8) | (frame.payload[1] & 0xFF);
                            if (frame.payload.length > 2) {
                                reason = new String(frame.payload, 2,
                                                    frame.payload.length - 2,
                                                    StandardCharsets.UTF_8);
                            }
                        }
                        // echo close back if we haven't already
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
                    case OP_TEXT, OP_BINARY -> {
                        accumulator.reset(frame.opcode);
                        accumulator.append(frame.payload);
                        while (!frame.fin) {
                            Frame next = readFrame();
                            if (next == null || next.opcode != OP_CONTINUATION) {
                                throw new IOException("expected continuation frame");
                            }
                            accumulator.append(next.payload);
                            frame = next;
                        }
                        Object message = accumulator.finish();
                        listener.onMessage(socketApi, message);
                    }
                    default -> throw new IOException("unknown opcode: " + frame.opcode);
                }
            }
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
        byte[] mask = new byte[4];
        readFully(mask, 0, 4);
        byte[] payload = new byte[(int) payloadLen];
        readFully(payload, 0, payload.length);
        for (int i = 0; i < payload.length; i++) {
            payload[i] ^= mask[i & 3];
        }
        return new Frame(fin, opcode, payload);
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
        if (buf.hasArray() && buf.arrayOffset() == 0 && buf.position() == 0
            && buf.limit() == buf.capacity()) {
            return buf.array();
        }
        byte[] arr = new byte[buf.remaining()];
        buf.duplicate().get(arr);
        return arr;
    }

    private static final class Frame {
        final boolean fin;
        final int opcode;
        final byte[] payload;

        Frame(boolean fin, int opcode, byte[] payload) {
            this.fin = fin;
            this.opcode = opcode;
            this.payload = payload;
        }
    }

    private static final class MessageAccumulator {
        private final int limit;
        private byte[] buf = new byte[0];
        private int len;
        private int opcode;

        MessageAccumulator(int limit) {
            this.limit = limit;
        }

        void reset(int opcode) {
            this.opcode = opcode;
            this.len = 0;
        }

        void append(byte[] data) throws IOException {
            if (len + data.length > limit) {
                throw new IOException("message exceeds " + limit + " bytes");
            }
            if (len + data.length > buf.length) {
                int newLen = Math.max(buf.length * 2, len + data.length);
                byte[] bigger = new byte[newLen];
                System.arraycopy(buf, 0, bigger, 0, len);
                buf = bigger;
            }
            System.arraycopy(data, 0, buf, len, data.length);
            len += data.length;
        }

        Object finish() {
            byte[] payload = new byte[len];
            System.arraycopy(buf, 0, payload, 0, len);
            if (opcode == OP_TEXT) {
                return new String(payload, StandardCharsets.UTF_8);
            }
            return ByteBuffer.wrap(payload);
        }
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

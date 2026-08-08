package com.s_exp.enso.quiche.h3;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Incremental HTTP/3 frame parser. Bytes arrive via {@link #feed(ByteBuffer)}
 * from {@code quiche_conn_stream_recv} and the caller polls {@link #poll()}
 * for complete frames. State survives partial input — a frame that spans
 * two stream_recv calls is buffered and emitted only when its length prefix
 * is fully satisfied.
 *
 * <p>Two frame types get special large-payload handling because their body
 * can be arbitrary bytes larger than any sane in-memory buffer:
 * <ul>
 *   <li>{@link H3FrameType#DATA} — payload streamed via
 *       {@link Frame#dataChunk} without ever accumulating the full body;
 *   <li>{@link H3FrameType#HEADERS} — accumulated whole so the QPACK
 *       decoder can process the field section in one shot (H3 field
 *       sections are size-capped by {@code SETTINGS_MAX_FIELD_SECTION_SIZE}).
 * </ul>
 * Other known frame types (SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH) are
 * accumulated whole; unknown types are consumed and skipped per §7.
 */
public final class H3FrameReader {

    /**
     * A parsed frame or a chunk of a streaming DATA body.
     */
    public static final class Frame {
        public final long type;
        /** Full payload for accumulating types; null for streaming DATA chunks. */
        public final byte[] payload;
        /** DATA chunk bytes for streaming; null for accumulated frames. */
        public final byte[] dataChunk;
        /** True when this is the final chunk of the DATA frame. */
        public final boolean dataFinalChunk;

        private Frame(long type, byte[] payload, byte[] dataChunk, boolean dataFinalChunk) {
            this.type = type;
            this.payload = payload;
            this.dataChunk = dataChunk;
            this.dataFinalChunk = dataFinalChunk;
        }

        public static Frame accumulated(long type, byte[] payload) {
            return new Frame(type, payload, null, false);
        }

        public static Frame dataChunk(byte[] chunk, boolean finalChunk) {
            return new Frame(H3FrameType.DATA, null, chunk, finalChunk);
        }

        public boolean isDataChunk() { return dataChunk != null; }
    }

    // Max bytes we buffer for a single non-DATA frame. Prevents an
    // adversary from OOMing us with a giant SETTINGS/HEADERS payload;
    // legitimate values are ~KB. HEADERS gets bumped to the negotiated
    // SETTINGS_MAX_FIELD_SECTION_SIZE by the caller if larger.
    private static final int DEFAULT_MAX_ACCUM = 64 * 1024;

    private final int maxAccum;
    // Rolling input buffer. Retains bytes across feed() calls when a frame
    // is only partially available.
    private ByteBuffer buf = ByteBuffer.allocate(4096);
    // Set when we've decoded a frame header but the payload hasn't fully
    // arrived. -1 = not-yet-parsed.
    private long pendingType = -1;
    private long pendingLength = -1;
    private long pendingConsumed = 0;   // bytes of payload already emitted (DATA path)

    private final Deque<Frame> ready = new ArrayDeque<>();

    public H3FrameReader() { this(DEFAULT_MAX_ACCUM); }

    public H3FrameReader(int maxAccumBytes) {
        this.maxAccum = maxAccumBytes;
    }

    /**
     * Feed more input bytes. The buffer is drained until either exhausted or
     * a partial frame header/payload blocks progress; unused bytes are held
     * for the next call.
     */
    public void feed(ByteBuffer more) {
        appendTo(more);
        drain();
    }

    /** Poll the next complete frame or DATA chunk, or {@code null}. */
    public Frame poll() { return ready.pollFirst(); }

    // --------------------------------------------------------------

    private void appendTo(ByteBuffer more) {
        int need = more.remaining();
        if (buf.remaining() < need) {
            int newCap = Math.max(buf.capacity() * 2, buf.position() + need);
            ByteBuffer bigger = ByteBuffer.allocate(newCap);
            buf.flip();
            bigger.put(buf);
            buf = bigger;
        }
        buf.put(more);
    }

    private void drain() {
        // buf is in write mode (position = write end). Flip to read for
        // parsing, then re-pack + restore write mode when done.
        buf.flip();
        try {
            while (true) {
                if (pendingType < 0) {
                    if (!tryReadHeader()) return;
                }
                if (!drainPayload()) return;
            }
        } finally {
            // Compact any unread bytes to the front, restore write mode.
            buf.compact();
        }
    }

    private boolean tryReadHeader() {
        int start = buf.position();
        int typeLen = Varint.peekLength(buf);
        if (typeLen < 0 || buf.remaining() < typeLen) return false;
        long type = Varint.decode(buf);
        int lenLen = Varint.peekLength(buf);
        if (lenLen < 0 || buf.remaining() < lenLen) {
            // Roll back — we peeked the length prefix but the length varint
            // isn't fully here.
            buf.position(start);
            return false;
        }
        long length = Varint.decode(buf);
        if (length < 0) throw new IllegalStateException("frame length overflow");
        pendingType = type;
        pendingLength = length;
        pendingConsumed = 0;
        return true;
    }

    private boolean drainPayload() {
        if (pendingType == H3FrameType.DATA) {
            return drainData();
        }
        // Accumulate — but only if the length is within cap.
        if (pendingLength > maxAccum) {
            throw new IllegalStateException(
                "frame type=" + pendingType + " length=" + pendingLength
                    + " exceeds accum cap " + maxAccum);
        }
        int need = (int) pendingLength;
        if (buf.remaining() < need) return false;
        byte[] payload = new byte[need];
        buf.get(payload);
        ready.add(Frame.accumulated(pendingType, payload));
        pendingType = -1;
        pendingLength = -1;
        pendingConsumed = 0;
        return true;
    }

    private boolean drainData() {
        long remaining = pendingLength - pendingConsumed;
        if (remaining <= 0) {
            // Zero-length DATA — still emit an empty final chunk so callers
            // can distinguish it from "no data seen".
            ready.add(Frame.dataChunk(new byte[0], true));
            pendingType = -1;
            pendingLength = -1;
            pendingConsumed = 0;
            return true;
        }
        int take = (int) Math.min(remaining, buf.remaining());
        if (take == 0) return false;
        byte[] chunk = new byte[take];
        buf.get(chunk);
        pendingConsumed += take;
        boolean finalChunk = pendingConsumed == pendingLength;
        ready.add(Frame.dataChunk(chunk, finalChunk));
        if (finalChunk) {
            pendingType = -1;
            pendingLength = -1;
            pendingConsumed = 0;
        }
        return true;
    }
}

package com.s_exp.enso.http3;

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
 *   <li>{@link Http3FrameType#DATA} — payload streamed via
 *       {@link Frame#dataChunk} without ever accumulating the full body;
 *   <li>{@link Http3FrameType#HEADERS} — accumulated whole so the QPACK
 *       decoder can process the field section in one shot (H3 field
 *       sections are size-capped by {@code SETTINGS_MAX_FIELD_SECTION_SIZE}).
 * </ul>
 * Other known frame types (SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH) are
 * accumulated whole; unknown types are consumed and skipped per §7.
 */
public final class Http3FrameReader {

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
            return new Frame(Http3FrameType.DATA, null, chunk, finalChunk);
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

    public Http3FrameReader() { this(DEFAULT_MAX_ACCUM); }

    public Http3FrameReader(int maxAccumBytes) {
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

    /**
     * byte[]-input overload that avoids the {@link ByteBuffer#wrap} the
     * {@link ByteBuffer} variant would need — task #125 alloc profile
     * showed HeapByteBuffer wrappers accumulating on the hot per-recv
     * path.
     */
    public void feed(byte[] data, int off, int len) {
        appendTo(data, off, len);
        drain();
    }

    /** Poll the next complete frame or DATA chunk, or {@code null}. */
    public Frame poll() { return ready.pollFirst(); }

    /**
     * Clear all reader state so the instance can be reused for a fresh
     * stream. Keeps the rolling {@link #buf} allocation to amortise it
     * across pooled reuse; the buffer's position is reset. Pooled by
     * {@link Http3Session} to avoid per-stream reader allocations.
     */
    public void reset() {
        buf.clear();
        pendingType = -1;
        pendingLength = -1;
        pendingConsumed = 0;
        ready.clear();
    }

    // --------------------------------------------------------------

    private void appendTo(ByteBuffer more) {
        int need = more.remaining();
        ensureCapacity(need);
        buf.put(more);
    }

    private void appendTo(byte[] data, int off, int len) {
        ensureCapacity(len);
        buf.put(data, off, len);
    }

    private void ensureCapacity(int need) {
        if (buf.remaining() < need) {
            long target = Math.max((long) buf.capacity() * 2L,
                (long) buf.position() + (long) need);
            long ceiling = (long) maxAccum + 16L;
            if (target > ceiling) {
                if ((long) buf.position() + (long) need > ceiling) {
                    throw new IllegalStateException(
                        "Http3FrameReader input would exceed maxAccum=" + maxAccum);
                }
                target = ceiling;
            }
            ByteBuffer bigger = ByteBuffer.allocate((int) target);
            buf.flip();
            bigger.put(buf);
            buf = bigger;
        }
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
        int typeLen = Http3Varint.peekLength(buf);
        if (typeLen < 0 || buf.remaining() < typeLen) return false;
        long type = Http3Varint.decode(buf);
        int lenLen = Http3Varint.peekLength(buf);
        if (lenLen < 0 || buf.remaining() < lenLen) {
            // Roll back — we peeked the length prefix but the length varint
            // isn't fully here.
            buf.position(start);
            return false;
        }
        long length = Http3Varint.decode(buf);
        if (length < 0) throw new IllegalStateException("frame length overflow");
        pendingType = type;
        pendingLength = length;
        pendingConsumed = 0;
        return true;
    }

    private boolean drainPayload() {
        if (pendingType == Http3FrameType.DATA) {
            return drainData();
        }
        // Unknown types (and other reserved types) MUST be discarded per
        // RFC 9114 §7.2.8. Peer could set arbitrary lengths — stream-skip
        // rather than accumulate, so we never OOM on adversarial input.
        if (!isKnownAccumulatedType(pendingType)) {
            return skipPayload();
        }
        // Known bounded types — cap enforced. HEADERS/SETTINGS/GOAWAY
        // sizes are all small in practice; exceeding the cap is a
        // malformed-frame condition to raise at the connection layer.
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

    private static boolean isKnownAccumulatedType(long t) {
        return t == Http3FrameType.HEADERS
            || t == Http3FrameType.SETTINGS
            || t == Http3FrameType.GOAWAY
            || t == Http3FrameType.MAX_PUSH_ID
            || t == Http3FrameType.CANCEL_PUSH
            || t == Http3FrameType.PUSH_PROMISE;
    }

    /** Streaming-skip unknown-type payloads. No allocation, no emission. */
    private boolean skipPayload() {
        long remaining = pendingLength - pendingConsumed;
        if (remaining <= 0) {
            pendingType = -1;
            pendingLength = -1;
            pendingConsumed = 0;
            return true;
        }
        int take = (int) Math.min(remaining, buf.remaining());
        if (take == 0) return false;
        buf.position(buf.position() + take);
        pendingConsumed += take;
        if (pendingConsumed == pendingLength) {
            pendingType = -1;
            pendingLength = -1;
            pendingConsumed = 0;
        }
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

// ABOUTME: Jazzer target for the HTTP/3 stream parsers reachable without quiche: peer uni streams
// ABOUTME: (control, QPACK), request-stream frames, QPACK field sections and the request-body pipe.
package com.s_exp.enso.fuzz;

import com.s_exp.enso.core.MemoryBudget;
import com.s_exp.enso.core.RequestBodyException;
import com.s_exp.enso.http3.Http3BodyPipe;
import com.s_exp.enso.http3.Http3ConnectionException;
import com.s_exp.enso.http3.Http3FrameReader;
import com.s_exp.enso.http3.Http3Varint;
import com.s_exp.enso.http3.qpack.QpackDecoder;
import com.s_exp.enso.http3.qpack.QpackException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * The bytes a client sends on its HTTP/3 streams, delivered twice: once
 * cut into the chunks the input chooses (as quiche hands out stream data)
 * and once one read per operation. Peer unidirectional streams go to the
 * connection's {@code Http3ControlStreams} (package-private, reached by
 * reflection; no quiche: its output only records STOP_SENDING); request
 * streams to one {@link Http3FrameReader} each, their HEADERS payloads to
 * a {@link QpackDecoder} and their DATA to an {@link Http3BodyPipe}.
 * {@code Http3RequestReader}, which parses request streams on the server,
 * isn't reachable: it reads through its {@code Http3Connection}'s
 * {@code QuicheConnection} and loop.
 *
 * <p>Input layout: a list of operations, an opcode byte (low 3 bits
 * select it) and its operands, which read as 0 past the end of the
 * input. A stream byte {@code s} names uni stream {@code 2 + 4 (s & 7)}
 * or request stream {@code 4 (s & 3)}; a chunk byte {@code c} cuts the
 * operation's bytes into reads of {@code c & 15} bytes (0: one read) and
 * sets FIN on the last when bit 7 is set.
 * <pre>
 * 0 uni type     s, c, type selector: a stream-type varint (control, push, QPACK
 *                encoder / decoder, grease, unknown, raw)
 * 1 uni frame    s, c, frame
 * 2 uni raw      s, c, len, bytes
 * 3 uni reset    s: the peer reset the stream
 * 4 request frame s, c, frame
 * 5 request raw  s, c, len, bytes
 * 6 qpack        s, c, instruction selector: an encoder or decoder stream instruction
 * 7 fin          s (bit 7: a request stream): an empty read with FIN
 * </pre>
 * A frame is a selector byte and its operands: DATA (u16 size), HEADERS
 * (a QPACK section of static, literal and raw lines), SETTINGS (pairs),
 * GOAWAY, MAX_PUSH_ID, CANCEL_PUSH (a varint, optionally one byte too
 * long), PUSH_PROMISE, an HTTP/2-only type, a grease type, or a raw type
 * with a declared length that may lie.
 *
 * <p>Checks: control streams raise only {@link Http3ConnectionException}
 * with an RFC 9114 / RFC 9204 code, and both deliveries fail on the same
 * operation or neither does, then agree on the peer's
 * SETTINGS_MAX_FIELD_SECTION_SIZE, the tracked streams and STOP_SENDING.
 * Frame readers raise only {@link IllegalStateException} (a frame over
 * the accumulation cap), and both deliveries yield the same frames (DATA
 * merged per frame), first frame type and partial state, failing on the
 * same operation. QPACK raises only {@link QpackException} with such a
 * code. The body pipe hands out exactly the bytes it accepted, in order,
 * then EOF after the end, a 413 after the cap or an IOException after a
 * truncation, and its memory budgets return to 0 once discarded.
 */
public final class Http3StreamFuzz {

    private static final long[] STREAM_TYPES = {0x00, 0x01, 0x02, 0x03, 0x21, 0x40, 0x54, 0x3fffffffL};
    private static final long[] SETTING_IDS = {0x01, 0x06, 0x07, 0x02, 0x03, 0x04, 0x05, 0x21, 0x08, 0x33, 0x00};
    private static final long[] SETTING_VALUES = {0, 1, 100, 4096, 16384, 1L << 30, Http3Varint.MAX_VALUE};
    private static final long[] IDS = {0, 1, 4, 8, 100, 1L << 30, Http3Varint.MAX_VALUE};
    private static final int[] HTTP2_TYPES = {0x02, 0x06, 0x08, 0x09};
    // QPACK static table indexes (RFC 9204 Appendix A) of request fields.
    private static final int[] STATIC_FIELDS = {17, 20, 21, 1, 23, 22, 4, 31, 15, 16, 0, 2, 5, 6, 98, 99, 100};
    private static final String[] NAMES = {"x-a", "content-length", "te", "connection", ":path", "Upper", ":status",
        "expect", "host", ":protocol"};
    private static final String[] VALUES = {"0", "5", "trailers", "/", "100-continue", "localhost", "", "x",
        "keep-alive", "é"};
    private static final byte[][] QPACK_INSTRUCTIONS = {
        {0x20}, {0x25}, {0x3f, (byte) 0xe1, 0x1f}, {(byte) 0xc1, 0x01, 0x61}, {0x00}, {0x01},
        {(byte) 0x80}, {(byte) 0x84}, {0x40}, {0x44}, {0x3f}, {(byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x01}};

    private static final int BODY_CAP = 4096;
    private static final long FIELD_SECTION_CAP = 16384;
    private static final QpackDecoder QPACK = new QpackDecoder();

    private static final Class<?> OUTPUT;
    private static final MethodHandle NEW_CONTROL;
    private static final MethodHandle ON_PEER_DATA;
    private static final MethodHandle ON_PEER_RESET;
    private static final MethodHandle TRACKED;
    private static final VarHandle PEER_MAX_FIELD_SECTION;

    static {
        try {
            Class<?> control = Class.forName("com.s_exp.enso.http3.Http3ControlStreams");
            OUTPUT = Class.forName("com.s_exp.enso.http3.Http3ControlStreams$Output");
            MethodHandles.Lookup l = MethodHandles.privateLookupIn(control, MethodHandles.lookup());
            NEW_CONTROL = l.findConstructor(control, MethodType.methodType(void.class, OUTPUT, long.class))
                .asType(MethodType.methodType(Object.class, Object.class, long.class));
            ON_PEER_DATA = l.findVirtual(control, "onPeerData", MethodType.methodType(
                    void.class, long.class, byte[].class, int.class, int.class, boolean.class))
                .asType(MethodType.methodType(
                    void.class, Object.class, long.class, byte[].class, int.class, int.class, boolean.class));
            ON_PEER_RESET = l.findVirtual(control, "onPeerReset", MethodType.methodType(void.class, long.class))
                .asType(MethodType.methodType(void.class, Object.class, long.class));
            TRACKED = l.findVirtual(control, "trackedPeerStreams", MethodType.methodType(int.class))
                .asType(MethodType.methodType(int.class, Object.class));
            PEER_MAX_FIELD_SECTION = l.findVarHandle(control, "peerMaxFieldSectionSize", long.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Http3StreamFuzz() {}

    /** One operation's bytes for one stream. */
    private record Delivery(boolean request, long streamId, byte[] bytes, int chunk, boolean fin, boolean reset) {}

    public static void fuzzerTestOneInput(byte[] data) {
        List<Delivery> ops = new OpBuilder(data).build();
        Run chunked = new Run(true);
        Run whole = new Run(false);
        for (int i = 0; i < ops.size(); i++) {
            chunked.deliver(i, ops.get(i));
            whole.deliver(i, ops.get(i));
        }
        chunked.finish();
        whole.finish();
        compare(chunked, whole);
    }

    private static void compare(Run a, Run b) {
        if (a.controlFailedAt != b.controlFailedAt) {
            throw new IllegalStateException("chunking changed where the control streams failed: operation "
                + a.controlFailedAt + " (" + a.controlFailure + ") vs " + b.controlFailedAt
                + " (" + b.controlFailure + ")");
        }
        if (a.controlFailedAt < 0 && !a.controlState().equals(b.controlState())) {
            throw new IllegalStateException("chunking changed the control-stream state: "
                + a.controlState() + " vs " + b.controlState());
        }
        if (!a.requestEvents().equals(b.requestEvents())) {
            throw new IllegalStateException("chunking changed the request-stream frames:\n"
                + a.requestEvents() + "\nvs\n" + b.requestEvents());
        }
    }

    // ---- Delivery ---------------------------------------------------------------------

    /** One delivery of every operation to fresh parsers. */
    private static final class Run {
        private final boolean chunked;
        private final Object control;
        private final List<Long> stopSending = new ArrayList<>();
        int controlFailedAt = -1;
        Throwable controlFailure;
        private final Map<Long, RequestStream> requests = new TreeMap<>();

        Run(boolean chunked) {
            this.chunked = chunked;
            Object out = Proxy.newProxyInstance(OUTPUT.getClassLoader(), new Class<?>[] {OUTPUT}, (proxy, m, args) ->
                switch (m.getName()) {
                    case "write" -> Boolean.TRUE;
                    case "stopSending" -> {
                        stopSending.add((Long) args[0]);
                        yield null;
                    }
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> "Output";
                });
            try {
                control = NEW_CONTROL.invokeExact(out, 16384L);
            } catch (Throwable t) {
                throw new IllegalStateException(t);
            }
        }

        void deliver(int index, Delivery d) {
            if (d.request) {
                requests.computeIfAbsent(d.streamId, id -> new RequestStream(chunked)).deliver(index, d);
                return;
            }
            if (controlFailedAt >= 0) return;
            try {
                // As quiche: a stream we sent STOP_SENDING for delivers
                // nothing more, not even its end.
                if (stopSending.contains(d.streamId)) return;
                if (d.reset) {
                    ON_PEER_RESET.invokeExact(control, d.streamId);
                    return;
                }
                byte[] b = d.bytes;
                int step = chunked && d.chunk > 0 ? d.chunk : Math.max(1, b.length);
                if (b.length == 0) {
                    ON_PEER_DATA.invokeExact(control, d.streamId, b, 0, 0, d.fin);
                }
                for (int off = 0; off < b.length && !stopSending.contains(d.streamId); off += step) {
                    int n = Math.min(step, b.length - off);
                    ON_PEER_DATA.invokeExact(control, d.streamId, b, off, n, d.fin && off + n == b.length);
                }
            } catch (Http3ConnectionException e) {
                if (!definedCode(e.errorCode())) {
                    throw new IllegalStateException("undefined HTTP/3 error code 0x" + Long.toHexString(e.errorCode()), e);
                }
                controlFailedAt = index;
                controlFailure = e;
            } catch (Throwable t) {
                throw new IllegalStateException("control streams raised " + t, t);
            }
        }

        void finish() {
            for (RequestStream r : requests.values()) r.finish();
        }

        String controlState() {
            try {
                return "maxFieldSection=" + (long) PEER_MAX_FIELD_SECTION.get(control)
                    + " tracked=" + (int) TRACKED.invokeExact(control) + " stopSending=" + stopSending;
            } catch (Throwable t) {
                throw new IllegalStateException(t);
            }
        }

        String requestEvents() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<Long, RequestStream> e : requests.entrySet()) {
                sb.append(e.getKey()).append(": ").append(e.getValue().events()).append('\n');
            }
            return sb.toString();
        }
    }

    private static boolean definedCode(long code) {
        return (code >= Http3ConnectionException.H3_NO_ERROR && code <= Http3ConnectionException.H3_VERSION_FALLBACK)
            || (code >= Http3ConnectionException.QPACK_DECOMPRESSION_FAILED
                && code <= Http3ConnectionException.QPACK_DECODER_STREAM_ERROR);
    }

    /** A request stream: frame reader, then QPACK and the body pipe (chunked run only). */
    private static final class RequestStream {
        private final boolean checkContent;
        private final Http3FrameReader reader = new Http3FrameReader();
        private final List<String> events = new ArrayList<>();
        private final ByteArrayOutputStream dataFrame = new ByteArrayOutputStream();
        private boolean dataOpen;
        private int failedAt = -1;
        private boolean ended;
        private boolean reset;
        private final MemoryBudget budget = new MemoryBudget(1 << 20);
        private final MemoryBudget connectionBudget = new MemoryBudget(1 << 16);
        private Http3BodyPipe pipe;
        private boolean headersSeen;
        private boolean pipeStopped;
        private final ByteArrayOutputStream accepted = new ByteArrayOutputStream();
        private final ByteArrayOutputStream read = new ByteArrayOutputStream();

        RequestStream(boolean checkContent) {
            this.checkContent = checkContent;
        }

        void deliver(int index, Delivery d) {
            if (failedAt >= 0 || ended || reset) return;
            if (d.reset) {
                reset = true;
                return;
            }
            byte[] b = d.bytes;
            int step = checkContent && d.chunk > 0 ? d.chunk : Math.max(1, b.length);
            try {
                for (int off = 0; off < b.length; off += step) {
                    reader.feed(b, off, Math.min(step, b.length - off));
                    poll();
                }
            } catch (IllegalStateException e) {
                failedAt = index;
                poll();
                events.add("failed@" + index);
                return;
            }
            drainPipe();
            if (d.fin) ended = true;
        }

        private void poll() {
            Http3FrameReader.Frame f;
            while ((f = reader.poll()) != null) {
                if (f.isDataChunk()) {
                    dataFrame.writeBytes(f.dataChunk);
                    dataOpen = true;
                    body(f.dataChunk);
                    if (f.dataFinalChunk) {
                        events.add("DATA " + HexFormat.of().formatHex(dataFrame.toByteArray()));
                        dataFrame.reset();
                        dataOpen = false;
                    }
                } else if (f.oversized) {
                    events.add("HEADERS oversized");
                } else {
                    events.add("frame 0x" + Long.toHexString(f.type) + " " + HexFormat.of().formatHex(f.payload));
                    if (f.type == 0x01) headers(f.payload);
                }
            }
        }

        String events() {
            List<String> all = new ArrayList<>(events);
            if (dataOpen) all.add("DATA partial " + HexFormat.of().formatHex(dataFrame.toByteArray()));
            all.add("first=" + reader.firstFrameType() + " partial=" + reader.hasPartial());
            return all.toString();
        }

        private void headers(byte[] section) {
            if (!checkContent) return;
            long[] contentLength = {-1};
            try {
                QPACK.decode(section, 0, section.length, FIELD_SECTION_CAP, (name, value) -> {
                    if (name.equals("content-length") && value.matches("[0-9]{1,18}")) {
                        contentLength[0] = Long.parseLong(value);
                    }
                });
            } catch (QpackException e) {
                if (!definedCode(e.errorCode())) {
                    throw new IllegalStateException("undefined QPACK error code 0x" + Long.toHexString(e.errorCode()), e);
                }
                return;
            }
            if (!headersSeen) {
                headersSeen = true;
                pipe = new Http3BodyPipe(BODY_CAP, contentLength[0], 0, 0, 0, budget.account(), connectionBudget);
            }
        }

        private void body(byte[] chunk) {
            if (!checkContent || pipe == null || pipeStopped || chunk.length == 0) return;
            if (chunk.length > pipe.room()) drainPipe();
            if (chunk.length > pipe.room()) return;
            int r = pipe.offer(chunk, 0, chunk.length);
            if (r == Http3BodyPipe.ACCEPTED) {
                accepted.writeBytes(chunk);
            } else {
                pipeStopped = true;
                if (r == Http3BodyPipe.OVER_DECLARED_LENGTH) pipe.signalTruncated();
            }
        }

        /** Reads what the pipe holds without blocking. */
        private void drainPipe() {
            if (pipe == null) return;
            InputStream in = pipe.inputStream();
            byte[] buf = new byte[1024];
            try {
                int n;
                while (in.available() > 0 && (n = in.read(buf)) > 0) {
                    read.write(buf, 0, n);
                }
            } catch (IOException e) {
                throw new IllegalStateException("body pipe failed a read with bytes available", e);
            }
            if (!Arrays.equals(read.toByteArray(), 0, read.size(), accepted.toByteArray(), 0, read.size())) {
                throw new IllegalStateException("body pipe handed out bytes it did not accept");
            }
        }

        void finish() {
            if (pipe == null) return;
            boolean overCap = pipe.rejected();
            boolean complete = ended && failedAt < 0 && !reset && !reader.hasPartial() && !pipeStopped
                && pipe.matchesDeclaredLength();
            if (complete) {
                pipe.signalEnd();
            } else {
                pipe.signalTruncated();
            }
            drainPipe();
            if (read.size() != accepted.size()) {
                throw new IllegalStateException("body pipe lost bytes: read " + read.size() + " of " + accepted.size());
            }
            try {
                int n = pipe.inputStream().read(new byte[16]);
                if (n != -1 || !complete) {
                    throw new IllegalStateException("body pipe read " + n + " after a "
                        + (complete ? "complete" : "truncated") + " body was drained");
                }
            } catch (RequestBodyException e) {
                if (!overCap) throw new IllegalStateException("413 from a body pipe under its cap", e);
            } catch (IOException e) {
                if (complete) throw new IllegalStateException("complete body pipe failed its last read", e);
            }
            pipe.discard();
            if (budget.used() != 0 || connectionBudget.used() != 0) {
                throw new IllegalStateException("body pipe left " + budget.used() + " / " + connectionBudget.used()
                    + " bytes charged");
            }
        }
    }

    // ---- Input decoding ---------------------------------------------------------------

    private static final class OpBuilder {
        private final FuzzInput in;
        private final List<Delivery> ops = new ArrayList<>();

        OpBuilder(byte[] data) {
            this.in = new FuzzInput(data, 0);
        }

        List<Delivery> build() {
            while (in.hasMore()) {
                int code = in.u8() & 7;
                int s = in.u8();
                long uni = 2 + 4L * (s & 7);
                long request = 4L * (s & 3);
                switch (code) {
                    case 0 -> add(false, uni, () -> varint(pickType(in.u8())));
                    case 1 -> add(false, uni, this::frame);
                    case 2 -> add(false, uni, () -> in.bytes(in.u8()));
                    case 3 -> ops.add(new Delivery(false, uni, new byte[0], 0, false, true));
                    case 4 -> add(true, request, this::frame);
                    case 5 -> add(true, request, () -> in.bytes(in.u8()));
                    case 6 -> add(false, uni, () -> QPACK_INSTRUCTIONS[in.u8() % QPACK_INSTRUCTIONS.length].clone());
                    default -> ops.add(new Delivery((s & 0x80) != 0, (s & 0x80) != 0 ? request : uni, new byte[0], 0,
                        true, false));
                }
            }
            return ops;
        }

        /** An operation: its chunk byte, then the operands {@code bytes} reads. */
        private void add(boolean requestStream, long id, Supplier<byte[]> bytes) {
            int c = in.u8();
            ops.add(new Delivery(requestStream, id, bytes.get(), c & 0x0F, (c & 0x80) != 0, false));
        }

        private long pickType(int selector) {
            return selector < 0xF0 ? STREAM_TYPES[selector % STREAM_TYPES.length] : in.u32() & 0xFFFFFFFFL;
        }

        private long pick(long[] table, int selector) {
            return selector < 0xF0 ? table[selector % table.length] : in.u32() & 0xFFFFFFFFL;
        }

        private byte[] frame() {
            int t = in.u8();
            return switch (t % 10) {
                case 0 -> frame(0x00, pattern(in.u16() % 4096));
                case 1 -> frame(0x01, section());
                case 2 -> {
                    ByteArrayOutputStream p = new ByteArrayOutputStream();
                    int n = in.u8() % 6;
                    for (int i = 0; i < n; i++) {
                        p.writeBytes(varint(pick(SETTING_IDS, in.u8())));
                        p.writeBytes(varint(pick(SETTING_VALUES, in.u8())));
                    }
                    yield frame(0x04, p.toByteArray());
                }
                case 3, 4, 5 -> {
                    long type = t % 10 == 3 ? 0x07 : t % 10 == 4 ? 0x0D : 0x03;
                    int sel = in.u8();
                    byte[] v = varint(pick(IDS, sel & 0x7F));
                    if ((sel & 0x80) != 0) v = Arrays.copyOf(v, v.length + 1);
                    yield frame(type, v);
                }
                case 6 -> frame(0x05, in.bytes(in.u8() % 16));
                case 7 -> frame(HTTP2_TYPES[in.u8() % HTTP2_TYPES.length], in.bytes(in.u8() % 8));
                case 8 -> frame(0x21 + 0x1fL * in.u8(), in.bytes(in.u8() % 8));
                default -> {
                    long type = in.u16();
                    int declaredSel = in.u8();
                    byte[] p = in.bytes(in.u8() % 32);
                    long declared = switch (declaredSel % 4) {
                        case 0 -> p.length;
                        case 1 -> p.length + 1L;
                        case 2 -> 1L << 20;
                        default -> Http3Varint.MAX_VALUE;
                    };
                    ByteArrayOutputStream b = new ByteArrayOutputStream();
                    b.writeBytes(varint(type));
                    b.writeBytes(varint(declared));
                    b.writeBytes(p);
                    yield b.toByteArray();
                }
            };
        }

        /**
         * A QPACK field section: a prefix (required insert count and base 0,
         * or two raw bytes) and lines: static indexed, literal with a static
         * name, literal with a literal name, or raw bytes.
         */
        private byte[] section() {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int flags = in.u8();
            if ((flags & 0x80) != 0) {
                b.writeBytes(in.bytes(2));
            } else {
                b.write(0);
                b.write(0);
            }
            int n = flags & 0x0F;
            for (int i = 0; i < n; i++) {
                int kind = in.u8();
                switch (kind & 3) {
                    case 0 -> b.writeBytes(prefixed(0xC0, 6, STATIC_FIELDS[(kind >> 2) % STATIC_FIELDS.length]));
                    case 1 -> {
                        b.writeBytes(prefixed(0x50, 4, STATIC_FIELDS[(kind >> 2) % STATIC_FIELDS.length]));
                        b.writeBytes(string(0x00, 7, VALUES[in.u8() % VALUES.length]));
                    }
                    case 2 -> {
                        b.writeBytes(string(0x20, 3, NAMES[(kind >> 2) % NAMES.length]));
                        b.writeBytes(string(0x00, 7, VALUES[in.u8() % VALUES.length]));
                    }
                    default -> b.writeBytes(in.bytes(in.u8() % 8));
                }
            }
            return b.toByteArray();
        }

        private static byte[] string(int pattern, int bits, String s) {
            byte[] v = s.getBytes(StandardCharsets.UTF_8);
            byte[] len = prefixed(pattern, bits, v.length);
            byte[] out = Arrays.copyOf(len, len.length + v.length);
            System.arraycopy(v, 0, out, len.length, v.length);
            return out;
        }

        /** An RFC 7541 §5.1 prefixed integer with {@code pattern} in the high bits. */
        private static byte[] prefixed(int pattern, int bits, long v) {
            int max = (1 << bits) - 1;
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            if (v < max) {
                b.write(pattern | (int) v);
                return b.toByteArray();
            }
            b.write(pattern | max);
            v -= max;
            while (v >= 0x80) {
                b.write((int) (v & 0x7F) | 0x80);
                v >>>= 7;
            }
            b.write((int) v);
            return b.toByteArray();
        }

        private static byte[] pattern(int n) {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte) ('a' + i % 26);
            return b;
        }

        private static byte[] frame(long type, byte[] payload) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            b.writeBytes(varint(type));
            b.writeBytes(varint(payload.length));
            b.writeBytes(payload);
            return b.toByteArray();
        }

        private static byte[] varint(long v) {
            v = Math.min(v, Http3Varint.MAX_VALUE);
            byte[] b = new byte[Http3Varint.size(v)];
            Http3Varint.encode(b, 0, v);
            return b;
        }
    }
}

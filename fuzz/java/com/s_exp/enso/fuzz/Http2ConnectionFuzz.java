// ABOUTME: Jazzer target driving a whole cleartext HTTP/2 connection in-process over an in-memory socket:
// ABOUTME: structured client frame sequences in, a well-formed, flow-controlled server frame sequence out.
package com.s_exp.enso.fuzz;

import clojure.lang.Keyword;
import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.StreamingBody;
import com.s_exp.enso.http2.Hpack;
import com.s_exp.enso.http2.Http2Connection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Drives {@link Http2Connection#run()} (cleartext, prior knowledge) over
 * a {@link FakeSocket} whose input is built from the fuzz input.
 *
 * <p>Input layout: byte 0 sets up the connection (bit 0: no client
 * preface is sent, bit 1: no empty initial SETTINGS is sent, so the
 * operations must provide it). The rest is a list of operations, each an
 * opcode byte (low nibble selects it) and its operand bytes; operands
 * past the end of the input read as 0. Stream-id operands are one
 * selector byte: below 0x80, {@code s & 3} picks the next idle odd id,
 * the last opened stream, the one before it, or the raw id
 * {@code (s >> 2) & 31}; from 0x80 the next four bytes are a raw 32-bit
 * id (reserved bit included).
 * <pre>
 *  0 request    sid, flags, method/path, n, n x (name, value) [, pad]: HPACK-encoded
 *               head by the connection's encoder; flags: END_STREAM, PADDED,
 *               PRIORITY, self-dependency, 0-3 CONTINUATION splits, no END_HEADERS
 *  1 headers    sid, frame flags, len, raw block bytes
 *  2 continuation sid, frame flags, len, raw bytes
 *  3 data       sid, flags (END_STREAM, PADDED), u16 size, [pad]: generated payload
 *  4 settings   flags, n, n x (id, value selector)
 *  5 window     sid, increment selector
 *  6 rst        sid, error code
 *  7 priority   sid, dependency sid, weight, bit 0: 4-byte payload
 *  8 ping       flags, 8 payload bytes
 *  9 goaway     last-stream sid, error code, debug length
 * 10 push       sid, promised sid, len, bytes
 * 11 unknown    type (10 and up), flags, sid, len, bytes
 * 12 raw        len, bytes copied as they are
 * 13 bad length type, flags, sid, declared-length selector, len, bytes
 * 14 trailers   sid, flags, n, n x (name, value): a header block of regular fields
 * 15 burst      n, flags: n END_STREAM GETs on fresh streams (bit 0: each reset at once)
 * </pre>
 * The handler drains the request body and answers 200 (text, a 40000
 * byte array, a streamed body or an InputStream, by path) or 204, so it
 * never fails. When the input runs out the harness waits until the
 * connection's handlers are done or stuck (bounded), so responses that
 * can complete do; after {@code run()} it waits for the writer to stop
 * and every handler thread to end.
 *
 * <p>Checks: {@code run()} returns; nothing logged at WARNING or above
 * (the server's policy reserves it for server-side faults) and no
 * uncaught exception on any thread; the socket is closed; the output is
 * a sequence of whole frames: a SETTINGS first, then only SETTINGS ACKs
 * (no more than the client's SETTINGS), PING ACKs echoing a client PING,
 * lengths within 16384 (the handler's responses and our control frames
 * never need more), reserved bit clear, no PRIORITY or PUSH_PROMISE,
 * stream frames only on odd ids a client HEADERS named, RST_STREAM and
 * GOAWAY codes defined by RFC 9113, GOAWAY last-stream-ids never
 * increasing and no HEADERS or DATA above one, header blocks not
 * interleaved and decoding (in order, one HPACK decoder) to a single
 * {@code :status} (never 500) before DATA, nothing after END_STREAM or
 * our RST_STREAM on a stream, DATA within Content-Length, WINDOW_UPDATE
 * increments positive; DATA within the client's flow-control windows
 * (initial window at most the largest advertised plus every increment).
 */
public final class Http2ConnectionFuzz {

    private static final int DATA = 0x0;
    private static final int HEADERS = 0x1;
    private static final int PRIORITY = 0x2;
    private static final int RST_STREAM = 0x3;
    private static final int SETTINGS = 0x4;
    private static final int PUSH_PROMISE = 0x5;
    private static final int PING = 0x6;
    private static final int GOAWAY = 0x7;
    private static final int WINDOW_UPDATE = 0x8;
    private static final int CONTINUATION = 0x9;

    private static final int END_STREAM = 0x1;
    private static final int ACK = 0x1;
    private static final int END_HEADERS = 0x4;
    private static final int PADDED = 0x8;
    private static final int PRIORITY_FLAG = 0x20;

    private static final int MAX_FRAME = 16384;
    private static final int DEFAULT_WINDOW = 65535;
    private static final int LAST_ERROR_CODE = 0xd;

    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] DRAIN_PING = "ensodrai".getBytes(StandardCharsets.ISO_8859_1);

    private static final String[] METHODS = {"GET", "POST", "HEAD", "PUT", "CONNECT", "OPTIONS", "DELETE", "get"};
    private static final String[] PATHS = {"/", "/big", "/stream", "/in", "/empty", "*", "/a?b=c", ""};
    private static final String[] NAMES = {
        "content-length", "expect", "te", "connection", "cookie", "host", "content-type", "user-agent",
        "Upper", ":path", ":status", ":method", "x-a", "transfer-encoding", "keep-alive", ":protocol"};
    private static final String[] VALUES = {
        "0", "5", "10", "100", "100-continue", "trailers", "gzip", "a=b", "", "x", "v".repeat(300), "-1",
        "1, 1", "close", "localhost", "a\tb"};
    private static final long[] SETTING_VALUES = {
        0, 1, 2, 100, 4096, 16383, 16384, 16385, 65535, 65536, 1 << 20, 16777215, 16777216,
        0x7fffffffL, 0x80000000L, 0xffffffffL};
    private static final long[] INCREMENTS = {0, 1, 1024, 16384, 65535, 1 << 20, 0x7fffffffL, 0x80000000L};
    private static final int[] DECLARED_LENGTHS = {0, 1, 4, 5, 8, 16384, 16385, 0xffffff};

    private static final Keyword BODY = Keyword.intern("body");
    private static final Map<String, String> TEXT = Map.of("content-type", "text/plain");
    private static final byte[] BIG = new byte[40000];
    private static final byte[] CHUNK = new byte[6000];

    static {
        for (int i = 0; i < BIG.length; i++) BIG[i] = (byte) ('a' + i % 26);
        System.arraycopy(BIG, 0, CHUNK, 0, CHUNK.length);
    }

    // Failures off the fuzzing thread: WARNING records and uncaught exceptions.
    private static final AtomicReference<Throwable> FAILURE = new AtomicReference<>();
    private static final Logger ENSO_LOG = Logger.getLogger("com.s_exp.enso");
    // Threads that entered the handler during the current input.
    private static final Queue<Thread> HANDLER_THREADS = new ConcurrentLinkedQueue<>();

    private static final VarHandle ACTIVE_HANDLERS;
    private static final VarHandle WRITER;
    private static final VarHandle WRITER_FAILED;

    // Waiting at EOF for handlers: at most this long, done once the
    // handlers and the output stayed unchanged for STABLE_POLLS polls.
    private static final long QUIET_MAX_NANOS = 50_000_000L;
    private static final long POLL_NANOS = 250_000L;
    private static final int STABLE_POLLS = 4;
    private static final int UNACCOUNTED_POLLS = 20;
    private static final long STOP_MAX_NANOS = 5_000_000_000L;

    static {
        ENSO_LOG.addHandler(new Handler() {
            @Override
            public void publish(LogRecord r) {
                if (r.getLevel().intValue() >= Level.WARNING.intValue()) {
                    FAILURE.compareAndSet(null, new IllegalStateException(
                        "server logged " + r.getLevel() + " " + r.getLoggerName() + ": " + r.getMessage(),
                        r.getThrown()));
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        });
        Thread.setDefaultUncaughtExceptionHandler((t, e) ->
            FAILURE.compareAndSet(null, new IllegalStateException("uncaught exception on " + t, e)));
        try {
            MethodHandles.Lookup conn = MethodHandles.privateLookupIn(Http2Connection.class, MethodHandles.lookup());
            Class<?> writer = Class.forName("com.s_exp.enso.http2.Http2Writer");
            ACTIVE_HANDLERS = conn.findVarHandle(Http2Connection.class, "activeHandlers", AtomicInteger.class);
            WRITER = conn.findVarHandle(Http2Connection.class, "writer", writer);
            WRITER_FAILED = MethodHandles.privateLookupIn(writer, MethodHandles.lookup())
                .findVarHandle(writer, "failed", boolean.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // Low limits so floods, refusals, 413 and 431 are reachable with short inputs.
    private static final EnsoServer SERVER = FuzzServer.start(Http2ConnectionFuzz::handle, b -> b
        .http2MaxConcurrentStreams(8)
        .http2InitialWindowBytes(DEFAULT_WINDOW)
        .http2StreamResetLimit(20)
        .http2ContinuationLimit(16)
        .maxHeaderBytes(2048)
        .maxHeaderFields(16)
        .maxRequestBodyBytes(32768));

    private Http2ConnectionFuzz() {}

    private static Response handle(Request request) {
        HANDLER_THREADS.add(Thread.currentThread());
        Object body = request.valAt(BODY);
        if (body instanceof InputStream in) {
            try {
                in.transferTo(OutputStream.nullOutputStream());
            } catch (IOException e) {
                // A reset, truncated or oversized body: the connection answers it.
            }
        }
        return switch (request.uri) {
            case "/big" -> new Response(200, TEXT, BIG);
            case "/stream" -> new Response(200, TEXT, (StreamingBody) w -> {
                for (int i = 0; i < 3; i++) {
                    w.write(CHUNK);
                    w.flush();
                }
            });
            case "/in" -> new Response(200, TEXT, new FilterInputStream(new ByteArrayInputStream(BIG, 0, 20000)) {
            });
            case "/empty" -> new Response(204, Map.of(), null);
            default -> new Response(200, TEXT, "ok");
        };
    }

    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length == 0) return;
        FAILURE.set(null);
        HANDLER_THREADS.clear();
        byte[] wire = new WireBuilder(data).build();
        Http2Connection[] conn = new Http2Connection[1];
        FakeSocket[] socket = new FakeSocket[1];
        socket[0] = new FakeSocket(wire, () -> awaitQuiet(conn[0], socket[0]));
        conn[0] = new Http2Connection(socket[0], Http2ConnectionFuzz::handle, SERVER, 0L, false);
        try {
            conn[0].run();
        } catch (Throwable t) {
            throw new IllegalStateException("run() threw", t);
        }
        awaitWriterStopped(conn[0]);
        awaitHandlerThreads();
        Throwable failure = FAILURE.get();
        if (failure != null) {
            throw new IllegalStateException("server failed on client input", failure);
        }
        if (!socket[0].isClosed()) {
            throw new IllegalStateException("run() returned with the socket open");
        }
        new OutputChecker(new ClientView(wire)).check(socket[0].written());
    }

    // ---- Harness synchronisation ----------------------------------------------------

    /**
     * At EOF (on the framer): lets admitted streams finish before the
     * framer tears the connection down, until no handler is active or
     * nothing moved for a few polls (handlers parked on a body or window
     * that will never come), at most {@link #QUIET_MAX_NANOS}.
     */
    private static void awaitQuiet(Http2Connection conn, FakeSocket socket) {
        AtomicInteger active = (AtomicInteger) ACTIVE_HANDLERS.get(conn);
        long deadline = System.nanoTime() + QUIET_MAX_NANOS;
        long last = -1;
        int stable = 0;
        while (System.nanoTime() - deadline < 0) {
            int n = active.get();
            if (n == 0) return;
            long signature = ((long) n << 32) ^ socket.writtenLength() ^ ((long) HANDLER_THREADS.size() << 48);
            int parked = parkedHandlers();
            if (signature == last && parked >= 0) {
                // Streams without a parked handler thread of ours (not
                // started yet, answered without the handler, waiting for
                // credit) get longer to show progress.
                if (++stable >= (parked >= n ? STABLE_POLLS : UNACCOUNTED_POLLS)) return;
            } else {
                stable = 0;
            }
            last = signature;
            LockSupport.parkNanos(POLL_NANOS);
        }
    }

    /** Handler threads parked or done, or -1 while one of them runs. */
    private static int parkedHandlers() {
        int parked = 0;
        for (Thread t : HANDLER_THREADS) {
            Thread.State s = t.getState();
            if (s == Thread.State.RUNNABLE || s == Thread.State.NEW) return -1;
            if (s != Thread.State.TERMINATED) parked++;
        }
        return parked;
    }

    /** After run(): a lingering close flushes from another thread; wait until the writer stopped for good. */
    private static void awaitWriterStopped(Http2Connection conn) {
        Object writer = WRITER.get(conn);
        if (writer == null) return;
        long deadline = System.nanoTime() + STOP_MAX_NANOS;
        while (!(boolean) WRITER_FAILED.getVolatile(writer)) {
            if (System.nanoTime() - deadline >= 0) {
                throw new IllegalStateException("HTTP/2 writer still active 5 s after run() returned");
            }
            LockSupport.parkNanos(POLL_NANOS);
        }
    }

    private static void awaitHandlerThreads() {
        long deadline = System.nanoTime() + STOP_MAX_NANOS;
        for (Thread t : HANDLER_THREADS) {
            try {
                long left = deadline - System.nanoTime();
                if (left <= 0 || !t.join(java.time.Duration.ofNanos(left))) {
                    throw new IllegalStateException("handler thread " + t + " still running after run() returned");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }

    // ---- Client input -----------------------------------------------------------------

    /** Turns the fuzz input into the client's bytes. */
    private static final class WireBuilder {
        private final byte[] data;
        private final FuzzInput in;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final Hpack.Encoder encoder = new Hpack.Encoder(4096);
        private int nextId = 1;
        private int lastId;

        WireBuilder(byte[] data) {
            this.data = data;
            this.in = new FuzzInput(data, 1);
        }

        byte[] build() {
            int setup = data[0] & 0xFF;
            if ((setup & 1) == 0) out.writeBytes(PREFACE);
            if ((setup & 2) == 0) frame(SETTINGS, 0, 0, new byte[0]);
            while (in.hasMore()) {
                op(in.u8());
            }
            return out.toByteArray();
        }

        private void op(int code) {
            switch (code & 0x0F) {
                case 0 -> request();
                case 1 -> {
                    int sid = sid(in.u8());
                    int flags = in.u8();
                    frame(HEADERS, flags, sid, in.bytes(in.u8()));
                }
                case 2 -> {
                    int sid = sid(in.u8());
                    int flags = in.u8();
                    frame(CONTINUATION, flags, sid, in.bytes(in.u8()));
                }
                case 3 -> data();
                case 4 -> settings();
                case 5 -> {
                    int sid = sid(in.u8());
                    frame(WINDOW_UPDATE, 0, sid, int32((int) pick(INCREMENTS, in.u8())));
                }
                case 6 -> {
                    int sid = sid(in.u8());
                    frame(RST_STREAM, 0, sid, int32(in.u8()));
                }
                case 7 -> priority();
                case 8 -> {
                    int flags = in.u8();
                    frame(PING, flags, 0, in.bytes(8));
                }
                case 9 -> {
                    int last = sid(in.u8());
                    int code2 = in.u8();
                    byte[] debug = new byte[in.u8() % 16];
                    byte[] p = new byte[8 + debug.length];
                    System.arraycopy(int32(last), 0, p, 0, 4);
                    System.arraycopy(int32(code2), 0, p, 4, 4);
                    frame(GOAWAY, 0, 0, p);
                }
                case 10 -> {
                    int sid = sid(in.u8());
                    int promised = sid(in.u8());
                    byte[] rest = in.bytes(in.u8());
                    byte[] p = new byte[4 + rest.length];
                    System.arraycopy(int32(promised), 0, p, 0, 4);
                    System.arraycopy(rest, 0, p, 4, rest.length);
                    frame(PUSH_PROMISE, END_HEADERS, sid, p);
                }
                case 11 -> {
                    int type = in.u8();
                    if (type < 10) type += 10;
                    int flags = in.u8();
                    int sid = sid(in.u8());
                    frame(type, flags, sid, in.bytes(in.u8()));
                }
                case 12 -> out.writeBytes(in.bytes(in.u8()));
                case 13 -> {
                    int type = in.u8() % 10;
                    int flags = in.u8();
                    int sid = sid(in.u8());
                    int declared = DECLARED_LENGTHS[in.u8() % DECLARED_LENGTHS.length];
                    byte[] p = in.bytes(in.u8() % 32);
                    frame(type, flags, sid, declared, p);
                }
                case 14 -> trailers();
                default -> burst();
            }
        }

        /** Stream id from a selector byte (see the class comment). */
        private int sid(int s) {
            if (s >= 0x80) return in.u32();
            return switch (s & 3) {
                case 0 -> nextId;
                case 1 -> Math.max(1, lastId);
                case 2 -> Math.max(1, lastId - 2);
                default -> (s >> 2) & 0x1F;
            };
        }

        private void opened(int sid) {
            if ((sid & 1) == 1 && sid > 0 && sid >= nextId) {
                lastId = sid;
                nextId = sid + 2;
            }
        }

        private void request() {
            int sid = sid(in.u8());
            int flags = in.u8();
            int mp = in.u8();
            List<Hpack.HeaderField> fields = new ArrayList<>();
            fields.add(new Hpack.HeaderField(":method", METHODS[mp & 7]));
            fields.add(new Hpack.HeaderField(":scheme", "http"));
            fields.add(new Hpack.HeaderField(":path", PATHS[(mp >> 3) & 7]));
            if ((mp & 0x40) == 0) fields.add(new Hpack.HeaderField(":authority", "localhost"));
            extraFields(fields);
            byte[] block = encoder.encode(fields);
            int pad = (flags & 0x02) != 0 ? in.u8() : -1;
            headerBlock(sid, flags, block, pad);
            opened(sid);
        }

        private void trailers() {
            int sid = sid(in.u8());
            int flags = in.u8();
            List<Hpack.HeaderField> fields = new ArrayList<>();
            extraFields(fields);
            // Bit 0 clear: the trailer section ends the stream, as it must.
            headerBlock(sid, flags ^ 0x01, encoder.encode(fields), -1);
        }

        private void extraFields(List<Hpack.HeaderField> fields) {
            int n = in.u8() % 8;
            for (int i = 0; i < n; i++) {
                String name = NAMES[in.u8() % NAMES.length];
                fields.add(new Hpack.HeaderField(name, VALUES[in.u8() % VALUES.length]));
            }
        }

        /**
         * HEADERS (+ CONTINUATION) for {@code block}. Flags: bit 0
         * END_STREAM, 1 PADDED, 2 PRIORITY, 3 self-dependency, 4-5 number
         * of CONTINUATION frames, 6 no END_HEADERS on the last frame.
         */
        private void headerBlock(int sid, int flags, byte[] block, int pad) {
            int pieces = 1 + ((flags >> 4) & 3);
            int per = Math.max(1, (block.length + pieces - 1) / pieces);
            int off = 0;
            for (int i = 0; i < pieces; i++) {
                boolean firstFrame = i == 0;
                boolean lastFrame = i == pieces - 1;
                int end = lastFrame ? block.length : Math.min(block.length, off + per);
                byte[] fragment = java.util.Arrays.copyOfRange(block, off, end);
                off = end;
                int f = lastFrame && (flags & 0x40) == 0 ? END_HEADERS : 0;
                if (firstFrame) {
                    if ((flags & 0x01) != 0) f |= END_STREAM;
                    ByteArrayOutputStream p = new ByteArrayOutputStream();
                    if (pad >= 0) {
                        f |= PADDED;
                        p.write(pad);
                    }
                    if ((flags & 0x04) != 0) {
                        f |= PRIORITY_FLAG;
                        p.writeBytes(int32((flags & 0x08) != 0 ? sid : 0));
                        p.write(15);
                    }
                    p.writeBytes(fragment);
                    if (pad > 0) p.writeBytes(new byte[pad]);
                    frame(HEADERS, f, sid, p.toByteArray());
                } else {
                    frame(CONTINUATION, f, sid, fragment);
                }
            }
        }

        private void data() {
            int sid = sid(in.u8());
            int flags = in.u8();
            int size = in.u16() % 20000;
            byte[] p;
            int f = flags & END_STREAM;
            if ((flags & PADDED) != 0) {
                int pad = in.u8();
                p = new byte[1 + size + pad];
                p[0] = (byte) pad;
                System.arraycopy(pattern(size), 0, p, 1, size);
                f |= PADDED;
            } else {
                p = pattern(size);
            }
            frame(DATA, f, sid, p);
        }

        private static byte[] pattern(int n) {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte) ('0' + i % 10);
            return b;
        }

        private void settings() {
            int flags = in.u8();
            int n = in.u8() % 6;
            byte[] p = new byte[6 * n];
            for (int i = 0; i < n; i++) {
                int id = in.u8();
                long v = pick(SETTING_VALUES, in.u8());
                p[6 * i] = 0;
                p[6 * i + 1] = (byte) id;
                System.arraycopy(int32((int) v), 0, p, 6 * i + 2, 4);
            }
            frame(SETTINGS, flags & ACK, 0, p);
        }

        private void priority() {
            int sid = sid(in.u8());
            int dep = sid(in.u8());
            int weight = in.u8();
            int variant = in.u8();
            byte[] p = new byte[(variant & 1) != 0 ? 4 : 5];
            System.arraycopy(int32(dep), 0, p, 0, 4);
            if (p.length == 5) p[4] = (byte) weight;
            frame(PRIORITY, 0, sid, p);
        }

        private void burst() {
            int n = in.u8() % 32;
            int flags = in.u8();
            for (int i = 0; i < n; i++) {
                int sid = nextId;
                List<Hpack.HeaderField> fields = List.of(
                    new Hpack.HeaderField(":method", "GET"),
                    new Hpack.HeaderField(":scheme", "http"),
                    new Hpack.HeaderField(":path", "/"),
                    new Hpack.HeaderField(":authority", "localhost"));
                frame(HEADERS, END_STREAM | END_HEADERS, sid, encoder.encode(fields));
                opened(sid);
                if ((flags & 1) != 0) frame(RST_STREAM, 0, sid, int32(8));
            }
        }

        /** Selector byte below 0xF0: a table entry; otherwise four raw bytes follow. */
        private long pick(long[] table, int selector) {
            return selector < 0xF0 ? table[selector % table.length] : in.u32() & 0xFFFFFFFFL;
        }

        private void frame(int type, int flags, int sid, byte[] payload) {
            frame(type, flags, sid, payload.length, payload);
        }

        /** One frame whose length field says {@code declared}, whatever the payload's length. */
        private void frame(int type, int flags, int sid, int declared, byte[] payload) {
            out.write(declared >>> 16);
            out.write(declared >>> 8);
            out.write(declared);
            out.write(type);
            out.write(flags);
            out.writeBytes(int32(sid));
            out.writeBytes(payload);
        }

        private static byte[] int32(int v) {
            return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
        }
    }

    /** What the client's bytes allow the server to send, from a frame-by-frame parse. */
    private static final class ClientView {
        int maxHeadersStream;
        long maxInitialWindow = DEFAULT_WINDOW;
        final Map<Integer, Long> increments = new HashMap<>();
        int settingsFrames;
        int pingFrames;
        final Set<String> pingPayloads = new HashSet<>();

        ClientView(byte[] wire) {
            int p = startsWith(wire, PREFACE) ? PREFACE.length : 0;
            while (wire.length - p >= 9) {
                int len = ((wire[p] & 0xFF) << 16) | ((wire[p + 1] & 0xFF) << 8) | (wire[p + 2] & 0xFF);
                int type = wire[p + 3] & 0xFF;
                int flags = wire[p + 4] & 0xFF;
                int sid = int31(wire, p + 5);
                int q = p + 9;
                int have = Math.min(len, wire.length - q);
                switch (type) {
                    case HEADERS -> maxHeadersStream = Math.max(maxHeadersStream, sid);
                    case SETTINGS -> {
                        if ((flags & ACK) == 0) {
                            settingsFrames++;
                            for (int i = q; i + 6 <= q + have; i += 6) {
                                int id = ((wire[i] & 0xFF) << 8) | (wire[i + 1] & 0xFF);
                                long v = int32(wire, i + 2) & 0xFFFFFFFFL;
                                if (id == 4) maxInitialWindow = Math.max(maxInitialWindow, v);
                            }
                        }
                    }
                    case PING -> {
                        if ((flags & ACK) == 0 && have == 8) {
                            pingFrames++;
                            pingPayloads.add(new String(wire, q, 8, StandardCharsets.ISO_8859_1));
                        }
                    }
                    case WINDOW_UPDATE -> {
                        if (have == 4) increments.merge(sid, (long) int31(wire, q), Long::sum);
                    }
                    default -> {
                    }
                }
                p = q + len;
            }
        }

        long increments(int sid) {
            return increments.getOrDefault(sid, 0L);
        }
    }

    // ---- Server output ----------------------------------------------------------------

    private static final class StreamOut {
        boolean finalHeaders;
        boolean ended;
        boolean reset;
        long contentLength = -1;
        long data;
        long flowData;
    }

    private static final class OutputChecker {
        private final ClientView client;
        private final Hpack.Decoder decoder = new Hpack.Decoder(4096);
        private final Map<Integer, StreamOut> streams = new HashMap<>();
        private byte[] out;
        private long connData;
        private int settingsAcks;
        private int pingAcks;
        private long goawayLast = Long.MAX_VALUE;
        private int blockStream;
        private boolean blockEndStream;
        private final ByteArrayOutputStream block = new ByteArrayOutputStream();

        OutputChecker(ClientView client) {
            this.client = client;
        }

        void check(byte[] out) {
            this.out = out;
            int p = 0;
            boolean first = true;
            while (p < out.length) {
                if (out.length - p < 9) fail("truncated frame header at " + p);
                int len = ((out[p] & 0xFF) << 16) | ((out[p + 1] & 0xFF) << 8) | (out[p + 2] & 0xFF);
                int type = out[p + 3] & 0xFF;
                int flags = out[p + 4] & 0xFF;
                if ((out[p + 5] & 0x80) != 0) fail("reserved stream-id bit set at " + p);
                int sid = int31(out, p + 5);
                int q = p + 9;
                if (len > MAX_FRAME) fail("frame of " + len + " bytes at " + p);
                if (len > out.length - q) fail("truncated frame payload at " + p);
                if (blockStream != 0 && (type != CONTINUATION || sid != blockStream)) {
                    fail("frame type " + type + " interleaved in the header block of stream " + blockStream);
                }
                if (first) {
                    if (type != SETTINGS || flags != 0 || sid != 0 || len % 6 != 0) {
                        fail("output does not start with our SETTINGS");
                    }
                    first = false;
                } else {
                    frame(type, flags, sid, q, len);
                }
                p = q + len;
            }
            if (blockStream != 0) fail("header block of stream " + blockStream + " left open");
            if (connData > DEFAULT_WINDOW + client.increments(0)) {
                fail("DATA overran the connection window: " + connData);
            }
            for (Map.Entry<Integer, StreamOut> e : streams.entrySet()) {
                long allowed = client.maxInitialWindow + client.increments(e.getKey());
                if (e.getValue().flowData > allowed) {
                    fail("DATA overran stream " + e.getKey() + "'s window: " + e.getValue().flowData + " > " + allowed);
                }
            }
        }

        private void frame(int type, int flags, int sid, int q, int len) {
            switch (type) {
                case DATA -> data(flags, sid, q, len);
                case HEADERS -> headers(flags, sid, q, len);
                case CONTINUATION -> {
                    if (blockStream == 0) fail("CONTINUATION outside a header block, stream " + sid);
                    block.write(out, q, len);
                    if ((flags & END_HEADERS) != 0) endBlock();
                }
                case RST_STREAM -> {
                    clientStream(sid, "RST_STREAM");
                    if (len != 4) fail("RST_STREAM of " + len + " bytes");
                    long code = int32(out, q) & 0xFFFFFFFFL;
                    if (code > LAST_ERROR_CODE) fail("RST_STREAM code " + code);
                    stream(sid).reset = true;
                }
                case SETTINGS -> {
                    if ((flags & ACK) == 0 || len != 0 || sid != 0) fail("SETTINGS other than an ACK after the first");
                    if (++settingsAcks > client.settingsFrames) fail("more SETTINGS ACKs than client SETTINGS");
                }
                case PING -> {
                    if (len != 8 || sid != 0) fail("malformed PING");
                    String payload = new String(out, q, 8, StandardCharsets.ISO_8859_1);
                    if ((flags & ACK) != 0) {
                        if (!client.pingPayloads.contains(payload)) fail("PING ACK echoing no client PING");
                        if (++pingAcks > client.pingFrames) fail("more PING ACKs than client PINGs");
                    } else if (!payload.equals(new String(DRAIN_PING, StandardCharsets.ISO_8859_1))) {
                        fail("unexpected PING payload");
                    }
                }
                case GOAWAY -> {
                    if (sid != 0 || len < 8) fail("malformed GOAWAY");
                    if ((out[q] & 0x80) != 0) fail("GOAWAY reserved bit set");
                    int last = int31(out, q);
                    long code = int32(out, q + 4) & 0xFFFFFFFFL;
                    if (code > LAST_ERROR_CODE) fail("GOAWAY code " + code);
                    if (last > goawayLast) fail("GOAWAY last-stream-id increased " + goawayLast + " -> " + last);
                    goawayLast = last;
                }
                case WINDOW_UPDATE -> {
                    if (len != 4) fail("WINDOW_UPDATE of " + len + " bytes");
                    if ((out[q] & 0x80) != 0) fail("WINDOW_UPDATE reserved bit set");
                    if (int31(out, q) == 0) fail("WINDOW_UPDATE with increment 0");
                    if (sid != 0) clientStream(sid, "WINDOW_UPDATE");
                }
                default -> fail("server sent frame type " + type);
            }
        }

        private void clientStream(int sid, String what) {
            if (sid == 0 || (sid & 1) == 0 || sid > client.maxHeadersStream) {
                fail(what + " on stream " + sid + ", which no client HEADERS opened");
            }
        }

        private StreamOut stream(int sid) {
            return streams.computeIfAbsent(sid, k -> new StreamOut());
        }

        private StreamOut responseFrame(int sid, String what) {
            clientStream(sid, what);
            if (sid > goawayLast) fail(what + " on stream " + sid + " above GOAWAY last-stream-id " + goawayLast);
            StreamOut st = stream(sid);
            if (st.reset) fail(what + " on stream " + sid + " after our RST_STREAM");
            if (st.ended) fail(what + " on stream " + sid + " after END_STREAM");
            return st;
        }

        private void data(int flags, int sid, int q, int len) {
            StreamOut st = responseFrame(sid, "DATA");
            if (!st.finalHeaders) fail("DATA before the response head on stream " + sid);
            int body = len;
            if ((flags & PADDED) != 0) {
                if (len < 1 || (out[q] & 0xFF) > len - 1) fail("bad DATA padding");
                body = len - 1 - (out[q] & 0xFF);
            }
            st.data += body;
            st.flowData += len;
            connData += len;
            if (st.contentLength >= 0 && st.data > st.contentLength) {
                fail("DATA beyond content-length " + st.contentLength + " on stream " + sid);
            }
            if ((flags & END_STREAM) != 0) {
                st.ended = true;
                if (st.contentLength >= 0 && st.data != st.contentLength) {
                    fail("body of " + st.data + " bytes, content-length " + st.contentLength + " on stream " + sid);
                }
            }
        }

        private void headers(int flags, int sid, int q, int len) {
            responseFrame(sid, "HEADERS");
            int off = q;
            int end = q + len;
            if ((flags & PADDED) != 0) {
                if (len < 1) fail("bad HEADERS padding");
                end -= out[q] & 0xFF;
                off++;
            }
            if ((flags & PRIORITY_FLAG) != 0) off += 5;
            if (off > end) fail("bad HEADERS padding or priority");
            block.reset();
            block.write(out, off, end - off);
            blockStream = sid;
            blockEndStream = (flags & END_STREAM) != 0;
            if ((flags & END_HEADERS) != 0) endBlock();
        }

        private void endBlock() {
            int sid = blockStream;
            blockStream = 0;
            byte[] b = block.toByteArray();
            List<Hpack.HeaderField> fields;
            try {
                fields = decoder.decode(b, 0, b.length);
            } catch (IOException e) {
                throw new IllegalStateException("server header block does not decode on stream " + sid, e);
            }
            StreamOut st = stream(sid);
            if (fields.isEmpty() || !fields.get(0).name.equals(":status")) {
                // Trailers: after the head, ending the stream, no pseudo-headers.
                if (!st.finalHeaders || !blockEndStream) fail("header block without :status on stream " + sid);
                for (Hpack.HeaderField f : fields) {
                    if (f.name.startsWith(":")) fail("pseudo-header in trailers on stream " + sid);
                }
                st.ended = true;
                return;
            }
            String status = fields.get(0).value;
            if (!status.matches("[1-5][0-9][0-9]")) fail("bad :status " + status);
            if (status.equals("500")) fail("server answered 500 to client input on stream " + sid);
            for (int i = 1; i < fields.size(); i++) {
                Hpack.HeaderField f = fields.get(i);
                if (f.name.startsWith(":")) fail("pseudo-header " + f.name + " in a response on stream " + sid);
                if (f.name.equals("content-length")) st.contentLength = Long.parseLong(f.value);
            }
            if (status.charAt(0) == '1') {
                if (st.finalHeaders || blockEndStream) fail("misplaced interim response on stream " + sid);
                st.contentLength = -1;
                return;
            }
            if (st.finalHeaders) fail("second response head on stream " + sid);
            st.finalHeaders = true;
            if (blockEndStream) st.ended = true;
        }

        private void fail(String why) {
            throw new IllegalStateException(why);
        }
    }

    private static boolean startsWith(byte[] b, byte[] prefix) {
        return b.length >= prefix.length && java.util.Arrays.equals(b, 0, prefix.length, prefix, 0, prefix.length);
    }

    private static int int32(byte[] b, int p) {
        return ((b[p] & 0xFF) << 24) | ((b[p + 1] & 0xFF) << 16) | ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
    }

    private static int int31(byte[] b, int p) {
        return int32(b, p) & 0x7FFFFFFF;
    }
}

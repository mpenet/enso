package com.s_exp.enso.quiche;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;

/**
 * Manual FFM bindings for the {@code quiche_conn_stream_*} transport
 * primitives. jextract-generated {@code quiche_h.java} was originally
 * filtered to the h3-layer surface; when we dropped {@code quiche_h3_*}
 * in favour of a Java HTTP/3 implementation we needed these lower-level
 * stream calls, so they are bound here by hand rather than regenerating
 * the whole jextract output.
 *
 * <p>Loading this class assumes {@link Quiche} has already run its
 * static initialiser and dynamically linked libquiche.
 */
public final class QuicheStreams {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = SymbolLookup.loaderLookup();

    private QuicheStreams() {}

    // Force Quiche's classloader path to run so libquiche is loaded before
    // we look up its symbols.
    static {
        try {
            Class<?> c = Class.forName("com.s_exp.enso.quiche.Quiche");
            // Trigger init via a no-op reflective read on a static field.
            Method versionMethod;
            try {
                versionMethod = c.getDeclaredMethod("version");
                versionMethod.setAccessible(true);
                versionMethod.invoke(null);
            } catch (NoSuchMethodException ignored) {
                // Quiche class not shaped as expected; static { System.load }
                // still runs on Class.forName so we're fine.
            }
        } catch (Throwable t) {
            throw new IllegalStateException("libquiche not loaded", t);
        }
    }

    private static MethodHandle bind(String name, FunctionDescriptor desc) {
        MemorySegment sym = LOOKUP.find(name)
            .orElseThrow(() -> new IllegalStateException("libquiche symbol missing: " + name));
        return LINKER.downcallHandle(sym, desc);
    }

    // ssize_t quiche_conn_stream_recv(quiche_conn*, uint64_t stream_id,
    //   uint8_t* out, size_t buf_len, bool* fin, uint64_t* out_error_code)
    private static final MethodHandle MH_STREAM_RECV = bind(
        "quiche_conn_stream_recv",
        FunctionDescriptor.of(
            ValueLayout.JAVA_LONG,     // ssize_t return
            ValueLayout.ADDRESS,       // conn
            ValueLayout.JAVA_LONG,     // stream_id
            ValueLayout.ADDRESS,       // out buf
            ValueLayout.JAVA_LONG,     // buf_len
            ValueLayout.ADDRESS,       // fin* (bool*)
            ValueLayout.ADDRESS));     // out_error_code*

    public static long streamRecv(MemorySegment conn, long streamId,
                                   MemorySegment out, long bufLen,
                                   MemorySegment finOut, MemorySegment errOut) {
        try {
            return (long) MH_STREAM_RECV.invokeExact(conn, streamId, out, bufLen, finOut, errOut);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // ssize_t quiche_conn_stream_send(quiche_conn*, uint64_t stream_id,
    //   const uint8_t* buf, size_t buf_len, bool fin, uint64_t* out_error_code)
    private static final MethodHandle MH_STREAM_SEND = bind(
        "quiche_conn_stream_send",
        FunctionDescriptor.of(
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_BOOLEAN,
            ValueLayout.ADDRESS));

    public static long streamSend(MemorySegment conn, long streamId,
                                   MemorySegment buf, long bufLen, boolean fin,
                                   MemorySegment errOut) {
        try {
            return (long) MH_STREAM_SEND.invokeExact(conn, streamId, buf, bufLen, fin, errOut);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // bool quiche_conn_stream_finished(quiche_conn*, uint64_t stream_id)
    private static final MethodHandle MH_STREAM_FINISHED = bind(
        "quiche_conn_stream_finished",
        FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    public static boolean streamFinished(MemorySegment conn, long streamId) {
        try {
            return (boolean) MH_STREAM_FINISHED.invokeExact(conn, streamId);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // int quiche_conn_stream_shutdown(quiche_conn*, uint64_t stream_id,
    //   int direction, uint64_t err)
    //   direction: 0 = read, 1 = write
    private static final MethodHandle MH_STREAM_SHUTDOWN = bind(
        "quiche_conn_stream_shutdown",
        FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_LONG));

    public static int streamShutdown(MemorySegment conn, long streamId,
                                      int direction, long err) {
        try {
            return (int) MH_STREAM_SHUTDOWN.invokeExact(conn, streamId, direction, err);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // quiche_stream_iter* quiche_conn_readable(quiche_conn*)
    private static final MethodHandle MH_READABLE = bind(
        "quiche_conn_readable",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    public static MemorySegment readableIter(MemorySegment conn) {
        try {
            return (MemorySegment) MH_READABLE.invokeExact(conn);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // quiche_stream_iter* quiche_conn_writable(quiche_conn*)
    private static final MethodHandle MH_WRITABLE = bind(
        "quiche_conn_writable",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    public static MemorySegment writableIter(MemorySegment conn) {
        try {
            return (MemorySegment) MH_WRITABLE.invokeExact(conn);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // bool quiche_stream_iter_next(quiche_stream_iter*, uint64_t* stream_id)
    private static final MethodHandle MH_ITER_NEXT = bind(
        "quiche_stream_iter_next",
        FunctionDescriptor.of(
            ValueLayout.JAVA_BOOLEAN,
            ValueLayout.ADDRESS,
            ValueLayout.ADDRESS));

    public static boolean iterNext(MemorySegment iter, MemorySegment streamIdOut) {
        try {
            return (boolean) MH_ITER_NEXT.invokeExact(iter, streamIdOut);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // void quiche_stream_iter_free(quiche_stream_iter*)
    private static final MethodHandle MH_ITER_FREE = bind(
        "quiche_stream_iter_free",
        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    public static void iterFree(MemorySegment iter) {
        try {
            MH_ITER_FREE.invokeExact(iter);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // ssize_t quiche_conn_stream_capacity(quiche_conn*, uint64_t stream_id)
    private static final MethodHandle MH_STREAM_CAPACITY = bind(
        "quiche_conn_stream_capacity",
        FunctionDescriptor.of(
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG));

    public static long streamCapacity(MemorySegment conn, long streamId) {
        try {
            return (long) MH_STREAM_CAPACITY.invokeExact(conn, streamId);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}

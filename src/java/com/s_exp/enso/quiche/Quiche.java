package com.s_exp.enso.quiche;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * JNI shim over libquiche. Loads {@code libenso_quiche.<so|dylib>}
 * bundled in the jar (extracted to a temp dir on first use), which in
 * turn dlopens the system {@code libquiche}. All methods are 1:1 with
 * the C entry points in {@code native/enso_quiche/enso_quiche.c}.
 *
 * <p>We use JNI instead of FFM because JDK 25 + macOS ARM64 FFM downcall
 * paths corrupt libmalloc's freelist under connection churn (task
 * #86/#79; see also JDK-8357145 / JDK-8357268 which Netty's own
 * CleanerJava25.java steers around by gating MemorySegment usage on
 * JDK ≥ 25).
 *
 * <p>Pointer discipline: every quiche resource crosses the boundary as
 * an opaque {@code long} address. Java code treats them as tokens — do
 * not dereference. Use the {@code *Free} methods to release.
 *
 * <p>Sockaddr passing: instead of shipping {@code sockaddr_storage}
 * bytes (whose layout differs by OS), the shim takes {@code (byte[] ip,
 * int port)}. IPv4 addresses are 4-byte arrays; IPv6 addresses are
 * 16-byte arrays. The C side builds the real struct on the JNI stack.
 */
public final class Quiche {

    public static final int QUICHE_MAX_CONN_ID_LEN = 20;
    public static final int QUICHE_PROTOCOL_VERSION = 0x00000001;
    public static final long QUICHE_ERR_DONE = -1L;

    // enum quiche_shutdown
    public static final int QUICHE_SHUTDOWN_READ = 0;
    public static final int QUICHE_SHUTDOWN_WRITE = 1;

    static {
        loadLibrary();
    }

    private Quiche() {}

    private static void loadLibrary() {
        // Explicit override wins: user pointed us at a specific dylib
        // (typically for a locally-built shim during development).
        String override = System.getProperty("enso.quiche.shim");
        if (override != null && !override.isBlank()) {
            System.load(Path.of(override).toAbsolutePath().toString());
            return;
        }
        String arch = detectArch();
        String libName = System.mapLibraryName("enso_quiche");
        // Ordered list of classifier prefixes to try. On Linux+musl we
        // prefer the musl-built shim; if that isn't shipped, fall back
        // to the glibc build — libquiche links against libc which may
        // fail at runtime, but we bubble up a clear error rather than
        // silently misload.
        String[] osClassifiers = detectOsClassifiers();
        // 1) Try each candidate classpath resource in order.
        for (String os : osClassifiers) {
            String resPath = "/META-INF/native/" + os + "-" + arch + "/" + libName;
            try {
                if (Quiche.class.getResource(resPath) != null) {
                    Path extracted = extractResource(resPath, libName);
                    System.load(extracted.toAbsolutePath().toString());
                    return;
                }
            } catch (IOException e) {
                // fall through to the next candidate / filesystem probe
            }
        }
        // 2) Development / repl: probe local build output (same
        //    classifier list, first match wins).
        for (String os : osClassifiers) {
            Path devPath = Path.of("target/native/" + os + "-" + arch + "/" + libName);
            if (Files.exists(devPath)) {
                System.load(devPath.toAbsolutePath().toString());
                return;
            }
        }
        // 3) Standard library-path lookup (respects LD_LIBRARY_PATH,
        //    java.library.path, DYLD_LIBRARY_PATH).
        try {
            System.loadLibrary("enso_quiche");
        } catch (UnsatisfiedLinkError e) {
            throw new UnsatisfiedLinkError(
                "libenso_quiche not found for classifier(s) "
                + java.util.Arrays.toString(osClassifiers) + "-" + arch
                + ". Build with `make -C native/enso_quiche` or set"
                + " -Denso.quiche.shim=/abs/path/to/" + libName
                + ". Underlying error: " + e.getMessage());
        }
    }

    /**
     * OS classifiers in load-preference order. Standard `darwin` /
     * `linux` first; Alpine / musl systems get `linux-musl` prepended
     * so we prefer the musl-built shim over the glibc one. Detection
     * looks for {@code /lib/ld-musl-*.so.1} which is present on every
     * musl libc install (Alpine, Wolfi, Chimera).
     */
    private static String[] detectOsClassifiers() {
        String n = System.getProperty("os.name").toLowerCase();
        if (n.contains("mac") || n.contains("darwin")) {
            return new String[]{"darwin"};
        }
        if (n.contains("linux")) {
            if (isMusl()) {
                return new String[]{"linux-musl", "linux"};
            }
            return new String[]{"linux"};
        }
        return new String[]{n.replace(' ', '_')};
    }

    /**
     * Detect musl libc. Fast + cheap: check for the dynamic linker path
     * that musl always installs. Avoids exec of ldd + parse.
     */
    private static boolean isMusl() {
        Path lib = Path.of("/lib");
        if (!Files.isDirectory(lib)) return false;
        try (java.util.stream.Stream<Path> s = Files.list(lib)) {
            return s.anyMatch(p -> p.getFileName().toString().startsWith("ld-musl-"));
        } catch (IOException e) {
            return false;
        }
    }

    private static String detectArch() {
        String a = System.getProperty("os.arch").toLowerCase();
        if (a.equals("x86_64") || a.equals("amd64")) return "amd64";
        if (a.equals("aarch64") || a.equals("arm64")) return "arm64";
        return a;
    }

    /**
     * Extract the classpath resource into a per-JVM tempdir with a
     * random name, then return the path to the shim inside. Mirrors
     * Netty's netty_jni_util pattern (each JVM instance gets its own
     * filename so concurrent JVMs on the same host don't share a
     * dlopen'd file — some libc / kernel combinations refuse to
     * overwrite an in-use shared object). A shutdown hook removes the
     * dir + file on clean exit; {@link File#deleteOnExit} covers the
     * shutdown-hook-skipped paths (SIGKILL still leaks the tempdir,
     * which is expected).
     */
    private static Path extractResource(String resPath, String libName) throws IOException {
        Path dir = Files.createTempDirectory("enso-quiche-");
        Path lib = dir.resolve(libName);
        try (InputStream in = Quiche.class.getResourceAsStream(resPath);
             OutputStream out = Files.newOutputStream(lib,
                 StandardOpenOption.CREATE_NEW,
                 StandardOpenOption.WRITE)) {
            if (in == null) {
                throw new IOException("resource missing: " + resPath);
            }
            in.transferTo(out);
        }
        // Best-effort cleanup on normal shutdown. deleteOnExit + shutdown
        // hook are redundant to survive early-shutdown-hook-skip paths.
        lib.toFile().deleteOnExit();
        dir.toFile().deleteOnExit();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { Files.deleteIfExists(lib); } catch (IOException ignored) {}
            try { Files.deleteIfExists(dir); } catch (IOException ignored) {}
        }, "enso-quiche-shim-cleanup"));
        return lib;
    }

    // -----------------------------------------------------------------
    // Version
    // -----------------------------------------------------------------
    public static native String version();

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------
    public static native long configNew(int version);
    public static native void configFree(long config);
    public static native int configLoadCertChainFromPemFile(long config, String path);
    public static native int configLoadPrivKeyFromPemFile(long config, String path);
    public static native int configSetApplicationProtos(long config, byte[] protos);
    public static native void configSetMaxIdleTimeout(long config, long v);
    public static native void configSetMaxRecvUdpPayloadSize(long config, long v);
    public static native void configSetMaxSendUdpPayloadSize(long config, long v);
    public static native void configSetInitialMaxData(long config, long v);
    public static native void configSetInitialMaxStreamDataBidiLocal(long config, long v);
    public static native void configSetInitialMaxStreamDataBidiRemote(long config, long v);
    public static native void configSetInitialMaxStreamDataUni(long config, long v);
    public static native void configSetInitialMaxStreamsBidi(long config, long v);
    public static native void configSetInitialMaxStreamsUni(long config, long v);
    public static native void configSetAckDelayExponent(long config, long v);
    public static native void configSetMaxAckDelay(long config, long v);
    public static native void configSetActiveConnectionIdLimit(long config, long v);
    public static native void configSetDisableActiveMigration(long config, boolean v);

    // -----------------------------------------------------------------
    // Accept / retry / negotiate / header info
    // -----------------------------------------------------------------
    public static native long accept(byte[] scid, byte[] odcid,
                                     byte[] localIp, int localPort,
                                     byte[] peerIp, int peerPort,
                                     long config);
    /** Returns bytes written (>=0), QUICHE_ERR_DONE (-1), or < 0 on error. */
    public static native long retry(byte[] scid, byte[] dcid,
                                    byte[] newScid, byte[] token,
                                    int version, byte[] out);
    /** Returns bytes written, or < 0 on error. */
    public static native long negotiateVersion(byte[] scid, byte[] dcid, byte[] out);

    /**
     * Parses a QUIC packet header. Pre-fill scidLen[0]/dcidLen[0]/tokenLen[0]
     * with the maximum buffer size; C writes back the actual lengths on
     * success. Returns 0 on success or < 0 on error.
     */
    public static native int headerInfo(byte[] buf, int bufLen, int dcil,
                                        int[] versionOut, byte[] typeOut,
                                        byte[] scid, long[] scidLen,
                                        byte[] dcid, long[] dcidLen,
                                        byte[] token, long[] tokenLen);
    public static native boolean versionIsSupported(int version);

    // -----------------------------------------------------------------
    // Conn lifecycle + state
    // -----------------------------------------------------------------
    public static native void connFree(long conn);
    public static native boolean connIsClosed(long conn);
    public static native boolean connIsEstablished(long conn);
    /** Nanoseconds until next timeout, or -1 if no timeout is scheduled. */
    public static native long connTimeoutAsNanos(long conn);
    public static native void connOnTimeout(long conn);

    public static native long connRecv(long conn, byte[] buf, int bufLen,
                                       byte[] fromIp, int fromPort,
                                       byte[] toIp, int toPort);
    public static native long connSend(long conn, byte[] out, int outLen);
    /**
     * Initiate graceful/error connection close. {@code app=true} sends an
     * application-level close (H3 error codes); {@code app=false} sends a
     * transport-level QUIC close. {@code reason} may be null / empty.
     * Returns 0 on success or a quiche error code.
     */
    public static native int connClose(long conn, boolean app, long err,
                                       byte[] reason);

    // -----------------------------------------------------------------
    // Streams
    // -----------------------------------------------------------------
    /**
     * Bytes the stream can currently accept from stream_send (peer flow
     * control window minus in-flight). Negative on error. Zero means we
     * must defer sending and retry once the peer's window opens.
     */
    public static native long connStreamCapacity(long conn, long streamId);
    public static native long connStreamRecv(long conn, long streamId,
                                             byte[] out, int outLen,
                                             boolean[] finOut, long[] errOut);
    public static native long connStreamSend(long conn, long streamId,
                                             byte[] buf, int off, int len,
                                             boolean fin);
    public static native int connStreamShutdown(long conn, long streamId,
                                                int direction, long err);
    public static native long connReadable(long conn);
    public static native boolean streamIterNext(long iter, long[] streamIdOut);
    public static native void streamIterFree(long iter);
}

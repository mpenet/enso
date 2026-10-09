// ABOUTME: JNI entry points of the enso_quiche shim (libquiche plus UDP socket I/O): loading,
// ABOUTME: the libquiche version check, and the package-private natives the handle wrappers use.
package com.s_exp.enso.quiche;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * The shim {@code libenso_quiche.<so|dylib>} bundled in the jar (extracted
 * to a temp dir on first use), statically linking libquiche in release
 * builds and dynamically in development builds. Natives map 1:1 to the C
 * entry points in {@code native/enso_quiche/enso_quiche.c}.
 *
 * <p>The natives are package-private: raw quiche pointers and socket file
 * descriptors never leave this package. {@link QuicheConfig},
 * {@link QuicheConnection} and {@link UdpSocket} own them, check their
 * state on every call and refuse to touch a freed handle.
 *
 * <p>Packets, socket addresses and per-call results travel in
 * {@link NativeBuffer}s, passed as (address, capacity) and range-checked by
 * the shim (record layouts in {@link Records}); stream payloads in byte[]
 * accessed through one-call critical regions.
 *
 * <p>Loading checks the shim's ABI number ({@link #SHIM_ABI}) and record
 * layouts ({@link #requireLayout}), then {@link #version()} against
 * {@link #QUICHE_VERSION}: the shim is compiled against that release's
 * header, whose struct layouts change between releases, so a dynamically
 * linked libquiche of another version is refused rather than misread.
 */
public final class Quiche {

    /** The libquiche release the shim is built against. */
    public static final String QUICHE_VERSION = "0.29.3";

    public static final int QUICHE_MAX_CONN_ID_LEN = 20;
    public static final int QUICHE_PROTOCOL_VERSION = 0x00000001;
    public static final long QUICHE_ERR_DONE = -1L;
    // Selected quiche error codes we react to explicitly. Complete enum
    // lives in quiche.h — copy just the ones we branch on.
    public static final long QUICHE_ERR_STREAM_STOPPED = -15L;
    public static final long QUICHE_ERR_STREAM_RESET = -16L;
    public static final long QUICHE_ERR_INVALID_STATE = -6L;
    public static final long QUICHE_ERR_INVALID_STREAM_STATE = -7L;
    public static final long QUICHE_ERR_FINAL_SIZE = -13L;
    public static final long QUICHE_ERR_STREAM_LIMIT = -12L;
    /** Returned by the shim itself for invalid arguments (bounds, address). */
    public static final long SHIM_ERR_INVALID_ARGUMENT = -10000L;

    // enum quiche_shutdown
    public static final int QUICHE_SHUTDOWN_READ = 0;
    public static final int QUICHE_SHUTDOWN_WRITE = 1;

    /**
     * The JNI contract this class and the shim were built for: the shim's
     * {@code ENSO_SHIM_ABI}, bumped whenever a native's name, signature or
     * record layout changes. A stale shim (a development build left in
     * {@code target/native}, a classifier jar of another release) is
     * refused at load instead of failing on the first changed call.
     */
    public static final int SHIM_ABI = 2;

    /** System property naming the shim to load, bypassing every lookup. */
    static final String SHIM_PROPERTY = "enso.quiche.shim";
    /** System property, then environment variable, naming where the bundled shim is extracted. */
    static final String TMPDIR_PROPERTY = "enso.quiche.tmpdir";
    static final String TMPDIR_ENV = "ENSO_QUICHE_TMPDIR";

    static {
        loadLibrary();
        requireShimAbi(loadedShimAbi());
        requireLayout(loadedLayout());
        requireVersion(version());
    }

    /**
     * What the shim and the Java side must agree on, in the order of the
     * shim's {@code LAYOUT} table: record sizes and field offsets
     * ({@link Records}), flag and result bits ({@link UdpSocket}), limits
     * and the shim's own error code. Checked at load, so a layout edited
     * on one side only is refused by name even when the ABI number wasn't
     * bumped with it.
     */
    private static final String[] LAYOUT_NAMES = {
        "ADDR_LEN", "ADDR_FAMILY", "ADDR_PORT", "ADDR_SCOPE", "ADDR_IP",
        "RECV_META_LEN", "RECV_LEN", "RECV_FLAGS", "RECV_PEER", "RECV_LOCAL", "RECV_FLAG_TRUNCATED",
        "SEND_HEADER_LEN", "SEND_STATUS_DROPPED", "SEND_STATUS_ERRNO", "SEND_STATUS_FLAGS",
        "SEND_STATUS_GSO_DISABLED", "SEND_META_LEN", "SEND_OFF", "SEND_LEN", "SEND_TO", "SEND_FROM",
        "PKT_DELAY",
        "HDR_VERSION", "HDR_TYPE", "HDR_SCID_LEN", "HDR_DCID_LEN", "HDR_TOKEN_LEN", "HDR_SCID", "HDR_DCID",
        "HDR_TOKEN", "HDR_MAX_TOKEN", "HDR_LEN",
        "UDP_OPEN_REUSEPORT", "UDP_OPEN_PKTINFO", "UDP_SEND_GSO", "UDP_SEND_PKTINFO",
        "POLL_READABLE", "POLL_WAKE", "POLL_WRITABLE",
        "QUICHE_MAX_CONN_ID_LEN", "SHIM_ERR_INVALID_ARGUMENT"};

    static String[] layoutNames() {
        return LAYOUT_NAMES.clone();
    }

    /** The Java side's values for {@link #LAYOUT_NAMES}. */
    static int[] expectedLayout() {
        return new int[] {
            Records.ADDR_LEN, Records.ADDR_FAMILY, Records.ADDR_PORT, Records.ADDR_SCOPE, Records.ADDR_IP,
            Records.RECV_META_LEN, Records.RECV_LEN, Records.RECV_FLAGS, Records.RECV_PEER, Records.RECV_LOCAL,
            Records.RECV_FLAG_TRUNCATED,
            Records.SEND_HEADER_LEN, Records.SEND_STATUS_DROPPED, Records.SEND_STATUS_ERRNO,
            Records.SEND_STATUS_FLAGS, Records.SEND_STATUS_GSO_DISABLED, Records.SEND_META_LEN, Records.SEND_OFF,
            Records.SEND_LEN, Records.SEND_TO, Records.SEND_FROM,
            Records.PKT_DELAY,
            Records.HDR_VERSION, Records.HDR_TYPE, Records.HDR_SCID_LEN, Records.HDR_DCID_LEN,
            Records.HDR_TOKEN_LEN, Records.HDR_SCID, Records.HDR_DCID, Records.HDR_TOKEN, Records.HDR_MAX_TOKEN,
            Records.HDR_LEN,
            UdpSocket.OPEN_REUSEPORT, UdpSocket.OPEN_PKTINFO, UdpSocket.SEND_GSO, UdpSocket.SEND_PKTINFO,
            UdpSocket.Waker.READABLE, UdpSocket.Waker.WAKE, UdpSocket.Waker.WRITABLE,
            QUICHE_MAX_CONN_ID_LEN, (int) SHIM_ERR_INVALID_ARGUMENT};
    }

    /**
     * Refuses a shim whose {@code layout} (its LAYOUT table, null when it
     * has none) differs from {@link #expectedLayout}.
     *
     * @throws UnsatisfiedLinkError naming the first difference
     */
    static void requireLayout(int[] layout) {
        int[] expected = expectedLayout();
        if (layout == null || layout.length != expected.length) {
            throw new UnsatisfiedLinkError("enso_quiche shim record layout has "
                + (layout == null ? "no" : String.valueOf(layout.length)) + " entries, this enso expects "
                + expected.length + ": rebuild the shim (make -C native/enso_quiche)");
        }
        for (int i = 0; i < expected.length; i++) {
            if (layout[i] != expected[i]) {
                throw new UnsatisfiedLinkError("enso_quiche shim record layout differs at " + LAYOUT_NAMES[i]
                    + ": shim " + layout[i] + ", Java " + expected[i]
                    + ": rebuild the shim (make -C native/enso_quiche) or fix the layout on both sides");
            }
        }
    }

    /**
     * Refuses a libquiche other than {@link #QUICHE_VERSION}.
     *
     * @throws UnsatisfiedLinkError naming both versions
     */
    static void requireVersion(String actual) {
        if (!QUICHE_VERSION.equals(actual)) {
            throw new UnsatisfiedLinkError("libquiche " + actual + " loaded, but the enso_quiche shim"
                + " is built against " + QUICHE_VERSION + " (struct layouts differ between"
                + " releases). Install libquiche " + QUICHE_VERSION + " or use the statically"
                + " linked shim from the release jars.");
        }
    }

    /**
     * Refuses a shim built for another {@link #SHIM_ABI}.
     *
     * @throws UnsatisfiedLinkError naming both
     */
    static void requireShimAbi(int actual) {
        if (actual != SHIM_ABI) {
            throw new UnsatisfiedLinkError("enso_quiche shim ABI " + actual + " loaded, but this enso"
                + " expects ABI " + SHIM_ABI + ": rebuild the shim (make -C native/enso_quiche) or use"
                + " the classifier jar of the same release.");
        }
    }

    /** The loaded shim's ABI; 0 for a shim that predates the check (no shimAbi entry point). */
    private static int loadedShimAbi() {
        try {
            return shimAbi();
        } catch (UnsatisfiedLinkError e) {
            return 0;
        }
    }

    /** The loaded shim's LAYOUT table, or null for a shim without one. */
    private static int[] loadedLayout() {
        try {
            return layout();
        } catch (UnsatisfiedLinkError e) {
            return null;
        }
    }

    private Quiche() {}

    /**
     * Loads the shim from the first candidate that works, in order: the
     * {@value #SHIM_PROPERTY} override (alone: an explicit choice is never
     * second-guessed); the classpath resource of each OS classifier
     * (extracted, see {@link #extractResource}); in a development checkout
     * only, {@code target/native/} next to the class directory this class
     * was loaded from; the library path. A candidate that fails to load is
     * recorded and the next one tried; when none loads, the error lists
     * every candidate and why it failed.
     */
    private static void loadLibrary() {
        String override = System.getProperty(SHIM_PROPERTY);
        if (override != null && !override.isBlank()) {
            System.load(Path.of(override).toAbsolutePath().toString());
            return;
        }
        String arch = detectArch();
        String libName = System.mapLibraryName("enso_quiche");
        String[] osClassifiers = detectOsClassifiers();
        StringBuilder tried = new StringBuilder();
        for (String os : osClassifiers) {
            String resPath = "/META-INF/native/" + os + "-" + arch + "/" + libName;
            if (Quiche.class.getResource(resPath) == null) {
                tried.append("\n  classpath ").append(resPath).append(": absent");
                continue;
            }
            try {
                Path extracted = extractResource(resPath, libName);
                System.load(extracted.toAbsolutePath().toString());
                return;
            } catch (IOException | UnsatisfiedLinkError e) {
                tried.append("\n  classpath ").append(resPath).append(": ").append(e);
            }
        }
        Path dev = developmentDirectory();
        if (dev != null) {
            for (String os : osClassifiers) {
                Path devPath = dev.resolve(os + "-" + arch).resolve(libName);
                if (!Files.exists(devPath)) {
                    tried.append("\n  ").append(devPath).append(": absent");
                    continue;
                }
                try {
                    System.load(devPath.toAbsolutePath().toString());
                    return;
                } catch (UnsatisfiedLinkError e) {
                    tried.append("\n  ").append(devPath).append(": ").append(e.getMessage());
                }
            }
        }
        try {
            System.loadLibrary("enso_quiche");
            return;
        } catch (UnsatisfiedLinkError e) {
            tried.append("\n  java.library.path: ").append(e.getMessage());
        }
        String hint = osClassifiers[0].equals("linux-musl")
            ? " musl libc detected: add the linux-musl-" + arch + " classifier jar (a glibc shim"
                + " doesn't load on musl)."
            : " Add the " + osClassifiers[0] + "-" + arch + " classifier jar, build with"
                + " `make -C native/enso_quiche`, or set -D" + SHIM_PROPERTY + "=/abs/path/to/" + libName + ".";
        throw new UnsatisfiedLinkError("libenso_quiche could not be loaded." + hint + " Tried:" + tried);
    }

    /**
     * {@code target/native} of a development checkout: only when this class
     * was loaded from a directory ({@code target/classes}), never from a
     * jar, and never relative to the working directory (which could load a
     * library planted wherever the application happens to run). Null
     * otherwise.
     */
    static Path developmentDirectory() {
        try {
            java.security.CodeSource cs = Quiche.class.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            Path classes = Path.of(cs.getLocation().toURI());
            if (!Files.isDirectory(classes) || classes.getParent() == null) return null;
            return classes.getParent().resolve("native");
        } catch (RuntimeException | java.net.URISyntaxException e) {
            return null;
        }
    }

    /**
     * OS classifiers in load-preference order. Linux with musl libc (Alpine,
     * Wolfi, Chimera) loads only the musl build: the glibc one can't run
     * there, so it is never tried as a fallback. Detection: see
     * {@link #isMusl}.
     */
    private static String[] detectOsClassifiers() {
        String n = System.getProperty("os.name").toLowerCase();
        if (n.contains("mac") || n.contains("darwin")) {
            return new String[]{"darwin"};
        }
        if (n.contains("linux")) {
            return new String[]{isMusl() ? "linux-musl" : "linux"};
        }
        return new String[]{n.replace(' ', '_')};
    }

    /**
     * Whether this JVM runs on musl libc: the libc mapped into the process
     * ({@code /proc/self/maps}), so a glibc host that merely has the musl
     * package installed isn't mistaken for one. Without {@code /proc}, the
     * dynamic linker path musl always installs ({@code /lib/ld-musl-*}).
     */
    private static boolean isMusl() {
        try (java.io.BufferedReader maps = Files.newBufferedReader(Path.of("/proc/self/maps"),
                                                                    java.nio.charset.StandardCharsets.ISO_8859_1)) {
            String libc = libcFromMaps(maps);
            if (libc != null) return libc.equals("musl");
        } catch (IOException | RuntimeException e) {
            // No /proc: the installed loader decides.
        }
        Path lib = Path.of("/lib");
        if (!Files.isDirectory(lib)) return false;
        try (java.util.stream.Stream<Path> s = Files.list(lib)) {
            return s.anyMatch(p -> p.getFileName().toString().startsWith("ld-musl-"));
        } catch (IOException e) {
            return false;
        }
    }

    /** "musl" or "glibc" from a process's memory map (the libc it loaded), null when neither shows. */
    static String libcFromMaps(java.io.BufferedReader maps) throws IOException {
        String line;
        while ((line = maps.readLine()) != null) {
            if (line.contains("/ld-musl-") || line.contains("/libc.musl-")) return "musl";
            if (line.contains("/libc.so.6") || line.contains("/libc-2.")) return "glibc";
        }
        return null;
    }

    private static String detectArch() {
        String a = System.getProperty("os.arch").toLowerCase();
        if (a.equals("x86_64") || a.equals("amd64")) return "amd64";
        if (a.equals("aarch64") || a.equals("arm64")) return "arm64";
        return a;
    }

    /**
     * Where the bundled shim is extracted: the {@value #TMPDIR_PROPERTY}
     * system property, else the {@value #TMPDIR_ENV} environment variable,
     * else {@code java.io.tmpdir}. Set it when the default temp directory is
     * mounted noexec.
     */
    static Path extractionDirectory() {
        String dir = System.getProperty(TMPDIR_PROPERTY);
        if (dir == null || dir.isBlank()) dir = System.getenv(TMPDIR_ENV);
        if (dir == null || dir.isBlank()) dir = System.getProperty("java.io.tmpdir");
        return Path.of(dir);
    }

    /**
     * Extract the classpath resource into a per-JVM directory with a random
     * name under {@link #extractionDirectory}, then return the path to the
     * shim inside. Mirrors Netty's netty_jni_util pattern (each JVM instance
     * gets its own filename so concurrent JVMs on the same host don't share
     * a dlopen'd file — some libc / kernel combinations refuse to overwrite
     * an in-use shared object). A shutdown hook removes the dir + file on
     * clean exit; {@link java.io.File#deleteOnExit} covers the
     * shutdown-hook-skipped paths (SIGKILL still leaks the directory, which
     * is expected).
     */
    private static Path extractResource(String resPath, String libName) throws IOException {
        Path dir = Files.createTempDirectory(extractionDirectory(), "enso-quiche-");
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
    /** The loaded libquiche's version string. */
    public static String libraryVersion() {
        return version();
    }

    static native String version();

    /** The shim's ENSO_SHIM_ABI; see {@link #SHIM_ABI}. */
    static native int shimAbi();

    /** The shim's LAYOUT table: its values for {@link #LAYOUT_NAMES}, in order. */
    static native int[] layout();

    /** Address of a direct buffer's memory (0 for heap buffers); see {@link NativeBuffer}. */
    static native long bufferAddress(java.nio.ByteBuffer buf);

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------
    static native long configNew(int version);
    static native void configFree(long config);
    static native int configLoadCertChainFromPemFile(long config, String path);
    static native int configLoadPrivKeyFromPemFile(long config, String path);
    static native int configSetApplicationProtos(long config, byte[] protos);
    static native void configSetMaxIdleTimeout(long config, long v);
    static native void configSetMaxRecvUdpPayloadSize(long config, long v);
    static native void configSetMaxSendUdpPayloadSize(long config, long v);
    static native void configSetInitialMaxData(long config, long v);
    static native void configSetInitialMaxStreamDataBidiLocal(long config, long v);
    static native void configSetInitialMaxStreamDataBidiRemote(long config, long v);
    static native void configSetInitialMaxStreamDataUni(long config, long v);
    static native void configSetInitialMaxStreamsBidi(long config, long v);
    static native void configSetInitialMaxStreamsUni(long config, long v);
    static native void configSetAckDelayExponent(long config, long v);
    static native void configSetMaxAckDelay(long config, long v);
    static native void configSetActiveConnectionIdLimit(long config, long v);
    static native void configSetMaxConnectionWindow(long config, long v);
    static native void configSetMaxStreamWindow(long config, long v);
    static native void configSetDisableActiveMigration(long config, boolean v);
    static native void configVerifyPeer(long config, boolean v);

    // -----------------------------------------------------------------
    // Accept / connect / retry / header info
    // -----------------------------------------------------------------
    /** Addresses are ADDR records in {@code addrs}; {@code odcid} null without a Retry. 0 on failure. */
    static native long accept(byte[] scid, byte[] odcid, long addrs, int addrsCap,
                              int localOff, int peerOff, long config);
    static native long connect(String serverName, byte[] scid, long addrs, int addrsCap,
                               int localOff, int peerOff, long config);
    /** Writes a Retry packet into {@code out[off, off + cap)}; its length, or < 0. */
    static native long retry(byte[] scid, byte[] dcid, byte[] newScid, byte[] token,
                             int version, long out, int outCap, int off, int cap);
    /** Parses the header of {@code buf[off, off + len)} into the HDR record at {@code out[outOff]}. */
    static native int headerInfo(long buf, int bufCap, int off, int len, int dcil,
                                 long out, int outCap, int outOff);
    static native boolean versionIsSupported(int version);

    // -----------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------
    static native void connFree(long conn);
    static native boolean connIsClosed(long conn);
    static native boolean connIsEstablished(long conn);
    static native long connTimeoutAsNanos(long conn);
    /** {@link #connTimeoutAsNanos}, or -2 once the connection is closed: one call where both are asked. */
    static native long connTimeoutAsNanosOrClosed(long conn);
    static native void connOnTimeout(long conn);
    static native boolean connPeerError(long conn, long[] out);
    static native boolean connLocalError(long conn, long[] out);
    static native long connRecv(long conn, long buf, int bufCap, int off, int len,
                                long meta, int metaCap, int peerOff, int localOff);
    static native long connSend(long conn, long out, int outCap, int off, int cap,
                                long meta, int metaCap, int metaOff);
    static native int connClose(long conn, boolean app, long err, byte[] reason);
    static native long connSendAckEliciting(long conn);
    /** DER bytes of the peer's certificate, or null when it presented none. */
    static native byte[] connPeerCert(long conn);
    /** The path's smoothed round-trip time estimate, nanoseconds; -1 when unknown. */
    static native long connRttNanos(long conn);

    // -----------------------------------------------------------------
    // Streams
    // -----------------------------------------------------------------
    static native long connStreamCapacity(long conn, long streamId);
    /** {@code (bytes << 1) | fin}, or a negative quiche error. */
    static native long connStreamRecv(long conn, long streamId, byte[] out, int off, int len);
    static native long connStreamSend(long conn, long streamId, byte[] buf, int off, int len,
                                      boolean fin);
    static native int connStreamShutdown(long conn, long streamId, int direction, long err);
    static native long connStreamReadableNext(long conn);
    static native long connStreamWritableNext(long conn);

    // -----------------------------------------------------------------
    // UDP sockets, wake-ups, poll
    // -----------------------------------------------------------------
    static native int udpOpen(byte[] ip, int port, int flags, int rcvBuf, int sndBuf);
    static native int udpLocalAddress(int fd, long out, int outCap, int off);
    static native int udpBufferSize(int fd, boolean send);
    static native int udpClose(int fd);
    static native int udpAttachSteering(int fd, int n);
    static native int udpRecvBatch(int fd, long slab, int slabCap, int slotSize, int maxSlots,
                                   long meta, int metaCap);
    static native int udpSendBatch(int fd, long slab, int slabCap, long meta, int metaCap,
                                   int count, int flags);
    static native boolean udpGsoSupported(int fd);
    static native long wakeOpen();
    static native void wakeSignal(int writeFd);
    static native void wakeClose(long handle);
    static native int poll(int recvFd, int sendFd, int wakeFd, boolean wantWrite, long timeoutNanos);
}

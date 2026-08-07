package com.s_exp.enso.quiche;

import com.s_exp.enso.quiche.ffm.quiche_h;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Entry point for the libquiche FFM bindings. Loading this class triggers
 * a search for {@code libquiche} in common install locations, then falls
 * back to {@code System.loadLibrary("quiche")} so users can override with
 * {@code -Djava.library.path=…}. Any environment problem surfaces at
 * class-init time with a clear diagnostic.
 *
 * <p>The rest of Enso must never reach this class directly. HTTP/3 support
 * is behind a {@code Class.forName("com.s_exp.enso.quiche.Http3Listener")}
 * probe in {@link com.s_exp.enso.EnsoServer}, so users with {@code :http3
 * false} pay no classloading, memory, or startup cost for the FFM bindings.
 *
 * <p>Trimmed jextract output lives under {@code com.s_exp.enso.quiche.ffm}
 * with only the symbols Enso actually calls.
 */
public final class Quiche {

    // Common install prefixes. Homebrew on Apple Silicon puts things under
    // /opt/homebrew; Intel Homebrew and manual builds prefer /usr/local;
    // Linux distro packages land in /usr/lib*. Kept small on purpose — if
    // the user's setup is more exotic they can point at it via
    // -Djava.library.path or -Denso.quiche.path=/abs/path/libquiche.dylib.
    private static final String[] SEARCH_PREFIXES = {
        System.getProperty("enso.quiche.path"),
        "/opt/homebrew/opt/cloudflare-quiche/lib",
        "/opt/homebrew/lib",
        "/usr/local/opt/cloudflare-quiche/lib",
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    };

    private static final String LIB_FILE = System.mapLibraryName("quiche");

    static {
        loadLibrary();
    }

    private Quiche() {}

    private static void loadLibrary() {
        // Explicit override wins.
        String override = System.getProperty("enso.quiche.path");
        if (override != null && !override.isBlank()) {
            Path p = Path.of(override);
            if (Files.exists(p)) {
                System.load(p.toAbsolutePath().toString());
                return;
            }
        }
        // Try each common prefix; System.load takes an absolute path.
        for (String prefix : SEARCH_PREFIXES) {
            if (prefix == null) continue;
            Path candidate = Path.of(prefix, LIB_FILE);
            if (Files.exists(candidate)) {
                System.load(candidate.toAbsolutePath().toString());
                return;
            }
        }
        // Fall back to the standard loader — respects -Djava.library.path
        // and the LD_LIBRARY_PATH / DYLD_LIBRARY_PATH environment.
        try {
            System.loadLibrary("quiche");
        } catch (UnsatisfiedLinkError e) {
            throw new UnsatisfiedLinkError(
                "libquiche not found. Install cloudflare-quiche (macOS: "
                + "`brew install cloudflare-quiche`; Linux: build from "
                + "https://github.com/cloudflare/quiche with --features ffi) "
                + "and either place " + LIB_FILE + " on the system library "
                + "path or set -Denso.quiche.path=/abs/path/to/" + LIB_FILE
                + ". Underlying error: " + e.getMessage());
        }
    }

    /**
     * Returns the wire version string reported by {@code quiche_version}.
     * Also acts as a probe that libquiche loaded correctly.
     */
    public static String version() {
        var seg = quiche_h.quiche_version();
        return seg.reinterpret(64).getString(0);
    }
}

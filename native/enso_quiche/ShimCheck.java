// ABOUTME: Load test for a built libenso_quiche: loads it through Quiche's classpath-resource loader
// ABOUTME: and calls into libquiche and BoringSSL (version, patches, client config with TLS context).
import com.s_exp.enso.quiche.Quiche;
import com.s_exp.enso.quiche.QuicheConfig;

/**
 * Run by check-shim.sh as a single-file program from an empty directory,
 * with the shim staged under META-INF/native/&lt;classifier&gt;/ on the
 * classpath, exactly as a classifier jar ships it. Exits non-zero (via
 * the uncaught error) when the shim does not load, its libquiche version
 * differs from the one the Java side expects, it lacks the receive-window
 * control of native/enso_quiche/patches/ (release shims link the patched
 * libquiche), or creating a QUIC config (BoringSSL SSL_CTX) fails.
 */
public class ShimCheck {
    public static void main(String[] args) throws Exception {
        String version = Quiche.libraryVersion();
        if (!Quiche.QUICHE_VERSION.equals(version)) {
            throw new AssertionError("libquiche " + version + ", expected " + Quiche.QUICHE_VERSION);
        }
        if (!Quiche.RECV_WINDOW_CONTROL) {
            throw new AssertionError("libquiche lacks receive-window control: not built by build-libquiche.sh");
        }
        try (QuicheConfig config = QuicheConfig.client(1000)) {
            config.setInitialMaxData(1 << 20);
        }
        System.out.println("shim loaded: libquiche " + version + " on " + System.getProperty("os.name")
            + " " + System.getProperty("os.arch") + ", java " + System.getProperty("java.version"));
    }
}

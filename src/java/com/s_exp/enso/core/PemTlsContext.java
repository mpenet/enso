// ABOUTME: Builds one SSLContext from PEM certificate, key and optional CA bundle files and keeps
// ABOUTME: it current: a watcher reloads changed files for new handshakes, keeping the old on failure.
package com.s_exp.enso.core;

import com.s_exp.enso.api.Config;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * The TCP TLS context of the file source ({@code :ssl-cert-path},
 * {@code :ssl-key-path}, {@code :ssl-ca-path}). One {@link SSLContext}
 * lives for the server: a {@link ReloadableKeyManager} holds the server
 * identity and, when a CA bundle is set for mutual TLS, a
 * {@link ReloadableTrustManager} holds the client-auth trust. A watcher
 * thread checks the files every {@code :ssl-cert-reload-interval} and
 * swaps the holders on a change; a parse or read failure (a half-written
 * file) is logged and the current certificate kept. A handshake reads only
 * a volatile, so reloading costs nothing on the hot path.
 */
public final class PemTlsContext implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PemTlsContext.class.getName());
    private static final LogLimiter RELOAD_FAILURES = new LogLimiter(LOG, Level.WARNING);
    private static final String ALIAS = "enso";

    private final Config config;
    private final SSLContext context;
    private final ReloadableKeyManager keyManager;
    // null unless :ssl-ca-path configures mutual TLS.
    private final ReloadableTrustManager trustManager;
    // Files as last loaded and as last refused (not retried until they
    // change again). Watcher thread only.
    private PemFiles loaded;
    private PemFiles refused;
    // Run after a successful swap, so a shared file source can reload the
    // QUIC transport too; null when nothing shares the files. Watcher thread.
    private Runnable afterReload;
    private volatile Thread watcher;

    private PemTlsContext(Config config, SSLContext context, ReloadableKeyManager keyManager,
                          ReloadableTrustManager trustManager, PemFiles loaded) {
        this.config = config;
        this.context = context;
        this.keyManager = keyManager;
        this.trustManager = trustManager;
        this.loaded = loaded;
    }

    /** Reads the files, builds the context and its holders; throws when a file can't be loaded. */
    public static PemTlsContext create(Config config) throws IOException {
        // Stamped before loading: a change made while loading is seen by the
        // first check.
        PemFiles files = PemFiles.read(config);
        ReloadableKeyManager km = new ReloadableKeyManager(loadIdentity(config));
        ReloadableTrustManager tm = config.sslCaPath != null
            ? new ReloadableTrustManager(loadTrust(config.sslCaPath)) : null;
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[] {km}, tm != null ? new TrustManager[] {tm} : null, null);
        } catch (GeneralSecurityException e) {
            throw new IOException("TLS context init failed: " + e.getMessage(), e);
        }
        return new PemTlsContext(config, ctx, km, tm, files);
    }

    /** The context to serve on the TCP listener; its holders stay current across reloads. */
    public SSLContext sslContext() {
        return context;
    }

    /**
     * Parses the files again and installs them for new handshakes. Both are
     * parsed before either is swapped, so a failure leaves the current
     * certificate and CA bundle in place.
     */
    public void reload() throws IOException {
        ReloadableKeyManager.Identity id = loadIdentity(config);
        X509ExtendedTrustManager tm = config.sslCaPath != null ? loadTrust(config.sslCaPath) : null;
        keyManager.set(id);
        if (trustManager != null && tm != null) {
            trustManager.set(tm);
        }
    }

    /**
     * Starts the file watcher; a non-positive {@code :ssl-cert-reload-interval}
     * leaves none. {@code afterReload} (nullable) runs after a successful swap,
     * so a QUIC transport sharing the files reloads from the same watcher.
     */
    public void startWatcher(Runnable afterReload) {
        this.afterReload = afterReload;
        long interval = config.sslCertReloadIntervalMillis;
        if (interval <= 0) return;
        watcher = Thread.ofVirtual().name("enso-tls-cert-watcher").start(() -> {
            while (true) {
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException e) {
                    return;
                }
                try {
                    reloadIfChanged();
                } catch (RuntimeException e) {
                    RELOAD_FAILURES.log("TLS certificate check failed", e);
                }
            }
        });
    }

    /** Reloads when the files differ from the set loaded (or last refused). */
    private void reloadIfChanged() {
        PemFiles now;
        try {
            now = PemFiles.read(config);
        } catch (IOException e) {
            // Mid-rotation (a file briefly missing): next round.
            return;
        }
        if (now.equals(loaded) || now.equals(refused)) return;
        try {
            reload();
        } catch (IOException e) {
            refused = now;
            RELOAD_FAILURES.log("TLS certificate reload failed, keeping the current one: " + e.getMessage());
            return;
        }
        loaded = now;
        refused = null;
        LOG.info(() -> "TLS certificate reloaded from " + config.sslCertPath);
        if (afterReload != null) {
            afterReload.run();
        }
    }

    @Override
    public void close() {
        Thread t = watcher;
        if (t == null) return;
        t.interrupt();
        try {
            t.join(Duration.ofMillis(1000));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static ReloadableKeyManager.Identity loadIdentity(Config config) throws IOException {
        X509Certificate[] chain = readCertChain(config.sslCertPath);
        PrivateKey key = readPrivateKey(config.sslKeyPath);
        return new ReloadableKeyManager.Identity(ALIAS, key, chain);
    }

    /** The certificate chain, leaf first, as the file orders it. */
    private static X509Certificate[] readCertChain(String path) throws IOException {
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(in);
            if (certs.isEmpty()) {
                throw new IOException("no certificate in " + path);
            }
            List<X509Certificate> chain = new ArrayList<>(certs.size());
            for (Certificate c : certs) {
                chain.add((X509Certificate) c);
            }
            return chain.toArray(new X509Certificate[0]);
        } catch (GeneralSecurityException e) {
            throw new IOException("certificate load failed for " + path + ": " + e.getMessage(), e);
        }
    }

    /**
     * The private key, from the first PKCS8, PKCS1 or SEC1 block in the
     * file. PKCS1 and SEC1 are wrapped to PKCS8 first; the resulting PKCS8
     * is tried as RSA then EC, the algorithm the file does not name.
     */
    private static PrivateKey readPrivateKey(String path) throws IOException {
        Pem.Block block = Pem.firstPrivateKey(Files.readString(Path.of(path)), path);
        byte[] pkcs8 = switch (block.label()) {
            case "PRIVATE KEY" -> block.der();
            case "RSA PRIVATE KEY" -> Pem.pkcs8FromPkcs1Rsa(block.der());
            case "EC PRIVATE KEY" -> Pem.pkcs8FromSec1Ec(block.der(), path);
            default -> throw new IOException("unsupported private key in " + path);
        };
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        for (String algorithm : new String[] {"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (GeneralSecurityException next) {
                // Not this algorithm: try the next.
            }
        }
        throw new IOException("unsupported private key in " + path + " (expected an RSA or EC key)");
    }

    /** A JSSE trust manager over a key store of the CA bundle's certificates. */
    private static X509ExtendedTrustManager loadTrust(String caPath) throws IOException {
        X509Certificate[] cas = readCertChain(caPath);
        try {
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, null);
            for (int i = 0; i < cas.length; i++) {
                ts.setCertificateEntry("ca-" + i, cas[i]);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509ExtendedTrustManager x) {
                    return x;
                }
            }
            throw new IOException("no X509 trust manager from the CA bundle " + caPath);
        } catch (GeneralSecurityException e) {
            throw new IOException("CA bundle load failed for " + caPath + ": " + e.getMessage(), e);
        }
    }

    /** What identifies a version of the files: modification time, size, file key (inode). */
    private record PemFiles(long certModified, long certSize, Object certKey,
                            long keyModified, long keySize, Object keyKey,
                            long caModified, long caSize, Object caKey) {

        static PemFiles read(Config config) throws IOException {
            BasicFileAttributes c = Files.readAttributes(Path.of(config.sslCertPath), BasicFileAttributes.class);
            BasicFileAttributes k = Files.readAttributes(Path.of(config.sslKeyPath), BasicFileAttributes.class);
            if (config.sslCaPath == null) {
                return new PemFiles(c.lastModifiedTime().toMillis(), c.size(), c.fileKey(),
                                    k.lastModifiedTime().toMillis(), k.size(), k.fileKey(),
                                    0, 0, null);
            }
            BasicFileAttributes a = Files.readAttributes(Path.of(config.sslCaPath), BasicFileAttributes.class);
            return new PemFiles(c.lastModifiedTime().toMillis(), c.size(), c.fileKey(),
                                k.lastModifiedTime().toMillis(), k.size(), k.fileKey(),
                                a.lastModifiedTime().toMillis(), a.size(), a.fileKey());
        }
    }
}

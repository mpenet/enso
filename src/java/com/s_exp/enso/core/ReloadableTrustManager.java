// ABOUTME: X509 trust manager that verifies client certificates against a CA bundle held in a
// ABOUTME: volatile delegate, so a reloaded bundle applies to new handshakes without a context rebuild.
package com.s_exp.enso.core;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Mutual TLS trust whose CA bundle swaps under one SSLContext: every check
 * goes to the current delegate, replaced by {@link #set} when the bundle
 * file changes. The delegate is a stock JSSE trust manager over a key
 * store of the CA certificates.
 */
public final class ReloadableTrustManager extends X509ExtendedTrustManager {

    private volatile X509ExtendedTrustManager delegate;

    public ReloadableTrustManager(X509ExtendedTrustManager delegate) {
        this.delegate = delegate;
    }

    /** Installs the CA bundle new handshakes verify against; one volatile write. */
    public void set(X509ExtendedTrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}

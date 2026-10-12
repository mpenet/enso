// ABOUTME: Server-side X509 key manager whose current identity (private key, certificate chain,
// ABOUTME: alias) lives in a volatile, so a certificate reload is one write and a handshake one read.
package com.s_exp.enso.core;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * The server identity every handshake reads from a single volatile, the
 * way Go's {@code tls.Config.GetCertificate} hands out a live certificate:
 * one SSLContext for the server's life, the key and chain swapped under it
 * by {@link #set} without rebuilding anything. Server side only; the
 * client-alias methods return nothing.
 */
public final class ReloadableKeyManager extends X509ExtendedKeyManager {

    /** The server identity a handshake picks up: alias, key, and chain (leaf first). */
    public record Identity(String alias, PrivateKey key, X509Certificate[] chain) {}

    private volatile Identity identity;

    public ReloadableKeyManager(Identity identity) {
        this.identity = identity;
    }

    /** Installs the identity new handshakes present; one volatile write. */
    public void set(Identity identity) {
        this.identity = identity;
    }

    /** The alias when the certificate's key algorithm serves {@code keyType}, else null. */
    private String aliasFor(String keyType) {
        Identity id = identity;
        if (id == null) return null;
        if (keyType == null) return id.alias();
        String alg = id.chain()[0].getPublicKey().getAlgorithm();
        if (keyType.equals(alg)) return id.alias();
        // TLS 1.3 names RSA signatures RSASSA-PSS, served by an RSA key.
        if ("RSA".equals(alg) && "RSASSA-PSS".equals(keyType)) return id.alias();
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return aliasFor(keyType);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return aliasFor(keyType);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        String alias = aliasFor(keyType);
        return alias != null ? new String[] {alias} : null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        Identity id = identity;
        return id != null && id.alias().equals(alias) ? id.key() : null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        Identity id = identity;
        return id != null && id.alias().equals(alias) ? id.chain().clone() : null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return null;
    }
}

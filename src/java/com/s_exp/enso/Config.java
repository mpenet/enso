package com.s_exp.enso;

import javax.net.ssl.SSLContext;

/**
 * Server tuning parameters. All fields are final; construct via {@link Builder}.
 * Defaults are conservative for typical HTTP/1.1 keep-alive workloads.
 */
public final class Config {

    public final String host;
    public final int port;
    public final int backlog;
    public final int idleTimeoutMillis;
    public final int requestTimeoutMillis;
    public final int shutdownTimeoutMillis;
    public final int requestBufferSize;
    public final int maxHeaderBytes;
    public final int maxInlineBody;
    public final int coalesceHighWater;
    public final int chunkBufferSize;
    public final int maxDrainBytes;
    public final long maxRequestBodyBytes;
    public final SSLContext sslContext;
    public final boolean sslNeedClientAuth;
    public final boolean sslWantClientAuth;
    public final boolean http2;
    public final int http2MaxConcurrentStreams;
    public final int http2InitialWindowSize;
    public final int http2MaxFrameSize;
    public final int http2MaxHeaderListSize;

    private Config(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.backlog = b.backlog;
        this.idleTimeoutMillis = b.idleTimeoutMillis;
        this.requestTimeoutMillis = b.requestTimeoutMillis;
        this.shutdownTimeoutMillis = b.shutdownTimeoutMillis;
        this.requestBufferSize = b.requestBufferSize;
        this.maxHeaderBytes = b.maxHeaderBytes;
        this.maxInlineBody = b.maxInlineBody;
        this.coalesceHighWater = b.coalesceHighWater;
        this.chunkBufferSize = b.chunkBufferSize;
        this.maxDrainBytes = b.maxDrainBytes;
        this.maxRequestBodyBytes = b.maxRequestBodyBytes;
        this.sslContext = b.sslContext;
        this.sslNeedClientAuth = b.sslNeedClientAuth;
        this.sslWantClientAuth = b.sslWantClientAuth;
        this.http2 = b.http2;
        this.http2MaxConcurrentStreams = b.http2MaxConcurrentStreams;
        this.http2InitialWindowSize = b.http2InitialWindowSize;
        this.http2MaxFrameSize = b.http2MaxFrameSize;
        this.http2MaxHeaderListSize = b.http2MaxHeaderListSize;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private String host = "0.0.0.0";
        private int port = 8080;
        private int backlog = 1024;
        private int idleTimeoutMillis = 30_000;
        private int requestTimeoutMillis = 30_000;
        private int shutdownTimeoutMillis = 10_000;
        private int requestBufferSize = 16_384;
        private int maxHeaderBytes = 65_536;
        private int maxInlineBody = 16_384;
        private int coalesceHighWater = 32_768;
        private int chunkBufferSize = 8_192;
        private int maxDrainBytes = 65_536;
        private long maxRequestBodyBytes = 10L * 1024 * 1024;
        private SSLContext sslContext;
        private boolean sslNeedClientAuth;
        private boolean sslWantClientAuth;
        private boolean http2;
        private int http2MaxConcurrentStreams = 100;
        private int http2InitialWindowSize = 1 << 20;   // 1 MiB
        private int http2MaxFrameSize = 1 << 14;        // 16 KiB
        private int http2MaxHeaderListSize = 8192;

        public Builder host(String v) { this.host = v; return this; }
        public Builder port(int v) { this.port = v; return this; }
        public Builder backlog(int v) { this.backlog = v; return this; }
        public Builder idleTimeoutMillis(int v) { this.idleTimeoutMillis = v; return this; }
        public Builder requestTimeoutMillis(int v) { this.requestTimeoutMillis = v; return this; }
        public Builder shutdownTimeoutMillis(int v) { this.shutdownTimeoutMillis = v; return this; }
        public Builder requestBufferSize(int v) { this.requestBufferSize = v; return this; }
        public Builder maxHeaderBytes(int v) { this.maxHeaderBytes = v; return this; }
        public Builder maxInlineBody(int v) { this.maxInlineBody = v; return this; }
        public Builder coalesceHighWater(int v) { this.coalesceHighWater = v; return this; }
        public Builder chunkBufferSize(int v) { this.chunkBufferSize = v; return this; }
        public Builder maxDrainBytes(int v) { this.maxDrainBytes = v; return this; }
        public Builder maxRequestBodyBytes(long v) { this.maxRequestBodyBytes = v; return this; }
        public Builder sslContext(SSLContext v) { this.sslContext = v; return this; }
        public Builder sslNeedClientAuth(boolean v) { this.sslNeedClientAuth = v; return this; }
        public Builder sslWantClientAuth(boolean v) { this.sslWantClientAuth = v; return this; }
        public Builder http2(boolean v) { this.http2 = v; return this; }
        public Builder http2MaxConcurrentStreams(int v) { this.http2MaxConcurrentStreams = v; return this; }
        public Builder http2InitialWindowSize(int v) { this.http2InitialWindowSize = v; return this; }
        public Builder http2MaxFrameSize(int v) { this.http2MaxFrameSize = v; return this; }
        public Builder http2MaxHeaderListSize(int v) { this.http2MaxHeaderListSize = v; return this; }

        public Config build() {
            validate();
            return new Config(this);
        }

        private void validate() {
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("host must be non-empty");
            }
            if (port < 0 || port > 65535) {
                throw new IllegalArgumentException("port must be in [0, 65535], got " + port);
            }
            if (backlog < 1) {
                throw new IllegalArgumentException("backlog must be >= 1, got " + backlog);
            }
            // Timeouts: 0 disables, negatives are wrong.
            requireNonNegative("idleTimeoutMillis", idleTimeoutMillis);
            requireNonNegative("requestTimeoutMillis", requestTimeoutMillis);
            requireNonNegative("shutdownTimeoutMillis", shutdownTimeoutMillis);
            requirePositive("requestBufferSize", requestBufferSize);
            requirePositive("maxHeaderBytes", maxHeaderBytes);
            requirePositive("maxInlineBody", maxInlineBody);
            requirePositive("coalesceHighWater", coalesceHighWater);
            requirePositive("chunkBufferSize", chunkBufferSize);
            requirePositive("maxDrainBytes", maxDrainBytes);
            if (maxRequestBodyBytes < 0) {
                throw new IllegalArgumentException(
                    "maxRequestBodyBytes must be >= 0 (0 disables), got " + maxRequestBodyBytes);
            }
            // Documented tuning interactions (requestBufferSize <=
            // maxHeaderBytes; maxInlineBody <= coalesceHighWater) are
            // degradations, not hard errors — the runtime caps behaviour
            // accordingly. No validation here to avoid rejecting configs
            // that work but are suboptimal.

            // TLS.
            if (sslNeedClientAuth && sslWantClientAuth) {
                throw new IllegalArgumentException(
                    "sslNeedClientAuth and sslWantClientAuth are mutually exclusive");
            }
            if ((sslNeedClientAuth || sslWantClientAuth) && sslContext == null) {
                throw new IllegalArgumentException(
                    "sslContext required when client-auth options are set");
            }
            // HTTP/2.
            if (http2 && sslContext == null) {
                throw new IllegalArgumentException(
                    "http2 requires sslContext (h2c is not supported)");
            }
            requirePositive("http2MaxConcurrentStreams", http2MaxConcurrentStreams);
            // RFC 9113 §6.9.2 caps SETTINGS_INITIAL_WINDOW_SIZE at 2^31 - 1.
            if (http2InitialWindowSize < 0) {
                throw new IllegalArgumentException(
                    "http2InitialWindowSize must be in [0, 2^31-1], got " + http2InitialWindowSize);
            }
            // RFC 9113 §4.2 / §6.5.2: SETTINGS_MAX_FRAME_SIZE ∈ [16384, 16777215].
            if (http2MaxFrameSize < 16_384 || http2MaxFrameSize > 16_777_215) {
                throw new IllegalArgumentException(
                    "http2MaxFrameSize must be in [16384, 16777215], got " + http2MaxFrameSize);
            }
            if (http2MaxHeaderListSize < 0) {
                throw new IllegalArgumentException(
                    "http2MaxHeaderListSize must be >= 0 (0 disables), got " + http2MaxHeaderListSize);
            }
        }

        private static void requirePositive(String name, int v) {
            if (v < 1) {
                throw new IllegalArgumentException(name + " must be >= 1, got " + v);
            }
        }

        private static void requireNonNegative(String name, int v) {
            if (v < 0) {
                throw new IllegalArgumentException(name + " must be >= 0, got " + v);
            }
        }
    }
}

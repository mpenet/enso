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

        public Config build() {
            return new Config(this);
        }
    }
}

package com.s_exp.enso.api;

import java.util.concurrent.Executor;
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
    // HTTP/1.1 keep-alive.
    public final int maxKeepAliveRequests;
    /** 0 → falls back to {@link #idleTimeoutMillis}. */
    public final int keepAliveTimeoutMillis;
    // TCP socket options (applied to acceptor + accepted sockets).
    public final boolean soNodelay;
    public final boolean soReuseAddr;
    /** -1 disables SO_LINGER; otherwise close-timeout seconds. */
    public final int soLinger;
    /** 0 → OS default. */
    public final int soRcvBuf;
    /** 0 → OS default. */
    public final int soSndBuf;
    public final SSLContext sslContext;
    public final boolean sslNeedClientAuth;
    public final boolean sslWantClientAuth;
    /** null → auto (h2 + http/1.1 when http2 enabled). */
    public final String[] alpnProtocols;
    /** null → JVM default. */
    public final String[] enabledCipherSuites;
    /** null → JVM default. */
    public final String[] enabledTlsProtocols;
    /** 0 → JVM default. */
    public final int sslSessionCacheSize;
    public final boolean http2;
    public final int http2MaxConcurrentStreams;
    public final int http2InitialWindowSize;
    public final int http2MaxFrameSize;
    public final int http2MaxHeaderListSize;
    /**
     * Cap on RST_STREAM frames per connection (CVE-2023-44487 mitigation).
     * 0 disables — leave enabled unless you're behind a trusted LB.
     */
    public final int http2StreamResetLimit;
    /** 0 disables server-initiated PING. */
    public final int http2PingIntervalMillis;
    public final int http2PingTimeoutMillis;
    /** Cap CONTINUATION frames per HEADERS to bound HPACK work. */
    public final int http2ContinuationLimit;
    /** Whether to advertise SETTINGS_ENABLE_PUSH; we never push. */
    public final boolean http2EnablePush;
    public final boolean http3;
    public final int http3Port;
    public final int http3MaxIdleTimeoutMs;
    public final long http3InitialMaxData;
    public final int http3InitialMaxStreamsBidi;
    public final int http3InitialMaxStreamsUni;
    public final int http3MaxUdpPayloadSize;
    public final String http3CertPath;
    public final String http3KeyPath;
    public final boolean http3StatelessRetry;
    /** Advertised on outbound SETTINGS + enforced on peer→us HEADERS. */
    public final int http3MaxFieldSectionSize;
    /** RFC 9204 SETTINGS_QPACK_MAX_TABLE_CAPACITY. 0 disables dynamic table. */
    public final long http3QpackMaxTableCapacity;
    /** RFC 9204 SETTINGS_QPACK_BLOCKED_STREAMS. Only meaningful if capacity > 0. */
    public final long http3QpackBlockedStreams;
    /** -1 → derived from initialMaxData / initialMaxStreamsBidi. */
    public final long http3InitialMaxStreamDataBidiLocal;
    /** -1 → derived. */
    public final long http3InitialMaxStreamDataBidiRemote;
    /** -1 → derived. */
    public final long http3InitialMaxStreamDataUni;
    /** -1 → quiche default. */
    public final int http3AckDelayExponent;
    /** -1 → quiche default. */
    public final int http3MaxAckDelay;
    /** -1 → quiche default. */
    public final int http3ActiveConnectionIdLimit;
    public final boolean advertiseAltSvc;
    public final int altSvcMaxAge;
    /**
     * Custom {@code Server:} header value. null / empty → header is omitted.
     * The h1/h2/h3 emitters check this on response write.
     */
    public final String serverHeader;
    /** Optional override for the request-handler executor. null → virtual-thread-per-task. */
    public final Executor workerExecutor;

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
        this.maxKeepAliveRequests = b.maxKeepAliveRequests;
        this.keepAliveTimeoutMillis = b.keepAliveTimeoutMillis;
        this.soNodelay = b.soNodelay;
        this.soReuseAddr = b.soReuseAddr;
        this.soLinger = b.soLinger;
        this.soRcvBuf = b.soRcvBuf;
        this.soSndBuf = b.soSndBuf;
        this.sslContext = b.sslContext;
        this.sslNeedClientAuth = b.sslNeedClientAuth;
        this.sslWantClientAuth = b.sslWantClientAuth;
        this.alpnProtocols = b.alpnProtocols;
        this.enabledCipherSuites = b.enabledCipherSuites;
        this.enabledTlsProtocols = b.enabledTlsProtocols;
        this.sslSessionCacheSize = b.sslSessionCacheSize;
        this.http2 = b.http2;
        this.http2MaxConcurrentStreams = b.http2MaxConcurrentStreams;
        this.http2InitialWindowSize = b.http2InitialWindowSize;
        this.http2MaxFrameSize = b.http2MaxFrameSize;
        this.http2MaxHeaderListSize = b.http2MaxHeaderListSize;
        this.http2StreamResetLimit = b.http2StreamResetLimit;
        this.http2PingIntervalMillis = b.http2PingIntervalMillis;
        this.http2PingTimeoutMillis = b.http2PingTimeoutMillis;
        this.http2ContinuationLimit = b.http2ContinuationLimit;
        this.http2EnablePush = b.http2EnablePush;
        this.http3 = b.http3;
        this.http3Port = b.http3Port;
        this.http3MaxIdleTimeoutMs = b.http3MaxIdleTimeoutMs;
        this.http3InitialMaxData = b.http3InitialMaxData;
        this.http3InitialMaxStreamsBidi = b.http3InitialMaxStreamsBidi;
        this.http3InitialMaxStreamsUni = b.http3InitialMaxStreamsUni;
        this.http3MaxUdpPayloadSize = b.http3MaxUdpPayloadSize;
        this.http3CertPath = b.http3CertPath;
        this.http3KeyPath = b.http3KeyPath;
        this.http3StatelessRetry = b.http3StatelessRetry;
        this.http3MaxFieldSectionSize = b.http3MaxFieldSectionSize;
        this.http3QpackMaxTableCapacity = b.http3QpackMaxTableCapacity;
        this.http3QpackBlockedStreams = b.http3QpackBlockedStreams;
        this.http3InitialMaxStreamDataBidiLocal = b.http3InitialMaxStreamDataBidiLocal;
        this.http3InitialMaxStreamDataBidiRemote = b.http3InitialMaxStreamDataBidiRemote;
        this.http3InitialMaxStreamDataUni = b.http3InitialMaxStreamDataUni;
        this.http3AckDelayExponent = b.http3AckDelayExponent;
        this.http3MaxAckDelay = b.http3MaxAckDelay;
        this.http3ActiveConnectionIdLimit = b.http3ActiveConnectionIdLimit;
        this.serverHeader = b.serverHeader;
        this.workerExecutor = b.workerExecutor;
        // Auto-enable Alt-Svc when http3 is on so h1.1/h2 clients can
        // discover the h3 endpoint on the next request. Users can override.
        this.advertiseAltSvc = b.advertiseAltSvcExplicit != null
            ? b.advertiseAltSvcExplicit : b.http3;
        this.altSvcMaxAge = b.altSvcMaxAge;
        // Pre-format the Alt-Svc header value if enabled. RFC 7838 syntax:
        // `Alt-Svc: h3=":<port>"; ma=<seconds>`. Port defaults to the TCP
        // port when http3Port is 0 (shared UDP + TCP port number).
        if (this.advertiseAltSvc) {
            int altPort = b.http3Port > 0 ? b.http3Port : b.port;
            this.altSvcValue = "h3=\":" + altPort + "\"; ma=" + b.altSvcMaxAge;
        } else {
            this.altSvcValue = null;
        }
    }

    /** Pre-formatted {@code Alt-Svc} header value, or null if disabled. */
    public final String altSvcValue;

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
        // h1 keep-alive.
        private int maxKeepAliveRequests = 1000;
        private int keepAliveTimeoutMillis = 0;
        // TCP.
        private boolean soNodelay = true;
        private boolean soReuseAddr = true;
        private int soLinger = -1;
        private int soRcvBuf = 0;
        private int soSndBuf = 0;
        private SSLContext sslContext;
        private boolean sslNeedClientAuth;
        private boolean sslWantClientAuth;
        private String[] alpnProtocols;
        private String[] enabledCipherSuites;
        private String[] enabledTlsProtocols;
        private int sslSessionCacheSize = 0;
        private boolean http2;
        private int http2MaxConcurrentStreams = 100;
        private int http2InitialWindowSize = 1 << 20;   // 1 MiB
        private int http2MaxFrameSize = 1 << 14;        // 16 KiB
        private int http2MaxHeaderListSize = 8192;
        // Post-CVE-2023-44487 default: cap RST_STREAM per connection.
        // Nginx uses 400; go with the same conservative number.
        private int http2StreamResetLimit = 400;
        private int http2PingIntervalMillis = 0;
        private int http2PingTimeoutMillis = 10_000;
        private int http2ContinuationLimit = 64;
        private boolean http2EnablePush = false;
        private boolean http3;
        private int http3Port = 0;                      // 0 → reuse main port number over UDP
        private int http3MaxIdleTimeoutMs = 30_000;
        private long http3InitialMaxData = 1L << 30;    // 1 GiB
        private int http3InitialMaxStreamsBidi = 100;
        private int http3InitialMaxStreamsUni = 8;
        private int http3MaxUdpPayloadSize = 1350;
        private String http3CertPath;
        private String http3KeyPath;
        private boolean http3StatelessRetry = false;
        private int http3MaxFieldSectionSize = 64 * 1024;
        private long http3QpackMaxTableCapacity = 0;
        private long http3QpackBlockedStreams = 0;
        private long http3InitialMaxStreamDataBidiLocal = -1;
        private long http3InitialMaxStreamDataBidiRemote = -1;
        private long http3InitialMaxStreamDataUni = -1;
        private int http3AckDelayExponent = -1;
        private int http3MaxAckDelay = -1;
        private int http3ActiveConnectionIdLimit = -1;
        // null → auto (true iff http3 enabled). Explicit true/false overrides.
        private Boolean advertiseAltSvcExplicit;
        private int altSvcMaxAge = 86_400;    // 24h — RFC 7838 typical
        private String serverHeader;
        private Executor workerExecutor;

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
        public Builder maxKeepAliveRequests(int v) { this.maxKeepAliveRequests = v; return this; }
        public Builder keepAliveTimeoutMillis(int v) { this.keepAliveTimeoutMillis = v; return this; }
        public Builder soNodelay(boolean v) { this.soNodelay = v; return this; }
        public Builder soReuseAddr(boolean v) { this.soReuseAddr = v; return this; }
        public Builder soLinger(int v) { this.soLinger = v; return this; }
        public Builder soRcvBuf(int v) { this.soRcvBuf = v; return this; }
        public Builder soSndBuf(int v) { this.soSndBuf = v; return this; }
        public Builder sslContext(SSLContext v) { this.sslContext = v; return this; }
        public Builder sslNeedClientAuth(boolean v) { this.sslNeedClientAuth = v; return this; }
        public Builder sslWantClientAuth(boolean v) { this.sslWantClientAuth = v; return this; }
        public Builder alpnProtocols(String[] v) { this.alpnProtocols = v; return this; }
        public Builder enabledCipherSuites(String[] v) { this.enabledCipherSuites = v; return this; }
        public Builder enabledTlsProtocols(String[] v) { this.enabledTlsProtocols = v; return this; }
        public Builder sslSessionCacheSize(int v) { this.sslSessionCacheSize = v; return this; }
        public Builder http2(boolean v) { this.http2 = v; return this; }
        public Builder http2MaxConcurrentStreams(int v) { this.http2MaxConcurrentStreams = v; return this; }
        public Builder http2InitialWindowSize(int v) { this.http2InitialWindowSize = v; return this; }
        public Builder http2MaxFrameSize(int v) { this.http2MaxFrameSize = v; return this; }
        public Builder http2MaxHeaderListSize(int v) { this.http2MaxHeaderListSize = v; return this; }
        public Builder http2StreamResetLimit(int v) { this.http2StreamResetLimit = v; return this; }
        public Builder http2PingIntervalMillis(int v) { this.http2PingIntervalMillis = v; return this; }
        public Builder http2PingTimeoutMillis(int v) { this.http2PingTimeoutMillis = v; return this; }
        public Builder http2ContinuationLimit(int v) { this.http2ContinuationLimit = v; return this; }
        public Builder http2EnablePush(boolean v) { this.http2EnablePush = v; return this; }
        public Builder http3(boolean v) { this.http3 = v; return this; }
        public Builder http3Port(int v) { this.http3Port = v; return this; }
        public Builder http3MaxIdleTimeoutMs(int v) { this.http3MaxIdleTimeoutMs = v; return this; }
        public Builder http3InitialMaxData(long v) { this.http3InitialMaxData = v; return this; }
        public Builder http3InitialMaxStreamsBidi(int v) { this.http3InitialMaxStreamsBidi = v; return this; }
        public Builder http3InitialMaxStreamsUni(int v) { this.http3InitialMaxStreamsUni = v; return this; }
        public Builder http3MaxUdpPayloadSize(int v) { this.http3MaxUdpPayloadSize = v; return this; }
        public Builder http3CertPath(String v) { this.http3CertPath = v; return this; }
        public Builder http3KeyPath(String v) { this.http3KeyPath = v; return this; }
        public Builder http3StatelessRetry(boolean v) { this.http3StatelessRetry = v; return this; }
        public Builder http3MaxFieldSectionSize(int v) { this.http3MaxFieldSectionSize = v; return this; }
        public Builder http3QpackMaxTableCapacity(long v) { this.http3QpackMaxTableCapacity = v; return this; }
        public Builder http3QpackBlockedStreams(long v) { this.http3QpackBlockedStreams = v; return this; }
        public Builder http3InitialMaxStreamDataBidiLocal(long v) { this.http3InitialMaxStreamDataBidiLocal = v; return this; }
        public Builder http3InitialMaxStreamDataBidiRemote(long v) { this.http3InitialMaxStreamDataBidiRemote = v; return this; }
        public Builder http3InitialMaxStreamDataUni(long v) { this.http3InitialMaxStreamDataUni = v; return this; }
        public Builder http3AckDelayExponent(int v) { this.http3AckDelayExponent = v; return this; }
        public Builder http3MaxAckDelay(int v) { this.http3MaxAckDelay = v; return this; }
        public Builder http3ActiveConnectionIdLimit(int v) { this.http3ActiveConnectionIdLimit = v; return this; }
        public Builder advertiseAltSvc(boolean v) { this.advertiseAltSvcExplicit = v; return this; }
        public Builder altSvcMaxAge(int v) { this.altSvcMaxAge = v; return this; }
        public Builder serverHeader(String v) { this.serverHeader = v; return this; }
        public Builder workerExecutor(Executor v) { this.workerExecutor = v; return this; }

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

            // h1 keep-alive.
            requireNonNegative("maxKeepAliveRequests", maxKeepAliveRequests);
            requireNonNegative("keepAliveTimeoutMillis", keepAliveTimeoutMillis);
            // TCP.
            if (soLinger < -1) {
                throw new IllegalArgumentException(
                    "soLinger must be >= -1 (-1 disables), got " + soLinger);
            }
            requireNonNegative("soRcvBuf", soRcvBuf);
            requireNonNegative("soSndBuf", soSndBuf);

            // TLS.
            if (sslNeedClientAuth && sslWantClientAuth) {
                throw new IllegalArgumentException(
                    "sslNeedClientAuth and sslWantClientAuth are mutually exclusive");
            }
            if ((sslNeedClientAuth || sslWantClientAuth) && sslContext == null) {
                throw new IllegalArgumentException(
                    "sslContext required when client-auth options are set");
            }
            requireNonNegative("sslSessionCacheSize", sslSessionCacheSize);
            if (alpnProtocols != null) {
                for (String p : alpnProtocols) {
                    if (p == null || p.isEmpty()) {
                        throw new IllegalArgumentException(
                            "alpnProtocols entries must be non-empty");
                    }
                }
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
            requireNonNegative("http2StreamResetLimit", http2StreamResetLimit);
            requireNonNegative("http2PingIntervalMillis", http2PingIntervalMillis);
            requireNonNegative("http2PingTimeoutMillis", http2PingTimeoutMillis);
            requirePositive("http2ContinuationLimit", http2ContinuationLimit);
            // HTTP/3.
            if (http3) {
                if (http3CertPath == null || http3KeyPath == null) {
                    throw new IllegalArgumentException(
                        "http3 requires http3CertPath + http3KeyPath (PEM files "
                        + "— quiche loads cert/key from disk, not SSLContext)");
                }
            }
            if (http3Port < 0 || http3Port > 65535) {
                throw new IllegalArgumentException(
                    "http3Port must be in [0, 65535], got " + http3Port);
            }
            requireNonNegative("http3MaxIdleTimeoutMs", http3MaxIdleTimeoutMs);
            if (http3InitialMaxData < 0) {
                throw new IllegalArgumentException(
                    "http3InitialMaxData must be >= 0, got " + http3InitialMaxData);
            }
            requirePositive("http3InitialMaxStreamsBidi", http3InitialMaxStreamsBidi);
            // Need at least 3 uni streams: control + qpack encoder + qpack decoder.
            if (http3InitialMaxStreamsUni < 3) {
                throw new IllegalArgumentException(
                    "http3InitialMaxStreamsUni must be >= 3 (control + qpack enc/dec), got "
                    + http3InitialMaxStreamsUni);
            }
            // RFC 9000 §14.1: min IP+UDP payload for QUIC Initial is 1200.
            // Upper bound is UDP max ~65k, but real-world MTU-based caps kick in far below.
            if (http3MaxUdpPayloadSize < 1200 || http3MaxUdpPayloadSize > 65527) {
                throw new IllegalArgumentException(
                    "http3MaxUdpPayloadSize must be in [1200, 65527], got "
                    + http3MaxUdpPayloadSize);
            }
            // RFC 9114 §7.2.4.1: 0 → no limit advertised.
            requireNonNegative("http3MaxFieldSectionSize", http3MaxFieldSectionSize);
            if (http3QpackMaxTableCapacity < 0) {
                throw new IllegalArgumentException(
                    "http3QpackMaxTableCapacity must be >= 0, got " + http3QpackMaxTableCapacity);
            }
            if (http3QpackBlockedStreams < 0) {
                throw new IllegalArgumentException(
                    "http3QpackBlockedStreams must be >= 0, got " + http3QpackBlockedStreams);
            }
            requireDerivedOrNonNegative("http3InitialMaxStreamDataBidiLocal", http3InitialMaxStreamDataBidiLocal);
            requireDerivedOrNonNegative("http3InitialMaxStreamDataBidiRemote", http3InitialMaxStreamDataBidiRemote);
            requireDerivedOrNonNegative("http3InitialMaxStreamDataUni", http3InitialMaxStreamDataUni);
            // RFC 9000 §18.2: ack_delay_exponent in [0, 20].
            if (http3AckDelayExponent != -1 && (http3AckDelayExponent < 0 || http3AckDelayExponent > 20)) {
                throw new IllegalArgumentException(
                    "http3AckDelayExponent must be -1 (default) or in [0, 20], got "
                    + http3AckDelayExponent);
            }
            // RFC 9000 §18.2: max_ack_delay in [0, 2^14 - 1] (ms).
            if (http3MaxAckDelay != -1 && (http3MaxAckDelay < 0 || http3MaxAckDelay > 16_383)) {
                throw new IllegalArgumentException(
                    "http3MaxAckDelay must be -1 (default) or in [0, 16383] ms, got "
                    + http3MaxAckDelay);
            }
            // RFC 9000 §18.2: active_connection_id_limit >= 2.
            if (http3ActiveConnectionIdLimit != -1 && http3ActiveConnectionIdLimit < 2) {
                throw new IllegalArgumentException(
                    "http3ActiveConnectionIdLimit must be -1 (default) or >= 2, got "
                    + http3ActiveConnectionIdLimit);
            }
            if (altSvcMaxAge < 0) {
                throw new IllegalArgumentException(
                    "altSvcMaxAge must be >= 0, got " + altSvcMaxAge);
            }
        }

        private static void requireDerivedOrNonNegative(String name, long v) {
            if (v < -1) {
                throw new IllegalArgumentException(
                    name + " must be >= 0 or -1 (derived), got " + v);
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

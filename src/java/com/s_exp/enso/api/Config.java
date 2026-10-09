// ABOUTME: Immutable server configuration built and validated by Config.Builder; validation
// ABOUTME: errors name the run-server option keyword so they read the same from Clojure.
package com.s_exp.enso.api;

import com.s_exp.enso.core.RequestHead;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/**
 * Server configuration. All fields are final; construct via {@link Builder}.
 * Field and builder names follow the run-server option keywords
 * ({@code :idle-timeout} is {@link #idleTimeoutMillis}); the option table in
 * {@code s-exp.enso} documents every one. Durations are milliseconds,
 * 0 disables a timeout.
 */
public final class Config {

    // Network.
    public final String host;
    public final int port;
    public final int backlog;
    /** Open connections server-wide; 0 = unlimited. */
    public final int maxConnections;
    /** Open connections per client address; 0 = unlimited. */
    public final int maxConnectionsPerIp;

    // Timeouts, identical in meaning on every protocol.
    /** TLS handshake; h2 preface + first SETTINGS; h3 QUIC handshake. Wall clock. */
    public final int handshakeTimeoutMillis;
    /** A complete request head, from its first byte. Wall clock. */
    public final int headerTimeoutMillis;
    /** Request body: longest wait for read progress. */
    public final int readTimeoutMillis;
    /** Request body: least bytes per second while a reader waits, after the grace period. 0 = off. */
    public final int minDataRateBytes;
    /** Waiting for request body bytes allowed before {@link #minDataRateBytes} applies. */
    public final int minDataRateGraceMillis;
    /** Longest wait for write progress; expiry force-closes. */
    public final int writeTimeoutMillis;
    /** No request in progress: h1 between requests, h2/h3 no stream, WebSocket no frame. */
    public final int idleTimeoutMillis;
    /** Handler wall clock; 503 when nothing was sent yet. 0 = off. */
    public final int handlerTimeoutMillis;
    /** Graceful shutdown budget across all connections. */
    public final int shutdownTimeoutMillis;

    // Limits.
    /**
     * Request head size on every protocol: the HTTP/1.1 head, the decoded
     * HTTP/2 header list (SETTINGS_MAX_HEADER_LIST_SIZE) and the HTTP/3
     * field section (SETTINGS_MAX_FIELD_SECTION_SIZE).
     */
    public final int maxHeaderBytes;
    /** Request header fields per head on every protocol. */
    public final int maxHeaderFields;
    /** Server-wide bytes buffered for peers; 0 → a quarter of the max heap. */
    public final long maxBufferedBytes;
    public final long maxRequestBodyBytes;
    public final int maxKeepAliveRequests;

    // TCP.
    public final boolean soNodelay;
    public final boolean soReuseAddr;
    /** -1 disables SO_LINGER; otherwise seconds, as the socket option. */
    public final int soLinger;
    /** 0 → OS default. Set on the listening socket so accepted ones inherit it. */
    public final int soRcvBufBytes;
    /** 0 → OS default. */
    public final int soSndBufBytes;

    // TLS.
    /**
     * Context in use at startup: {@link #sslContextProvider}'s first value
     * when that is set. Non-null means the TCP listener speaks TLS.
     */
    public final SSLContext sslContext;
    /**
     * Called per accepted connection so rotated certificates apply to new
     * connections; null → {@link #sslContext} throughout.
     */
    public final Supplier<SSLContext> sslContextProvider;
    public final boolean sslNeedClientAuth;
    public final boolean sslWantClientAuth;
    /** null → h2 + http/1.1 when http2 is on, else http/1.1. */
    public final String[] sslAlpnProtocols;
    /** null → JVM default. */
    public final String[] sslCipherSuites;
    /** null → JVM default. */
    public final String[] sslProtocols;
    /** 0 → JVM default. */
    public final int sslSessionCacheSize;

    // HTTP/2.
    public final boolean http2;
    /** Cleartext HTTP/2 with prior knowledge (RFC 9113 §3.3) on a plain listener. */
    public final boolean http2c;
    public final int http2MaxConcurrentStreams;
    public final int http2InitialWindowBytes;
    public final int http2MaxFrameBytes;
    /** RST_STREAM frames per connection per 30 s (CVE-2023-44487); 0 disables. */
    public final int http2StreamResetLimit;
    public final int http2ContinuationLimit;

    // HTTP/3.
    public final boolean http3;
    /** 0 → the TCP port number, over UDP. */
    public final int http3Port;
    public final String http3CertPath;
    public final String http3KeyPath;
    public final long http3InitialMaxDataBytes;
    /**
     * Receive credit quiche may hold natively across connections (a
     * connection window each): a new connection is refused while its
     * window would pass it. -1 → the {@link #maxBufferedBytes} limit (at
     * least one window); 0 = unlimited.
     */
    public final long http3MaxNativeBytes;
    public final int http3InitialMaxStreamsBidi;
    public final int http3InitialMaxStreamsUni;
    public final int http3MaxUdpPayloadBytes;
    public final boolean http3StatelessRetry;
    /** -1 → a quarter of the initial max data (the connection window). */
    public final long http3InitialMaxStreamDataBidiLocalBytes;
    public final long http3InitialMaxStreamDataBidiRemoteBytes;
    public final long http3InitialMaxStreamDataUniBytes;
    /** -1 → quiche default. */
    public final int http3AckDelayExponent;
    /** -1 → quiche default. Milliseconds, as the transport parameter. */
    public final int http3MaxAckDelay;
    /** -1 → quiche default. */
    public final int http3ActiveConnectionIdLimit;
    /** Event loops (threads owning QUIC connections); 0 → one per core on Linux, 1 elsewhere. */
    public final int http3EventLoops;
    /** UDP socket receive buffer requested (best effort); 0 → OS default. */
    public final int http3SoRcvBufBytes;
    /** UDP socket send buffer requested (best effort); 0 → OS default. */
    public final int http3SoSndBufBytes;
    /**
     * Handshaking connections from which a client Initial without a valid
     * token gets a stateless Retry (address validation before any state or
     * handshake work); {@link #http3StatelessRetry} means always.
     */
    public final int http3RetryThreshold;
    /** Handshaking connections above which new Initials are dropped; 0 = unlimited. */
    public final int http3MaxHalfOpen;
    /** Peer stream resets per connection per 30 s (rapid-reset); 0 disables. */
    public final int http3StreamResetLimit;
    /**
     * Milliseconds between checks of {@link #http3CertPath} / {@link #http3KeyPath}
     * for changes; a changed pair is loaded for new connections (existing
     * ones keep theirs). 0 disables.
     */
    public final int http3CertReloadIntervalMillis;

    // Alt-Svc.
    public final boolean advertiseAltSvc;
    /** Seconds, as the {@code ma} parameter. */
    public final int altSvcMaxAge;
    /** Pre-formatted {@code Alt-Svc} header value, or null if disabled. */
    public final String altSvcValue;

    // WebSocket.
    /** Largest message, after decompression; larger ones close the connection with 1009. */
    public final int wsMaxMessageBytes;
    /** Payload bytes asynchronous sends may queue per connection; 0 = unlimited. */
    public final int wsMaxQueuedBytes;
    /** How long a closing handshake waits for the peer's CLOSE. */
    public final int wsCloseTimeoutMillis;
    /** Negotiate permessage-deflate (RFC 7692) when the client offers it. */
    public final boolean wsCompression;
    /** Ping a client that sent no frame for this long; 0 = never. */
    public final int wsPingIntervalMillis;
    /**
     * Decides whether a handshake's {@code Origin} may open a WebSocket;
     * null → only the origin whose host equals the {@code Host} header.
     */
    public final Predicate<String> wsAllowedOrigins;

    // Server-wide.
    /** {@code Server:} value; null / empty → omitted. */
    public final String serverHeader;
    /** null → no listener. */
    public final ServerEvents serverEvents;

    private Config(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.backlog = b.backlog;
        this.maxConnections = b.maxConnections;
        this.maxConnectionsPerIp = b.maxConnectionsPerIp;
        this.handshakeTimeoutMillis = b.handshakeTimeoutMillis;
        this.headerTimeoutMillis = b.headerTimeoutMillis;
        this.readTimeoutMillis = b.readTimeoutMillis;
        this.minDataRateBytes = b.minDataRateBytes;
        this.minDataRateGraceMillis = b.minDataRateGraceMillis;
        this.writeTimeoutMillis = b.writeTimeoutMillis;
        this.idleTimeoutMillis = b.idleTimeoutMillis;
        this.handlerTimeoutMillis = b.handlerTimeoutMillis;
        this.shutdownTimeoutMillis = b.shutdownTimeoutMillis;
        this.maxHeaderBytes = b.maxHeaderBytes;
        this.maxHeaderFields = b.maxHeaderFields;
        this.maxBufferedBytes = b.maxBufferedBytes;
        this.maxRequestBodyBytes = b.maxRequestBodyBytes;
        this.maxKeepAliveRequests = b.maxKeepAliveRequests;
        this.soNodelay = b.soNodelay;
        this.soReuseAddr = b.soReuseAddr;
        this.soLinger = b.soLinger;
        this.soRcvBufBytes = b.soRcvBufBytes;
        this.soSndBufBytes = b.soSndBufBytes;
        this.sslContext = b.sslContext;
        this.sslContextProvider = b.sslContextProvider;
        this.sslNeedClientAuth = b.sslNeedClientAuth;
        this.sslWantClientAuth = b.sslWantClientAuth;
        // Fields are public final but arrays are mutable: copies keep a
        // caller's later writes from changing server behaviour.
        this.sslAlpnProtocols = b.sslAlpnProtocols == null ? null : b.sslAlpnProtocols.clone();
        this.sslCipherSuites = b.sslCipherSuites == null ? null : b.sslCipherSuites.clone();
        this.sslProtocols = b.sslProtocols == null ? null : b.sslProtocols.clone();
        this.sslSessionCacheSize = b.sslSessionCacheSize;
        this.http2 = b.http2;
        this.http2c = b.http2c;
        this.http2MaxConcurrentStreams = b.http2MaxConcurrentStreams;
        this.http2InitialWindowBytes = b.http2InitialWindowBytes;
        this.http2MaxFrameBytes = b.http2MaxFrameBytes;
        this.http2StreamResetLimit = b.http2StreamResetLimit;
        this.http2ContinuationLimit = b.http2ContinuationLimit;
        this.http3 = b.http3;
        this.http3Port = b.http3Port;
        this.http3CertPath = b.http3CertPath;
        this.http3KeyPath = b.http3KeyPath;
        this.http3InitialMaxDataBytes = b.http3InitialMaxDataBytes;
        this.http3MaxNativeBytes = b.http3MaxNativeBytes;
        this.http3InitialMaxStreamsBidi = b.http3InitialMaxStreamsBidi;
        this.http3InitialMaxStreamsUni = b.http3InitialMaxStreamsUni;
        this.http3MaxUdpPayloadBytes = b.http3MaxUdpPayloadBytes;
        this.http3StatelessRetry = b.http3StatelessRetry;
        this.http3InitialMaxStreamDataBidiLocalBytes = b.http3InitialMaxStreamDataBidiLocalBytes;
        this.http3InitialMaxStreamDataBidiRemoteBytes = b.http3InitialMaxStreamDataBidiRemoteBytes;
        this.http3InitialMaxStreamDataUniBytes = b.http3InitialMaxStreamDataUniBytes;
        this.http3AckDelayExponent = b.http3AckDelayExponent;
        this.http3MaxAckDelay = b.http3MaxAckDelay;
        this.http3ActiveConnectionIdLimit = b.http3ActiveConnectionIdLimit;
        this.http3EventLoops = b.http3EventLoops;
        this.http3SoRcvBufBytes = b.http3SoRcvBufBytes;
        this.http3SoSndBufBytes = b.http3SoSndBufBytes;
        this.http3RetryThreshold = b.http3RetryThreshold;
        this.http3MaxHalfOpen = b.http3MaxHalfOpen;
        this.http3StreamResetLimit = b.http3StreamResetLimit;
        this.http3CertReloadIntervalMillis = b.http3CertReloadIntervalMillis;
        this.wsMaxMessageBytes = b.wsMaxMessageBytes;
        this.wsMaxQueuedBytes = b.wsMaxQueuedBytes;
        this.wsCloseTimeoutMillis = b.wsCloseTimeoutMillis;
        this.wsCompression = b.wsCompression;
        this.wsPingIntervalMillis = b.wsPingIntervalMillis;
        this.wsAllowedOrigins = b.wsAllowedOrigins;
        this.serverHeader = b.serverHeader;
        this.serverEvents = b.serverEvents;
        this.advertiseAltSvc = b.advertiseAltSvc();
        this.altSvcMaxAge = b.altSvcMaxAge;
        // RFC 7838: Alt-Svc: h3=":<port>"; ma=<seconds>. The h3 port is
        // the TCP port number when not set apart.
        if (this.advertiseAltSvc) {
            int altPort = b.http3Port > 0 ? b.http3Port : b.port;
            this.altSvcValue = "h3=\":" + altPort + "\"; ma=" + b.altSvcMaxAge;
        } else {
            this.altSvcValue = null;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private String host = "0.0.0.0";
        private int port = 8080;
        private int backlog = 1024;
        private int maxConnections = 10_000;
        private int maxConnectionsPerIp = 0;
        private int handshakeTimeoutMillis = 10_000;
        private int headerTimeoutMillis = 10_000;
        private int readTimeoutMillis = 30_000;
        // Kestrel's MinRequestBodyDataRate: 240 bytes/s after 5 s.
        private int minDataRateBytes = 240;
        private int minDataRateGraceMillis = 5000;
        private int writeTimeoutMillis = 30_000;
        private int idleTimeoutMillis = 75_000;
        private int handlerTimeoutMillis = 0;
        private int shutdownTimeoutMillis = 10_000;
        private int maxHeaderBytes = 65_536;
        private int maxHeaderFields = 100;
        private long maxBufferedBytes = 0;
        private long maxRequestBodyBytes = 10L * 1024 * 1024;
        private int maxKeepAliveRequests = 1000;
        private boolean soNodelay = true;
        private boolean soReuseAddr = true;
        private int soLinger = -1;
        private int soRcvBufBytes = 0;
        private int soSndBufBytes = 0;
        private SSLContext sslContext;
        private Supplier<SSLContext> sslContextProvider;
        private boolean sslNeedClientAuth;
        private boolean sslWantClientAuth;
        private String[] sslAlpnProtocols;
        private String[] sslCipherSuites;
        private String[] sslProtocols;
        private int sslSessionCacheSize = 0;
        private boolean http2;
        private boolean http2c;
        private int http2MaxConcurrentStreams = 100;
        // 256 KiB per stream, so a 1 MiB connection window (Go's and
        // Kestrel's): see :http2-initial-window-bytes.
        private int http2InitialWindowBytes = 256 * 1024;
        private int http2MaxFrameBytes = 1 << 14;        // 16 KiB
        // nginx's post-CVE-2023-44487 default.
        private int http2StreamResetLimit = 400;
        private int http2ContinuationLimit = 64;
        private boolean http3;
        private int http3Port = 0;
        private String http3CertPath;
        private String http3KeyPath;
        // Connection window: also bounds the unread request-body bytes
        // quiche buffers per connection (its autotuning is capped at it).
        private long http3InitialMaxDataBytes = 1L << 20; // 1 MiB
        private long http3MaxNativeBytes = -1;
        private int http3InitialMaxStreamsBidi = 100;
        private int http3InitialMaxStreamsUni = 8;
        private int http3MaxUdpPayloadBytes = 1350;
        private boolean http3StatelessRetry = false;
        private long http3InitialMaxStreamDataBidiLocalBytes = -1;
        private long http3InitialMaxStreamDataBidiRemoteBytes = -1;
        private long http3InitialMaxStreamDataUniBytes = -1;
        private int http3AckDelayExponent = -1;
        private int http3MaxAckDelay = -1;
        private int http3ActiveConnectionIdLimit = -1;
        private int http3EventLoops = 0;
        private int http3SoRcvBufBytes = 4 << 20;
        private int http3SoSndBufBytes = 4 << 20;
        private int http3RetryThreshold = 256;
        private int http3MaxHalfOpen = 1024;
        private int http3StreamResetLimit = 400;
        private int http3CertReloadIntervalMillis = 10_000;
        // null → auto (true iff http3 enabled).
        private Boolean advertiseAltSvcExplicit;
        private int altSvcMaxAge = 86_400;    // 24h, RFC 7838's default
        private int wsMaxMessageBytes = 1 << 20; // 1 MiB
        private int wsMaxQueuedBytes = 1 << 20; // 1 MiB
        private int wsCloseTimeoutMillis = 5_000;
        private boolean wsCompression;
        private int wsPingIntervalMillis;
        private Predicate<String> wsAllowedOrigins;
        private String serverHeader;
        private ServerEvents serverEvents;

        public Builder host(String v) { this.host = v; return this; }
        public Builder port(int v) { this.port = v; return this; }
        public Builder backlog(int v) { this.backlog = v; return this; }
        public Builder maxConnections(int v) { this.maxConnections = v; return this; }
        public Builder maxConnectionsPerIp(int v) { this.maxConnectionsPerIp = v; return this; }
        public Builder handshakeTimeoutMillis(int v) { this.handshakeTimeoutMillis = v; return this; }
        public Builder headerTimeoutMillis(int v) { this.headerTimeoutMillis = v; return this; }
        public Builder readTimeoutMillis(int v) { this.readTimeoutMillis = v; return this; }
        public Builder minDataRateBytes(int v) { this.minDataRateBytes = v; return this; }
        public Builder minDataRateGraceMillis(int v) { this.minDataRateGraceMillis = v; return this; }
        public Builder writeTimeoutMillis(int v) { this.writeTimeoutMillis = v; return this; }
        public Builder idleTimeoutMillis(int v) { this.idleTimeoutMillis = v; return this; }
        public Builder handlerTimeoutMillis(int v) { this.handlerTimeoutMillis = v; return this; }
        public Builder shutdownTimeoutMillis(int v) { this.shutdownTimeoutMillis = v; return this; }
        public Builder maxHeaderBytes(int v) { this.maxHeaderBytes = v; return this; }
        public Builder maxHeaderFields(int v) { this.maxHeaderFields = v; return this; }
        public Builder maxBufferedBytes(long v) { this.maxBufferedBytes = v; return this; }
        public Builder maxRequestBodyBytes(long v) { this.maxRequestBodyBytes = v; return this; }
        public Builder maxKeepAliveRequests(int v) { this.maxKeepAliveRequests = v; return this; }
        public Builder soNodelay(boolean v) { this.soNodelay = v; return this; }
        public Builder soReuseAddr(boolean v) { this.soReuseAddr = v; return this; }
        public Builder soLinger(int v) { this.soLinger = v; return this; }
        public Builder soRcvBufBytes(int v) { this.soRcvBufBytes = v; return this; }
        public Builder soSndBufBytes(int v) { this.soSndBufBytes = v; return this; }
        public Builder sslContext(SSLContext v) { this.sslContext = v; return this; }
        public Builder sslContextProvider(Supplier<SSLContext> v) { this.sslContextProvider = v; return this; }
        public Builder sslNeedClientAuth(boolean v) { this.sslNeedClientAuth = v; return this; }
        public Builder sslWantClientAuth(boolean v) { this.sslWantClientAuth = v; return this; }
        public Builder sslAlpnProtocols(String[] v) { this.sslAlpnProtocols = v == null ? null : v.clone(); return this; }
        public Builder sslCipherSuites(String[] v) { this.sslCipherSuites = v == null ? null : v.clone(); return this; }
        public Builder sslProtocols(String[] v) { this.sslProtocols = v == null ? null : v.clone(); return this; }
        public Builder sslSessionCacheSize(int v) { this.sslSessionCacheSize = v; return this; }
        public Builder http2(boolean v) { this.http2 = v; return this; }
        public Builder http2c(boolean v) { this.http2c = v; return this; }
        public Builder http2MaxConcurrentStreams(int v) { this.http2MaxConcurrentStreams = v; return this; }
        public Builder http2InitialWindowBytes(int v) { this.http2InitialWindowBytes = v; return this; }
        public Builder http2MaxFrameBytes(int v) { this.http2MaxFrameBytes = v; return this; }
        public Builder http2StreamResetLimit(int v) { this.http2StreamResetLimit = v; return this; }
        public Builder http2ContinuationLimit(int v) { this.http2ContinuationLimit = v; return this; }
        public Builder http3(boolean v) { this.http3 = v; return this; }
        public Builder http3Port(int v) { this.http3Port = v; return this; }
        public Builder http3CertPath(String v) { this.http3CertPath = v; return this; }
        public Builder http3KeyPath(String v) { this.http3KeyPath = v; return this; }
        public Builder http3InitialMaxDataBytes(long v) { this.http3InitialMaxDataBytes = v; return this; }
        public Builder http3MaxNativeBytes(long v) { this.http3MaxNativeBytes = v; return this; }
        public Builder http3InitialMaxStreamsBidi(int v) { this.http3InitialMaxStreamsBidi = v; return this; }
        public Builder http3InitialMaxStreamsUni(int v) { this.http3InitialMaxStreamsUni = v; return this; }
        public Builder http3MaxUdpPayloadBytes(int v) { this.http3MaxUdpPayloadBytes = v; return this; }
        public Builder http3StatelessRetry(boolean v) { this.http3StatelessRetry = v; return this; }
        public Builder http3InitialMaxStreamDataBidiLocalBytes(long v) { this.http3InitialMaxStreamDataBidiLocalBytes = v; return this; }
        public Builder http3InitialMaxStreamDataBidiRemoteBytes(long v) { this.http3InitialMaxStreamDataBidiRemoteBytes = v; return this; }
        public Builder http3InitialMaxStreamDataUniBytes(long v) { this.http3InitialMaxStreamDataUniBytes = v; return this; }
        public Builder http3AckDelayExponent(int v) { this.http3AckDelayExponent = v; return this; }
        public Builder http3MaxAckDelay(int v) { this.http3MaxAckDelay = v; return this; }
        public Builder http3ActiveConnectionIdLimit(int v) { this.http3ActiveConnectionIdLimit = v; return this; }
        public Builder http3EventLoops(int v) { this.http3EventLoops = v; return this; }
        public Builder http3SoRcvBufBytes(int v) { this.http3SoRcvBufBytes = v; return this; }
        public Builder http3SoSndBufBytes(int v) { this.http3SoSndBufBytes = v; return this; }
        public Builder http3RetryThreshold(int v) { this.http3RetryThreshold = v; return this; }
        public Builder http3MaxHalfOpen(int v) { this.http3MaxHalfOpen = v; return this; }
        public Builder http3StreamResetLimit(int v) { this.http3StreamResetLimit = v; return this; }
        public Builder http3CertReloadIntervalMillis(int v) { this.http3CertReloadIntervalMillis = v; return this; }
        public Builder advertiseAltSvc(boolean v) { this.advertiseAltSvcExplicit = v; return this; }
        public Builder altSvcMaxAge(int v) { this.altSvcMaxAge = v; return this; }
        public Builder wsMaxMessageBytes(int v) { this.wsMaxMessageBytes = v; return this; }
        public Builder wsMaxQueuedBytes(int v) { this.wsMaxQueuedBytes = v; return this; }
        public Builder wsCloseTimeoutMillis(int v) { this.wsCloseTimeoutMillis = v; return this; }
        public Builder wsCompression(boolean v) { this.wsCompression = v; return this; }
        public Builder wsPingIntervalMillis(int v) { this.wsPingIntervalMillis = v; return this; }
        public Builder wsAllowedOrigins(Predicate<String> v) { this.wsAllowedOrigins = v; return this; }
        public Builder serverHeader(String v) { this.serverHeader = v; return this; }
        public Builder serverEvents(ServerEvents v) { this.serverEvents = v; return this; }

        private boolean advertiseAltSvc() {
            return advertiseAltSvcExplicit != null ? advertiseAltSvcExplicit : http3;
        }

        public Config build() {
            validate();
            return new Config(this);
        }

        private void validate() {
            if (host == null || host.isEmpty()) {
                throw invalid(":host", host, ":host must be non-empty");
            }
            requireRange(":port", port, 0, 65535);
            requireAtLeast(":backlog", backlog, 1);
            requireAtLeast(":max-connections", maxConnections, 0);
            requireAtLeast(":max-connections-per-ip", maxConnectionsPerIp, 0);
            if (maxConnections > 0 && maxConnectionsPerIp > maxConnections) {
                throw invalid(":max-connections-per-ip", maxConnectionsPerIp,
                              ":max-connections-per-ip must be <= :max-connections, got "
                              + maxConnectionsPerIp + " > " + maxConnections);
            }
            requireAtLeast(":handshake-timeout", handshakeTimeoutMillis, 0);
            requireAtLeast(":header-timeout", headerTimeoutMillis, 0);
            requireAtLeast(":read-timeout", readTimeoutMillis, 0);
            requireAtLeast(":min-data-rate-bytes", minDataRateBytes, 0);
            requireAtLeast(":min-data-rate-grace", minDataRateGraceMillis, 0);
            requireAtLeast(":write-timeout", writeTimeoutMillis, 0);
            requireAtLeast(":idle-timeout", idleTimeoutMillis, 0);
            requireAtLeast(":handler-timeout", handlerTimeoutMillis, 0);
            requireAtLeast(":shutdown-timeout", shutdownTimeoutMillis, 0);
            requireAtLeast(":max-header-bytes", maxHeaderBytes, 1);
            requireAtLeast(":max-header-fields", maxHeaderFields, 1);
            if (maxBufferedBytes < 0) {
                throw invalid(":max-buffered-bytes", maxBufferedBytes,
                              ":max-buffered-bytes must be >= 0, got " + maxBufferedBytes);
            }
            if (maxRequestBodyBytes < 0) {
                throw invalid(":max-request-body-bytes", maxRequestBodyBytes,
                              ":max-request-body-bytes must be >= 0, got " + maxRequestBodyBytes);
            }
            requireAtLeast(":max-keep-alive-requests", maxKeepAliveRequests, 0);
            requireAtLeast(":so-linger", soLinger, -1);
            requireAtLeast(":so-rcv-buf-bytes", soRcvBufBytes, 0);
            requireAtLeast(":so-snd-buf-bytes", soSndBufBytes, 0);
            // serverHeader goes on the wire verbatim: a CR/LF would split
            // the response.
            if (serverHeader != null && !RequestHead.isFieldValue(serverHeader)) {
                throw invalid(":server-header", serverHeader, ":server-header must be a valid field value "
                              + "(no control characters, no leading or trailing whitespace)");
            }
            validateTls();
            validateHttp2();
            validateHttp3();
            requireAtLeast(":alt-svc-max-age", altSvcMaxAge, 0);
            requireAtLeast(":ws-max-message-bytes", wsMaxMessageBytes, 1);
            requireAtLeast(":ws-max-queued-bytes", wsMaxQueuedBytes, 0);
            requireAtLeast(":ws-close-timeout", wsCloseTimeoutMillis, 1);
            requireAtLeast(":ws-ping-interval", wsPingIntervalMillis, 0);
            // A ping has to go out, and be answered, before the idle
            // timeout closes the connection.
            if (wsPingIntervalMillis > 0 && idleTimeoutMillis > 0
                && wsPingIntervalMillis >= idleTimeoutMillis) {
                throw invalid(":ws-ping-interval", wsPingIntervalMillis,
                              ":ws-ping-interval must be < :idle-timeout, got "
                              + wsPingIntervalMillis + " >= " + idleTimeoutMillis);
            }
        }

        private void validateTls() {
            if (sslNeedClientAuth && sslWantClientAuth) {
                throw invalid(":ssl-want-client-auth", true,
                              ":ssl-need-client-auth and :ssl-want-client-auth are mutually exclusive");
            }
            if (sslContext != null && sslContextProvider != null) {
                throw invalid(":ssl-context-provider", sslContextProvider,
                              ":ssl-context and :ssl-context-provider are mutually exclusive");
            }
            // The provider's first context is the one validated against and
            // used for startup; it is asked again per accepted connection.
            if (sslContext == null && sslContextProvider != null) {
                SSLContext seed = sslContextProvider.get();
                if (seed == null) {
                    throw invalid(":ssl-context-provider", sslContextProvider,
                                  ":ssl-context-provider returned null on initial call");
                }
                sslContext = seed;
            }
            boolean tls = sslContext != null;
            if (!tls) {
                if (sslNeedClientAuth || sslWantClientAuth) {
                    throw invalid(sslNeedClientAuth ? ":ssl-need-client-auth" : ":ssl-want-client-auth", true,
                                  ":ssl-need-client-auth / :ssl-want-client-auth need :ssl-context");
                }
                if (sslAlpnProtocols != null) {
                    throw invalid(":ssl-alpn-protocols", sslAlpnProtocols,
                                  ":ssl-alpn-protocols needs :ssl-context");
                }
                if (sslCipherSuites != null) {
                    throw invalid(":ssl-cipher-suites", sslCipherSuites, ":ssl-cipher-suites needs :ssl-context");
                }
                if (sslProtocols != null) {
                    throw invalid(":ssl-protocols", sslProtocols, ":ssl-protocols needs :ssl-context");
                }
            }
            requireAtLeast(":ssl-session-cache-size", sslSessionCacheSize, 0);
            if (sslAlpnProtocols != null) {
                for (String p : sslAlpnProtocols) {
                    if (p == null || p.isEmpty()) {
                        throw invalid(":ssl-alpn-protocols", sslAlpnProtocols,
                                      ":ssl-alpn-protocols entries must be non-empty");
                    }
                    if (p.equals("h2") && !http2) {
                        throw invalid(":ssl-alpn-protocols", sslAlpnProtocols,
                                      ":ssl-alpn-protocols offers h2 but :http2 is off");
                    }
                }
            }
        }

        private void validateHttp2() {
            if (http2 && sslContext == null) {
                throw invalid(":http2", true, ":http2 needs :ssl-context (cleartext HTTP/2 is :http2c)");
            }
            if (http2c && (sslContext != null || sslContextProvider != null)) {
                throw invalid(":http2c", true, ":http2c serves a plain listener; with :ssl-context use :http2");
            }
            requireAtLeast(":http2-max-concurrent-streams", http2MaxConcurrentStreams, 1);
            // RFC 9113 §6.9.2 caps windows at 2^31-1. Below the 65535
            // default a peer's first request body would stall on credit.
            requireRange(":http2-initial-window-bytes", http2InitialWindowBytes, 65_535, Integer.MAX_VALUE);
            // RFC 9113 §4.2 / §6.5.2: SETTINGS_MAX_FRAME_SIZE ∈ [16384, 16777215].
            requireRange(":http2-max-frame-bytes", http2MaxFrameBytes, 16_384, 16_777_215);
            requireAtLeast(":http2-stream-reset-limit", http2StreamResetLimit, 0);
            requireAtLeast(":http2-continuation-limit", http2ContinuationLimit, 1);
        }

        private void validateHttp3() {
            requireRange(":http3-port", http3Port, 0, 65535);
            if (http3) {
                if (http3CertPath == null || http3KeyPath == null) {
                    throw invalid(":http3", true, ":http3 needs :http3-cert-path and :http3-key-path (PEM files: "
                                  + "quiche loads cert and key from disk, not from the SSLContext)");
                }
                // Alt-Svc must name the UDP port clients connect to: an
                // ephemeral one is only known after binding, separately
                // from the TCP one.
                if (port == 0 && http3Port == 0 && advertiseAltSvc()) {
                    throw invalid(":port", port, ":http3 with :port 0 can't advertise Alt-Svc: set :http3-port "
                                  + "or :advertise-alt-svc false");
                }
            } else {
                if (http3Port != 0) {
                    throw invalid(":http3-port", http3Port, ":http3-port needs :http3");
                }
                if (Boolean.TRUE.equals(advertiseAltSvcExplicit)) {
                    throw invalid(":advertise-alt-svc", true, ":advertise-alt-svc needs :http3");
                }
            }
            if (http3InitialMaxDataBytes < 0) {
                throw invalid(":http3-initial-max-data-bytes", http3InitialMaxDataBytes,
                              ":http3-initial-max-data-bytes must be >= 0, got " + http3InitialMaxDataBytes);
            }
            if (http3MaxNativeBytes < -1) {
                throw invalid(":http3-max-native-bytes", http3MaxNativeBytes,
                              ":http3-max-native-bytes must be >= -1, got " + http3MaxNativeBytes);
            }
            if (http3MaxNativeBytes > 0 && http3MaxNativeBytes < http3InitialMaxDataBytes) {
                throw invalid(":http3-max-native-bytes", http3MaxNativeBytes,
                              ":http3-max-native-bytes must hold one connection window"
                                  + " (:http3-initial-max-data-bytes " + http3InitialMaxDataBytes + "), got "
                                  + http3MaxNativeBytes);
            }
            requireAtLeast(":http3-initial-max-streams-bidi", http3InitialMaxStreamsBidi, 1);
            // Control + QPACK encoder + QPACK decoder.
            requireAtLeast(":http3-initial-max-streams-uni", http3InitialMaxStreamsUni, 3);
            // RFC 9000 §14.1: QUIC needs at least 1200-byte datagrams.
            requireRange(":http3-max-udp-payload-bytes", http3MaxUdpPayloadBytes, 1200, 65527);
            // RFC 9114 §7.2.4.1: 0 → no limit advertised.
            requireDerivedOrNonNegative(":http3-initial-max-stream-data-bidi-local-bytes",
                                        http3InitialMaxStreamDataBidiLocalBytes);
            requireDerivedOrNonNegative(":http3-initial-max-stream-data-bidi-remote-bytes",
                                        http3InitialMaxStreamDataBidiRemoteBytes);
            requireDerivedOrNonNegative(":http3-initial-max-stream-data-uni-bytes",
                                        http3InitialMaxStreamDataUniBytes);
            // RFC 9000 §18.2 transport parameter ranges.
            if (http3AckDelayExponent != -1) {
                requireRange(":http3-ack-delay-exponent", http3AckDelayExponent, 0, 20);
            }
            if (http3MaxAckDelay != -1) {
                requireRange(":http3-max-ack-delay", http3MaxAckDelay, 0, 16_383);
            }
            if (http3ActiveConnectionIdLimit != -1) {
                requireAtLeast(":http3-active-connection-id-limit", http3ActiveConnectionIdLimit, 2);
            }
            requireRange(":http3-event-loops", http3EventLoops, 0, 64);
            requireAtLeast(":http3-so-rcv-buf-bytes", http3SoRcvBufBytes, 0);
            requireAtLeast(":http3-so-snd-buf-bytes", http3SoSndBufBytes, 0);
            requireAtLeast(":http3-retry-threshold", http3RetryThreshold, 0);
            requireAtLeast(":http3-max-half-open", http3MaxHalfOpen, 0);
            requireAtLeast(":http3-stream-reset-limit", http3StreamResetLimit, 0);
            requireAtLeast(":http3-cert-reload-interval", http3CertReloadIntervalMillis, 0);
        }

        /** {@code option}: the option's keyword as written, e.g. ":port". */
        private static InvalidOptionException invalid(String option, Object value, String message) {
            return new InvalidOptionException(option.substring(1), value, message);
        }

        private static void requireDerivedOrNonNegative(String option, long v) {
            if (v < -1) {
                throw invalid(option, v, option + " must be >= 0 or -1 (derived), got " + v);
            }
        }

        private static void requireAtLeast(String option, int v, int min) {
            if (v < min) {
                throw invalid(option, v, option + " must be >= " + min + ", got " + v);
            }
        }

        private static void requireRange(String option, int v, int min, int max) {
            if (v < min || v > max) {
                throw invalid(option, v, option + " must be in [" + min + ", " + max + "], got " + v);
            }
        }
    }

    /**
     * A {@link Builder#build} validation failure, naming the option at
     * fault (its keyword name, e.g. "idle-timeout") and the value it was
     * given; for a contradiction between options, the one that needs the
     * other.
     */
    public static final class InvalidOptionException extends IllegalArgumentException {
        private final String option;
        private final transient Object value;

        InvalidOptionException(String option, Object value, String message) {
            super(message);
            this.option = option;
            this.value = value;
        }

        /** The option's keyword name, without the colon. */
        public String option() {
            return option;
        }

        /** The value the option was given (boxed). */
        public Object value() {
            return value;
        }
    }
}

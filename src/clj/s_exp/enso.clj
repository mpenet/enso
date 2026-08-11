(ns s-exp.enso
  "Ring adapter backed by a zero-dependency Java core: blocking I/O on virtual
  threads, one virtual thread per connection."
  (:import (com.s_exp.enso EnsoServer)
           (com.s_exp.enso.api ChunkedWriter Config Response
                               RingErrorHandler RingHandler StreamingBody)
           (com.s_exp.enso.websocket WebSocketListener WebSocketSocket)))

(set! *warn-on-reflection* true)

(declare ^:private streamable-body-proto write-body-to-stream-fn
         chunked-writer->output-stream)

(defn- coerce-body [response body]
  (cond
    ;; fast paths recognised by the Java writer directly, zero adapter cost
    (or (nil? body) (string? body) (bytes? body)
        (instance? java.io.InputStream body)
        (instance? java.io.File body))
    body

    ;; SSE / long-poll streaming writer
    (fn? body)
    (reify StreamingBody
      (write [_ writer]
        (body writer)))

    ;; Ring's StreamableResponseBody protocol: any user-extended body type.
    ;; Written via chunked transfer encoding — the body drives its own writes
    ;; onto the wrapped OutputStream, flushed per user's write-body-to-stream
    ;; implementation.
    (and streamable-body-proto
         (satisfies? streamable-body-proto body))
    (reify StreamingBody
      (write [_ writer]
        (let [os (chunked-writer->output-stream writer)]
          (write-body-to-stream-fn body response os))))

    ;; Ring seq body → stream element-by-element via chunked transfer, mirroring
    ;; Ring's default ISeq StreamableResponseBody impl. Avoids materialising
    ;; large lazy seqs into a single String.
    (seq? body)
    (reify StreamingBody
      (write [_ writer]
        (doseq [chunk body]
          (.write writer ^String (str chunk)))
        (.flush writer)))

    :else body))

(defn- ring-listener->java
  "Converts a WebSocket listener map into a WebSocketListener. Keys:
  `:on-open` `:on-message` `:on-ping` `:on-pong` `:on-error` `:on-close`."
  ^WebSocketListener [listener]
  (let [invoke (fn [k default] (or (get listener k) default))
        on-open (invoke :on-open (fn [_]))
        on-message (invoke :on-message (fn [_ _]))
        on-pong (invoke :on-pong (fn [_ _]))
        on-error (invoke :on-error (fn [_ _]))
        on-close (invoke :on-close (fn [_ _ _]))
        on-ping (get listener :on-ping)]
    (reify WebSocketListener
      (onOpen [_ socket] (on-open socket))
      (onMessage [_ socket message] (on-message socket message))
      (onPing [_ socket data]
        (if on-ping
          (on-ping socket data)
          (try (.sendPong ^WebSocketSocket socket data) (catch Exception _))))
      (onPong [_ socket data] (on-pong socket data))
      (onError [_ socket t] (on-error socket t))
      (onClose [_ socket code reason] (on-close socket code reason)))))

;; Optional support for Ring's StreamableResponseBody protocol. When
;; ring.core.protocols is on the classpath, any body value satisfying the
;; protocol is written by delegating to write-body-to-stream. Fast paths for
;; String/byte[]/InputStream/File/StreamingBody keep priority.
(defonce ^:private streamable-body-proto
  (try
    (require 'ring.core.protocols)
    @(resolve 'ring.core.protocols/StreamableResponseBody)
    (catch Throwable _ nil)))

(defonce ^:private write-body-to-stream-fn
  (when streamable-body-proto
    @(resolve 'ring.core.protocols/write-body-to-stream)))

(defn- chunked-writer->output-stream ^java.io.OutputStream [^ChunkedWriter w]
  (proxy [java.io.OutputStream] []
    (write
      ([b]
       (if (bytes? b)
         (.write w ^bytes b)
         (.write w (int b))))
      ([b off len]
       (.write w ^bytes b (int off) (int len))))
    (flush [] (.flush w))
    (close [])))

(defn- websocket-response? [response]
  (contains? response :ring.websocket/listener))

(defn- ->response ^Response [response]
  (when (nil? response)
    (throw (IllegalArgumentException. "handler returned nil response")))
  (if (websocket-response? response)
    (Response. 101
               nil
               nil
               (ring-listener->java (:ring.websocket/listener response))
               (:ring.websocket/protocol response))
    (Response. (int (:status response 200))
               (:headers response)
               (coerce-body response (:body response)))))

(defn- ^Config build-config [opts]
  (let [b (Config/builder)]
    (when-let [v (:host opts)] (.host b ^String v))
    (when-let [v (:port opts)] (.port b (int v)))
    (when-let [v (:backlog opts)] (.backlog b (int v)))
    (when-let [v (:idle-timeout opts)] (.idleTimeoutMillis b (int v)))
    (when-let [v (:request-timeout opts)] (.requestTimeoutMillis b (int v)))
    (when-let [v (:shutdown-timeout opts)] (.shutdownTimeoutMillis b (int v)))
    (when-let [v (:request-buffer-size opts)] (.requestBufferSize b (int v)))
    (when-let [v (:max-header-bytes opts)] (.maxHeaderBytes b (int v)))
    (when-let [v (:max-inline-body opts)] (.maxInlineBody b (int v)))
    (when-let [v (:coalesce-high-water opts)] (.coalesceHighWater b (int v)))
    (when-let [v (:chunk-buffer-size opts)] (.chunkBufferSize b (int v)))
    (when-let [v (:max-drain-bytes opts)] (.maxDrainBytes b (int v)))
    (when-let [v (:max-request-body-bytes opts)] (.maxRequestBodyBytes b (long v)))
    ;; h1 keep-alive
    (when-let [v (:max-keep-alive-requests opts)] (.maxKeepAliveRequests b (int v)))
    (when-let [v (:keep-alive-timeout opts)] (.keepAliveTimeoutMillis b (int v)))
    ;; TCP
    (when (contains? opts :so-nodelay) (.soNodelay b (boolean (:so-nodelay opts))))
    (when (contains? opts :so-reuse-addr) (.soReuseAddr b (boolean (:so-reuse-addr opts))))
    (when-let [v (:so-linger opts)] (.soLinger b (int v)))
    (when-let [v (:so-rcv-buf opts)] (.soRcvBuf b (int v)))
    (when-let [v (:so-snd-buf opts)] (.soSndBuf b (int v)))
    ;; TLS
    (when-let [v (:ssl-context opts)] (.sslContext b ^javax.net.ssl.SSLContext v))
    (when-let [v (:ssl-context-provider opts)]
      (.sslContextProvider b ^java.util.function.Supplier
                           (if (fn? v)
                             (reify java.util.function.Supplier (get [_] (v)))
                             v)))
    (when (:ssl-need-client-auth opts) (.sslNeedClientAuth b true))
    (when (:ssl-want-client-auth opts) (.sslWantClientAuth b true))
    (when-let [v (:alpn-protocols opts)] (.alpnProtocols b (into-array String (map str v))))
    (when-let [v (:enabled-cipher-suites opts)] (.enabledCipherSuites b (into-array String (map str v))))
    (when-let [v (:enabled-tls-protocols opts)] (.enabledTlsProtocols b (into-array String (map str v))))
    (when-let [v (:ssl-session-cache-size opts)] (.sslSessionCacheSize b (int v)))
    ;; h2
    (when (:http2 opts) (.http2 b true))
    (when-let [v (:http2-max-concurrent-streams opts)] (.http2MaxConcurrentStreams b (int v)))
    (when-let [v (:http2-initial-window-size opts)] (.http2InitialWindowSize b (int v)))
    (when-let [v (:http2-max-frame-size opts)] (.http2MaxFrameSize b (int v)))
    (when-let [v (:http2-max-header-list-size opts)] (.http2MaxHeaderListSize b (int v)))
    (when-let [v (:http2-stream-reset-limit opts)] (.http2StreamResetLimit b (int v)))
    (when-let [v (:http2-continuation-limit opts)] (.http2ContinuationLimit b (int v)))
    ;; h3
    (when (:http3 opts) (.http3 b true))
    (when-let [v (:http3-port opts)] (.http3Port b (int v)))
    (when-let [v (:http3-max-idle-timeout opts)] (.http3MaxIdleTimeoutMs b (int v)))
    (when-let [v (:http3-initial-max-data opts)] (.http3InitialMaxData b (long v)))
    (when-let [v (:http3-initial-max-streams-bidi opts)] (.http3InitialMaxStreamsBidi b (int v)))
    (when-let [v (:http3-initial-max-streams-uni opts)] (.http3InitialMaxStreamsUni b (int v)))
    (when-let [v (:http3-max-udp-payload-size opts)] (.http3MaxUdpPayloadSize b (int v)))
    (when-let [v (:http3-cert-path opts)] (.http3CertPath b ^String v))
    (when-let [v (:http3-key-path opts)] (.http3KeyPath b ^String v))
    (when (contains? opts :http3-stateless-retry) (.http3StatelessRetry b (boolean (:http3-stateless-retry opts))))
    (when-let [v (:http3-max-field-section-size opts)] (.http3MaxFieldSectionSize b (int v)))
    (when-let [v (:http3-qpack-max-table-capacity opts)] (.http3QpackMaxTableCapacity b (long v)))
    (when-let [v (:http3-qpack-blocked-streams opts)] (.http3QpackBlockedStreams b (long v)))
    (when-let [v (:http3-initial-max-stream-data-bidi-local opts)] (.http3InitialMaxStreamDataBidiLocal b (long v)))
    (when-let [v (:http3-initial-max-stream-data-bidi-remote opts)] (.http3InitialMaxStreamDataBidiRemote b (long v)))
    (when-let [v (:http3-initial-max-stream-data-uni opts)] (.http3InitialMaxStreamDataUni b (long v)))
    (when-let [v (:http3-ack-delay-exponent opts)] (.http3AckDelayExponent b (int v)))
    (when-let [v (:http3-max-ack-delay opts)] (.http3MaxAckDelay b (int v)))
    (when-let [v (:http3-active-connection-id-limit opts)] (.http3ActiveConnectionIdLimit b (int v)))
    ;; Alt-Svc
    (when (contains? opts :advertise-alt-svc) (.advertiseAltSvc b (boolean (:advertise-alt-svc opts))))
    (when-let [v (:alt-svc-max-age opts)] (.altSvcMaxAge b (int v)))
    ;; Server-wide
    (when-let [v (:server-header opts)] (.serverHeader b ^String v))
    (when-let [v (:worker-executor opts)] (.workerExecutor b ^java.util.concurrent.Executor v))
    (.build b)))

(defn run-server
  "Starts an HTTP server calling `handler` with Ring request maps.
  Returns the server, stop it with [[stop]].

  Network options:
  - `:port` - listen port, 0 picks an ephemeral port (default 8080)
  - `:host` - bind address (default \"0.0.0.0\")
  - `:backlog` - accept queue length (default 1024)

  Timeouts:
  - `:idle-timeout` - per-read socket timeout in ms, 0 disables (default 30000)
  - `:request-timeout` - wall-clock deadline for reading a full request in ms,
    0 disables (default 30000). Slowloris protection.
  - `:shutdown-timeout` - graceful shutdown wait for in-flight requests in ms
    (default 10000). Idle keep-alive connections close immediately.

  TLS:
  - `:ssl-context` - `javax.net.ssl.SSLContext`. When set, listens as TLS with
    the context's keystore/truststore/protocols. Falls back to a user-space
    file transfer for File response bodies (no zero-copy on TLS).
  - `:ssl-need-client-auth` - require a valid client certificate (default false)
  - `:ssl-want-client-auth` - request but not require a client cert (default false)
  - `:alpn-protocols` - seq of ALPN protocol IDs to advertise. Defaults to
    `[\"h2\" \"http/1.1\"]` when `:http2` is enabled, otherwise JVM default.
  - `:enabled-cipher-suites` - seq of cipher suite names to enable (JVM default when nil)
  - `:enabled-tls-protocols` - seq of TLS protocol versions to enable (JVM default when nil)
  - `:ssl-session-cache-size` - SSL session cache size in entries. 0 = JVM
    default (10000 on OpenJDK). Larger caches help session-resumption hit
    rate under many short-lived TLS clients.

  HTTP/1.1 keep-alive:
  - `:max-keep-alive-requests` - cap on requests per connection, 0 = unlimited (default 1000)
  - `:keep-alive-timeout` - between-request idle timeout in ms, 0 = fall back to
    `:idle-timeout` (default 0). Distinct from mid-request idle.

  TCP socket options (applied to acceptor + accepted sockets):
  - `:so-nodelay` - TCP_NODELAY (default true)
  - `:so-reuse-addr` - SO_REUSEADDR (default true)
  - `:so-linger` - SO_LINGER seconds, -1 disables (default -1)
  - `:so-rcv-buf` / `:so-snd-buf` - socket buffer sizes, 0 = OS default

  HTTP/2 hardening:
  - `:http2-stream-reset-limit` - RST_STREAM cap per connection, CVE-2023-44487
    mitigation (default 400, matches Nginx)
  - `:http2-continuation-limit` - CONTINUATION frames per HEADERS (default 64)

  HTTP/3 (opt-in; requires PEM cert + key on disk since quiche loads them
  itself rather than from `:ssl-context`):
  - `:http3` (false) — enables HTTP/3 listener. `Alt-Svc` auto-advertised on
    h1/h2 responses when both enabled.
  - `:http3-cert-path`, `:http3-key-path` — PEM cert chain + private key.
    Required when `:http3` is true.
  - `:http3-port` — UDP port. Defaults to `:port` (co-exists on the same
    port number over UDP + TCP).
  - `:http3-max-idle-timeout` (30000) — quiche idle timeout in ms.
  - `:http3-initial-max-data` (1 GiB) — connection flow control window.
  - `:http3-initial-max-streams-bidi` (100) — concurrent request streams.
  - `:http3-max-udp-payload-size` (1350) — MTU-safe default.
  - `:http3-stateless-retry` (false) — force clients to prove reachability
    before we allocate conn state (RFC 9000 §8.1.2). Enable under DDoS.
  - `:advertise-alt-svc` — override auto behavior (auto = true iff `:http3`).
  - `:alt-svc-max-age` (86400) — `ma=` field on the emitted `Alt-Svc`.

  HTTP/3 advanced (QPACK, transport):
  - `:http3-initial-max-streams-uni` - peer's unidirectional stream credit (default 8; min 3)
  - `:http3-max-field-section-size` - SETTINGS_MAX_FIELD_SECTION_SIZE, our
    inbound cap advertised to the peer (default 64 KiB, 0 = no limit)
  - `:http3-qpack-max-table-capacity` - SETTINGS_QPACK_MAX_TABLE_CAPACITY (default 0 = static-table only)
  - `:http3-qpack-blocked-streams` - SETTINGS_QPACK_BLOCKED_STREAMS (default 0)
  - `:http3-initial-max-stream-data-bidi-local`
  - `:http3-initial-max-stream-data-bidi-remote`
  - `:http3-initial-max-stream-data-uni` - per-stream flow control windows.
    Default -1 means derive from `:http3-initial-max-data` / stream count.
  - `:http3-ack-delay-exponent` - RFC 9000 ack_delay_exponent, [0, 20]. -1 = quiche default
  - `:http3-max-ack-delay` - RFC 9000 max_ack_delay ms, [0, 16383]. -1 = quiche default
  - `:http3-active-connection-id-limit` - RFC 9000 active_connection_id_limit, >= 2. -1 = quiche default

  Server-wide:
  - `:server-header` - value emitted as the `Server:` response header. Nil/empty
    omits the header (default nil). Handler-supplied `Server` header wins.
  - `:worker-executor` - `java.util.concurrent.Executor` for request-handler
    tasks. Nil = built-in virtual-thread-per-task (default). The server does not
    shutdown() a user-supplied executor.

  Error handling:
  - `:error-handler` - `(fn [request throwable])` returning a Ring response map.
    Invoked when the main handler throws or returns nil. If the error handler
    itself throws or returns nil, a fallback 500 text response is sent.

  Buffers / limits (tune only if you know why):
  - `:request-buffer-size` - initial request parse buffer size (default 16384).
    Grown up to `:max-header-bytes` as headers arrive.
  - `:max-header-bytes` - hard cap for request headers, 431 above (default 65536).
    Also caps how large the parse buffer may grow.
  - `:max-inline-body` - response bodies at or below this size are inlined into
    the header write buffer for one-syscall dispatch (default 16384). Larger
    values reduce syscalls for big responses at the cost of more short-term
    heap during pipelined bursts.
  - `:coalesce-high-water` - pending response bytes at which a pipelined batch
    is force-flushed (default 32768). Should be a small multiple of
    `:max-inline-body` — batches beyond this cost more in memory than they
    save in syscalls.
  - `:chunk-buffer-size` - read chunk size when streaming response bodies with
    Transfer-Encoding: chunked (default 8192). Reused across pipelined
    responses on the same connection.
  - `:max-drain-bytes` - largest ignored request body size drained before the
    connection is closed instead of reused (default 65536). If the handler
    ignores a POST body larger than this, keep-alive is dropped.
  - `:max-request-body-bytes` - cap for the incoming request body in bytes,
    0 disables (default 10 MiB). Content-Length above the cap → 413 upfront;
    chunked bodies get 413 mid-stream once the cap is exceeded. Also caps
    WebSocket frame payload size (uses same limit).

  Interaction notes:
  - `:request-buffer-size` and `:max-header-bytes` should typically be equal
    or `request-buffer-size <= max-header-bytes`. Otherwise the initial buffer
    caps at `max-header-bytes` and pipelined batches larger than that get
    fragmented reads.
  - `:max-inline-body <= :coalesce-high-water` — otherwise a single large
    response triggers a flush before the next pipelined request can be
    coalesced, defeating the batching.
  - `:request-timeout` interacts with `:idle-timeout`: the per-read timeout is
    `min(idle, remaining-request-budget)`. Set both to sensible values.

  Errors are routed through `java.util.logging` under the loggers
  `com.s_exp.enso.http1.HttpConnection` and `com.s_exp.enso.EnsoServer`. Wire a
  handler / SLF4J bridge in your application to redirect them."
  (^EnsoServer [handler]
   (run-server handler nil))
  (^EnsoServer [handler {:keys [error-handler] :as opts}]
   (let [ring-handler (reify RingHandler
                        (handle [_ request]
                          (->response (handler request))))
         error-h (when error-handler
                   (reify RingErrorHandler
                     (handle [_ request throwable]
                       (some-> (error-handler request throwable) ->response))))
         server (EnsoServer. ring-handler error-h (build-config opts))]
     ;; .start binds sockets + spins executors + can throw (port in use,
     ;; SSL misconfig). Close the half-initialised server so we don't
     ;; leak the acceptor / worker executor / h3 driver threads.
     (try
       (.start server)
       server
       (catch Throwable t
         (try (.close server) (catch Throwable _))
         (throw t))))))

(defn port
  "Actual listening port of `server`."
  [^EnsoServer server]
  (.port server))

(defn stop
  "Stops `server`. In-flight requests complete, open connections close."
  [^EnsoServer server]
  (.close server))

(defn write!
  "Buffers bytes into the pending chunk. String is UTF-8 encoded."
  [^ChunkedWriter w data]
  (cond
    (string? data) (.write w ^String data)
    (bytes? data) (.write w ^bytes data)
    :else (throw (IllegalArgumentException. (str "unsupported chunk type: " (class data))))))

(defn flush!
  "Emits any pending bytes as a chunk and forces them onto the wire."
  [^ChunkedWriter w]
  (.flush w))

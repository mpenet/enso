(ns s-exp.enso
  "Ring adapter backed by a zero-dependency Java core: blocking I/O on virtual
  threads, one virtual thread per connection."
  (:import (com.s_exp.enso ChunkedWriter Config EnsoServer Response
                           RingErrorHandler RingHandler StreamingBody
                           WebSocketListener WebSocketSocket)))

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
         (.write w (byte-array [(byte b)]))))
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
    (when-let [v (:ssl-context opts)] (.sslContext b ^javax.net.ssl.SSLContext v))
    (when (:ssl-need-client-auth opts) (.sslNeedClientAuth b true))
    (when (:ssl-want-client-auth opts) (.sslWantClientAuth b true))
    (when (:http2 opts) (.http2 b true))
    (when-let [v (:http2-max-concurrent-streams opts)] (.http2MaxConcurrentStreams b (int v)))
    (when-let [v (:http2-initial-window-size opts)] (.http2InitialWindowSize b (int v)))
    (when-let [v (:http2-max-frame-size opts)] (.http2MaxFrameSize b (int v)))
    (when-let [v (:http2-max-header-list-size opts)] (.http2MaxHeaderListSize b (int v)))
    (when (:http3 opts) (.http3 b true))
    (when-let [v (:http3-port opts)] (.http3Port b (int v)))
    (when-let [v (:http3-max-idle-timeout opts)] (.http3MaxIdleTimeoutMs b (int v)))
    (when-let [v (:http3-initial-max-data opts)] (.http3InitialMaxData b (long v)))
    (when-let [v (:http3-initial-max-streams-bidi opts)] (.http3InitialMaxStreamsBidi b (int v)))
    (when-let [v (:http3-max-udp-payload-size opts)] (.http3MaxUdpPayloadSize b (int v)))
    (when-let [v (:http3-cert-path opts)] (.http3CertPath b ^String v))
    (when-let [v (:http3-key-path opts)] (.http3KeyPath b ^String v))
    (when (contains? opts :http3-stateless-retry) (.http3StatelessRetry b (boolean (:http3-stateless-retry opts))))
    (when (contains? opts :advertise-alt-svc) (.advertiseAltSvc b (boolean (:advertise-alt-svc opts))))
    (when-let [v (:alt-svc-max-age opts)] (.altSvcMaxAge b (int v)))
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
  `com.s_exp.enso.HttpConnection` and `com.s_exp.enso.EnsoServer`. Wire a
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
     (.start server)
     server)))

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

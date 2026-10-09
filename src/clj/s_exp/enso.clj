;; ABOUTME: Ring adapter over the Java core: run-server and its option table, Ring response
;; ABOUTME: and body coercion, WebSocket listeners, and Ring protocol support when on the classpath.
(ns s-exp.enso
  "Ring adapter backed by a zero-dependency Java core: blocking I/O on virtual
  threads, one virtual thread per connection."
  (:require [clojure.string :as str])
  (:import (com.s_exp.enso EnsoServer)
           (com.s_exp.enso.api ChunkedOutputStream ChunkedWriter Config Config$Builder
                               Config$InvalidOptionException Request Response RingErrorHandler RingHandler
                               ServerEvents StreamingBody WebSocketListener WebSocketSocket
                               WebSocketSocket$SendCallback)
           (com.s_exp.enso.core HttpFields)
           (java.nio ByteBuffer)
           (java.util Locale)
           (java.util.function Predicate Supplier)
           (javax.net.ssl SSLContext)))

(set! *warn-on-reflection* true)

;; Optional support for Ring's protocols (ring.core.protocols,
;; ring.websocket.protocols), used when those libraries are on the
;; classpath. Their vars are held, not their values: extend-protocol
;; replaces a protocol's value (and its fns), so types extended after this
;; namespace loaded are only seen through the var. A var root read per use
;; is one volatile read.

(defn- optional-var
  "The var `sym` of namespace `ns-sym`, loading it; nil when unavailable."
  [ns-sym sym]
  (try
    (require ns-sym)
    (ns-resolve (find-ns ns-sym) sym)
    (catch Throwable _ nil)))

(defonce ^:private streamable-body-var
  (optional-var 'ring.core.protocols 'StreamableResponseBody))
(defonce ^:private write-body-to-stream-var
  (optional-var 'ring.core.protocols 'write-body-to-stream))
(defonce ^:private ws-listener-var (optional-var 'ring.websocket.protocols 'Listener))
(defonce ^:private ws-ping-listener-var (optional-var 'ring.websocket.protocols 'PingListener))
(defonce ^:private ws-on-open-var (optional-var 'ring.websocket.protocols 'on-open))
(defonce ^:private ws-on-message-var (optional-var 'ring.websocket.protocols 'on-message))
(defonce ^:private ws-on-ping-var (optional-var 'ring.websocket.protocols 'on-ping))
(defonce ^:private ws-on-pong-var (optional-var 'ring.websocket.protocols 'on-pong))
(defonce ^:private ws-on-error-var (optional-var 'ring.websocket.protocols 'on-error))
(defonce ^:private ws-on-close-var (optional-var 'ring.websocket.protocols 'on-close))

(defmacro ^:private current
  "The current root value of var `v`."
  [v]
  `(.getRawRoot ~(with-meta v {:tag 'clojure.lang.Var})))

(defn- coerce-body
  "`body` as the Java writer takes it. `async`: the handler is asynchronous,
  so a StreamableResponseBody may write after write-body-to-stream returned
  and ends when it closes the stream (Ring's contract)."
  [response body async]
  (cond
    ;; fast paths recognised by the Java writer directly, zero adapter cost
    (or (nil? body) (string? body) (bytes? body)
        (instance? java.io.InputStream body)
        (instance? java.io.File body))
    body

    ;; enso extension: (fn [ChunkedWriter]) streams SSE / long-poll output.
    ;; Strings written with write! use the response charset, as String
    ;; and seq bodies do.
    (fn? body)
    (let [charset (HttpFields/responseCharset (:headers response))]
      (reify StreamingBody
        (write [_ writer]
          (.charset writer charset)
          (body writer))))

    ;; Ring seq body → stream element-by-element via chunked transfer, mirroring
    ;; Ring's default ISeq StreamableResponseBody impl. Avoids materialising
    ;; large lazy seqs into a single String. Checked before the protocol
    ;; below so common body types never pay for satisfies?.
    (seq? body)
    (let [charset (HttpFields/responseCharset (:headers response))]
      (reify StreamingBody
        (write [_ writer]
          (doseq [chunk body]
            (.write writer (.getBytes ^String (str chunk) charset)))
          (.flush writer))))

    ;; Ring's StreamableResponseBody protocol: any user-extended body type.
    ;; Written via chunked transfer encoding — the body drives its own writes
    ;; onto the wrapped OutputStream, flushed per user's write-body-to-stream
    ;; implementation.
    (and streamable-body-var
         (satisfies? (current streamable-body-var) body))
    (reify StreamingBody
      (write [_ writer]
        (let [out (ChunkedOutputStream. writer)]
          ((current write-body-to-stream-var) body response out)
          (when async
            (.awaitClose out)))))

    :else body))

(defn- map-listener->java
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

(defn- protocol-listener->java
  "Converts a `ring.websocket.protocols/Listener` implementation into a
  WebSocketListener. `on-ping` dispatches to `PingListener` when the
  listener implements it, otherwise answers with a pong."
  ^WebSocketListener [listener]
  ;; PingListener is absent from older ring-websocket-protocols versions.
  (let [ping-listener (and ws-ping-listener-var
                           (satisfies? (current ws-ping-listener-var) listener))]
    (reify WebSocketListener
      (onOpen [_ socket] ((current ws-on-open-var) listener socket))
      (onMessage [_ socket message] ((current ws-on-message-var) listener socket message))
      (onPing [_ socket data]
        (if ping-listener
          ((current ws-on-ping-var) listener socket data)
          (try (.sendPong ^WebSocketSocket socket data) (catch Exception _))))
      (onPong [_ socket data] ((current ws-on-pong-var) listener socket data))
      (onError [_ socket t] ((current ws-on-error-var) listener socket t))
      (onClose [_ socket code reason] ((current ws-on-close-var) listener socket code reason)))))

(defn- ring-listener->java
  "Converts a `:ring.websocket/listener` value: a map of `:on-*` fns, or,
  when ring.websocket.protocols is on the classpath, anything implementing
  its Listener protocol. Records are maps too, so they are checked for the
  protocol before being read as a map of `:on-*` fns."
  ^WebSocketListener [listener]
  (cond
    (and (map? listener) (not (record? listener)))
    (map-listener->java listener)

    (and ws-listener-var (satisfies? (current ws-listener-var) listener))
    (protocol-listener->java listener)

    (map? listener)
    (map-listener->java listener)

    :else
    (throw (IllegalArgumentException.
            (str "unsupported :ring.websocket/listener: " (class listener))))))

(defn- send-message! [^WebSocketSocket socket message]
  (cond
    (instance? CharSequence message) (.sendText socket ^CharSequence message)
    (instance? ByteBuffer message) (.sendBinary socket ^ByteBuffer message)
    :else (throw (IllegalArgumentException.
                  (str "unsupported websocket message type: " (class message))))))

(defn- send-message-async! [^WebSocketSocket socket message ^WebSocketSocket$SendCallback callback]
  (cond
    (instance? CharSequence message) (.sendTextAsync socket ^CharSequence message callback)
    (instance? ByteBuffer message) (.sendBinaryAsync socket ^ByteBuffer message callback)
    :else (throw (IllegalArgumentException.
                  (str "unsupported websocket message type: " (class message))))))

(defn- ->byte-buffer ^ByteBuffer [data]
  (if (bytes? data) (ByteBuffer/wrap ^bytes data) data))

;; Ring's websocket protocols (Ring 1.11+): listeners implementing its
;; Listener protocol are accepted, and the socket handed to listeners
;; implements Socket and AsyncSocket, so ring.websocket/send & co work.
(when ws-listener-var
  (extend WebSocketSocket
    @(optional-var 'ring.websocket.protocols 'Socket)
    {:-open? (fn [^WebSocketSocket socket] (.isOpen socket))
     :-send (fn [socket message] (send-message! socket message))
     :-ping (fn [^WebSocketSocket socket data] (.sendPing socket (->byte-buffer data)))
     :-pong (fn [^WebSocketSocket socket data] (.sendPong socket (->byte-buffer data)))
     :-close (fn [^WebSocketSocket socket code reason] (.close socket (int code) reason))}
    @(optional-var 'ring.websocket.protocols 'AsyncSocket)
    ;; Queued and written in call order by the connection's writer thread;
    ;; succeed runs once the frame is written, fail when it can't be
    ;; (socket closed, send queue over :ws-max-queued-bytes).
    {:-send-async (fn [socket message succeed fail]
                    (send-message-async! socket message
                                         (reify WebSocketSocket$SendCallback
                                           (onSuccess [_] (succeed))
                                           (onFailure [_ t] (fail t)))))}))

(defn- websocket-response? [response]
  (contains? response :ring.websocket/listener))

(defn- status-error [response status]
  (throw (IllegalArgumentException.
          (str "response :status must be an integer, got " (pr-str status)
               (when-not (map? response) (str " (handler returned " (.getName (class response)) ")"))))))

(defn- other-status
  "`status` (the response's :status, not a Long) as an integer: 200 when
  the key is absent, else it must be an integer."
  [response status]
  (cond
    (integer? status) status
    (and (nil? status) (map? response) (not (contains? response :status))) 200
    :else (status-error response status)))

(defn- ->response
  "The handler's Ring response as a Response; `async` as for coerce-body."
  (^Response [response] (->response response false))
  (^Response [response async]
   (when (nil? response)
     (throw (IllegalArgumentException. "handler returned nil response")))
   (if (websocket-response? response)
     (Response. 101
                (:headers response)
                nil
                (ring-listener->java (:ring.websocket/listener response))
                (:ring.websocket/protocol response))
     (let [status (:status response)]
       (Response. (if (instance? Long status)
                    (.intValue ^Long status)
                    (int (other-status response status)))
                  (:headers response)
                  (coerce-body response (:body response) async))))))

;; ---- Options ----------------------------------------------------------------

(defn- invalid-option [k msg v]
  (throw (ex-info (str k " " msg ", got " (pr-str v))
                  {:type ::invalid-option :option k :value v})))

(defn- check-int [k v]
  (if (and (integer? v) (<= Integer/MIN_VALUE v Integer/MAX_VALUE))
    (int v)
    (invalid-option k "must be an integer" v)))

(defn- check-long [k v]
  (if (and (integer? v) (<= Long/MIN_VALUE v Long/MAX_VALUE))
    (long v)
    (invalid-option k "must be an integer" v)))

(defn- check-bool [k v]
  (if (boolean? v) v (invalid-option k "must be a boolean" v)))

(defn- check-string [k v]
  (if (string? v) v (invalid-option k "must be a string" v)))

(defn- check-strings [k v]
  (if (and (sequential? v) (every? string? v))
    (into-array String v)
    (invalid-option k "must be a sequence of strings" v)))

(defn- function?
  "Whether option value `v` is a function: a fn, or a var (holding one),
  so `#'handler` picks up redefinitions. Not any IFn: keywords, maps and
  sets are values here, not functions."
  [v]
  (or (fn? v) (var? v)))

(defn- check-ssl-context [k v]
  (if (instance? SSLContext v) v (invalid-option k "must be a javax.net.ssl.SSLContext" v)))

(defn- check-supplier [k v]
  (cond
    ;; Before Supplier: a var is a Supplier of its root (Clojure 1.12),
    ;; here it is the function to call.
    (function? v) (reify Supplier (get [_] (v)))
    (instance? Supplier v) v
    :else (invalid-option k "must be a function or a java.util.function.Supplier" v)))

(defn- check-fn [k v]
  (if (function? v) v (invalid-option k "must be a function" v)))

(defn- map->server-events
  "ServerEvents calling the fns of `m`; keys are optional. Addresses are
  formatted as the request's `:remote-addr` (IPv6 in RFC 5952 form)."
  ^ServerEvents [m]
  (let [{:keys [connection-opened connection-closed request-completed protocol-error]} m]
    (reify ServerEvents
      (connectionOpened [_ protocol remote]
        (when connection-opened
          (connection-opened protocol (Request/formatAddress remote))))
      (connectionClosed [_ protocol remote nanos]
        (when connection-closed
          (connection-closed protocol (Request/formatAddress remote) nanos)))
      (requestCompleted [_ protocol method status request-bytes response-bytes nanos]
        (when request-completed
          (request-completed protocol method status request-bytes response-bytes nanos)))
      (protocolError [_ protocol kind]
        (when protocol-error
          (protocol-error protocol kind))))))

(defn- check-origins [k v]
  (cond
    (instance? Predicate v) v
    (function? v) (reify Predicate (test [_ origin] (boolean (v origin))))
    (and (coll? v) (not (map? v)) (every? string? v))
    (let [allowed (into #{} (map #(.toLowerCase ^String % Locale/ROOT)) v)]
      (if (contains? allowed "*")
        (reify Predicate (test [_ _] true))
        (reify Predicate
          (test [_ origin] (contains? allowed (.toLowerCase ^String origin Locale/ROOT))))))
    :else (invalid-option k "must be a collection of origin strings or a function" v)))

(def ^:private server-event-keys
  [:connection-opened :connection-closed :request-completed :protocol-error])

(declare suggest-among)

(defn- check-server-events [k v]
  (cond
    (instance? ServerEvents v) v
    (map? v) (do (doseq [[ek ev] v]
                   (when-not (some #{ek} server-event-keys)
                     (let [suggestion (suggest-among ek server-event-keys)]
                       (throw (ex-info (str "Unknown " k " key " ek
                                            (when suggestion (str ", did you mean " suggestion "?")))
                                       {:type ::invalid-option :option k :value v :key ek
                                        :suggestion suggestion}))))
                   (when-not (or (nil? ev) (function? ev))
                     (invalid-option k (str ek " must be a function") v)))
                 (map->server-events v))
    :else (invalid-option k "must be a map of event fns or a com.s_exp.enso.api.ServerEvents" v)))

(def ^:private options
  "Every run-server option, in documentation order. `:check` validates and
  coerces a value, `:set` hands it to the Config builder, `:field` names
  the Config field holding the default (checked against `:default` by the
  tests). Rendered into the run-server docstring and mirrored by
  doc/options.md."
  [;; Network
   {:key :port :group "Network" :default 8080 :field "port" :check check-int
    :set (fn [^Config$Builder b v] (.port b (int v)))
    :doc "listen port, 0 picks an ephemeral port"}
   {:key :host :group "Network" :default "0.0.0.0" :field "host" :check check-string
    :set (fn [^Config$Builder b v] (.host b ^String v))
    :doc "bind address"}
   {:key :backlog :group "Network" :default 1024 :field "backlog" :check check-int
    :set (fn [^Config$Builder b v] (.backlog b (int v)))
    :doc "accept queue length"}
   {:key :max-connections :group "Network" :default 10000 :field "maxConnections" :check check-int
    :set (fn [^Config$Builder b v] (.maxConnections b (int v)))
    :doc "open connections server-wide, TCP and QUIC together, 0 = unlimited. TCP connections over the limit are closed at accept, QUIC Initials dropped."}
   {:key :max-connections-per-ip :group "Network" :default 0 :field "maxConnectionsPerIp" :check check-int
    :set (fn [^Config$Builder b v] (.maxConnectionsPerIp b (int v)))
    :doc "open connections per client address, 0 = unlimited. Leave off behind a proxy or NAT, where clients share an address."}

   ;; Timeouts
   {:key :handshake-timeout :group "Timeouts" :default 10000 :field "handshakeTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.handshakeTimeoutMillis b (int v)))
    :doc "ms to complete the TLS handshake (plus the HTTP/2 preface and first SETTINGS, or the QUIC handshake), wall clock."}
   {:key :header-timeout :group "Timeouts" :default 10000 :field "headerTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.headerTimeoutMillis b (int v)))
    :doc "ms to receive a complete request head from its first byte, wall clock (slowloris protection). Answered with 408."}
   {:key :read-timeout :group "Timeouts" :default 30000 :field "readTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.readTimeoutMillis b (int v)))
    :doc "longest ms without progress reading a request body; the read fails (408 unless the handler catches it). Also bounds head reads when `:header-timeout` is 0, and is the wall-clock time a WebSocket message may take from its first frame to its last (CLOSE 1008)."}
   {:key :min-data-rate-bytes :group "Timeouts" :default 240 :field "minDataRateBytes" :check check-int
    :set (fn [^Config$Builder b v] (.minDataRateBytes b (int v)))
    :doc "least request body bytes per second while a handler waits for them, once `:min-data-rate-grace` of waiting is spent (Kestrel's default), 0 = off. Below it the read fails (408, protocol error \"min-data-rate\"): a body trickled just inside `:read-timeout` can't hold a request forever. Time the handler isn't reading doesn't count."}
   {:key :min-data-rate-grace :group "Timeouts" :default 5000 :field "minDataRateGraceMillis" :check check-int
    :set (fn [^Config$Builder b v] (.minDataRateGraceMillis b (int v)))
    :doc "ms of waiting for request body bytes allowed before `:min-data-rate-bytes` applies."}
   {:key :write-timeout :group "Timeouts" :default 30000 :field "writeTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.writeTimeoutMillis b (int v)))
    :doc "longest ms without write progress (a peer that stopped reading); the connection is force-closed."}
   {:key :idle-timeout :group "Timeouts" :default 75000 :field "idleTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.idleTimeoutMillis b (int v)))
    :doc "ms a connection may sit with no request in progress: HTTP/1.1 between requests (and before the first), HTTP/2 and HTTP/3 with no open stream, a WebSocket with no frame from the client (closing handshake with 1001)."}
   {:key :handler-timeout :group "Timeouts" :default 0 :field "handlerTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.handlerTimeoutMillis b (int v)))
    :doc "ms a handler may run, 0 = off. On expiry the client gets 503 (nothing was sent yet) and the handler thread is interrupted."}
   {:key :shutdown-timeout :group "Timeouts" :default 10000 :field "shutdownTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.shutdownTimeoutMillis b (int v)))
    :doc "ms `stop` waits for in-flight requests across all connections before force-closing them."}

   ;; Limits
   {:key :max-header-bytes :group "Limits" :default 65536 :field "maxHeaderBytes" :check check-int
    :set (fn [^Config$Builder b v] (.maxHeaderBytes b (int v)))
    :doc "request head size cap on every protocol, 431 above: the HTTP/1.1 head (and chunked trailers), the decoded HTTP/2 header list (advertised as SETTINGS_MAX_HEADER_LIST_SIZE), the decoded HTTP/3 field section (SETTINGS_MAX_FIELD_SECTION_SIZE). Over 4x this (at least 64 KiB) an HTTP/2 connection ends with GOAWAY(ENHANCE_YOUR_CALM), an HTTP/3 stream is reset."}
   {:key :max-header-fields :group "Limits" :default 100 :field "maxHeaderFields" :check check-int
    :set (fn [^Config$Builder b v] (.maxHeaderFields b (int v)))
    :doc "request header fields per head on every protocol, 431 above (Apache's LimitRequestFields and Tomcat's maxHeaderCount default)."}
   {:key :max-request-body-bytes :group "Limits" :default 10485760 :field "maxRequestBodyBytes" :check check-long
    :set (fn [^Config$Builder b v] (.maxRequestBodyBytes b (long v)))
    :doc "request body cap on every protocol, 0 = none. A larger Content-Length gets 413 upfront; a body without one fails mid-stream. WebSocket messages have their own cap, `:ws-max-message-bytes`."}
   {:key :max-keep-alive-requests :group "Limits" :default 1000 :field "maxKeepAliveRequests" :check check-int
    :set (fn [^Config$Builder b v] (.maxKeepAliveRequests b (int v)))
    :doc "requests per HTTP/1.1 connection, 0 = unlimited. The last response carries Connection: close."}
   {:key :max-buffered-bytes :group "Limits" :default 0 :field "maxBufferedBytes" :check check-long
    :set (fn [^Config$Builder b v] (.maxBufferedBytes b (long v)))
    :doc "bytes the server buffers or promises (flow-control credit) for peers, server-wide: unread request bodies (HTTP/2, HTTP/3) and the HTTP/2 credit granted for them, streamed HTTP/2 response bytes, queued WebSocket sends and incoming WebSocket messages past 64 KiB. 0 = a quarter of the maximum heap. Credit is paid for before it is granted. From three quarters of it connections over their fair share are throttled, at the limit all are: HTTP/2 grants connection credit only up to the initial 65535 octets, HTTP/3 stops reading request streams until bodies are read and a WebSocket stops reading a large message until there is room (backpressure); WebSocket asynchronous sends fail at once."}

   ;; TCP
   {:key :so-nodelay :group "TCP" :default true :field "soNodelay" :check check-bool
    :set (fn [^Config$Builder b v] (.soNodelay b (boolean v)))
    :doc "TCP_NODELAY on accepted sockets."}
   {:key :so-reuse-addr :group "TCP" :default true :field "soReuseAddr" :check check-bool
    :set (fn [^Config$Builder b v] (.soReuseAddr b (boolean v)))
    :doc "SO_REUSEADDR on the listening socket."}
   {:key :so-linger :group "TCP" :default -1 :field "soLinger" :check check-int
    :set (fn [^Config$Builder b v] (.soLinger b (int v)))
    :doc "SO_LINGER on accepted sockets, in seconds as the socket option, -1 = off."}
   {:key :so-rcv-buf-bytes :group "TCP" :default 0 :field "soRcvBufBytes" :check check-int
    :set (fn [^Config$Builder b v] (.soRcvBufBytes b (int v)))
    :doc "SO_RCVBUF, set on the listening socket before bind so accepted sockets inherit it; 0 = OS default."}
   {:key :so-snd-buf-bytes :group "TCP" :default 0 :field "soSndBufBytes" :check check-int
    :set (fn [^Config$Builder b v] (.soSndBufBytes b (int v)))
    :doc "SO_SNDBUF on accepted sockets, 0 = OS default."}

   ;; TLS
   {:key :ssl-context :group "TLS" :default nil :check check-ssl-context
    :set (fn [^Config$Builder b v] (.sslContext b ^SSLContext v))
    :doc "`javax.net.ssl.SSLContext`; when set the TCP listener speaks TLS. File bodies then go through user space (no zero-copy)."}
   {:key :ssl-context-provider :group "TLS" :default nil :check check-supplier
    :set (fn [^Config$Builder b v] (.sslContextProvider b ^Supplier v))
    :doc "fn (or `java.util.function.Supplier`) returning an `SSLContext`, called at startup and per accepted connection so rotated certificates apply to new connections; return a cached context (one built per call costs that per connection and loses session resumption). Exclusive with `:ssl-context`."}
   {:key :ssl-need-client-auth :group "TLS" :default false :field "sslNeedClientAuth" :check check-bool
    :set (fn [^Config$Builder b v] (.sslNeedClientAuth b (boolean v)))
    :doc "require a valid client certificate."}
   {:key :ssl-want-client-auth :group "TLS" :default false :field "sslWantClientAuth" :check check-bool
    :set (fn [^Config$Builder b v] (.sslWantClientAuth b (boolean v)))
    :doc "request a client certificate without requiring one."}
   {:key :ssl-alpn-protocols :group "TLS" :default nil :check check-strings
    :set (fn [^Config$Builder b v] (.sslAlpnProtocols b ^"[Ljava.lang.String;" v))
    :doc "ALPN protocol ids offered; default [\"h2\" \"http/1.1\"] with `:http2`, else [\"http/1.1\"]."}
   {:key :ssl-cipher-suites :group "TLS" :default nil :check check-strings
    :set (fn [^Config$Builder b v] (.sslCipherSuites b ^"[Ljava.lang.String;" v))
    :doc "enabled cipher suites, nil = JVM default."}
   {:key :ssl-protocols :group "TLS" :default nil :check check-strings
    :set (fn [^Config$Builder b v] (.sslProtocols b ^"[Ljava.lang.String;" v))
    :doc "enabled TLS protocol versions, nil = JVM default."}
   {:key :ssl-session-cache-size :group "TLS" :default 0 :field "sslSessionCacheSize" :check check-int
    :set (fn [^Config$Builder b v] (.sslSessionCacheSize b (int v)))
    :doc "server TLS session cache entries, set on every context the server uses; 0 = JVM default."}

   ;; HTTP/2
   {:key :http2 :group "HTTP/2" :default false :field "http2" :check check-bool
    :set (fn [^Config$Builder b v] (.http2 b (boolean v)))
    :doc "serve \"h2\" over TLS + ALPN (needs `:ssl-context`; cleartext HTTP/2 is `:http2c`)."}
   {:key :http2c :group "HTTP/2" :default false :field "http2c" :check check-bool
    :set (fn [^Config$Builder b v] (.http2c b (boolean v)))
    :doc "serve cleartext HTTP/2 with prior knowledge (RFC 9113 §3.3) on a plain listener next to HTTP/1.1: a connection that opens with the HTTP/2 preface is HTTP/2. No `Upgrade: h2c` (deprecated by RFC 9113). Not with `:ssl-context` (use `:http2`)."}
   {:key :http2-max-concurrent-streams :group "HTTP/2" :default 100 :field "http2MaxConcurrentStreams" :check check-int
    :set (fn [^Config$Builder b v] (.http2MaxConcurrentStreams b (int v)))
    :doc "SETTINGS_MAX_CONCURRENT_STREAMS."}
   {:key :http2-initial-window-bytes :group "HTTP/2" :default 262144 :field "http2InitialWindowBytes" :check check-int
    :set (fn [^Config$Builder b v] (.http2InitialWindowBytes b (int v)))
    :doc "per-stream receive window, [65535, 2^31-1]; the connection window grows to 4x this (1 MiB by default) once request body bytes arrive, as far as `:max-buffered-bytes` pays for it. Credit returns as handlers read. Raise it for large uploads over long round trips."}
   {:key :http2-max-frame-bytes :group "HTTP/2" :default 16384 :field "http2MaxFrameBytes" :check check-int
    :set (fn [^Config$Builder b v] (.http2MaxFrameBytes b (int v)))
    :doc "SETTINGS_MAX_FRAME_SIZE, [16384, 16777215]."}
   {:key :http2-stream-reset-limit :group "HTTP/2" :default 400 :field "http2StreamResetLimit" :check check-int
    :set (fn [^Config$Builder b v] (.http2StreamResetLimit b (int v)))
    :doc "client RST_STREAMs allowed per connection, refilling at that many per 30 s; above it ENHANCE_YOUR_CALM (CVE-2023-44487). 0 = off."}
   {:key :http2-continuation-limit :group "HTTP/2" :default 64 :field "http2ContinuationLimit" :check check-int
    :set (fn [^Config$Builder b v] (.http2ContinuationLimit b (int v)))
    :doc "CONTINUATION frames per header block."}

   ;; HTTP/3
   {:key :http3 :group "HTTP/3 (QUIC via quiche)" :default false :field "http3" :check check-bool
    :set (fn [^Config$Builder b v] (.http3 b (boolean v)))
    :doc "serve HTTP/3 over UDP; needs `:http3-cert-path` and `:http3-key-path`."}
   {:key :http3-port :group "HTTP/3 (QUIC via quiche)" :default 0 :field "http3Port" :check check-int
    :set (fn [^Config$Builder b v] (.http3Port b (int v)))
    :doc "UDP port, 0 = the `:port` number. With `:port` 0 set this (or `:advertise-alt-svc` false): Alt-Svc must name a fixed port."}
   {:key :http3-cert-path :group "HTTP/3 (QUIC via quiche)" :default nil :field "http3CertPath" :check check-string
    :set (fn [^Config$Builder b v] (.http3CertPath b ^String v))
    :doc "PEM certificate chain (quiche reads it from disk)."}
   {:key :http3-key-path :group "HTTP/3 (QUIC via quiche)" :default nil :field "http3KeyPath" :check check-string
    :set (fn [^Config$Builder b v] (.http3KeyPath b ^String v))
    :doc "PEM private key."}
   {:key :http3-initial-max-data-bytes :group "HTTP/3 (QUIC via quiche)" :default 1048576 :field "http3InitialMaxDataBytes" :check check-long
    :set (fn [^Config$Builder b v] (.http3InitialMaxDataBytes b (long v)))
    :doc "connection flow-control window, a hard bound (no autotuning past it); also bounds request-body bytes buffered per connection."}
   {:key :http3-max-native-bytes :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3MaxNativeBytes" :check check-long
    :set (fn [^Config$Builder b v] (.http3MaxNativeBytes b (long v)))
    :doc "receive credit quiche may hold natively, a connection window per connection: new connections are refused past it; -1 = the `:max-buffered-bytes` limit (at least one window), 0 = unlimited."}
   {:key :http3-initial-max-streams-bidi :group "HTTP/3 (QUIC via quiche)" :default 100 :field "http3InitialMaxStreamsBidi" :check check-int
    :set (fn [^Config$Builder b v] (.http3InitialMaxStreamsBidi b (int v)))
    :doc "concurrent request streams per connection; twice this many live handlers make new requests H3_REQUEST_REJECTED."}
   {:key :http3-initial-max-streams-uni :group "HTTP/3 (QUIC via quiche)" :default 8 :field "http3InitialMaxStreamsUni" :check check-int
    :set (fn [^Config$Builder b v] (.http3InitialMaxStreamsUni b (int v)))
    :doc "peer unidirectional stream credit, at least 3 (control + QPACK encoder/decoder)."}
   {:key :http3-max-udp-payload-bytes :group "HTTP/3 (QUIC via quiche)" :default 1350 :field "http3MaxUdpPayloadBytes" :check check-int
    :set (fn [^Config$Builder b v] (.http3MaxUdpPayloadBytes b (int v)))
    :doc "max UDP payload, [1200, 65527]; the default is MTU-safe."}
   {:key :http3-stateless-retry :group "HTTP/3 (QUIC via quiche)" :default false :field "http3StatelessRetry" :check check-bool
    :set (fn [^Config$Builder b v] (.http3StatelessRetry b (boolean v)))
    :doc "make clients prove their address before any state is allocated (RFC 9000 §8.1.2); for floods."}
   {:key :http3-cert-reload-interval :group "HTTP/3 (QUIC via quiche)" :default 10000 :field "http3CertReloadIntervalMillis" :check check-int
    :set (fn [^Config$Builder b v] (.http3CertReloadIntervalMillis b (int v)))
    :doc "milliseconds between checks of :http3-cert-path / :http3-key-path for changes; a changed pair is loaded for new connections, existing ones keep theirs; 0 = off."}
   {:key :http3-retry-threshold :group "HTTP/3 (QUIC via quiche)" :default 256 :field "http3RetryThreshold" :check check-int
    :set (fn [^Config$Builder b v] (.http3RetryThreshold b (int v)))
    :doc "handshaking connections from which a client Initial without a valid token gets a stateless Retry."}
   {:key :http3-max-half-open :group "HTTP/3 (QUIC via quiche)" :default 1024 :field "http3MaxHalfOpen" :check check-int
    :set (fn [^Config$Builder b v] (.http3MaxHalfOpen b (int v)))
    :doc "handshaking connections above which new Initials are dropped; 0 = unlimited."}
   {:key :http3-stream-reset-limit :group "HTTP/3 (QUIC via quiche)" :default 400 :field "http3StreamResetLimit" :check check-int
    :set (fn [^Config$Builder b v] (.http3StreamResetLimit b (int v)))
    :doc "peer stream resets allowed per connection, refilling at that many per 30 s (rapid reset); 0 = off."}
   {:key :http3-event-loops :group "HTTP/3 (QUIC via quiche)" :default 0 :field "http3EventLoops" :check check-int
    :set (fn [^Config$Builder b v] (.http3EventLoops b (int v)))
    :doc "event loop threads owning QUIC connections, [0, 64]; 0 = one per core on Linux, 1 elsewhere."}
   {:key :http3-so-rcv-buf-bytes :group "HTTP/3 (QUIC via quiche)" :default 4194304 :field "http3SoRcvBufBytes" :check check-int
    :set (fn [^Config$Builder b v] (.http3SoRcvBufBytes b (int v)))
    :doc "UDP socket receive buffer requested (best effort); 0 = OS default."}
   {:key :http3-so-snd-buf-bytes :group "HTTP/3 (QUIC via quiche)" :default 4194304 :field "http3SoSndBufBytes" :check check-int
    :set (fn [^Config$Builder b v] (.http3SoSndBufBytes b (int v)))
    :doc "UDP socket send buffer requested (best effort); 0 = OS default."}
   {:key :http3-initial-max-stream-data-bidi-local-bytes :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3InitialMaxStreamDataBidiLocalBytes" :check check-long
    :set (fn [^Config$Builder b v] (.http3InitialMaxStreamDataBidiLocalBytes b (long v)))
    :doc "per-stream window, -1 = a quarter of `:http3-initial-max-data-bytes` (256 KiB by default), so one unread stream can't stall the connection."}
   {:key :http3-initial-max-stream-data-bidi-remote-bytes :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3InitialMaxStreamDataBidiRemoteBytes" :check check-long
    :set (fn [^Config$Builder b v] (.http3InitialMaxStreamDataBidiRemoteBytes b (long v)))
    :doc "same, for peer-initiated streams."}
   {:key :http3-initial-max-stream-data-uni-bytes :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3InitialMaxStreamDataUniBytes" :check check-long
    :set (fn [^Config$Builder b v] (.http3InitialMaxStreamDataUniBytes b (long v)))
    :doc "same, for unidirectional streams."}
   {:key :http3-ack-delay-exponent :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3AckDelayExponent" :check check-int
    :set (fn [^Config$Builder b v] (.http3AckDelayExponent b (int v)))
    :doc "RFC 9000 ack_delay_exponent, [0, 20]; -1 = quiche default."}
   {:key :http3-max-ack-delay :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3MaxAckDelay" :check check-int
    :set (fn [^Config$Builder b v] (.http3MaxAckDelay b (int v)))
    :doc "RFC 9000 max_ack_delay in ms as the transport parameter, [0, 16383]; -1 = quiche default."}
   {:key :http3-active-connection-id-limit :group "HTTP/3 (QUIC via quiche)" :default -1 :field "http3ActiveConnectionIdLimit" :check check-int
    :set (fn [^Config$Builder b v] (.http3ActiveConnectionIdLimit b (int v)))
    :doc "RFC 9000 active_connection_id_limit, >= 2; -1 = quiche default."}
   {:key :advertise-alt-svc :group "HTTP/3 (QUIC via quiche)" :default nil :check check-bool
    :set (fn [^Config$Builder b v] (.advertiseAltSvc b (boolean v)))
    :doc "send `Alt-Svc` on HTTP/1.1 and HTTP/2 responses; nil = whenever `:http3` is on. True needs `:http3`."}
   {:key :alt-svc-max-age :group "HTTP/3 (QUIC via quiche)" :default 86400 :field "altSvcMaxAge" :check check-int
    :set (fn [^Config$Builder b v] (.altSvcMaxAge b (int v)))
    :doc "`ma` of the `Alt-Svc` header, in seconds as the header parameter."}

   ;; WebSocket
   {:key :ws-max-message-bytes :group "WebSocket" :default 1048576 :field "wsMaxMessageBytes" :check check-int
    :set (fn [^Config$Builder b v] (.wsMaxMessageBytes b (int v)))
    :doc "largest message once reassembled and decompressed; a larger one closes the connection with 1009. Messages are buffered whole."}
   {:key :ws-max-queued-bytes :group "WebSocket" :default 1048576 :field "wsMaxQueuedBytes" :check check-int
    :set (fn [^Config$Builder b v] (.wsMaxQueuedBytes b (int v)))
    :doc "payload bytes asynchronous sends may queue per connection (plus 64 per frame), 0 = unlimited. A send over it fails at once (its fail callback runs); one message larger than the limit is accepted when nothing is queued."}
   {:key :ws-close-timeout :group "WebSocket" :default 5000 :field "wsCloseTimeoutMillis" :check check-int
    :set (fn [^Config$Builder b v] (.wsCloseTimeoutMillis b (int v)))
    :doc "ms a closing handshake the server started (close, failure, idle timeout, shutdown) waits for the client's CLOSE before dropping TCP; at least 1."}
   {:key :ws-compression :group "WebSocket" :default false :field "wsCompression" :check check-bool
    :set (fn [^Config$Builder b v] (.wsCompression b (boolean v)))
    :doc "negotiate permessage-deflate (RFC 7692) when the client offers it. A compressing connection holds a Deflater and an Inflater (about 300 KiB of native memory); without the server's context takeover its Deflater is borrowed from a pool per message."}
   {:key :ws-ping-interval :group "WebSocket" :default 0 :field "wsPingIntervalMillis" :check check-int
    :set (fn [^Config$Builder b v] (.wsPingIntervalMillis b (int v)))
    :doc "ms without a frame from the client after which the server sends a ping (and again at that interval), 0 = never. The client's pongs count as frames, so a live but silent client outlasts `:idle-timeout`; less than `:idle-timeout`."}
   {:key :ws-allowed-origins :group "WebSocket" :default nil :check check-origins
    :set (fn [^Config$Builder b v] (.wsAllowedOrigins b ^Predicate v))
    :doc "origins allowed to open a WebSocket (cross-site WebSocket hijacking protection): a collection of origins such as \"https://app.example.com\" (\"*\" for any) or a fn of the `Origin` value. nil = same origin: the `Origin` host must equal the `Host` header. A handshake without `Origin` (not from a browser) is allowed; a refused one gets 403."}

   ;; Handler and observability
   {:key :async :group "Handler and observability" :default false :check check-bool
    :doc "`handler` is a Ring asynchronous handler, `(fn [request respond raise])`. It runs on the request's virtual thread, which waits until `respond` or `raise` is called (from any thread), without bound unless `:handler-timeout` is set; `raise` goes to `:error-handler`. Only the first call counts. A StreamableResponseBody may write after returning and ends when it closes its stream."}
   {:key :error-handler :group "Handler and observability" :default nil :check check-fn
    :doc "`(fn [request throwable])` returning a Ring response, when the handler throws or returns nil, on every protocol. If it throws or returns nil too, a plain 500 is sent."}
   {:key :server-header :group "Handler and observability" :default nil :field "serverHeader" :check check-string
    :set (fn [^Config$Builder b v] (.serverHeader b ^String v))
    :doc "`Server` response header value; nil or empty omits it. A handler-supplied `Server` wins."}
   {:key :server-events :group "Handler and observability" :default nil :check check-server-events
    :set (fn [^Config$Builder b v] (.serverEvents b ^ServerEvents v))
    :doc "map of fns `{:connection-opened (fn [protocol remote-addr]) :connection-closed (fn [protocol remote-addr nanos]) :request-completed (fn [protocol method status request-bytes response-bytes nanos]) :protocol-error (fn [protocol kind])}`, or a `com.s_exp.enso.api.ServerEvents`. `remote-addr` is formatted as `:remote-addr`. `method` is nil for a head refused before it was parsed. Protocols: \"http/1.1\", \"h2\", \"h2c\", \"h3\"; \"websocket\" for an upgraded connection's open / close; \"tcp\" (connection refused at accept) and \"tls\" (handshake failures) for protocol errors. Delivered in order from one dedicated thread, never from a server thread; past 8192 queued events (a listener that fell behind) new ones are dropped and counted (`EnsoServer.droppedEvents`, a log warning, a JFR event). Exceptions are logged and ignored. No cost when absent."}])

(def ^:private options-by-key
  (into {} (map (juxt :key identity)) options))

(defn- edit-distance
  "Levenshtein distance between strings `a` and `b`."
  [^String a ^String b]
  (let [n (.length b)]
    (peek
     (reduce (fn [prev i]
               (reduce (fn [row j]
                         (let [same (= (.charAt a (int i)) (.charAt b (int j)))]
                           (conj row (min (inc (peek row))
                                          (inc (nth prev (inc j)))
                                          (+ (nth prev j) (if same 0 1))))))
                       [(inc i)]
                       (range n)))
             (vec (range (inc n)))
             (range (.length a))))))

(defn- suggest-among
  "The key of `candidates` closest to unknown key `k`, when close enough to
  be a typo."
  [k candidates]
  (when (or (keyword? k) (string? k))
    (let [s (name k)
          [d best] (first (sort-by first (map (fn [c] [(edit-distance s (name c)) c]) candidates)))]
      (when (<= d (max 2 (quot (count s) 4)))
        best))))

(defn- suggest
  "The option key closest to unknown key `k`, when close enough to be a typo."
  [k]
  (suggest-among k (map :key options)))

(defn- check-options!
  "Validates `opts` against the option table: unknown keys and wrong types
  throw ex-info naming the option."
  [opts]
  (doseq [[k v] opts]
    (if-let [{:keys [check]} (options-by-key k)]
      (when (some? v) (check k v))
      (let [suggestion (suggest k)]
        (throw (ex-info (str "Unknown option " k
                             (when suggestion (str ", did you mean " suggestion "?")))
                        {:type ::unknown-option :option k :suggestion suggestion}))))))

(defn- build-config ^Config [opts]
  (check-options! opts)
  (let [b (Config/builder)]
    (doseq [{:keys [key check set]} options
            :let [v (get opts key)]
            :when (and set (some? v))]
      (set b (check key v)))
    (try
      (.build b)
      (catch Config$InvalidOptionException e
        (throw (ex-info (ex-message e)
                        {:type ::invalid-option :option (keyword (.option e)) :value (.value e)}
                        e))))))

(defn- render-default [{:keys [default]}]
  (cond
    (nil? default) "none"
    (string? default) (pr-str default)
    :else (str default)))

(defn- wrap-words
  "`text` as lines of at most `width` chars, every line after the first
  indented by `indent`."
  [^String text width indent]
  (loop [words (str/split text #" ") line "" lines []]
    (if-let [w (first words)]
      (if (and (seq line) (> (+ (count line) 1 (count w)) width))
        (recur (rest words) (str indent w) (conj lines line))
        (recur (rest words) (if (seq line) (str line " " w) w) lines))
      (str/join "\n" (conj lines line)))))

(defn- options-doc
  "The options part of the run-server docstring, from the option table."
  []
  (apply str
         (for [opts (partition-by :group options)]
           (str "\n  " (:group (first opts)) ":\n"
                (apply str
                       (for [o opts]
                         (str (wrap-words (str "  - `" (:key o) "` (" (render-default o) ") - " (:doc o))
                                          78 "    ")
                              "\n")))))))

(defn- call-async
  "Calls the Ring asynchronous `handler` and waits, on the request's
  virtual thread, for its response or the exception it raised."
  [handler request]
  (let [result (promise)]
    (handler request #(deliver result %) #(deliver result %))
    (let [v @result]
      (if (instance? Throwable v)
        (throw ^Throwable v)
        v))))

(defn run-server
  "Starts an HTTP server calling `handler` with Ring request maps.
  Returns the server, stop it with [[stop]]. Unknown options and invalid
  values throw ex-info naming the option.

  `handler` is `(fn [request] response)`, or with `:async` true a Ring
  asynchronous handler `(fn [request respond raise])`. It runs on a
  virtual thread per request (per connection on HTTP/1.1).

  Response `:body`: nil, String, byte array, InputStream, File, a seq
  (each element `str`'d), `(fn [ChunkedWriter])` streaming with
  [[write!]] / [[flush!]] (an enso extension), or anything satisfying
  `ring.core.protocols/StreamableResponseBody` when on the classpath.
  `:status` defaults to 200 when absent.

  WebSocket (HTTP/1.1): answer an upgrade request with
  `{:ring.websocket/listener l}`, `l` a map of `:on-open` `:on-message`
  `:on-ping` `:on-pong` `:on-error` `:on-close` fns or a
  `ring.websocket.protocols/Listener`. See doc/handlers.md.
  "
  (^EnsoServer [handler]
   (run-server handler nil))
  (^EnsoServer [handler {:keys [error-handler async] :as opts}]
   (let [config (build-config opts)
         ring-handler (if async
                        (reify RingHandler
                          (handle [_ request]
                            (->response (call-async handler request) true)))
                        (reify RingHandler
                          (handle [_ request]
                            (->response (handler request)))))
         error-h (when error-handler
                   (reify RingErrorHandler
                     (handle [_ request throwable]
                       (some-> (error-handler request throwable) ->response))))
         server (EnsoServer. ring-handler error-h config)]
     ;; start releases whatever it bound when it fails (port in use, TLS
     ;; or HTTP/3 setup).
     (.start server)
     server)))

(alter-meta! #'run-server update :doc str
             "\n  Durations are milliseconds, 0 disables a timeout; sizes are bytes.\n"
             (options-doc)
             "\n  Errors are logged through `java.util.logging` under `com.s_exp.enso.*`:\n"
             "  client-caused failures at FINE, server-side faults at WARNING (rate-limited).")

(defn port
  "Actual listening port of `server`."
  [^EnsoServer server]
  (.port server))

(defn stop
  "Stops `server`. In-flight requests complete, open connections close."
  [^EnsoServer server]
  (.close server))

(defn write!
  "Buffers `data` (a String or byte array) into the pending chunk of a
  streamed (fn) body. Strings are encoded with the response's charset (the
  `charset` of its Content-Type), UTF-8 when it has none."
  [^ChunkedWriter w data]
  (cond
    (string? data) (.write w ^String data)
    (bytes? data) (.write w ^bytes data)
    :else (throw (IllegalArgumentException. (str "unsupported chunk type: " (class data))))))

(defn flush!
  "Emits any pending bytes as a chunk and forces them onto the wire."
  [^ChunkedWriter w]
  (.flush w))

;; ABOUTME: Tests for server option validation: per-option type and range checks, contradictions,
;; ABOUTME: defaults, error messages naming the option keyword, and the sslContextProvider rules.
(ns s-exp.enso-config-test
  "Config builder validation: keyword-phrased errors, contradictions
  between options, defaults, and the sslContextProvider rules."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (com.s_exp.enso.api Config)
           (java.util.concurrent.atomic AtomicReference)
           (java.util.function Supplier)
           (javax.net.ssl SSLContext)))

;; ---- serverHeader CR/LF/NUL rejection ------------------------------------

(deftest server-header-plain-accepted
  (let [b (Config/builder)]
    (.serverHeader b "enso/1.0")
    (is (instance? Config (.build b)))))

(deftest server-header-with-cr-rejected
  (let [b (Config/builder)]
    (.serverHeader b "enso\rInjected: 1")
    (is (thrown-with-msg? IllegalArgumentException #":server-header must be a valid field value"
                          (.build b)))))

(deftest server-header-with-lf-rejected
  (let [b (Config/builder)]
    (.serverHeader b "enso\nInjected: 1")
    (is (thrown-with-msg? IllegalArgumentException #":server-header must be a valid field value"
                          (.build b)))))

(deftest server-header-with-nul-rejected
  (let [b (Config/builder)]
    (.serverHeader b "enso\u0000")
    (is (thrown-with-msg? IllegalArgumentException #":server-header must be a valid field value"
                          (.build b)))))

(deftest server-header-empty-accepted
  (let [b (Config/builder)]
    (.serverHeader b "")
    (is (instance? Config (.build b)))))

(deftest server-header-nil-accepted
  (let [b (Config/builder)]
    ;; Not calling serverHeader leaves it nil — build succeeds.
    (is (instance? Config (.build b)))))

;; ---- sslContext + sslContextProvider mutex -------------------------------

(defn- default-context ^SSLContext []
  (SSLContext/getDefault))

(deftest ssl-context-and-provider-mutually-exclusive
  (let [b (Config/builder)]
    (.sslContext b (default-context))
    (.sslContextProvider b (reify Supplier (get [_] (default-context))))
    (is (thrown-with-msg? IllegalArgumentException #"mutually exclusive"
                          (.build b)))))

(deftest ssl-context-provider-seeds-static-context
  (let [called (atom 0)
        b (Config/builder)]
    (.sslContextProvider b (reify Supplier
                             (get [_]
                               (swap! called inc)
                               (default-context))))
    (let [cfg (.build b)]
      (is (some? (.-sslContext cfg))
          "sslContext field mirrors provider.get() at build time")
      (is (pos? @called)))))

(deftest ssl-context-provider-returning-nil-rejected
  (let [b (Config/builder)]
    (.sslContextProvider b (reify Supplier (get [_] nil)))
    (is (thrown-with-msg? IllegalArgumentException #"returned null"
                          (.build b)))))

(deftest ssl-context-provider-atomic-swap-usage-pattern
  ;; Documented pattern: back the provider with an AtomicReference so
  ;; rotation is atomic and non-blocking.
  (let [ar (AtomicReference. (default-context))
        b (Config/builder)]
    (.sslContextProvider b (reify Supplier (get [_] (.get ar))))
    (let [cfg (.build b)]
      (is (some? (.get ^Supplier (.-sslContextProvider cfg))))
      ;; Swap → subsequent provider.get returns the new context.
      (.set ar (default-context))
      (is (some? (.get ^Supplier (.-sslContextProvider cfg)))))))

;; ---- Other validation regressions ----------------------------------------

(deftest host-must-be-non-empty
  (let [b (Config/builder)]
    (.host b "")
    (is (thrown-with-msg? IllegalArgumentException #":host must be non-empty"
                          (.build b)))))

(deftest port-out-of-range-rejected
  (let [b (Config/builder)]
    (.port b 70000)
    (is (thrown? IllegalArgumentException (.build b)))))

;; ---- Timeout model and limits --------------------------------------------

(deftest defaults
  (let [c (.build (Config/builder))]
    (is (= 10000 (.-handshakeTimeoutMillis c)))
    (is (= 10000 (.-headerTimeoutMillis c)))
    (is (= 30000 (.-readTimeoutMillis c)))
    (is (= 30000 (.-writeTimeoutMillis c)))
    (is (= 75000 (.-idleTimeoutMillis c)))
    (is (= 0 (.-handlerTimeoutMillis c)))
    (is (= 10000 (.-shutdownTimeoutMillis c)))
    (is (= 10000 (.-maxConnections c)))
    (is (= 0 (.-maxConnectionsPerIp c)))))

(defn- build-error [f]
  (try (.build ^com.s_exp.enso.api.Config$Builder (doto (Config/builder) f)) nil
       (catch IllegalArgumentException e (.getMessage e))))

(deftest errors-name-the-option-keyword
  (doseq [[f msg] [[#(.handshakeTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":handshake-timeout must be >= 0, got -1"]
                   [#(.headerTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":header-timeout must be >= 0"]
                   [#(.readTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":read-timeout must be >= 0"]
                   [#(.writeTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":write-timeout must be >= 0"]
                   [#(.idleTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":idle-timeout must be >= 0"]
                   [#(.handlerTimeoutMillis ^com.s_exp.enso.api.Config$Builder % -1) #":handler-timeout must be >= 0"]
                   [#(.maxConnections ^com.s_exp.enso.api.Config$Builder % -1) #":max-connections must be >= 0"]
                   [#(.port ^com.s_exp.enso.api.Config$Builder % 70000) #":port must be in \[0, 65535\]"]
                   [#(.backlog ^com.s_exp.enso.api.Config$Builder % 0) #":backlog must be >= 1"]
                   [#(.soRcvBufBytes ^com.s_exp.enso.api.Config$Builder % -1) #":so-rcv-buf-bytes must be >= 0"]
                   [#(.http3MaxUdpPayloadBytes ^com.s_exp.enso.api.Config$Builder % 500) #":http3-max-udp-payload-bytes must be in \[1200, 65527\]"]]]
    (is (re-find msg (str (build-error f))) (str msg))))

(def ^:private ssl (delay (SSLContext/getDefault)))

(deftest contradictions-are-rejected
  (doseq [[f msg]
          [[#(doto ^com.s_exp.enso.api.Config$Builder % (.sslContext @ssl) (.sslAlpnProtocols (into-array String ["h2" "http/1.1"])))
            #":ssl-alpn-protocols offers h2 but :http2 is off"]
           [#(.sslAlpnProtocols ^com.s_exp.enso.api.Config$Builder % (into-array String ["http/1.1"]))
            #":ssl-alpn-protocols needs :ssl-context"]
           [#(.sslCipherSuites ^com.s_exp.enso.api.Config$Builder % (into-array String ["TLS_AES_128_GCM_SHA256"]))
            #":ssl-cipher-suites needs :ssl-context"]
           [#(.sslProtocols ^com.s_exp.enso.api.Config$Builder % (into-array String ["TLSv1.3"]))
            #":ssl-protocols needs :ssl-context"]
           [#(.advertiseAltSvc ^com.s_exp.enso.api.Config$Builder % true)
            #":advertise-alt-svc needs :http3"]
           [#(.http3Port ^com.s_exp.enso.api.Config$Builder % 4433)
            #":http3-port needs :http3"]
           [#(doto ^com.s_exp.enso.api.Config$Builder % (.port 0) (.http3 true) (.http3CertPath "c") (.http3KeyPath "k"))
            #":port 0"]
           [#(doto ^com.s_exp.enso.api.Config$Builder % (.sslContext @ssl) (.http2 true) (.http2InitialWindowBytes 1000))
            #":http2-initial-window-bytes must be in \[65535, 2147483647\]"]
           [#(doto ^com.s_exp.enso.api.Config$Builder % (.sslContext @ssl) (.http2 true) (.http2MaxWindowBytes 1000))
            #":http2-max-window-bytes must be in \[65535, 2147483647\]"]
           [#(doto ^com.s_exp.enso.api.Config$Builder % (.sslContext @ssl) (.http2 true) (.http2InitialWindowBytes 1048576)
                   (.http2MaxWindowBytes 524288))
            #":http2-max-window-bytes must be >= :http2-initial-window-bytes"]
           [#(doto ^com.s_exp.enso.api.Config$Builder % (.maxConnections 10) (.maxConnectionsPerIp 20))
            #":max-connections-per-ip must be <= :max-connections"]
           [#(.serverHeader ^com.s_exp.enso.api.Config$Builder % " enso")
            #":server-header must be a valid field value"]
           [#(.http2 ^com.s_exp.enso.api.Config$Builder % true)
            #":http2 needs :ssl-context"]]]
    (is (re-find msg (str (build-error f))) (str msg))))

(deftest http3-on-ephemeral-port-allowed-without-alt-svc
  (is (some? (.build (doto (Config/builder) (.port 0) (.http3 true) (.http3CertPath "c")
                           (.http3KeyPath "k") (.advertiseAltSvc false)))))
  (is (some? (.build (doto (Config/builder) (.port 0) (.http3 true) (.http3CertPath "c")
                           (.http3KeyPath "k") (.http3Port 4433))))))

;; ---- run-server option table ---------------------------------------------

(defn- option-error [opts]
  (try (enso/stop (enso/run-server (fn [_] {:status 200}) (merge {:port 0} opts)))
       nil
       (catch clojure.lang.ExceptionInfo e e)))

(deftest unknown-options-are-rejected-with-a-suggestion
  (let [e (option-error {:idle-timout 1000})]
    (is (some? e))
    (is (re-find #"Unknown option :idle-timout" (str (ex-message e))))
    (is (re-find #"did you mean :idle-timeout\?" (str (ex-message e))))
    (is (= :idle-timeout (:suggestion (ex-data e)))))
  (testing "removed options are unknown"
    (doseq [k [:request-timeout :keep-alive-timeout :max-inline-body :coalesce-high-water
               :request-buffer-size :chunk-buffer-size :max-drain-bytes :worker-executor
               :http3-max-idle-timeout :http3-qpack-max-table-capacity :http3-qpack-blocked-streams
               :alpn-protocols :enabled-cipher-suites :enabled-tls-protocols]]
      (is (re-find #"Unknown option" (str (some-> (option-error {k 1}) ex-message))) (str k))))
  (testing "a far-off key gets no suggestion"
    (let [e (option-error {:zzzzzzzzzzzz 1})]
      (is (some? e))
      (is (nil? (:suggestion (ex-data e)))))))

(deftest option-types-are-checked
  (doseq [[opts msg] [[{:port "80"} #":port must be an integer"]
                      [{:port 1.5} #":port must be an integer"]
                      [{:port 99999999999} #":port must be an integer"]
                      [{:http2 "yes"} #":http2 must be a boolean"]
                      [{:server-header 42} #":server-header must be a string"]
                      [{:ssl-protocols "TLSv1.3"} #":ssl-protocols must be a sequence of strings"]
                      [{:ssl-context "ctx"} #":ssl-context must be a javax.net.ssl.SSLContext"]
                      [{:error-handler 1} #":error-handler must be a function"]
                      [{:server-events 1} #":server-events must be"]]]
    (is (re-find msg (str (some-> (option-error opts) ex-message))) (pr-str opts))))

(deftest config-validation-errors-name-the-option
  (let [e (option-error {:idle-timeout -1})]
    (is (instance? clojure.lang.ExceptionInfo e))
    (is (re-find #":idle-timeout must be >= 0" (str (ex-message e))))))

(deftest config-validation-errors-carry-the-option-and-value
  (doseq [[opts option value] [[{:idle-timeout -1} :idle-timeout -1]
                               [{:port 70000} :port 70000]
                               [{:ws-ping-interval 80000} :ws-ping-interval 80000]
                               [{:max-buffered-bytes -5} :max-buffered-bytes -5]
                               [{:server-header " x"} :server-header " x"]
                               [{:http2 true} :http2 true]]]
    (let [e (option-error opts)]
      (is (= {:type ::enso/invalid-option :option option :value value}
             (select-keys (ex-data e) [:type :option :value]))
          (pr-str opts))
      (is (instance? com.s_exp.enso.api.Config$InvalidOptionException (ex-cause e)) (pr-str opts)))))

(defn- var-error-handler [_ _] {:status 418 :body "from a var"})
(defn- var-origins [origin] (= origin "https://ok.example"))
(defn- var-ssl-context [] (SSLContext/getDefault))
(def ^:private opened-calls (atom []))
(defn- var-opened [protocol addr] (swap! opened-calls conj [protocol addr]))

(deftest vars-are-accepted-where-fns-are
  (reset! opened-calls [])
  (let [^Config c (#'enso/build-config {:error-handler #'var-error-handler
                                        :ws-allowed-origins #'var-origins
                                        :ssl-context-provider #'var-ssl-context
                                        :server-events {:connection-opened #'var-opened}})]
    (is (.test ^java.util.function.Predicate (.-wsAllowedOrigins c) "https://ok.example"))
    (is (not (.test ^java.util.function.Predicate (.-wsAllowedOrigins c) "https://no.example")))
    (is (some? (.-sslContext c)))
    (.connectionOpened (.-serverEvents c) "h2" (java.net.InetAddress/getByName "127.0.0.1"))
    (is (= [["h2" "127.0.0.1"]] @opened-calls)))
  (testing "a var error handler is called"
    (let [srv (enso/run-server (fn [_] (throw (RuntimeException. "x"))) {:port 0 :error-handler #'var-error-handler})]
      (try
        (with-open [sock (java.net.Socket. "127.0.0.1" (int (enso/port srv)))]
          (.write (.getOutputStream sock) (.getBytes "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
          (is (re-find #"^HTTP/1.1 418" (String. (.readAllBytes (.getInputStream sock))))))
        (finally (enso/stop srv)))))
  (testing "other IFns (keywords, maps, sets) are not functions here"
    (is (re-find #":error-handler must be a function" (str (some-> (option-error {:error-handler :k}) ex-message))))
    (is (re-find #":ws-allowed-origins must be" (str (some-> (option-error {:ws-allowed-origins {"a" 1}}) ex-message))))))

(deftest server-events-keys-and-values-are-checked
  (let [e (option-error {:server-events {:conection-opened (fn [_ _])}})]
    (is (re-find #"Unknown :server-events key :conection-opened, did you mean :connection-opened\?"
                 (str (ex-message e))))
    (is (= {:option :server-events :key :conection-opened :suggestion :connection-opened}
           (select-keys (ex-data e) [:option :key :suggestion]))))
  (is (re-find #":server-events :protocol-error must be a function"
               (str (some-> (option-error {:server-events {:protocol-error "log"}}) ex-message))))
  (is (nil? (option-error {:server-events {:protocol-error nil}})) "nil values mean no listener"))

(deftest server-event-addresses-are-formatted-like-remote-addr
  ;; RFC 5952 for IPv6, as :remote-addr (InetAddress.getHostAddress would
  ;; give 0:0:0:0:0:0:0:1).
  (let [seen (atom [])
        ^Config c (#'enso/build-config {:server-events {:connection-opened (fn [_ a] (swap! seen conj a))
                                                        :connection-closed (fn [_ a _] (swap! seen conj a))}})
        events (.-serverEvents c)
        v6 (java.net.InetAddress/getByName "::1")
        v4 (java.net.InetAddress/getByName "10.0.0.1")]
    (.connectionOpened events "http/1.1" v6)
    (.connectionClosed events "http/1.1" v4 1)
    (is (= ["::1" "10.0.0.1"] @seen))
    (is (= "2001:db8::1" (com.s_exp.enso.api.Request/formatAddress
                          (java.net.InetAddress/getByName "2001:db8:0:0:0:0:0:1"))))))

(defn- option-table [] @#'enso/options)

(deftest option-table-defaults-match-config
  (let [cfg (.build (Config/builder))]
    (doseq [{:keys [key default field]} (option-table)
            :when field]
      (is (= default (.get (.getField Config ^String field) cfg)) (str key)))))

(deftest every-option-is-documented-exactly-once
  (let [documented (fn [text]
                     (into (sorted-map)
                           (frequencies (map second (re-seq #"(?m)^\s*- `(:[a-z0-9-]+)`" text)))))
        expected (into (sorted-map) (map (fn [{:keys [key]}] [(str key) 1])) (option-table))]
    (is (= expected (documented (slurp "doc/options.md"))) "doc/options.md")
    (is (= expected (documented (:doc (meta #'enso/run-server)))) "run-server docstring")))

(deftest websocket-options
  (let [c (.build (Config/builder))]
    (is (= 1048576 (.-wsMaxMessageBytes c)))
    (is (= 1048576 (.-wsMaxQueuedBytes c)))
    (is (= 5000 (.-wsCloseTimeoutMillis c)))
    (is (false? (.-wsCompression c)))
    (is (nil? (.-wsAllowedOrigins c)))
    (is (= 0 (.-wsPingIntervalMillis c))))
  (is (= 20000 (.-wsPingIntervalMillis (#'enso/build-config {:ws-ping-interval 20000}))))
  (doseq [[opts msg] [[{:ws-max-message-bytes 0} #":ws-max-message-bytes must be >= 1"]
                      [{:ws-ping-interval -1} #":ws-ping-interval must be >= 0"]
                      [{:ws-ping-interval 75000} #":ws-ping-interval must be < :idle-timeout"]
                      [{:ws-max-queued-bytes -1} #":ws-max-queued-bytes must be >= 0"]
                      [{:ws-close-timeout 0} #":ws-close-timeout must be >= 1"]
                      [{:ws-compression 1} #":ws-compression must be a boolean"]
                      [{:ws-allowed-origins "https://a"} #":ws-allowed-origins must be a collection of origin strings or a function"]
                      [{:ws-allowed-origins [1]} #":ws-allowed-origins must be"]
                      [{:async "yes"} #":async must be a boolean"]]]
    (is (re-find msg (str (some-> (option-error opts) ex-message))) (pr-str opts)))
  (testing "origin collections are case-insensitive, \"*\" allows any"
    (let [^java.util.function.Predicate p (#'enso/check-origins :ws-allowed-origins ["https://App.example"])
          ^java.util.function.Predicate any (#'enso/check-origins :ws-allowed-origins ["*"])]
      (is (.test p "https://app.example"))
      (is (.test p "HTTPS://APP.EXAMPLE"))
      (is (not (.test p "https://evil.example")))
      (is (.test any "https://evil.example")))))

(deftest http3-transport-options
  ;; Event loops, socket buffers and the flood defences of the HTTP/3
  ;; listener are settable from the option map.
  (let [^Config c (#'enso/build-config {:http3-event-loops 3
                                        :http3-so-rcv-buf-bytes 1048576
                                        :http3-so-snd-buf-bytes 2097152
                                        :http3-retry-threshold 64
                                        :http3-max-half-open 512
                                        :http3-stream-reset-limit 100})]
    (is (= 3 (.-http3EventLoops c)))
    (is (= 1048576 (.-http3SoRcvBufBytes c)))
    (is (= 2097152 (.-http3SoSndBufBytes c)))
    (is (= 64 (.-http3RetryThreshold c)))
    (is (= 512 (.-http3MaxHalfOpen c)))
    (is (= 100 (.-http3StreamResetLimit c)))))

(deftest h2c-and-cert-reload-options
  ;; Cleartext HTTP/2 and HTTP/3 certificate reloading are settable from
  ;; the option map.
  (let [^Config c (#'enso/build-config {:http2c true :http3-cert-reload-interval 2500})]
    (is (true? (.-http2c c)))
    (is (= 2500 (.-http3CertReloadIntervalMillis c))))
  (is (re-find #":http2c" (str (some-> (option-error {:http2c true :ssl-context (default-context)}) ex-message)))))

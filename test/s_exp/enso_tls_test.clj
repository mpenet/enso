;; ABOUTME: TLS integration tests: reloadable SSL contexts via sslContextProvider, handshake and idle
;; ABOUTME: timeouts, stalled writers, renegotiation refusal and TLS socket adapter behaviour.
(ns s-exp.enso-tls-test
  "TLS integration tests focused on reloadable SSL context.
  Verifies the sslContextProvider path serves live-swapped contexts on
  new connections without restart."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (java.io File FileInputStream)
           (java.security KeyStore)
           (java.security.cert X509Certificate)
           (java.util.concurrent.atomic AtomicReference)
           (java.util.function Supplier)
           (javax.net.ssl KeyManagerFactory SSLContext TrustManager X509TrustManager)))

;; ---- Helpers -------------------------------------------------------------

(defn- keytool-gen!
  "Shell out to keytool to create a PKCS12 keystore with a self-signed
  cert whose CN is `cn`. Returns loaded SSLContext ready for server-side
  use. `cn` distinguishes cert-A from cert-B in the reload test."
  ^SSLContext [cn]
  (let [pass "changeit"
        ks-file (File/createTempFile "enso-tls-reload" ".p12")
        _ (.delete ks-file)
        cmd ["keytool" "-genkeypair" "-alias" cn "-keyalg" "RSA" "-keysize" "2048"
             "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
             "-storepass" pass "-validity" "365"
             "-dname" (str "CN=" cn ", OU=test, O=enso, L=x, S=x, C=US")
             "-ext" "SAN=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true)
                 (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info (str "keytool failed: "
                           (slurp (.getInputStream proc)))
                      {})))
    (let [ks (KeyStore/getInstance "PKCS12")
          _ (with-open [in (FileInputStream. ks-file)]
              (.load ks in (.toCharArray pass)))
          kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
          _ (.init kmf ks (.toCharArray pass))
          ctx (SSLContext/getInstance "TLS")]
      (.init ctx (.getKeyManagers kmf) nil nil)
      (.delete ks-file)
      ctx)))

(defn- capturing-trust-context
  "SSLContext whose trust manager captures every seen server cert into
  `captured` for inspection. Accepts anything (test-only)."
  ^SSLContext [captured]
  (let [tm (reify X509TrustManager
             (checkClientTrusted [_ _ _])
             (checkServerTrusted [_ chain _]
               (when (pos? (alength chain))
                 (swap! captured conj ^X509Certificate (aget chain 0))))
             (getAcceptedIssuers [_]
               (make-array X509Certificate 0)))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx nil (into-array TrustManager [tm]) nil)
    ctx))

(defn- do-tls-get!
  "One TLS GET / against `port`, ignoring the response body. Returns
  the response status line."
  [^SSLContext trust-ctx port]
  (let [factory (.getSocketFactory trust-ctx)]
    (with-open [^javax.net.ssl.SSLSocket sock
                (.createSocket factory "127.0.0.1" (int port))]
      (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
      (.startHandshake sock)
      (let [out (.getOutputStream sock)
            in (.getInputStream sock)]
        (.write out (.getBytes "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                               java.nio.charset.StandardCharsets/ISO_8859_1))
        (.flush out)
        (.readAllBytes in)))))

;; ---- Tests ---------------------------------------------------------------

(deftest ssl-context-provider-serves-initial-cert
  ;; Baseline: provider that returns a fixed context works exactly like
  ;; the static :ssl-context option would.
  (let [ctx-a (keytool-gen! "cert-a")
        captured (atom [])
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier (get [_] ctx-a))})]
    (try
      (do-tls-get! (capturing-trust-context captured) (enso/port srv))
      (is (pos? (count @captured)) "server presented a cert")
      (let [subject (.getName (.getSubjectX500Principal ^X509Certificate (first @captured)))]
        (is (re-find #"CN=cert-a" subject)
            (str "expected CN=cert-a in " subject)))
      (finally (enso/stop srv)))))

(deftest ssl-context-provider-swap-serves-new-cert
  ;; Reload semantics: swap the atom, next TLS handshake uses the new
  ;; cert. Old cert should not resurface on later connections.
  (let [ctx-a (keytool-gen! "cert-alpha")
        ctx-b (keytool-gen! "cert-beta")
        ref (AtomicReference. ctx-a)
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier (get [_] (.get ref)))})]
    (try
      (let [captured-1 (atom [])
            captured-2 (atom [])]
        (do-tls-get! (capturing-trust-context captured-1) (enso/port srv))
        (let [subj-1 (.getName (.getSubjectX500Principal
                                ^X509Certificate (first @captured-1)))]
          (is (re-find #"CN=cert-alpha" subj-1) "1st conn saw alpha"))
        ;; Swap; TLS session cache could reuse — force a fresh context
        ;; on client side too so we're not reusing a resumed session.
        (.set ref ctx-b)
        (do-tls-get! (capturing-trust-context captured-2) (enso/port srv))
        (let [subj-2 (.getName (.getSubjectX500Principal
                                ^X509Certificate (first @captured-2)))]
          (is (re-find #"CN=cert-beta" subj-2)
              (str "2nd conn expected beta, got " subj-2))))
      (finally (enso/stop srv)))))

(deftest ssl-context-provider-called-per-accept
  ;; Provider.get() is invoked on every accept — count calls to verify.
  (let [ctx (keytool-gen! "cert-count")
        calls (atom 0)
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier
                (get [_]
                  (swap! calls inc)
                  ctx))})]
    (try
      (let [initial @calls]
        (dotimes [_ 3]
          (do-tls-get! (capturing-trust-context (atom [])) (enso/port srv)))
        (is (<= (+ initial 3) @calls)
            (str "provider called on each accept: initial=" initial
                 " now=" @calls)))
      (finally (enso/stop srv)))))

(defn- ms-until-server-closes
  "Runs `drive!` on a raw TCP socket to `port` (it may write bytes), then
  waits for the server to close the connection. Returns elapsed ms from
  connect, or nil if still open after `limit-ms`."
  [port limit-ms drive!]
  (with-open [sock (java.net.Socket. "127.0.0.1" (int port))]
    (let [t0 (System/nanoTime)
          in (.getInputStream sock)]
      (drive! sock)
      (.setSoTimeout sock (int limit-ms))
      (try
        (loop []
          (when (>= (.read in) 0)
            (recur)))
        (/ (- (System/nanoTime) t0) 1e6)
        (catch java.net.SocketTimeoutException _ nil)
        (catch java.net.SocketException _ (/ (- (System/nanoTime) t0) 1e6))))))

(defn- with-tls-server [opts f]
  (let [srv (enso/run-server (:handler opts (fn [_] {:status 200 :body "ok"}))
                             (merge {:port 0 :http2 true :ssl-context (keytool-gen! "cert-timeout")}
                                    (dissoc opts :handler)))]
    (try (f (enso/port srv)) (finally (enso/stop srv)))))

(deftest tls-silent-client-closed-after-idle-timeout
  (with-tls-server {:idle-timeout 300 :handshake-timeout 5000}
    (fn [port]
      (let [ms (ms-until-server-closes port 4000 (fn [_]))]
        (is (some? ms) "server never closed a silent TLS connection")))))

(deftest tls-drip-fed-handshake-bounded-by-handshake-timeout
  ;; One byte every 100ms keeps every read under the idle timeout; only a
  ;; wall-clock handshake deadline stops it.
  (with-tls-server {:idle-timeout 2000 :handshake-timeout 500}
    (fn [port]
      (let [ms (ms-until-server-closes
                port 1000
                (fn [^java.net.Socket sock]
                  (let [out (.getOutputStream sock)]
                    (try
                      (doseq [b [0x16 0x03 0x01 0x02 0x00 0x01 0x00 0x01 0xfc 0x03 0x03
                                 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]]
                        (.write out (int b))
                        (.flush out)
                        (Thread/sleep 100))
                      (catch java.io.IOException _)))))]
        (is (some? ms) "drip-fed handshake was never cut off")
        (when ms
          (is (< ms 3000) (str "took " ms "ms")))))))

(deftest tls-http1-stalled-request-times-out
  (with-tls-server {:header-timeout 300}
    (fn [port]
      (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
        (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
          (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
          (.startHandshake sock)
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)
                t0 (System/nanoTime)]
            (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n" java.nio.charset.StandardCharsets/ISO_8859_1))
            (.flush out)
            (.setSoTimeout sock 4000)
            (let [closed (try
                           (loop []
                             (when (>= (.read in) 0)
                               (recur)))
                           true
                           (catch java.net.SocketTimeoutException _ false)
                           (catch java.io.IOException _ true))]
              (is closed "stalled HTTPS/1 request never timed out")
              (is (< (/ (- (System/nanoTime) t0) 1e6) 3000)))))))))

(deftest tls-socket-adapter-forwards-socket-options
  ;; The adapter has no socket of its own: options must reach the
  ;; accepted channel.
  (with-open [server-ch (doto (java.nio.channels.ServerSocketChannel/open)
                          (.bind (java.net.InetSocketAddress. "127.0.0.1" 0)))
              client (java.nio.channels.SocketChannel/open (.getLocalAddress server-ch))
              accepted (.accept server-ch)]
    (let [engine (.createSSLEngine (SSLContext/getDefault))
          adapter (.asSocket (com.s_exp.enso.core.TlsSocket. accepted engine))]
      (.setTcpNoDelay adapter false)
      (is (false? (.getOption accepted java.net.StandardSocketOptions/TCP_NODELAY)))
      (.setTcpNoDelay adapter true)
      (is (true? (.getOption accepted java.net.StandardSocketOptions/TCP_NODELAY)))
      (.setSoLinger adapter true 3)
      (is (= 3 (.getOption accepted java.net.StandardSocketOptions/SO_LINGER)))
      (.setSoLinger adapter false 0)
      (is (neg? (.getOption accepted java.net.StandardSocketOptions/SO_LINGER))))))

(deftest tls-handshake-recovers-from-app-buffer-overflow
  ;; Scripted engine: the first handshake unwrap reports BUFFER_OVERFLOW,
  ;; the next produces one plaintext byte and finishes. The enlarged
  ;; buffer must keep working (and keep that byte) instead of looping.
  (with-open [server-ch (doto (java.nio.channels.ServerSocketChannel/open)
                          (.bind (java.net.InetSocketAddress. "127.0.0.1" 0)))
              client (java.nio.channels.SocketChannel/open (.getLocalAddress server-ch))
              accepted (.accept server-ch)]
    (.write client (java.nio.ByteBuffer/wrap (byte-array 8 (byte 1))))
    (let [unwraps (atom 0)
          session (reify javax.net.ssl.SSLSession
                    (getPacketBufferSize [_] 64)
                    (getApplicationBufferSize [_] 16))
          hs (atom javax.net.ssl.SSLEngineResult$HandshakeStatus/NEED_UNWRAP)
          engine (proxy [javax.net.ssl.SSLEngine] []
                   (setUseClientMode [_])
                   (getSession [] session)
                   (beginHandshake [])
                   (getHandshakeStatus [] @hs)
                   (unwrap [^java.nio.ByteBuffer src ^java.nio.ByteBuffer dst]
                     (let [n (swap! unwraps inc)]
                       (when (> n 5)
                         (throw (IllegalStateException. "unwrap looping on overflow")))
                       (if (or (= n 1) (zero? (.remaining dst)))
                         (javax.net.ssl.SSLEngineResult.
                          javax.net.ssl.SSLEngineResult$Status/BUFFER_OVERFLOW @hs 0 0)
                         (let [consumed (.remaining src)]
                           (.position src (.limit src))
                           (.put dst (byte 88))
                           (reset! hs javax.net.ssl.SSLEngineResult$HandshakeStatus/FINISHED)
                           (javax.net.ssl.SSLEngineResult.
                            javax.net.ssl.SSLEngineResult$Status/OK @hs consumed 1))))))
          tls (com.s_exp.enso.core.TlsSocket. accepted engine)]
      (.handshake tls 2000)
      (is (= 88 (.read (.getInputStream tls)))))))

(deftest tls-http1-large-bodies-round-trip
  (let [ascii (apply str (repeat 70000 "q"))
        bytes-body (byte-array (map #(unchecked-byte (mod % 251)) (range 100000)))]
    (with-tls-server {:handler (fn [req] {:status 200 :body (if (= "/a" (:uri req)) ascii bytes-body)})}
      (fn [port]
        (let [srv-port port]
          (doseq [[path expected] [["/a" (.getBytes ascii java.nio.charset.StandardCharsets/ISO_8859_1)]
                                   ["/b" bytes-body]]]
            (let [raw ^bytes (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
                               (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int srv-port))]
                                 (.write (.getOutputStream sock)
                                         (.getBytes (str "GET " path " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                                                    java.nio.charset.StandardCharsets/ISO_8859_1))
                                 (.readAllBytes (.getInputStream sock))))
                  s (String. raw java.nio.charset.StandardCharsets/ISO_8859_1)
                  start (+ 4 (.indexOf s "\r\n\r\n"))]
              (is (= (seq expected) (seq (java.util.Arrays/copyOfRange raw start (alength raw)))) path))))))
    nil))

(deftest tls-stop-not-blocked-by-stalled-writer
  ;; The client never reads a large response, so the server's writer
  ;; blocks holding the TLS write lock. Forced shutdown must still finish.
  (let [writing (promise)
        srv (enso/run-server
             (fn [_] {:status 200
                      :body (fn [w]
                              (deliver writing true)
                              (dotimes [_ 64] (enso/write! w (byte-array (* 1024 1024)))))})
             {:port 0 :http2 true :ssl-context (keytool-gen! "cert-stall")
              :shutdown-timeout 300})
        factory (.getSocketFactory (capturing-trust-context (atom [])))]
    (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int (enso/port srv)))]
      (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
      (.startHandshake sock)
      (let [out (.getOutputStream sock)]
        (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                               java.nio.charset.StandardCharsets/ISO_8859_1))
        (.flush out))
      ;; The body is far larger than the socket buffers: once it is being
      ;; written, the writer stalls (on stop or before it).
      (is (deref writing 3000 false))
      (let [t0 (System/nanoTime)
            stopped (deref (future (enso/stop srv) :stopped) 5000 :timed-out)]
        (is (= :stopped stopped))
        (is (< (/ (- (System/nanoTime) t0) 1e6) 3000))))))

(deftest ssl-context-provider-failure-does-not-stop-acceptor
  (let [ctx (keytool-gen! "cert-flaky")
        failing (atom false)
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier
                (get [_]
                  (when @failing
                    (throw (IllegalStateException. "provider down")))
                  ctx))})]
    (try
      (reset! failing true)
      (is (thrown? java.io.IOException
                   (do-tls-get! (capturing-trust-context (atom [])) (enso/port srv))))
      (reset! failing false)
      ;; Bounded: with a dead acceptor the handshake would block forever.
      (let [resp (deref (future
                          (String. ^bytes (do-tls-get! (capturing-trust-context (atom [])) (enso/port srv))
                                   java.nio.charset.StandardCharsets/ISO_8859_1))
                        5000
                        "timed out")]
        (is (.startsWith ^String resp "HTTP/1.1 200") resp))
      (finally (enso/stop srv)))))

(deftest ssl-session-cache-size-applied
  ;; :ssl-session-cache-size sizes the server session cache of every
  ;; context the server uses, static or provided.
  (doseq [[opts ^SSLContext ctx] (let [a (keytool-gen! "cache-a") b (keytool-gen! "cache-b")]
                                   [[{:ssl-context a} a]
                                    [{:http2 true :ssl-context b} b]
                                    (let [c (keytool-gen! "cache-c")]
                                      [{:http2 true :ssl-context-provider (reify Supplier (get [_] c))} c])])]
    (let [srv (enso/run-server (fn [_] {:status 200 :body "ok"})
                               (merge {:port 0 :ssl-session-cache-size 7} opts))]
      (try
        (is (= 7 (.getSessionCacheSize (.getServerSessionContext ctx))) (pr-str (keys opts)))
        (finally (enso/stop srv))))))

(deftest tls-read-timeout-does-not-replay-plaintext
  ;; A body read that times out must leave no readable bytes behind: the
  ;; handler swallows the timeout and answers, and draining the unread
  ;; body must not see earlier decrypted plaintext (which would parse as
  ;; a phantom second request).
  (with-tls-server {:read-timeout 300
                    :handler (fn [req]
                               (try (slurp (:body req)) (catch Exception _))
                               {:status 200 :body "ok"})}
    (fn [port]
      (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
        (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
          (.startHandshake sock)
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)
                resp (StringBuilder.)]
            ;; One TLS record: headers, then 200 body bytes of a declared
            ;; 200 + d. A replay re-reads the record from its start: the
            ;; drain eats d bytes and the parser lands on the phantom
            ;; request placed at offset d.
            (let [head-len (count "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 000\r\n\r\n")
                  d (+ head-len 12)
                  phantom "GET /phantom HTTP/1.1\r\nHost: x\r\n\r\n"
                  body (str (apply str (repeat 12 "x")) phantom
                            (apply str (repeat (- 200 12 (count phantom)) "y")))
                  req (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " (+ 200 d) "\r\n\r\n" body)]
              (.write out (.getBytes req java.nio.charset.StandardCharsets/ISO_8859_1)))
            (.flush out)
            (.setSoTimeout sock 4000)
            (try
              (loop []
                (let [b (.read in)]
                  (when (>= b 0)
                    (.append resp (char b))
                    (recur))))
              (catch java.io.IOException _))
            (is (= 1 (count (re-seq #"HTTP/1\.1 \d{3}" (str resp)))) (str resp))))))))

(defn- tls-ws-handshake!
  "Opens a WebSocket over `sock` (HTTP/1.1 on the TLS listener) and
  consumes the 101 response headers."
  [^javax.net.ssl.SSLSocket sock]
  (let [out (.getOutputStream sock)
        in (.getInputStream sock)]
    (.write out (.getBytes (str "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                                "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n\r\n")
                           java.nio.charset.StandardCharsets/ISO_8859_1))
    (.flush out)
    (loop [tail 0]
      (let [b (.read in)]
        (when (neg? b) (throw (java.io.EOFException. "handshake closed early")))
        (let [tail (bit-and 0xFFFFFFFF (bit-or (bit-shift-left tail 8) b))]
          (when-not (= tail 0x0D0A0D0A)
            (recur tail)))))))

(deftest tls-ws-close-not-blocked-by-stalled-writer
  ;; Over TLS a writer stalled on a peer that stopped reading holds the
  ;; TLS write lock. Closing the WebSocket must still drop the connection
  ;; in bounded time and report onClose.
  (let [sock-p (promise)
        closed (promise)
        ;; when the send in progress started
        send-started (atom nil)]
    (with-tls-server {:idle-timeout 0
                      :handler (fn [_]
                                 {:ring.websocket/listener
                                  {:on-open (fn [^com.s_exp.enso.api.WebSocketSocket s]
                                              (deliver sock-p s)
                                              (Thread/startVirtualThread
                                               (fn []
                                                 (try
                                                   (let [chunk (java.nio.ByteBuffer/allocate (* 1024 1024))]
                                                     (while (.isOpen s)
                                                       (reset! send-started (System/nanoTime))
                                                       (.sendBinary s (.duplicate chunk))))
                                                   (catch java.io.IOException _)))))
                                   :on-close (fn [_ code _] (deliver closed code))}})}
      (fn [port]
        (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
          (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
            (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
            (.startHandshake sock)
            (tls-ws-handshake! sock)
            (let [^com.s_exp.enso.api.WebSocketSocket s (deref sock-p 2000 nil)]
              (is s)
              ;; Wait until a send has been blocked for a while: the
              ;; client reads nothing, so the socket buffers are full.
              (let [deadline (+ (System/currentTimeMillis) 5000)]
                (while (and (not (when-let [t @send-started] (> (- (System/nanoTime) t) 200000000)))
                            (< (System/currentTimeMillis) deadline))
                  (Thread/sleep 20)))
              (let [closer (future (.close s 1000 "") :returned)]
                (is (= :returned (deref closer 10000 :timed-out))
                    "close returns despite the stalled TLS writer")
                (is (number? (deref closed 10000 :timed-out))
                    "onClose fires")))))))))

(deftest tls12-client-renegotiation-refused
  ;; TLS 1.2 renegotiation started by the client after the handshake is
  ;; refused: the connection closes (reported as a "renegotiation" TLS
  ;; protocol error), serves nothing more, and the server keeps serving.
  (let [errors (atom [])]
    (with-tls-server {:server-events {:protocol-error (fn [p kind] (swap! errors conj [p kind]))}}
      (fn [port]
        (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
          (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
            (.setEnabledProtocols sock (into-array String ["TLSv1.2"]))
            (.setSoTimeout sock 4000)
            (.startHandshake sock)
            (let [out (.getOutputStream sock)
                  in (.getInputStream sock)
                  request (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" java.nio.charset.StandardCharsets/ISO_8859_1)
                  read-head (fn []
                              (let [sb (StringBuilder.)]
                                (try
                                  (loop []
                                    (let [b (.read in)]
                                      (when (>= b 0)
                                        (.append sb (char b))
                                        (when-not (.endsWith (str sb) "ok")
                                          (recur)))))
                                  (catch java.io.IOException _))
                                (str sb)))]
              (.write out request)
              (.flush out)
              (is (clojure.string/starts-with? (read-head) "HTTP/1.1 200"))
              (let [renegotiated (try (.startHandshake sock) (.write out request) (.flush out) true
                                      (catch java.io.IOException _ false))]
                (is (not (and renegotiated (clojure.string/includes? (read-head) "HTTP/1.1")))
                    "no response after a renegotiation")))))
        (let [deadline (+ (System/currentTimeMillis) 3000)]
          (while (and (empty? @errors) (< (System/currentTimeMillis) deadline))
            (Thread/sleep 10)))
        (is (= [["tls" "renegotiation"]] @errors))
        (is (.startsWith ^String (String. ^bytes (do-tls-get! (capturing-trust-context (atom [])) port)
                                          java.nio.charset.StandardCharsets/ISO_8859_1)
                         "HTTP/1.1 200")
            "server still serves new connections")))))

(deftest tls-handshake-timeout-reported-as-its-own-kind
  (let [errors (promise)]
    (with-tls-server {:handshake-timeout 300
                      :server-events {:protocol-error (fn [p kind] (deliver errors [p kind]))}}
      (fn [port]
        (with-open [sock (java.net.Socket. "127.0.0.1" (int port))]
          (is (= ["tls" "handshake-timeout"] (deref errors 3000 :none))))))))

(deftest tls-error-response-survives-an-unread-upload
  ;; Lingering close over TLS: close_notify and FIN, then the refused
  ;; upload is read and discarded, so the client finishes sending and
  ;; reads the 413 instead of hitting a reset.
  (with-tls-server {:max-request-body-bytes 1000}
    (fn [port]
      (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
        (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
          (.startHandshake sock)
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)
                writer (future
                         (try
                           (.write out (.getBytes "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n"
                                                  java.nio.charset.StandardCharsets/ISO_8859_1))
                           (dotimes [_ 100] (.write out (byte-array 40000)))
                           :uploaded
                           (catch java.io.IOException e e)))
                resp (StringBuilder.)]
            (.setSoTimeout sock 4000)
            (try
              (loop []
                (let [b (.read in)]
                  (when (>= b 0)
                    (.append resp (char b))
                    (recur))))
              (catch java.io.IOException _))
            (is (.startsWith (str resp) "HTTP/1.1 413") (str resp))
            (is (= :uploaded (deref writer 5000 :timed-out)))))))))

(deftest tls-keep-alive-request-after-idle-buffer-release
  ;; Idle past the buffer-release delay, the TLS record buffers were
  ;; swapped for small ones; the next request (a multi-record one) grows
  ;; them back.
  (with-tls-server {:handler (fn [req] {:status 200 :body (str (count (slurp (:body req))))})}
    (fn [port]
      (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
        (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
          (.startHandshake sock)
          (.setSoTimeout sock 4000)
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)
                read-response (fn []
                                (let [sb (StringBuilder.)]
                                  (loop []
                                    (let [b (.read in)]
                                      (when (>= b 0)
                                        (.append sb (char b))
                                        (when-not (.endsWith (str sb) "\r\n\r\n")
                                          (recur)))))
                                  (let [n (Long/parseLong (second (re-find #"Content-Length: (\d+)" (str sb))))]
                                    (dotimes [_ n] (.append sb (char (.read in)))))
                                  (str sb)))
                post (fn [n] (.write out (.getBytes (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " n "\r\n\r\n"
                                                         (apply str (repeat n "q")))
                                                    java.nio.charset.StandardCharsets/ISO_8859_1))
                       (.flush out))]
            (post 10)
            (is (.endsWith ^String (read-response) "\r\n\r\n10"))
            (Thread/sleep 1300)
            (post 50000)
            (is (.endsWith ^String (read-response) "\r\n\r\n50000"))))))))

;; ---- Records trickled under the timeouts -------------------------------------

(defn- drip-proxy
  "A TCP proxy in front of 127.0.0.1:`port` for one connection. Client
  bytes go through at once, or one byte every `@drip-ms` ms while that is
  positive (a TLS record trickled under the socket timeouts). Returns the
  proxy's ServerSocket; closing it ends the proxy."
  ^java.net.ServerSocket [port drip-ms]
  (let [ss (java.net.ServerSocket. 0 1 (java.net.InetAddress/getLoopbackAddress))]
    (future
      (try
        (with-open [client (.accept ss)
                    server (java.net.Socket. "127.0.0.1" (int port))]
          (future
            (try
              (let [in (.getInputStream client)
                    out (.getOutputStream server)
                    buf (byte-array 16384)]
                (loop []
                  (let [n (.read in buf)]
                    (when (pos? n)
                      (let [d (long @drip-ms)]
                        (if (pos? d)
                          (dotimes [i n]
                            (Thread/sleep d)
                            (.write out (int (aget buf i)))
                            (.flush out))
                          (.write out buf 0 n)))
                      (recur)))))
              (catch Exception _)))
          (let [in (.getInputStream server)
                out (.getOutputStream client)
                buf (byte-array 16384)]
            (loop []
              (let [n (.read in buf)]
                (when (pos? n)
                  (.write out buf 0 n)
                  (recur))))))
        (catch Exception _)))
    ss))

(defn- tls-connect
  ^javax.net.ssl.SSLSocket [port]
  (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
    (doto ^javax.net.ssl.SSLSocket (.createSocket factory "127.0.0.1" (int port))
      (.startHandshake))))

(defn- tls-write! [^javax.net.ssl.SSLSocket sock ^String s]
  (doto (.getOutputStream sock)
    (.write (.getBytes s java.nio.charset.StandardCharsets/ISO_8859_1))
    (.flush)))

(defn- tls-read-to-end!
  "Reads `sock` to its end: [text, :eof / :reset / :timeout, elapsed ms]."
  [^javax.net.ssl.SSLSocket sock ms]
  (.setSoTimeout sock (int ms))
  (let [t0 (System/nanoTime)
        in (.getInputStream sock)
        sb (StringBuilder.)
        end (try
              (loop []
                (let [b (.read in)]
                  (if (neg? b)
                    :eof
                    (do (.append sb (char b)) (recur)))))
              (catch java.net.SocketTimeoutException _ :timeout)
              (catch java.io.IOException _ :reset))]
    [(str sb) end (/ (- (System/nanoTime) t0) 1e6)]))

(defn- tls-round-trip!
  "One keep-alive GET answered \"ok\" on `sock`: once it returns, the
  server has finished its side of the handshake (the client's Finished
  may otherwise still be in flight when a test starts trickling)."
  [^javax.net.ssl.SSLSocket sock]
  (tls-write! sock "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
  (.setSoTimeout sock 5000)
  (let [in (.getInputStream sock)
        sb (StringBuilder.)]
    (loop []
      (let [b (.read in)]
        (when (neg? b) (throw (java.io.EOFException. (str "closed before the response: " sb))))
        (.append sb (char b))
        (when-not (.endsWith (str sb) "\r\n\r\nok")
          (recur))))))

(deftest tls-trickled-records-bounded-by-the-idle-and-head-clocks
  ;; SO_TIMEOUT restarts with every byte, and over TLS those bytes are
  ;; ciphertext: a record trickled a byte at a time would hold one read
  ;; for as long as the client likes. Reads are held to the wall clock
  ;; of their phase instead.
  (with-tls-server {:idle-timeout 2000 :header-timeout 500}
    (fn [port]
      (testing "a request record trickled into an idle connection"
        (let [drip (atom 0)
              proxy (drip-proxy port drip)]
          (try
            (with-open [sock (tls-connect (.getLocalPort proxy))]
              (tls-round-trip! sock)
              (reset! drip 150)
              (tls-write! sock "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
              (let [[resp _ ms] (tls-read-to-end! sock 6000)]
                (is (.startsWith ^String resp "HTTP/1.1 408") (pr-str resp))
                (is (< ms 3000) (str "closed after " ms "ms"))))
            (finally (.close proxy)))))
      (testing "the rest of a request head trickled"
        (let [drip (atom 0)
              proxy (drip-proxy port drip)]
          (try
            (with-open [sock (tls-connect (.getLocalPort proxy))]
              (tls-round-trip! sock)
              (tls-write! sock "GET / HTTP/1.1\r\n")
              (Thread/sleep 100)
              (reset! drip 100)
              (tls-write! sock "Host: x\r\n\r\n")
              (let [[resp _ ms] (tls-read-to-end! sock 6000)]
                (is (.startsWith ^String resp "HTTP/1.1 408") (pr-str resp))
                (is (< ms 2000) (str "closed after " ms "ms"))))
            (finally (.close proxy))))))))

(deftest tls-trickled-body-record-bounded-by-the-min-data-rate
  (with-tls-server {:min-data-rate-bytes 1000 :min-data-rate-grace 500 :read-timeout 10000
                    :handler (fn [req] {:status 200 :body (str (count (slurp (:body req))))})}
    (fn [port]
      (let [drip (atom 0)
            proxy (drip-proxy port drip)]
        (try
          (with-open [sock (tls-connect (.getLocalPort proxy))]
            (tls-write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n")
            (Thread/sleep 100)
            (reset! drip 100)
            (tls-write! sock (apply str (repeat 50 "b")))
            (let [[resp _ ms] (tls-read-to-end! sock 6000)]
              (is (.startsWith ^String resp "HTTP/1.1 408") (pr-str resp))
              (is (< ms 3000) (str "closed after " ms "ms"))))
          (finally (.close proxy)))))))

(deftest tls-failing-close-delimited-body-aborts
  ;; An HTTP/1.0 body of unknown length ends with the connection: one
  ;; that fails ends it without close_notify (and with a reset), so the
  ;; client can't take the truncated body for a complete one.
  (with-tls-server {:handler (fn [_]
                               (let [left (atom 20000)]
                                 {:status 200
                                  :body (proxy [java.io.InputStream] []
                                          (read
                                            ([] (throw (UnsupportedOperationException.)))
                                            ([^bytes b off len]
                                             (let [k (min (long len) (long @left))]
                                               (if (pos? k)
                                                 (do (swap! left - k) (int k))
                                                 (throw (java.io.IOException. "body source failed")))))))}))}
    (fn [port]
      (with-open [sock (tls-connect port)]
        (tls-write! sock "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        (let [[_ end] (tls-read-to-end! sock 3000)]
          (is (= :reset end)))))))

(deftest tls-input-pending-sees-what-the-socket-received
  ;; Closing with unread input makes the kernel reset the connection, so
  ;; the HTTP/1.1 driver closes lingering whenever input is waiting:
  ;; plaintext or ciphertext held by the TLS socket, or bytes the socket
  ;; received.
  (with-open [server-ch (doto (java.nio.channels.ServerSocketChannel/open)
                          (.bind (java.net.InetSocketAddress. "127.0.0.1" 0)))
              client (java.nio.channels.SocketChannel/open (.getLocalAddress server-ch))
              accepted (.accept server-ch)]
    (let [tls (com.s_exp.enso.core.TlsSocket. accepted (.createSSLEngine (SSLContext/getDefault)))]
      (is (false? (.inputPending tls)))
      (.write client (java.nio.ByteBuffer/wrap (byte-array [22 3 3])))
      (is (loop [n 0]
            (cond
              (.inputPending tls) true
              (< n 200) (do (Thread/sleep 10) (recur (inc n)))
              :else false))))))

(ns s-exp.enso-tls-test
  "TLS integration tests focused on reloadable SSL context (#242).
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
  (with-tls-server {:idle-timeout 300 :request-timeout 5000}
    (fn [port]
      (let [ms (ms-until-server-closes port 4000 (fn [_]))]
        (is (some? ms) "server never closed a silent TLS connection")))))

(deftest tls-drip-fed-handshake-bounded-by-request-timeout
  ;; One byte every 100ms keeps every read under the idle timeout; only a
  ;; wall-clock handshake deadline stops it.
  (with-tls-server {:idle-timeout 2000 :request-timeout 500}
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
  (with-tls-server {:idle-timeout 300 :request-timeout 5000}
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
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body (byte-array (* 64 1024 1024))})
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
      (Thread/sleep 500)
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
  (with-tls-server {:idle-timeout 300 :request-timeout 5000
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
        closed (promise)]
    (with-tls-server {:idle-timeout 0
                      :handler (fn [_]
                                 {:ring.websocket/listener
                                  {:on-open (fn [^com.s_exp.enso.websocket.WebSocketSocket s]
                                              (deliver sock-p s)
                                              (Thread/startVirtualThread
                                               (fn []
                                                 (try
                                                   (let [chunk (java.nio.ByteBuffer/allocate (* 1024 1024))]
                                                     (while (.isOpen s)
                                                       (.sendBinary s (.duplicate chunk))))
                                                   (catch java.io.IOException _)))))
                                   :on-close (fn [_ code _] (deliver closed code))}})}
      (fn [port]
        (let [factory (.getSocketFactory (capturing-trust-context (atom [])))]
          (with-open [^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int port))]
            (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
            (.startHandshake sock)
            (tls-ws-handshake! sock)
            (let [^com.s_exp.enso.websocket.WebSocketSocket s (deref sock-p 2000 nil)]
              (is s)
              ;; Let the writer fill the socket buffers and block.
              (Thread/sleep 500)
              (let [closer (future (.close s 1000 "") :returned)]
                (is (= :returned (deref closer 10000 :timed-out))
                    "close returns despite the stalled TLS writer")
                (is (number? (deref closed 10000 :timed-out))
                    "onClose fires")))))))))

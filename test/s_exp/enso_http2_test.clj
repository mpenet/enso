;; ABOUTME: HTTP/2 end-to-end tests over TLS and h2c, using java.net.http and a raw-frame client for
;; ABOUTME: protocol edge cases: HPACK state, flow control, stream resets, GOAWAY, timeouts and limits.
(ns s-exp.enso-http2-test
  "HTTP/2 end-to-end tests via java.net.http. Server runs h2 over TLS,
  plus a raw-frame client for protocol edge cases: HPACK state across
  requests, trailers, stream state races, flow control, GOAWAY, the
  timeout model, the shared response and request-head policy, and
  cleartext HTTP/2 with prior knowledge (h2c) on the plain listener."
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.string :as str]
            [s-exp.enso :as enso])
  (:import (java.io ByteArrayInputStream)
           (java.net URI)
           (java.net.http HttpClient HttpClient$Version HttpRequest
                          HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
           (java.nio.charset StandardCharsets)
           (java.security KeyStore)
           (java.security.cert X509Certificate)
           (java.time Duration)
           (java.util.concurrent CompletableFuture CountDownLatch TimeUnit)
           (javax.net.ssl KeyManagerFactory SSLContext SSLParameters
                          TrustManager X509TrustManager)))

;; ---- Shared TLS helpers --------------------------------------------------

(defn- gen-server-context ^SSLContext []
  (let [pass "changeit"
        ks-file (java.io.File/createTempFile "enso-h2" ".p12")
        _ (.delete ks-file)
        cmd ["keytool" "-genkeypair" "-alias" "enso" "-keyalg" "RSA" "-keysize" "2048"
             "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
             "-storepass" pass "-validity" "365"
             "-dname" "CN=localhost, OU=test, O=enso, L=x, S=x, C=US"
             "-ext" "SAN=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true) (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info "keytool failed" {})))
    (let [ks (KeyStore/getInstance "PKCS12")
          _ (with-open [in (java.io.FileInputStream. ks-file)]
              (.load ks in (.toCharArray pass)))
          kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
          _ (.init kmf ks (.toCharArray pass))
          ctx (SSLContext/getInstance "TLS")]
      (.init ctx (.getKeyManagers kmf) nil nil)
      (.delete ks-file)
      ctx)))

(defn- trust-all-context ^SSLContext []
  (let [tm (reify X509TrustManager
             (checkClientTrusted [_ _ _])
             (checkServerTrusted [_ _ _])
             (getAcceptedIssuers [_] (make-array X509Certificate 0)))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx nil (into-array TrustManager [tm]) nil)
    ctx))

(defn- h2-client
  "Fresh HttpClient forced to HTTP/2 over TLS with our trust-all
  context. Our cert's SAN includes IP:127.0.0.1 so default HTTPS
  endpoint identification accepts the loopback dial."
  ^HttpClient []
  (-> (HttpClient/newBuilder)
      (.version HttpClient$Version/HTTP_2)
      (.sslContext (trust-all-context))
      .build))

(def ^:dynamic *port* nil)

(defn- with-h2-server [handler f]
  (let [srv (enso/run-server handler
                             {:port 0 :http2 true
                              :ssl-context (gen-server-context)})]
    (try
      (binding [*port* (enso/port srv)]
        (f))
      (finally (enso/stop srv)))))

(defn- get! [^String path]
  (let [client (h2-client)
        req (-> (HttpRequest/newBuilder
                 (URI/create (str "https://127.0.0.1:" *port* path)))
                (.version HttpClient$Version/HTTP_2)
                (.GET) .build)]
    (.send client req (HttpResponse$BodyHandlers/ofString))))

(defn- post! [^String path ^String body]
  (let [client (h2-client)
        req (-> (HttpRequest/newBuilder
                 (URI/create (str "https://127.0.0.1:" *port* path)))
                (.version HttpClient$Version/HTTP_2)
                (.POST (HttpRequest$BodyPublishers/ofString body))
                .build)]
    (.send client req (HttpResponse$BodyHandlers/ofString))))

;; ---- Baseline shape ------------------------------------------------------

(deftest h2-get-negotiated
  (with-h2-server
    (fn [_] {:status 200 :body "h2-hi"})
    (fn []
      (let [resp (get! "/")]
        (is (= HttpClient$Version/HTTP_2 (.version resp))
            "ALPN chose h2")
        (is (= 200 (.statusCode resp)))
        (is (= "h2-hi" (.body resp)))))))

(deftest h2-post-body-echoed
  (with-h2-server
    (fn [req] {:status 200 :body (slurp (:body req))})
    (fn []
      (let [resp (post! "/echo" "payload-abc")]
        (is (= 200 (.statusCode resp)))
        (is (= "payload-abc" (.body resp)))))))

(deftest h2-response-headers-round-trip
  (with-h2-server
    (fn [_] {:status 201
             :headers {"x-custom" "yes"
                       "content-type" "text/plain"}
             :body "ok"})
    (fn []
      (let [resp (get! "/")
            h (.headers resp)]
        (is (= 201 (.statusCode resp)))
        (is (= "yes" (.orElse (.firstValue h "x-custom") nil)))
        (is (str/starts-with? (.orElse (.firstValue h "content-type") "")
                              "text/plain"))))))

;; ---- Request / method verbs ---------------------------------------------

(deftest h2-method-in-request-map
  (let [captured (atom nil)]
    (with-h2-server
      (fn [req] (reset! captured (:request-method req))
        {:status 200 :body "ok"})
      (fn []
        (post! "/x" "y")
        (is (= :post @captured))))))

(deftest h2-scheme-in-request-map
  ;; h2 is only served over TLS (ALPN), so the transport scheme is :https.
  (with-h2-server
    (fn [req] {:status 200 :body (name (:scheme req))})
    (fn []
      (is (= "https" (.body (get! "/")))))))

(deftest h2-path-and-query-parsed
  (let [captured (atom nil)]
    (with-h2-server
      (fn [req] (reset! captured (select-keys req [:uri :query-string]))
        {:status 200 :body "ok"})
      (fn []
        (get! "/api/items?limit=5&offset=10")
        (is (= "/api/items" (:uri @captured)))
        (is (= "limit=5&offset=10" (:query-string @captured)))))))

;; ---- Reuse connection: multiple requests share the h2 conn --------------
;; This exercises HPACK dynamic-table state across streams. If the
;; encoder had a bug that emitted a stale table-size update or leaked
;; state, later requests would fail.

(deftest h2-multiple-requests-on-same-connection
  (let [call-count (atom 0)]
    (with-h2-server
      (fn [_] (swap! call-count inc)
        {:status 200 :body "ok"})
      (fn []
        (let [client (h2-client)]
          (dotimes [_ 10]
            (let [req (-> (HttpRequest/newBuilder
                           (URI/create (str "https://127.0.0.1:" *port* "/")))
                          (.version HttpClient$Version/HTTP_2)
                          .GET .build)
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= HttpClient$Version/HTTP_2 (.version resp)))))
          (is (= 10 @call-count)))))))

;; ---- Concurrent streams --------------------------------------------------
;; HttpClient may multiplex multiple requests over the same connection.
;; The server must handle concurrent stream dispatch without dropping.

(deftest h2-concurrent-streams-serve-all
  (let [n 20
        seen (atom #{})]
    (with-h2-server
      (fn [req]
        (swap! seen conj (:uri req))
        {:status 200 :body (:uri req)})
      (fn []
        (let [client (h2-client)
              futures (mapv (fn [i]
                              (let [req (-> (HttpRequest/newBuilder
                                             (URI/create (str "https://127.0.0.1:" *port*
                                                              "/req/" i)))
                                            (.version HttpClient$Version/HTTP_2)
                                            .GET .build)]
                                (.sendAsync client req (HttpResponse$BodyHandlers/ofString))))
                            (range n))]
          (doseq [^CompletableFuture f futures]
            (let [resp (.get f 10 TimeUnit/SECONDS)]
              (is (= 200 (.statusCode resp)))))
          (is (= n (count @seen))))))))

;; ---- Large body over DATA frames (FrameSeg envelope + emitData copy) ----

(deftest h2-large-response-body-integrity
  ;; Response ≥ 32 KiB fans out into multiple DATA frames. The
  ;; emitData copy fix (from the review pass) ensures the bytes
  ;; observed by the client match the source byte-for-byte.
  (let [payload (byte-array 65536)]
    (dotimes [i (alength payload)]
      (aset payload i (unchecked-byte (mod i 251))))
    (with-h2-server
      (fn [_] {:status 200 :body payload})
      (fn []
        (let [client (h2-client)
              req (-> (HttpRequest/newBuilder
                       (URI/create (str "https://127.0.0.1:" *port* "/")))
                      (.version HttpClient$Version/HTTP_2)
                      .GET .build)
              resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
              body (.body resp)]
          (is (= 200 (.statusCode resp)))
          (is (= (alength payload) (alength body))
              "body length matches")
          (is (java.util.Arrays/equals ^bytes payload ^bytes body)
              "byte-for-byte match — proves FrameSeg copy fix"))))))

(deftest h2-inputstream-response-body
  ;; Streaming InputStream body → server chunks into DATA frames via
  ;; streamInputStream(). Verify byte integrity end-to-end.
  (let [payload (byte-array 40000 (unchecked-byte 42))]
    (with-h2-server
      (fn [_] {:status 200
               :body (ByteArrayInputStream. payload)})
      (fn []
        (let [client (h2-client)
              req (-> (HttpRequest/newBuilder
                       (URI/create (str "https://127.0.0.1:" *port* "/")))
                      (.version HttpClient$Version/HTTP_2)
                      .GET .build)
              resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
              body (.body resp)]
          (is (= 200 (.statusCode resp)))
          (is (= 40000 (alength body)))
          (is (every? #(= 42 (bit-and % 0xFF)) body)))))))

;; ---- Error handler on h2 -------------------------------------------------

(deftest h2-handler-throws-500
  (with-h2-server
    (fn [_] (throw (RuntimeException. "boom")))
    (fn []
      (let [resp (get! "/")]
        (is (= 500 (.statusCode resp)))))))

;; ---- HEAD via h2 ---------------------------------------------------------

(deftest h2-handler-timeout-returns-503
  ;; Handler sleeps past the configured handler-timeout. Server must
  ;; emit 503 + reset the stream. Handler interruption unblocks the
  ;; sleep so no zombie vthread lingers.
  (let [interrupted (promise)
        started (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [_]
                 (.countDown started)
                 (try (Thread/sleep 3000)
                      (catch InterruptedException _
                        (deliver interrupted true)))
                 {:status 200 :body "late"})
               {:port 0
                :http2 true
                :ssl-context (gen-server-context)
                :handler-timeout 300})]
      (try
        (binding [*port* (enso/port srv)]
          (let [resp (get! "/slow")]
            (is (= 503 (.statusCode resp))
                "expired handler → 503")
            (is (.await started 2 TimeUnit/SECONDS))
            (is (deref interrupted 2000 false) "handler vthread interrupted on timeout")))
        (finally (enso/stop srv))))))

(deftest h2-head-omits-body-but-keeps-content-length
  (with-h2-server
    (fn [_] {:status 200 :body "hello"})
    (fn []
      (let [client (h2-client)
            req (-> (HttpRequest/newBuilder
                     (URI/create (str "https://127.0.0.1:" *port* "/")))
                    (.version HttpClient$Version/HTTP_2)
                    (.method "HEAD" (HttpRequest$BodyPublishers/noBody))
                    .build)
            resp (.send client req (HttpResponse$BodyHandlers/ofString))]
        (is (= 200 (.statusCode resp)))
        (is (= "" (.body resp))
            "HEAD response body is empty on the wire")
        (is (= "5"
               (.orElse (.firstValue (.headers resp) "content-length") nil))
            "content-length reflects would-be body size")))))

;; ---- Raw-frame client ----------------------------------------------------
;; Drives the server frame-by-frame over TLS (ALPN h2) for protocol edge
;; cases java.net.http can't produce.

(def ^:private frame-data 0x0)
(def ^:private frame-headers 0x1)
(def ^:private frame-priority 0x2)
(def ^:private frame-rst 0x3)
(def ^:private frame-settings 0x4)
(def ^:private frame-ping 0x6)
(def ^:private frame-goaway 0x7)
(def ^:private frame-window-update 0x8)
(def ^:private frame-continuation 0x9)

(def ^:private flag-end-stream 0x1)
(def ^:private flag-end-headers 0x4)

(defn- u32 [^bytes b off]
  (bit-or (bit-shift-left (bit-and (aget b off) 0x7F) 24)
          (bit-shift-left (bit-and (aget b (+ off 1)) 0xFF) 16)
          (bit-shift-left (bit-and (aget b (+ off 2)) 0xFF) 8)
          (bit-and (aget b (+ off 3)) 0xFF)))

(defn- u32-bytes ^bytes [n]
  (byte-array (mapv unchecked-byte [(bit-shift-right n 24) (bit-shift-right n 16)
                                    (bit-shift-right n 8) n])))

(defn- raw-bytes ^bytes [xs]
  (byte-array (mapv unchecked-byte xs)))

(defn- write-frame! [{:keys [^java.io.OutputStream out]} type flags sid ^bytes payload]
  (let [len (alength payload)
        hdr (raw-bytes [(bit-shift-right len 16) (bit-shift-right len 8) len
                        type flags
                        (bit-shift-right sid 24) (bit-shift-right sid 16)
                        (bit-shift-right sid 8) sid])]
    (locking out
      (.write out hdr)
      (.write out payload)
      (.flush out))))

(defn- decode-block
  "Decoded header block as a vector of [name value] pairs, in wire order."
  [{:keys [^com.s_exp.enso.http2.Hpack$Decoder dec]} ^bytes block]
  (mapv (fn [^com.s_exp.enso.http2.Hpack$HeaderField hf]
          [(.name hf) (.value hf)])
        (.decode dec block 0 (alength block))))

(defn- read-frame-blocking
  "Next frame off the socket as a map, or nil on EOF / error."
  [{:keys [^java.io.InputStream in]}]
  (try
    (let [hdr (.readNBytes in 9)]
      (when (= 9 (alength hdr))
        (let [len (bit-or (bit-shift-left (bit-and (aget hdr 0) 0xFF) 16)
                          (bit-shift-left (bit-and (aget hdr 1) 0xFF) 8)
                          (bit-and (aget hdr 2) 0xFF))
              payload (.readNBytes in (int len))]
          {:type (bit-and (aget hdr 3) 0xFF)
           :flags (bit-and (aget hdr 4) 0xFF)
           :sid (u32 hdr 5)
           :payload payload})))
    (catch java.io.IOException _ nil)))

(defn- reader-loop
  "Pumps frames into the conn's queue. Header blocks (HEADERS +
  CONTINUATIONs) are decoded in order so the client HPACK state tracks
  the server's; the frame carrying END_HEADERS gets :headers. Reading
  stalls while the conn's :paused atom is true."
  [conn]
  (let [^java.util.concurrent.BlockingQueue q (:frames conn)]
    (loop [pending nil]
      (while @(:paused conn) (Thread/sleep 5))
      (when-let [delay-ms @(:read-delay-ms conn)] (Thread/sleep (long delay-ms)))
      (if-let [f (read-frame-blocking conn)]
        (let [block? (#{0x1 0x9} (:type f))
              block (when block? (byte-array (concat pending (:payload f))))
              done? (and block? (pos? (bit-and 0x4 (:flags f))))]
          (.put q (if done?
                    (let [fields (decode-block conn block)]
                      (assoc f :headers (into {} fields) :header-fields fields))
                    f))
          (recur (when (and block? (not done?)) block)))
        (.put q :eof)))))

(defn- read-frame
  "Next frame, or nil on EOF or when none arrives within `timeout-ms`
  (default 5000)."
  ([conn] (read-frame conn 5000))
  ([{:keys [^java.util.concurrent.BlockingQueue frames]} timeout-ms]
   (let [f (.poll frames timeout-ms TimeUnit/MILLISECONDS)]
     (if (= :eof f)
       (do (.put frames :eof) nil)
       f))))

(defn- read-until
  "Reads frames until `pred` matches (returns that frame) or the
  connection ends / goes quiet for `timeout-ms` (returns nil). Every
  frame seen is conj'd to `seen` when supplied."
  ([conn pred] (read-until conn pred nil 5000))
  ([conn pred seen] (read-until conn pred seen 5000))
  ([conn pred seen timeout-ms]
   (loop []
     (when-let [f (read-frame conn timeout-ms)]
       (when seen (swap! seen conj f))
       (if (pred f) f (recur))))))

(defn- eof-within?
  "True when the server closes the connection within `ms`, whatever frames
  (a graceful close's GOAWAY / PING, the tail of a response) come first."
  [{:keys [^java.util.concurrent.BlockingQueue frames]} ms]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (let [left (- deadline (System/currentTimeMillis))
            f (when (pos? left) (.poll frames left TimeUnit/MILLISECONDS))]
        (cond
          (= :eof f) (do (.put frames :eof) true)
          (nil? f) false
          :else (recur))))))

(defn- drain-frames
  "All frames that arrive until the connection goes quiet for
  `quiet-ms` or ends."
  [conn quiet-ms]
  (let [seen (atom [])]
    (read-until conn (constantly false) seen quiet-ms)
    @seen))

(defn- goaway-code [f]
  (u32 (:payload f) 4))

(defn- rst-code [f]
  (u32 (:payload f) 0))

(defn- tls-h2-socket
  "TLS socket to the server with ALPN h2 negotiated, nothing sent yet."
  ^javax.net.ssl.SSLSocket []
  (let [factory (.getSocketFactory (trust-all-context))
        ^javax.net.ssl.SSLSocket sock (.createSocket factory "127.0.0.1" (int *port*))
        params (.getSSLParameters sock)]
    ;; As real h2 clients do: with Nagle on, a small frame written right
    ;; after another waits for the server's (delayed, up to 40 ms on
    ;; Linux) ACK, which skews every timing a test observes.
    (.setTcpNoDelay sock true)
    (.setApplicationProtocols params (into-array String ["h2"]))
    (.setSSLParameters sock params)
    (.startHandshake sock)
    sock))

(defn- h2-connect-on!
  "Starts HTTP/2 on the connected `sock`: preface (unless `preface?` is
  false: already sent), client SETTINGS (`settings` is a seq of [id
  value]). Returns a conn map; the server's SETTINGS / ACK frames are
  left on the wire."
  ([sock settings] (h2-connect-on! sock settings true))
  ([^java.net.Socket sock settings preface?]
   (let [conn {:sock sock
               :frames (java.util.concurrent.LinkedBlockingQueue.)
               :paused (atom false)
               :read-delay-ms (atom nil)
               :in (java.io.BufferedInputStream. (.getInputStream sock))
               :out (java.io.BufferedOutputStream. (.getOutputStream sock))
               :enc (com.s_exp.enso.http2.Hpack$Encoder. 4096)
               :dec (com.s_exp.enso.http2.Hpack$Decoder. 4096)}
         ^java.io.OutputStream out (:out conn)]
     (when preface?
       (.write out (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1)))
     (write-frame! conn frame-settings 0 0
                   (byte-array (mapcat (fn [[id v]]
                                         (concat [(unchecked-byte (bit-shift-right id 8))
                                                  (unchecked-byte id)]
                                                 (u32-bytes v)))
                                       settings)))
     (.start (Thread. (fn [] (reader-loop conn))))
     conn)))

(defn- h2-connect!
  "Opens a raw h2 connection over TLS + ALPN h2 (see h2-connect-on!)."
  ([] (h2-connect! []))
  ([settings] (h2-connect-on! (tls-h2-socket) settings)))

(defn- close-conn!
  "Closes the connection; a paused reader resumes, sees the end and exits
  (a parked one would keep the JVM alive)."
  [{:keys [^java.net.Socket sock paused]}]
  (.close sock)
  (some-> paused (reset! false)))

(defn- header-block
  "HPACK-encodes `pairs` with the connection's encoder."
  ^bytes [{:keys [^com.s_exp.enso.http2.Hpack$Encoder enc]} pairs]
  (let [l (java.util.ArrayList.)]
    (doseq [[k v] pairs]
      (.add l (com.s_exp.enso.http2.Hpack$HeaderField. k v)))
    (.encode enc l)))

(defn- request-headers
  ([method path] (request-headers method path []))
  ([method path extra]
   (into [[":method" method] [":scheme" "https"] [":path" path]
          [":authority" "localhost"]]
         extra)))

(defn- send-request!
  "HEADERS (END_HEADERS) for `sid`; END_STREAM when `end-stream`."
  [conn sid pairs end-stream]
  (write-frame! conn frame-headers
                (bit-or flag-end-headers (if end-stream flag-end-stream 0))
                sid (header-block conn pairs)))

(defn- response-on
  "Reads until the response HEADERS for `sid`; returns decoded headers."
  [conn sid]
  (:headers (read-until conn #(and (= frame-headers (:type %)) (= sid (:sid %))))))

(defmacro ^:private with-conn
  "Binds `conn` to a fresh raw h2 connection for `body`, closing it after."
  [[conn settings] & body]
  `(let [~conn (h2-connect! ~(or settings []))]
     (try ~@body (finally (close-conn! ~conn)))))

(defn- frame-bytes
  "One frame as bytes, for building a burst written in a single call."
  ^bytes [type flags sid ^bytes payload]
  (let [len (alength payload)]
    (byte-array (concat (map unchecked-byte [(bit-shift-right len 16) (bit-shift-right len 8) len
                                             type flags
                                             (bit-shift-right sid 24) (bit-shift-right sid 16)
                                             (bit-shift-right sid 8) sid])
                        payload))))

(defn- write-raw! [{:keys [^java.io.OutputStream out]} ^bytes bytes]
  (locking out
    (.write out bytes)
    (.flush out)))

(defn- send-split-headers!
  "Header block `block` for `sid` as HEADERS + CONTINUATION frames of at
  most 16384 bytes."
  [conn sid ^bytes block end-stream]
  (let [n (alength block)
        pieces (partition-all 16384 (seq block))
        last-i (dec (count pieces))]
    (doseq [[i piece] (map-indexed vector pieces)]
      (write-frame! conn (if (zero? i) frame-headers frame-continuation)
                    (bit-or (if (= i last-i) flag-end-headers 0)
                            (if (and (zero? i) end-stream) flag-end-stream 0))
                    sid (byte-array piece)))
    n))

(defn- ping-ack? [f]
  (and (= frame-ping (:type f)) (pos? (bit-and 0x1 (:flags f)))))

(defn- ping-round-trip!
  "Sends a PING and waits for its ACK: every frame sent before it has
  been handled by the server."
  [conn]
  (write-frame! conn frame-ping 0 0 (byte-array 8))
  (read-until conn ping-ack?))

(defn- data-bytes-on [frames sid]
  (reduce + 0 (map #(alength ^bytes (:payload %))
                   (filter #(and (= frame-data (:type %)) (= sid (:sid %))) frames))))

(defn- end-stream-on [sid]
  #(and (#{frame-data frame-headers} (:type %)) (= sid (:sid %))
        (pos? (bit-and flag-end-stream (:flags %)))))

(defmacro ^:private with-server
  "Runs `body` with *port* bound to a TLS h2 server for `handler` and
  extra run-server `opts`, stopping it afterwards."
  [handler opts & body]
  `(let [srv# (enso/run-server ~handler (merge {:port 0 :http2 true :ssl-context (gen-server-context)} ~opts))]
     (try
       (binding [*port* (enso/port srv#)] ~@body)
       (finally (enso/stop srv#)))))

(deftest h2-raw-client-get
  (with-h2-server
    (fn [_] {:status 200 :body "raw"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (= "200" (get (response-on conn 1) ":status")))))))

(deftest h2-hpack-integer-overflow-is-compression-error
  (with-h2-server
    (fn [_] {:status 200 :body "ok"})
    (fn []
      (with-conn [conn]
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                      (raw-bytes [0x00 0x01 0x61 0x7F 0xFF 0xFF 0xFF 0xFF 0x08]))
        (let [ga (read-until conn #(= frame-goaway (:type %)))]
          (is (some? ga) "GOAWAY sent")
          (is (= 0x9 (some-> ga goaway-code)) "COMPRESSION_ERROR"))))))

;; ---- Flow control --------------------------------------------------------

(deftest h2-upload-larger-than-default-connection-window
  ;; RFC 9113 §6.9.2: the connection window starts at 65535 regardless of
  ;; SETTINGS_INITIAL_WINDOW_SIZE. A 256 KiB upload only completes if the
  ;; server grows / replenishes the connection window it actually has.
  (let [payload (apply str (repeat (* 256 1024) "x"))]
    (with-h2-server
      (fn [req] {:status 200 :body (str (count (slurp (:body req))))})
      (fn []
        (let [client (h2-client)
              req (-> (HttpRequest/newBuilder
                       (URI/create (str "https://127.0.0.1:" *port* "/up")))
                      (.version HttpClient$Version/HTTP_2)
                      (.POST (HttpRequest$BodyPublishers/ofString payload))
                      .build)
              resp (try (.get (.sendAsync client req (HttpResponse$BodyHandlers/ofString))
                              10 TimeUnit/SECONDS)
                        (catch java.util.concurrent.TimeoutException _ nil))]
          (is (some? resp) "upload did not stall")
          (is (= (str (count payload)) (some-> resp .body))))))))

(defn- send-data!
  "Sends `n` zero bytes on `sid` as DATA frames of at most 16384 bytes."
  [conn sid n end-stream]
  (loop [left n]
    (let [chunk (min left 16384)
          last? (= chunk left)]
      (write-frame! conn frame-data (if (and last? end-stream) flag-end-stream 0)
                    sid (byte-array chunk))
      (when-not last? (recur (- left chunk))))))

(defn- window-updates [frames sid]
  (filter #(and (= frame-window-update (:type %)) (= sid (:sid %))) frames))

(deftest h2-receive-credit-returned-on-consumption
  ;; Flow-control credit must track what the handler has consumed, not
  ;; what arrived: otherwise a non-reading handler lets a fast uploader
  ;; buffer unbounded memory on the server.
  (let [release (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [req]
                 (.await release 10 TimeUnit/SECONDS)
                 {:status 200
                  :body (str (alength (.readNBytes ^java.io.InputStream (:body req) 65535)))})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-initial-window-bytes 65535})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            ;; Handshake frames, including the connection window growth.
            (drain-frames conn 300)
            (send-request! conn 1 (request-headers "POST" "/up") false)
            (send-data! conn 1 65535 false)
            (let [before (drain-frames conn 500)]
              (is (empty? (window-updates before 1))
                  "no stream credit while the handler hasn't read")
              (is (empty? (window-updates before 0))
                  "no connection credit while the handler hasn't read"))
            (.countDown release)
            (let [seen (atom [])]
              (read-until conn #(and (= frame-headers (:type %)) (= 1 (:sid %))) seen)
              (swap! seen into (drain-frames conn 300))
              (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
              (is (seq (window-updates @seen 0))
                  "connection credit returned once consumed"))))
        (finally (enso/stop srv))))))

;; ---- HEADERS processing --------------------------------------------------

(defn- frame-on [sid type]
  #(and (= type (:type %)) (= sid (:sid %))))

(deftest h2-refused-stream-still-decodes-hpack
  ;; A HEADERS block refused for MAX_CONCURRENT_STREAMS must still be
  ;; HPACK-decoded, otherwise the dynamic-table entries it inserts are
  ;; missing from the server's view and later blocks decode wrongly.
  (let [release (CountDownLatch. 1)
        blocking (CountDownLatch. 1)
        seen-header (atom nil)]
    (let [srv (enso/run-server
               (fn [req]
                 (if (= "/block" (:uri req))
                   (do (.countDown blocking) (.await release 10 TimeUnit/SECONDS))
                   (reset! seen-header (get-in req [:headers "x-a"])))
                 {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 1})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/block") true)
            (.await blocking 5 TimeUnit/SECONDS)
            (send-request! conn 3 (request-headers "GET" "/x" [["x-a" "secret"]]) true)
            (let [rst (read-until conn (frame-on 3 frame-rst))]
              (is (= 0x7 (some-> rst rst-code)) "REFUSED_STREAM"))
            (.countDown release)
            (is (= "200" (get (response-on conn 1) ":status")))
            (send-request! conn 5 (request-headers "GET" "/x" [["x-a" "secret"]]) true)
            (is (= "200" (get (response-on conn 5) ":status")))
            (is (= "secret" @seen-header))))
        (finally (enso/stop srv))))))

(deftest h2-self-dependent-headers-still-decodes-hpack
  (let [seen-header (atom nil)]
    (with-h2-server
      (fn [req] (reset! seen-header (get-in req [:headers "x-a"]))
        {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (let [block (header-block conn (request-headers "GET" "/" [["x-a" "secret"]]))
                prio (byte-array (concat (u32-bytes 1) [(unchecked-byte 15)]))]
            ;; PRIORITY flag (0x20), dependency on itself.
            (write-frame! conn frame-headers (bit-or 0x20 flag-end-headers flag-end-stream) 1
                          (byte-array (concat prio block))))
          (let [rst (read-until conn (frame-on 1 frame-rst))]
            (is (= 0x1 (some-> rst rst-code)) "PROTOCOL_ERROR stream error"))
          (send-request! conn 3 (request-headers "GET" "/" [["x-a" "secret"]]) true)
          (is (= "200" (get (response-on conn 3) ":status")))
          (is (= "secret" @seen-header)))))))

(deftest h2-trailers-not-refused-at-concurrency-limit
  ;; Trailers belong to an existing stream; the MAX_CONCURRENT_STREAMS
  ;; check only applies to new streams.
  (let [srv (enso/run-server
             (fn [req] {:status 200 :body (slurp (:body req))})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :http2-max-concurrent-streams 1})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (write-frame! conn frame-data 0 1 (.getBytes "abc"))
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                        (header-block conn [["x-trailer" "t"]]))
          (let [seen (atom [])]
            (read-until conn #(and (= 1 (:sid %))
                                   (or (= frame-rst (:type %))
                                       (= frame-headers (:type %))))
                        seen)
            (is (not-any? #(= frame-rst (:type %)) @seen) "no RST on trailers")
            (is (= "200" (some #(get-in % [:headers ":status"]) @seen))))))
      (finally (enso/stop srv)))))

(deftest h2-stalled-upload-leaves-connection-window-for-others
  ;; A handler that never reads its body holds a full stream window of
  ;; credit; the connection window must be larger so other streams on the
  ;; connection can still upload.
  (let [release (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [req]
                 (if (= "/stall" (:uri req))
                   (.await release 10 TimeUnit/SECONDS)
                   (slurp (:body req)))
                 {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-initial-window-bytes 65535})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/stall") false)
            (send-data! conn 1 65535 false)
            (send-request! conn 3 (request-headers "POST" "/up") false)
            (send-data! conn 3 1000 true)
            (let [seen (atom [])]
              (read-until conn (frame-on 3 frame-headers) seen)
              (is (not-any? #(= frame-goaway (:type %)) @seen) "no GOAWAY")
              (is (= "200" (some #(get-in % [:headers ":status"]) @seen))))
            (.countDown release)))
        (finally (enso/stop srv))))))

;; ---- Closed-stream DATA --------------------------------------------------

(deftest h2-data-after-early-response-keeps-connection
  ;; Handler answers without reading the body. The client's in-flight
  ;; DATA on the now-closed stream must not kill the connection, and the
  ;; server asks the client to stop with RST_STREAM(NO_ERROR) (§8.1).
  (with-h2-server
    (fn [_] {:status 200 :body "early"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (let [seen (atom [])]
          (read-until conn (frame-on 1 frame-rst) seen)
          (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
          (is (= 0x0 (some-> (last @seen) rst-code)) "RST_STREAM(NO_ERROR)"))
        (send-data! conn 1 1000 true)
        (send-request! conn 3 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (read-until conn (frame-on 3 frame-headers) seen)
          (is (not-any? #(= frame-goaway (:type %)) @seen) "no GOAWAY")
          (is (= "200" (some #(get-in % [:headers ":status"]) @seen))))))))

(deftest h2-trailers-after-early-response-keep-connection
  ;; §5.1: frames the client had in flight when we reset the stream are
  ;; ignored. Its trailer block still updates the HPACK state, so a later
  ;; request referencing that dynamic-table entry decodes correctly.
  (let [seen-header (atom nil)]
    (with-h2-server
      (fn [req] (reset! seen-header (get-in req [:headers "x-a"])) {:status 200 :body "early"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (is (= 0x0 (some-> (read-until conn (frame-on 1 frame-rst)) rst-code))
              "RST_STREAM(NO_ERROR) after the early response")
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                        (header-block conn [["x-a" "secret"]]))
          (send-request! conn 3 (request-headers "GET" "/" [["x-a" "secret"]]) true)
          (let [seen (atom [])]
            (read-until conn (frame-on 3 frame-headers) seen)
            (is (not-any? #(= frame-goaway (:type %)) @seen) "no GOAWAY")
            (is (= "200" (some #(get-in % [:headers ":status"]) @seen))))
          (is (= "secret" @seen-header)))))))

(deftest h2-trailers-on-stream-ignored-after-goaway
  ;; A stream above our GOAWAY's last-stream-id is ignored (§6.8), its
  ;; trailers too; the stream still in flight must complete.
  (let [started (CountDownLatch. 1)
        srv (enso/run-server
             (fn [req] (.countDown started) {:status 200 :body (slurp (:body req))})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :shutdown-timeout 5000})]
    (binding [*port* (enso/port srv)]
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (.await started 5 TimeUnit/SECONDS)
        (future (enso/stop srv))
        ;; Graceful shutdown is two-phase (§6.8): GOAWAY(2^31-1) + PING,
        ;; then the real last stream id once the PING is answered.
        (is (some? (read-until conn #(= frame-goaway (:type %)))))
        (let [ping (read-until conn #(and (= frame-ping (:type %)) (zero? (:flags %))))]
          (write-frame! conn frame-ping 0x1 0 (:payload ping)))
        (is (= 1 (some-> (read-until conn #(= frame-goaway (:type %))) :payload (u32 0))))
        (send-request! conn 3 (request-headers "POST" "/") false)
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 3
                      (header-block conn [["x-trailer" "t"]]))
        (write-frame! conn frame-data flag-end-stream 1 (.getBytes "done"))
        (let [seen (atom [])]
          (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                 (pos? (bit-and flag-end-stream (:flags %))))
                      seen)
          (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
          (is (= "done" (apply str (map #(String. ^bytes (:payload %))
                                        (filter #(= frame-data (:type %)) @seen))))))))))

(deftest h2-data-on-refused-stream-credits-connection
  ;; DATA on a refused stream is dropped, but its bytes still count
  ;; against (and must be returned to) the connection window.
  (let [release (CountDownLatch. 1)
        blocking (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [req]
                 (when (= "/block" (:uri req))
                   (.countDown blocking)
                   (.await release 10 TimeUnit/SECONDS))
                 {:status 200 :body (some-> (:body req) slurp)})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 1
                :http2-initial-window-bytes 65535})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/block") true)
            (.await blocking 5 TimeUnit/SECONDS)
            (send-request! conn 3 (request-headers "POST" "/x") false)
            (is (= 0x7 (some-> (read-until conn (frame-on 3 frame-rst)) rst-code)))
            (send-data! conn 3 65535 true)
            (.countDown release)
            (is (= "200" (get (response-on conn 1) ":status")))
            (send-request! conn 5 (request-headers "POST" "/x") false)
            (send-data! conn 5 100 true)
            (let [seen (atom [])]
              (read-until conn (frame-on 5 frame-headers) seen)
              (is (not-any? #(= frame-goaway (:type %)) @seen) "no GOAWAY")
              (is (= "200" (some #(get-in % [:headers ":status"]) @seen))))))
        (finally (enso/stop srv))))))

;; ---- Reset streams surface to the handler --------------------------------

(defn- streaming-until-error
  "Streaming body that writes `chunk` + flush forever, delivering the
  exception that stops it to `p`."
  [p ^String chunk]
  (fn [w]
    (try
      (loop []
        (enso/write! w chunk)
        (enso/flush! w)
        (Thread/sleep 5)
        (recur))
      (catch Throwable t (deliver p t) (throw t)))))

(deftest h2-peer-reset-stops-streaming-handler
  (let [p (promise)]
    (with-h2-server
      (fn [_] {:status 200 :body (streaming-until-error p "data: x\n\n")})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/sse") true)
          (is (some? (read-until conn (frame-on 1 frame-data))))
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          (is (instance? Exception (deref p 3000 nil))
              "handler stops once the peer reset the stream: interrupted, or its write fails")
          (is (or (instance? java.io.IOException @p) (instance? InterruptedException @p))))))))

(deftest h2-peer-reset-fails-body-read
  ;; A body cut short by RST_STREAM is not a complete body: the handler's
  ;; read fails instead of reaching EOF.
  ;; (A stream reset before its handler starts is never served at all.)
  (let [p (promise)
        started (CountDownLatch. 1)]
    (with-h2-server
      (fn [req]
        (.countDown started)
        (deliver p (try (slurp (:body req)) :eof (catch java.io.IOException _ :error)))
        {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (write-frame! conn frame-data 0 1 (.getBytes "partial"))
          (is (.await started 5 TimeUnit/SECONDS))
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          (is (= :error (deref p 3000 :timeout))))))))

(defn- read-twice
  "Reads `in` to the end twice, returning how each attempt ended."
  [^java.io.InputStream in]
  (letfn [(attempt [] (try (slurp in) :eof (catch java.io.IOException e (class e))))]
    (let [first-attempt (attempt)]
      ;; A reset also interrupts the handler: clear it to wait below.
      (Thread/interrupted)
      [first-attempt (deref (future (attempt)) 2000 :blocked)])))

(deftest h2-failed-body-keeps-failing
  ;; Once a body read has failed, later reads fail the same way rather
  ;; than blocking on a queue nothing will fill again.
  (testing "body over max-request-body-bytes"
    (let [p (promise)
          started (CountDownLatch. 1)
          srv (enso/run-server
               (fn [req]
                 (.countDown started)
                 (deliver p (read-twice (:body req)))
                 {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :max-request-body-bytes 1000})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/") false)
            ;; A body already over the cap when the handler would start
            ;; is answered 413 without running it.
            (.await started 5 TimeUnit/SECONDS)
            (send-data! conn 1 5000 true)
            (let [too-large com.s_exp.enso.core.RequestBodyException]
              (is (= [too-large too-large] (deref p 5000 :timeout))))))
        (finally (enso/stop srv)))))
  (testing "body aborted by RST_STREAM"
    (let [p (promise)
          started (CountDownLatch. 1)]
      (with-h2-server
        (fn [req] (.countDown started) (deliver p (read-twice (:body req))) {:status 200 :body "ok"})
        (fn []
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/") false)
            (is (.await started 5 TimeUnit/SECONDS))
            (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
            (is (every? #(isa? % java.io.IOException) (deref p 5000 [:timeout])))))))))

(deftest h2-no-response-headers-on-reset-stream
  ;; §5.1: nothing but PRIORITY may be sent on a closed stream, so a
  ;; response finishing after the peer's RST_STREAM is dropped.
  (let [release (CountDownLatch. 1)]
    (with-h2-server
      (fn [req]
        (when (= "/slow" (:uri req)) (.await release 5 TimeUnit/SECONDS))
        {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/slow") true)
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          ;; The framer handles frames in order: once the PING is answered
          ;; the reset has been processed.
          (write-frame! conn frame-ping 0 0 (byte-array 8))
          (is (some? (read-until conn #(and (= frame-ping (:type %)) (pos? (:flags %))))))
          (.countDown release)
          (send-request! conn 3 (request-headers "GET" "/") true)
          (let [seen (atom [])]
            (read-until conn (frame-on 3 frame-headers) seen)
            (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
            (is (not-any? #(= 1 (:sid %)) @seen) "nothing sent on the reset stream")))))))

(deftest h2-peer-reset-wakes-handler-blocked-on-flow-control
  ;; Client advertises a zero stream window, so the handler parks waiting
  ;; for credit; RST_STREAM must wake it with an error.
  (let [p (promise)]
    (with-h2-server
      (fn [_] {:status 200 :body (streaming-until-error p "x")})
      (fn []
        (with-conn [conn [[0x4 0]]]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (is (some? (read-until conn (frame-on 1 frame-headers))))
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          (is (instance? java.io.IOException (deref p 3000 nil))
              "parked handler woken with an error"))))))

;; ---- Outbound framing ----------------------------------------------------

(deftest h2-data-frames-capped-despite-large-peer-max-frame-size
  ;; A peer advertising MAX_FRAME_SIZE 2^24-1 must not make the server
  ;; build multi-megabyte frames / scratch buffers.
  (let [payload (byte-array (* 200 1024))]
    (with-h2-server
      (fn [_] {:status 200 :body payload})
      (fn []
        ;; MAX_FRAME_SIZE = 2^24-1, INITIAL_WINDOW_SIZE = 1 MiB.
        (with-conn [conn [[0x5 16777215] [0x4 (* 1024 1024)]]]
          (write-frame! conn frame-window-update 0 0 (u32-bytes (* 1024 1024)))
          (send-request! conn 1 (request-headers "GET" "/") true)
          (let [seen (atom [])]
            (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                   (pos? (bit-and flag-end-stream (:flags %))))
                        seen)
            (let [data (filter #(= frame-data (:type %)) @seen)]
              (is (= (alength payload) (reduce + (map #(alength ^bytes (:payload %)) data))))
              (is (every? #(<= (alength ^bytes (:payload %)) 16384) data)))))))))

(deftest h2-frame-larger-than-writer-buffer-intact
  ;; With a large peer MAX_FRAME_SIZE a header block goes out as one
  ;; HEADERS frame bigger than the writer's coalescing buffer.
  (let [big (apply str (repeat (* 40 1024) "h"))]
    (with-h2-server
      (fn [_] {:status 200 :headers {"x-big" big} :body "ok"})
      (fn []
        (with-conn [conn [[0x5 16777215]]]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (let [f (read-until conn (frame-on 1 frame-headers))]
            (is (= big (get (:headers f) "x-big")))
            (is (> (alength ^bytes (:payload f)) (* 32 1024)) "sent as one frame"))
          (send-request! conn 3 (request-headers "GET" "/") true)
          (is (= "200" (get (response-on conn 3) ":status"))))))))

(deftest h2-response-write-failure-resets-stream
  ;; A header value whose toString throws is a handler error caught while
  ;; preparing the response: 500, as on HTTP/1.1. A body that fails once
  ;; its headers are out can only be cut: RST_STREAM(INTERNAL_ERROR). The
  ;; connection is kept either way.
  (with-h2-server
    (fn [req]
      (case (:uri req)
        "/header" {:status 200
                   :headers {"x-bad" (reify Object (toString [_] (throw (RuntimeException. "bad"))))}
                   :body "ok"}
        "/body" {:status 200
                 :body (fn [w]
                         (enso/write! w "partial")
                         (enso/flush! w)
                         (throw (RuntimeException. "body failed")))}))
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/header") true)
        (is (= "500" (get (response-on conn 1) ":status")))
        (send-request! conn 3 (request-headers "GET" "/body") true)
        (let [rst (read-until conn (frame-on 3 frame-rst))]
          (is (= 0x2 (some-> rst rst-code)) "RST_STREAM(INTERNAL_ERROR)"))
        (is (nil? (read-until conn #(= frame-goaway (:type %)) nil 300))
            "connection kept")))))

(defn- open-windows!
  "Grows the connection window to the maximum (streams via SETTINGS)."
  [conn]
  (write-frame! conn frame-window-update 0 0 (u32-bytes (- 0x7FFFFFFF 65535))))

(deftest h2-header-block-not-interleaved-with-other-frames
  ;; §4.3: a header block split over HEADERS + CONTINUATION must be
  ;; contiguous on the wire, even while another stream emits DATA.
  (let [big (apply str (repeat (* 40 1024) "h"))
        stop (promise)]
    (with-h2-server
      (fn [req]
        (if (= "/stream" (:uri req))
          ;; Endless InputStream body: DATA frames enqueued back to back.
          {:status 200
           :body (proxy [java.io.InputStream] []
                   (read
                     ([] 100)
                     ([^bytes b] (if (realized? stop) -1 (alength b)))
                     ([^bytes b off len]
                      (if (realized? stop) -1 len))))}
          {:status 200 :headers {"x-big" big} :body "ok"}))
      (fn []
        (with-conn [conn [[0x4 0x7FFFFFFF]]]
          (open-windows! conn)
          (send-request! conn 1 (request-headers "GET" "/stream") true)
          (read-until conn (frame-on 1 frame-data))
          ;; Stop reading so the server's socket and write queue back up;
          ;; header-block writers then contend with the DATA producer.
          (reset! (:paused conn) true)
          (doseq [i (range 10)]
            (send-request! conn (+ 3 (* 2 i)) (request-headers "GET" "/big") true))
          ;; A PING round trip once reading resumes: the requests above
          ;; have all been taken by the framer.
          (write-frame! conn frame-ping 0 0 (byte-array 8))
          (reset! (:paused conn) false)
          (let [seen (atom [])
                answered (atom 0)]
            (read-until conn #(and (:headers %) (> (:sid %) 1) (= 10 (swap! answered inc))) seen)
            (deliver stop true)
            (let [violations (->> (partition 2 1 @seen)
                                  (filter (fn [[a b]]
                                            (and (#{frame-headers frame-continuation} (:type a))
                                                 (zero? (bit-and flag-end-headers (:flags a)))
                                                 (not (and (= frame-continuation (:type b))
                                                           (= (:sid a) (:sid b))))))))]
              (is (empty? violations) "only CONTINUATION follows an open header block")
              (is (= 10 (count (filter #(and (:headers %) (= "200" (get (:headers %) ":status"))
                                             (odd? (:sid %)) (> (:sid %) 1))
                                       @seen)))))))))))

(deftest h2-peer-that-stops-reading-is-cut-off
  ;; A peer that stops reading stalls the server's writes; once nothing
  ;; has been written for :write-timeout the connection is aborted instead
  ;; of holding its handler, writer and socket forever.
  (let [payload (byte-array (* 32 1024 1024))]
    (let [srv (enso/run-server
               (fn [_] {:status 200 :body payload})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :write-timeout 500})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn [[0x4 0x7FFFFFFF]]]
            (open-windows! conn)
            (send-request! conn 1 (request-headers "GET" "/") true)
            (reset! (:paused conn) true)
            (Thread/sleep 2500)
            (reset! (:paused conn) false)
            (is (nil? (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                             (pos? (bit-and flag-end-stream (:flags %))))))
                "response cut off rather than completed")))
        (finally (enso/stop srv))))))

;; ---- GOAWAY --------------------------------------------------------------

(deftest h2-peer-goaway-lets-in-flight-streams-finish
  ;; A client GOAWAY announces no new streams; existing ones still
  ;; complete (§6.8).
  (let [started (CountDownLatch. 1)
        release (CountDownLatch. 1)]
    (with-h2-server
      (fn [_] (.countDown started) (.await release 5 TimeUnit/SECONDS) {:status 200 :body "done"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (.await started 5 TimeUnit/SECONDS)
          (write-frame! conn frame-goaway 0 0 (byte-array 8))
          ;; Frames are handled in order: the PING ACK means the GOAWAY
          ;; was seen while the handler still runs.
          (write-frame! conn frame-ping 0 0 (byte-array 8))
          (is (some? (read-until conn #(and (= frame-ping (:type %)) (pos? (:flags %))))))
          (.countDown release)
          (let [seen (atom [])]
            (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                   (pos? (bit-and flag-end-stream (:flags %))))
                        seen)
            (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
            (is (= "done" (apply str (map #(String. ^bytes (:payload %))
                                          (filter #(= frame-data (:type %)) @seen))))))
          (is (eof-within? conn 2000) "server closes once drained"))))))

;; ---- Rapid reset ---------------------------------------------------------

(deftest h2-reset-streams-still-count-while-handler-runs
  ;; CVE-2023-44487: a reset interrupts the stream's handler, but one that
  ;; ignores the interrupt keeps running, so the concurrency limit counts
  ;; running handlers, not just open streams.
  (let [release (CountDownLatch. 1)
        started (java.util.concurrent.Semaphore. 0)
        await-ignoring-interrupts (fn [^CountDownLatch l]
                                    (loop []
                                      (when-not (try (.await l 10 TimeUnit/SECONDS)
                                                     (catch InterruptedException _ false))
                                        (when (pos? (.getCount l)) (recur)))))]
    (let [srv (enso/run-server
               (fn [_] (.release started) (await-ignoring-interrupts release) {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 2})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (doseq [sid [1 3]]
              (send-request! conn sid (request-headers "GET" "/") true)
              (.tryAcquire started 5 TimeUnit/SECONDS)
              (write-frame! conn frame-rst 0 sid (u32-bytes 0x8)))
            (send-request! conn 5 (request-headers "GET" "/") true)
            (is (= 0x7 (some-> (read-until conn (frame-on 5 frame-rst) nil 1000) rst-code))
                "REFUSED_STREAM while both reset handlers still run")
            (.countDown release)))
        (finally (enso/stop srv))))))

(defn- request-and-reset! [conn sids]
  (doseq [sid sids]
    (send-request! conn sid (request-headers "GET" "/") true)
    (write-frame! conn frame-rst 0 sid (u32-bytes 0x8))))

(deftest h2-reset-limit-is-a-rate
  ;; Long-lived connections (browsers cancel requests routinely) must not
  ;; be killed by a lifetime RST_STREAM count; only a burst over the
  ;; budget is (budget refills at limit per 30 s).
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :http2-stream-reset-limit 30})]
    (try
      (binding [*port* (enso/port srv)]
        (testing "spread out resets are fine"
          (with-conn [conn]
            (request-and-reset! conn (range 1 61 2))
            (Thread/sleep 2100)
            (request-and-reset! conn [61])
            (is (nil? (read-until conn #(= frame-goaway (:type %)) nil 500)))))
        (testing "a burst over the budget is cut off"
          (with-conn [conn]
            ;; The server may close mid-burst.
            (try (request-and-reset! conn (range 1 65 2))
                 (catch java.io.IOException _))
            (let [ga (read-until conn #(= frame-goaway (:type %)))]
              (is (= 0xb (some-> ga goaway-code)) "ENHANCE_YOUR_CALM")))))
      (finally (enso/stop srv)))))

;; ---- Idle timeout --------------------------------------------------------

(deftest h2-idle-timeout-spares-busy-connections
  ;; :idle-timeout is about idle connections; a handler that takes longer
  ;; than it (quiet SSE, slow backend) must still get its response out.
  (let [srv (enso/run-server
             (fn [_] (Thread/sleep 1500) {:status 200 :body "slow"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :idle-timeout 500})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (is (= "200" (get (response-on conn 1) ":status")))))
      (finally (enso/stop srv)))))

(deftest h2-silent-client-before-preface-is-closed
  ;; A client that negotiates h2 then never sends the preface must not
  ;; hold the connection open forever.
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :idle-timeout 300})]
    (try
      (binding [*port* (enso/port srv)]
        (let [sock (tls-h2-socket)]
          (try
            (.setSoTimeout sock 3000)
            ;; The server's SETTINGS may come first.
            (is (= -1 (try (loop [] (if (neg? (.read (.getInputStream sock))) -1 (recur)))
                           (catch java.net.SocketTimeoutException _ :timeout)
                           (catch java.io.IOException _ -1)))
                "server closed the connection")
            (finally (.close sock)))))
      (finally (enso/stop srv)))))

(deftest h2-idle-connection-closed-with-goaway
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :idle-timeout 500})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (is (= "200" (get (response-on conn 1) ":status")))
          (let [ga (read-until conn #(= frame-goaway (:type %)) nil 3000)]
            (is (= 0x0 (some-> ga goaway-code)) "GOAWAY(NO_ERROR) when idle"))))
      (finally (enso/stop srv)))))

(deftest h2-server-stop-sends-goaway-and-drains
  ;; Stopping the server announces GOAWAY(NO_ERROR) and lets the in-flight
  ;; stream finish before closing, well inside :shutdown-timeout.
  (let [started (CountDownLatch. 1)
        srv (enso/run-server
             (fn [_] (.countDown started) (Thread/sleep 500) {:status 200 :body "done"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :shutdown-timeout 5000})]
    (binding [*port* (enso/port srv)]
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (.await started 5 TimeUnit/SECONDS)
        (let [t0 (System/nanoTime)
              stopped (future (enso/stop srv) (/ (- (System/nanoTime) t0) 1e6))
              seen (atom [])]
          (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                 (pos? (bit-and flag-end-stream (:flags %))))
                      seen)
          (is (= 0x0 (some->> @seen (filter #(= frame-goaway (:type %))) first goaway-code))
              "GOAWAY(NO_ERROR) announced")
          (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
          (is (= "done" (apply str (map #(String. ^bytes (:payload %))
                                        (filter #(= frame-data (:type %)) @seen)))))
          (is (eof-within? conn 3000) "server closes once drained")
          (is (< (deref stopped 6000 Double/MAX_VALUE) 3000) "stop doesn't wait out the timeout"))))))

;; ---- WebSocket over h2 ---------------------------------------------------

(deftest h2-websocket-response-is-501
  ;; RFC 9113 §8.6: 101 is not allowed over HTTP/2 (no RFC 8441 support),
  ;; so a WebSocket response is answered with the server's own 501.
  (with-h2-server
    (fn [_] {:ring.websocket/listener {:on-open (fn [_])}})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/ws") true)
        (let [seen (atom [])
              f (read-until conn (frame-on 1 frame-headers))]
          (is (= "501" (get (:headers f) ":status")))
          (read-until conn (end-stream-on 1) seen)
          (is (= "Not Implemented" (String. ^bytes (byte-array (mapcat :payload (filter (frame-on 1 frame-data) @seen)))))
              "the shared error body"))))))

;; ---- Empty DATA ----------------------------------------------------------

(deftest h2-empty-data-never-triggers-zero-window-update
  ;; WINDOW_UPDATE with a 0 increment is a PROTOCOL_ERROR for the peer.
  (with-h2-server
    (fn [req] {:status 200 :body (slurp (:body req))})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (dotimes [_ 3] (write-frame! conn frame-data 0 1 (byte-array 0)))
        (write-frame! conn frame-data flag-end-stream 1 (byte-array 0))
        (let [seen (atom [])]
          (read-until conn (frame-on 1 frame-headers) seen)
          (swap! seen into (drain-frames conn 300))
          (is (not-any? #(and (= frame-window-update (:type %))
                              (zero? (u32 (:payload %) 0)))
                        @seen)))))))

(deftest h2-empty-data-flood-is-cut-off
  ;; CVE-2019-9518: a stream of empty non-final DATA frames costs the
  ;; server work while carrying nothing.
  (let [release (CountDownLatch. 1)]
    (with-h2-server
      (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          ;; The server may close mid-flood.
          (try (dotimes [_ 20] (write-frame! conn frame-data 0 1 (byte-array 0)))
               (catch java.io.IOException _))
          (let [ga (read-until conn #(= frame-goaway (:type %)))]
            (is (= 0xb (some-> ga goaway-code)) "ENHANCE_YOUR_CALM"))
          (.countDown release))))))

(deftest h2-empty-data-flood-on-reset-stream-is-cut-off
  ;; Frames on a stream we reset are ignored (they may have been in
  ;; flight), but empty non-final DATA carries nothing even then: a flood
  ;; of them is cut off like one on a live stream.
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (with-conn [conn]
      ;; Malformed (no :path): stream error, the stream is reset by us.
      (send-request! conn 1 [[":method" "POST"] [":scheme" "https"] [":authority" "localhost"]] false)
      (is (some? (read-until conn (frame-on 1 frame-rst))))
      (try (dotimes [_ 20] (write-frame! conn frame-data 0 1 (byte-array 0)))
           (catch java.io.IOException _))
      (let [ga (read-until conn #(= frame-goaway (:type %)) nil 2000)]
        (is (= 0xb (some-> ga goaway-code)) "ENHANCE_YOUR_CALM")))))

;; ---- Request validation --------------------------------------------------

(deftest h2-malformed-requests-are-stream-errors
  ;; RFC 9113 §8.1.1 / §8.2.1 / §8.3.1: malformed requests get
  ;; RST_STREAM(PROTOCOL_ERROR) and never reach the handler.
  (let [called (atom [])]
    (with-h2-server
      (fn [req] (swap! called conj (:uri req)) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (doseq [[sid label pairs]
                  [[1 "space in name" (request-headers "GET" "/1" [["x y" "v"]])]
                   [3 "colon mid-name" (request-headers "GET" "/3" [["x:y" "v"]])]
                   [5 "DEL in name" (request-headers "GET" "/5" [["x\u007f" "v"]])]
                   [7 "NUL in name" (request-headers "GET" "/7" [["x\u0000" "v"]])]
                   [9 "leading space in value" (request-headers "GET" "/9" [["x-a" " v"]])]
                   [11 "trailing tab in value" (request-headers "GET" "/11" [["x-a" "v\t"]])]
                   [13 "relative :path" (request-headers "GET" "11")]
                   [15 "asterisk :path for GET" (request-headers "GET" "*")]
                   [17 "non-token :method" (request-headers "G T" "/17")]
                   [19 "signed content-length" (request-headers "POST" "/19" [["content-length" "+0"]])]
                   [21 "CR in :path" (request-headers "GET" "/2\r1")]]]
            (send-request! conn sid pairs true)
            (is (= 0x1 (some-> (read-until conn (frame-on sid frame-rst) nil 1000) rst-code))
                label))
          (send-request! conn 23 (request-headers "OPTIONS" "*") true)
          (is (= "200" (get (response-on conn 23) ":status")) "OPTIONS * is valid")
          (is (= ["*"] @called) "only the valid request reached the handler"))))))

(deftest h2-host-header-kept-without-authority
  ;; §8.3.1: :authority may be omitted in favour of Host; it must not be
  ;; replaced by an empty value.
  (let [seen (atom nil)]
    (with-h2-server
      (fn [req] (reset! seen (get-in req [:headers "host"])) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 [[":method" "GET"] [":scheme" "https"] [":path" "/"]
                                 ["host" "example.org"]]
                         true)
          (is (= "200" (get (response-on conn 1) ":status")))
          (is (= "example.org" @seen)))))))

;; ---- Request timeout -----------------------------------------------------

(deftest h2-timeout-503-is-not-followed-by-internal-error
  ;; A complete 503 (END_STREAM) on a request that already ended needs no
  ;; RST_STREAM at all; RST(INTERNAL_ERROR) would turn it into a failure.
  (let [closed (promise)]
    (let [srv (enso/run-server
               (fn [_]
                 (try (Thread/sleep 1000) (catch InterruptedException _))
                 {:status 200
                  :body (proxy [java.io.ByteArrayInputStream] [(.getBytes "late")]
                          (close [] (deliver closed true)))})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :handler-timeout 200})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/") true)
            (let [seen (atom [])]
              (read-until conn (frame-on 1 frame-headers) seen)
              (swap! seen into (drain-frames conn 500))
              (is (= "503" (some #(get-in % [:headers ":status"]) @seen)))
              (is (not-any? #(and (= frame-rst (:type %)) (= 1 (:sid %))) @seen)
                  "no RST_STREAM after the complete 503"))
            (is (deref closed 2000 false) "losing response body closed")))
        (finally (enso/stop srv))))))

(deftest h2-head-closes-unsent-body
  (let [closed (promise)]
    (with-h2-server
      (fn [_] {:status 200
               :body (proxy [java.io.ByteArrayInputStream] [(.getBytes "body")]
                       (close [] (deliver closed true)))})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "HEAD" "/") true)
          (is (= "200" (get (response-on conn 1) ":status")))
          (is (deref closed 2000 false) "InputStream body closed though never sent"))))))

(deftest h2-flush-not-starved-by-busy-neighbour-stream
  ;; flush! must wait for this stream's bytes, not for the whole
  ;; connection queue to go empty (which a busy stream may never allow).
  (let [stop (promise)
        flushed (promise)]
    (with-h2-server
      (fn [req]
        (if (= "/busy" (:uri req))
          {:status 200
           :body (proxy [java.io.InputStream] []
                   (read
                     ([] 100)
                     ([^bytes b] (if (realized? stop) -1 (alength b)))
                     ([^bytes b off len] (if (realized? stop) -1 len))))}
          {:status 200
           :body (fn [w]
                   (enso/write! w "event")
                   (enso/flush! w)
                   (deliver flushed true))}))
      (fn []
        (with-conn [conn [[0x4 0x7FFFFFFF]]]
          (open-windows! conn)
          (send-request! conn 1 (request-headers "GET" "/busy") true)
          (read-until conn (frame-on 1 frame-data))
          (send-request! conn 3 (request-headers "GET" "/sse") true)
          (is (deref flushed 3000 false) "flush returned while the neighbour streams")
          (deliver stop true))))))

;; ---- Trailers ------------------------------------------------------------

(deftest h2-trailers-enforce-content-length
  (let [release (CountDownLatch. 1)]
    (with-h2-server
      (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/" [["content-length" "10"]]) false)
          (write-frame! conn frame-data 0 1 (.getBytes "abc"))
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                        (header-block conn [["x-trailer" "t"]]))
          (is (= 0x1 (some-> (read-until conn (frame-on 1 frame-rst)) rst-code))
              "body shorter than content-length")
          (.countDown release))))))

(deftest h2-trailers-enforce-max-header-list-size
  ;; A trailer block over SETTINGS_MAX_HEADER_LIST_SIZE (but under the
  ;; hard ceiling) is decoded, keeping HPACK in sync, and resets its
  ;; stream with ENHANCE_YOUR_CALM; the connection is kept.
  (let [release (CountDownLatch. 1)]
    (with-server (fn [req]
                   (if (= "/hold" (:uri req))
                     (.await release 5 TimeUnit/SECONDS)
                     (get-in req [:headers "x-t"]))
                   {:status 200 :body (str (get-in req [:headers "x-t"]))})
      {:max-header-bytes 300}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/hold") false)
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                      (header-block conn [["x-trailer" (apply str (repeat 400 "t"))]
                                          ["x-t" "indexed"]]))
        (let [seen (atom [])]
          (read-until conn (frame-on 1 frame-rst) seen)
          (is (= 0xb (some-> (last @seen) rst-code)) "RST_STREAM(ENHANCE_YOUR_CALM)")
          (is (not-any? #(= frame-goaway (:type %)) @seen)))
        (.countDown release)
        ;; x-t was inserted into the dynamic table by the oversized block.
        (send-request! conn 3 (request-headers "GET" "/" [["x-t" "indexed"]]) true)
        (let [seen (atom [])]
          (read-until conn (end-stream-on 3) seen)
          (is (= "indexed" (String. ^bytes (byte-array (mapcat :payload (filter (frame-on 3 frame-data) @seen)))))
              "HPACK state kept in sync"))))))

(deftest h2-headers-on-half-closed-stream-is-stream-error
  ;; §5.1 half-closed (remote): further HEADERS is a stream error
  ;; STREAM_CLOSED, not a connection error.
  (let [release (CountDownLatch. 1)]
    (with-h2-server
      (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                        (header-block conn [["x-trailer" "t"]]))
          (let [seen (atom [])]
            (read-until conn (frame-on 1 frame-rst) seen)
            (is (= 0x5 (some-> (last @seen) rst-code)) "RST_STREAM(STREAM_CLOSED)")
            (is (not-any? #(= frame-goaway (:type %)) @seen)))
          (send-request! conn 3 (request-headers "GET" "/") true)
          (.countDown release)
          (is (= "200" (get (response-on conn 3) ":status")) "connection still usable"))))))

;; ---- PRIORITY ------------------------------------------------------------

(deftest h2-self-dependent-priority-on-idle-stream-no-rst
  ;; RST_STREAM must never be sent on an idle stream (§6.4); escalate to
  ;; a connection error instead.
  (with-h2-server
    (fn [_] {:status 200 :body "ok"})
    (fn []
      (with-conn [conn]
        (write-frame! conn frame-priority 0 5 (byte-array (concat (u32-bytes 5) [(unchecked-byte 15)])))
        (let [seen (atom [])]
          (read-until conn #(= frame-goaway (:type %)) seen)
          (is (not-any? #(= frame-rst (:type %)) @seen) "no RST on idle stream")
          (is (= 0x1 (some-> (last @seen) goaway-code))))))))

(deftest h2-bad-priority-length-is-stream-error
  ;; §6.3: a PRIORITY frame not 5 octets long is a stream error
  ;; FRAME_SIZE_ERROR.
  (let [release (CountDownLatch. 1)]
    (with-h2-server
      (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "GET" "/") true)
          (write-frame! conn frame-priority 0 1 (byte-array 4))
          (let [seen (atom [])]
            (read-until conn (frame-on 1 frame-rst) seen)
            (is (= 0x6 (some-> (last @seen) rst-code)) "RST_STREAM(FRAME_SIZE_ERROR)")
            (is (not-any? #(= frame-goaway (:type %)) @seen)))
          (.countDown release))))))

(deftest h2-request-header-block-split-over-continuation
  (let [seen (atom nil)]
    (with-h2-server
      (fn [req] (reset! seen (get-in req [:headers "x-a"])) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (doseq [sid [1 3]]
            (let [block (header-block conn (request-headers "GET" "/" [["x-a" (str "v" sid)]]))
                  n (alength block)
                  cut (quot n 3)]
              (write-frame! conn frame-headers flag-end-stream sid
                            (java.util.Arrays/copyOfRange block 0 cut))
              (write-frame! conn frame-continuation 0 sid
                            (java.util.Arrays/copyOfRange block cut (* 2 cut)))
              (write-frame! conn frame-continuation flag-end-headers sid
                            (java.util.Arrays/copyOfRange block (* 2 cut) n))
              (is (= "200" (get (response-on conn sid) ":status")))
              (is (= (str "v" sid) @seen)))))))))

(defn- server-settings
  "The server's initial SETTINGS on `conn` as a map of id → value."
  [conn]
  (let [f (read-until conn #(and (= frame-settings (:type %)) (zero? (:flags %))))
        ^bytes p (:payload f)]
    (into {} (for [i (range 0 (alength p) 6)]
               [(bit-or (bit-shift-left (bit-and (aget p i) 0xFF) 8) (bit-and (aget p (inc i)) 0xFF))
                (u32 p (+ i 2))]))))

(deftest h2-max-header-list-size-is-max-header-bytes
  ;; One head limit for every protocol: SETTINGS_MAX_HEADER_LIST_SIZE
  ;; advertises :max-header-bytes.
  (let [srv (enso/run-server (fn [_] {:status 200 :body "ok"})
                             {:port 0 :http2 true :ssl-context (gen-server-context)
                              :max-header-bytes 16384})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (let [settings (server-settings conn)]
            (is (contains? settings 0x3) "MAX_CONCURRENT_STREAMS still sent")
            (is (= 16384 (get settings 0x6)) "MAX_HEADER_LIST_SIZE = :max-header-bytes"))))
      (finally (enso/stop srv)))))

(deftest h2-request-body-cap-enforced
  ;; :max-request-body-bytes applies to h2 like h1: a declared length over
  ;; the cap is 413 without running the handler; an undeclared body that
  ;; grows past it fails the handler's read and is answered 413.
  (let [ran (atom 0)
        srv (enso/run-server
             (fn [req] (swap! ran inc) (slurp (:body req)) {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :max-request-body-bytes 1000})]
    (try
      (binding [*port* (enso/port srv)]
        (testing "declared Content-Length over the cap"
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/" [["content-length" "5000"]]) false)
            (is (= "413" (get (response-on conn 1) ":status")))
            (is (zero? @ran) "handler not run")))
        (testing "undeclared body growing past the cap"
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/") false)
            (send-data! conn 1 5000 true)
            (is (= "413" (get (response-on conn 1) ":status")))))
        (testing "body within the cap"
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/") false)
            (send-data! conn 1 1000 true)
            (is (= "200" (get (response-on conn 1) ":status"))))))
      (finally (enso/stop srv)))))

(deftest h2-discarded-oversized-body-still-flow-controlled
  ;; DATA discarded because the body is over max-request-body-bytes still
  ;; counts against the stream window (§6.9.1): overrunning it is a
  ;; FLOW_CONTROL_ERROR.
  (let [started (CountDownLatch. 1)
        release (CountDownLatch. 1)
        srv (enso/run-server
             (fn [_] (.countDown started) (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :max-request-body-bytes 1000 :http2-initial-window-bytes 65535})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (.await started 5 TimeUnit/SECONDS)
          (send-data! conn 1 2000 false)
          (send-data! conn 1 65535 false)
          (is (= 0x3 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))
              "FLOW_CONTROL_ERROR")
          (.countDown release)))
      (finally (enso/stop srv)))))

(deftest h2-response-header-values
  ;; Ring header values may be a seq of strings, one field per value; an
  ;; illegal value or an unknown body type is a 500, as on HTTP/1.1.
  (with-h2-server
    (fn [req]
      (case (:uri req)
        "/multi" {:status 200 :headers {"set-cookie" ["a=1" "b=2"]} :body "x"}
        "/crlf" {:status 200 :headers {"x-bad" "a\r\nb"} :body "x"}
        "/name" {:status 200 :headers {"bad name" "v"} :body "x"}
        "/body" {:status 200 :body (Object.)}))
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/multi") true)
        (let [f (read-until conn (frame-on 1 frame-headers))]
          (is (= [["set-cookie" "a=1"] ["set-cookie" "b=2"]]
                 (filterv #(= "set-cookie" (first %)) (:header-fields f)))))
        (doseq [[sid path] [[3 "/crlf"] [5 "/name"] [7 "/body"]]]
          (send-request! conn sid (request-headers "GET" path) true)
          (let [f (read-until conn (frame-on sid frame-headers))]
            (is (= "500" (get (:headers f) ":status")) path)
            (is (not-any? #(#{"x-bad" "bad name"} (first %)) (:header-fields f)) path)))))))

(deftest h2-string-body-uses-content-type-charset
  (with-h2-server
    (fn [_] {:status 200 :headers {"content-type" "text/plain; charset=ISO-8859-1"} :body "\u00e9t\u00e9"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                 (pos? (bit-and flag-end-stream (:flags %))))
                      seen)
          (is (= [0xE9 0x74 0xE9]
                 (mapv #(bit-and % 0xFF)
                       (mapcat :payload (filter #(= frame-data (:type %)) @seen))))))
        (send-request! conn 3 (request-headers "HEAD" "/") true)
        (is (= "3" (get (response-on conn 3) "content-length")))))))

(deftest h2-error-handler
  ;; :error-handler answers when the handler throws or returns nil, as on
  ;; HTTP/1.1.
  (let [srv (enso/run-server
             (fn [req] (when (= "/boom" (:uri req)) (throw (ex-info "boom" {}))))
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :error-handler (fn [_ t] {:status 418 :body (.getSimpleName (class t))})})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (doseq [[sid path cls] [[1 "/boom" "ExceptionInfo"] [3 "/nil" "IllegalArgumentException"]]]
            (send-request! conn sid (request-headers "GET" path) true)
            (let [seen (atom [])]
              (read-until conn #(and (= frame-data (:type %)) (= sid (:sid %))
                                     (pos? (bit-and flag-end-stream (:flags %))))
                          seen)
              (is (= "418" (some #(get-in % [:headers ":status"]) @seen)) path)
              (is (= cls (apply str (map #(String. ^bytes (:payload %))
                                         (filter #(= frame-data (:type %)) @seen))))
                  path)))))
      (finally (enso/stop srv)))))

;; ---- Shared timeout model, response and request-head policy ---------------

(defn- closed-within?
  "Whether the server closes `sock` within `ms`, while `drip` (a fn of the
  socket's OutputStream, or nil) keeps writing to it."
  [^java.net.Socket sock ms drip]
  (let [out (.getOutputStream sock)
        dripper (when drip (future (try (drip out) (catch Exception _))))]
    (try
      (.setSoTimeout sock (int ms))
      (= -1 (try (loop [] (if (neg? (.read (.getInputStream sock))) -1 (recur)))
                 (catch java.net.SocketTimeoutException _ :timeout)
                 (catch java.io.IOException _ -1)))
      (finally (some-> dripper future-cancel)))))

(deftest h2-handshake-timeout-bounds-preface-and-first-settings
  ;; :handshake-timeout is wall clock up to the client's first SETTINGS,
  ;; however the bytes trickle in; :idle-timeout doesn't apply yet.
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :handshake-timeout 500 :idle-timeout 30000})]
    (try
      (binding [*port* (enso/port srv)]
        (testing "a preface dripped byte by byte"
          (with-open [sock (tls-h2-socket)]
            (is (closed-within? sock 3000
                                (fn [^java.io.OutputStream out]
                                  (doseq [b (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1)]
                                    (.write out (int b))
                                    (.flush out)
                                    (Thread/sleep 150)))))))
        (testing "a preface without the first SETTINGS"
          (with-open [sock (tls-h2-socket)]
            (let [out (.getOutputStream sock)]
              (.write out (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1))
              (.flush out))
            (is (closed-within? sock 3000 nil))))
        (testing "a prompt client is not affected afterwards"
          (with-conn [conn]
            (Thread/sleep 800)
            (send-request! conn 1 (request-headers "GET" "/") true)
            (is (= "200" (get (response-on conn 1) ":status"))))))
      (finally (enso/stop srv)))))

(deftest h2-responses-carry-date
  (with-h2-server
    (fn [_] {:status 200 :body "ok"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (re-matches #"\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT"
                        (str (get (response-on conn 1) "date"))))))))

(deftest h2-handler-date-wins
  (with-h2-server
    (fn [_] {:status 200 :headers {"Date" "Tue, 15 Nov 1994 08:12:31 GMT"} :body "ok"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [f (read-until conn (frame-on 1 frame-headers))]
          (is (= [["date" "Tue, 15 Nov 1994 08:12:31 GMT"]]
                 (filterv #(= "date" (first %)) (:header-fields f)))))))))

(deftest h2-invalid-response-status-is-500
  ;; 200-599 only: 1xx can't be a final response, and 101 has no meaning
  ;; on HTTP/2 (RFC 9113 §8.6).
  (with-h2-server
    (fn [req] {:status (parse-long (subs (:uri req) 1)) :body "x"})
    (fn []
      (with-conn [conn]
        (doseq [[sid status] [[1 99] [3 101] [5 103] [7 600] [9 1000]]]
          (send-request! conn sid (request-headers "GET" (str "/" status)) true)
          (is (= "500" (get (response-on conn sid) ":status")) (str status)))
        (send-request! conn 11 (request-headers "GET" "/599") true)
        (is (= "599" (get (response-on conn 11) ":status")))))))

(deftest h2-request-head-rules
  ;; The shared request-head rules (RFC 9113 §8.3.1, RFC 9110 §5.5):
  ;; malformed heads are stream errors that never reach the handler.
  (let [called (atom [])]
    (with-h2-server
      (fn [req] (swap! called conj (:uri req)) {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (doseq [[sid label pairs]
                  [[1 "unsupported :scheme" [[":method" "GET"] [":scheme" "ftp"] [":path" "/1"] [":authority" "localhost"]]]
                   [3 "userinfo in :authority" [[":method" "GET"] [":scheme" "https"] [":path" "/3"] [":authority" "u@localhost"]]]
                   [5 ":authority and host differ" (request-headers "GET" "/5" [["host" "other.example"]])]
                   [7 "control char in value" (request-headers "GET" "/7" [["x-a" "a\u0001b"]])]
                   [9 "no :authority and no host" [[":method" "GET"] [":scheme" "https"] [":path" "/9"]]]
                   [11 "TE other than trailers" (request-headers "GET" "/11" [["te" "gzip"]])]
                   [13 "content-length values disagree" (request-headers "POST" "/13" [["content-length" "1"] ["content-length" "2"]])]]]
            (send-request! conn sid pairs true)
            (is (= 0x1 (some-> (read-until conn (frame-on sid frame-rst) nil 1000) rst-code))
                label))
          (testing "CONNECT is well-formed but not served"
            (send-request! conn 15 [[":method" "CONNECT"] [":authority" "example.org:443"]] true)
            (is (= "501" (get (response-on conn 15) ":status"))))
          (send-request! conn 17 (request-headers "GET" "/ok" [["host" "LOCALHOST"]]) true)
          (is (= "200" (get (response-on conn 17) ":status")) "host matches :authority ignoring case")
          (is (= ["/ok"] @called) "only the valid request reached the handler"))))))

;; ---- Send-side flow control deadlines ----------------------------------------

(deftest h2-stream-window-stall-is-cancelled
  ;; A peer that never opens a stream window can't pin the handler and its
  ;; response body: no send progress for :write-timeout resets the stream
  ;; with CANCEL and releases the body; the connection is kept.
  (let [closed (promise)]
    (with-server (fn [_] {:status 200
                          :body (proxy [java.io.ByteArrayInputStream] [(byte-array 100000)]
                                  (close [] (deliver closed true)))})
      {:write-timeout 300}
      (with-conn [conn [[0x4 0]]]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (read-until conn (frame-on 1 frame-rst) seen 3000)
          (is (= 0x8 (some-> (last @seen) rst-code)) "RST_STREAM(CANCEL)")
          (is (not-any? #(= frame-goaway (:type %)) @seen)))
        (is (deref closed 2000 false) "response body released")
        (send-request! conn 3 (request-headers "HEAD" "/") true)
        (is (= "200" (get (response-on conn 3) ":status")) "connection kept")))))

(deftest h2-connection-window-stall-closes-connection
  ;; Stream windows open but the connection window never replenished: no
  ;; stream can progress, so after :write-timeout the connection is closed
  ;; with GOAWAY(ENHANCE_YOUR_CALM).
  (with-server (fn [_] {:status 200 :body (byte-array 200000)})
    {:write-timeout 300}
    (with-conn [conn [[0x4 0x7FFFFFFF]]]
      (send-request! conn 1 (request-headers "GET" "/") true)
      (let [seen (atom [])
            ga (read-until conn #(= frame-goaway (:type %)) seen 3000)]
        (is (= 65535 (data-bytes-on @seen 1)) "the connection window was used up")
        (is (= 0xb (some-> ga goaway-code)) "GOAWAY(ENHANCE_YOUR_CALM)")
        (is (eof-within? conn 2000) "connection closed")))))

(deftest h2-window-dribble-is-coalesced
  ;; CVE-2019-9511 (data dribble): one-byte WINDOW_UPDATEs must not turn
  ;; into one-byte DATA frames; credit below a useful size is pooled and
  ;; sent as one frame, so a stream sends such small frames at most once
  ;; per Http2Writer/DRIBBLE_NANOS (20 ms). The bound is on that rate, not
  ;; on a count, so a slow client loop can't make it flaky.
  (with-server (fn [_] {:status 200 :body (byte-array 65536)}) {}
    (with-conn [conn [[0x4 0]]]
      (send-request! conn 1 (request-headers "GET" "/") true)
      (is (some? (read-until conn (frame-on 1 frame-headers))))
      ;; Each update is handled before the next is sent.
      (let [seen (atom [])
            start (System/nanoTime)
            _ (dotimes [_ 50]
                (write-frame! conn frame-window-update 0 1 (u32-bytes 1))
                (write-frame! conn frame-ping 0 0 (byte-array 8))
                (read-until conn ping-ack? seen))
            elapsed-ms (quot (- (System/nanoTime) start) 1000000)]
        (swap! seen into (drain-frames conn 500))
        (let [data (filter (frame-on 1 frame-data) @seen)
              ;; One per 20 ms while updates arrive, plus the first (the
              ;; stream had waited since its HEADERS) and the pooled rest.
              bound (+ 2 (quot elapsed-ms 20))]
          (is (= 50 (data-bytes-on @seen 1)) "all the credit is used")
          (is (<= (count data) bound)
              (str (count data) " DATA frames for 50 one-byte updates in " elapsed-ms " ms")))))))

(deftest h2-tiny-window-still-progresses
  ;; A peer that legitimately grants less than the coalescing size still
  ;; gets its bytes (h2spec 6.9.1/1: a 1-byte window gets a 1-byte frame).
  (with-server (fn [_] {:status 200 :body "hello"}) {}
    (with-conn [conn [[0x4 1]]]
      (send-request! conn 1 (request-headers "GET" "/") true)
      (let [f (read-until conn (frame-on 1 frame-data) nil 2000)]
        (is (= 1 (some-> f :payload alength)))))))

;; ---- Outbound memory and fairness ----------------------------------------------

(deftest h2-header-block-filling-a-batch-is-sent-before-its-data
  ;; A header block that leaves too little room in the writer's batch for
  ;; the first DATA frame: the block must still go out in that batch and
  ;; the DATA in the next one. Header sizes sweep the batch end so some
  ;; response lands in that window whatever the exact encoded sizes.
  (with-server (fn [req]
                 {:status 200
                  :headers {"x-pad" (apply str (repeat (Long/parseLong (subs (:uri req) 1)) \a))}
                  :body (byte-array 4096)})
    {}
    (with-conn [conn [[0x4 0x7FFFFFFF]]]
      (open-windows! conn)
      (loop [sid 1 pad 64800]
        (when (< pad 65536)
          (send-request! conn sid (request-headers "GET" (str "/" pad)) true)
          (let [seen (atom [])
                done (read-until conn (end-stream-on sid) seen 3000)
                own (filter #(= sid (:sid %)) @seen)]
            (when (and (is (some? done) (str "response with a " pad "-byte header completed"))
                       (is (= frame-headers (:type (first own))) (str "HEADERS first with a " pad "-byte header"))
                       (is (= 4096 (data-bytes-on own sid)) (str "whole body with a " pad "-byte header")))
              (recur (+ sid 2) (+ pad 16)))))))))

(deftest h2-reset-stream-stops-buffered-output
  ;; Output is bounded in bytes per stream, and a peer RST_STREAM purges
  ;; what the stream had buffered: once the reset is seen, little more than
  ;; the socket buffers' worth of that stream's DATA arrives. Control
  ;; replies (PING ACK) don't wait behind buffered DATA.
  (let [stop (promise)]
    (with-server (fn [_]
                   {:status 200
                    :body (proxy [java.io.InputStream] []
                            (read
                              ([] 100)
                              ([^bytes b] (if (realized? stop) -1 (alength b)))
                              ([^bytes b off len] (if (realized? stop) -1 len))))})
      {}
      (with-conn [conn [[0x4 0x7FFFFFFF]]]
        (open-windows! conn)
        (send-request! conn 1 (request-headers "GET" "/") true)
        (read-until conn (frame-on 1 frame-data))
        (reset! (:paused conn) true)
        ;; Let the server back up against the stalled socket.
        (Thread/sleep 300)
        (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
        (write-frame! conn frame-ping 0 0 (byte-array 8))
        (reset! (:paused conn) false)
        (let [seen (atom [])]
          (is (some? (read-until conn ping-ack? seen 10000)) "PING answered")
          (swap! seen into (drain-frames conn 500))
          (is (< (data-bytes-on @seen 1) (* 10 1024 1024))
              (str (data-bytes-on @seen 1) " bytes of a reset stream still sent")))
        (deliver stop true)))))

(deftest h2-slow-but-steady-reader-is-not-cut-off
  ;; :write-timeout bounds one write making no progress: a peer that reads
  ;; slowly but steadily gets a large flushed response in full.
  (let [payload (byte-array (* 2 1024 1024) (unchecked-byte 1))]
    (with-server (fn [_] {:status 200 :body (fn [w] (enso/write! w payload) (enso/flush! w))})
      {:write-timeout 500}
      (with-conn [conn [[0x4 0x7FFFFFFF]]]
        (open-windows! conn)
        (reset! (:read-delay-ms conn) 10)
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (is (some? (read-until conn (end-stream-on 1) seen 20000)) "response completed")
          (is (= (alength payload) (data-bytes-on @seen 1))))))))

;; ---- Closed streams --------------------------------------------------------------

(deftest h2-data-after-peer-reset-is-stream-closed
  ;; §5.1: frames after the peer's own RST_STREAM are a stream error
  ;; STREAM_CLOSED (h2spec 5.1/8).
  (let [release (CountDownLatch. 1)]
    (with-server (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"}) {}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
        (write-frame! conn frame-data 0 1 (.getBytes "late"))
        (let [seen (atom [])]
          (read-until conn (frame-on 1 frame-rst) seen)
          (is (= 0x5 (some-> (last @seen) rst-code)) "RST_STREAM(STREAM_CLOSED)")
          (is (not-any? #(= frame-goaway (:type %)) @seen)))
        (.countDown release)
        (send-request! conn 3 (request-headers "GET" "/") true)
        (is (= "200" (get (response-on conn 3) ":status")) "connection kept")))))

(deftest h2-frames-on-ended-stream-are-connection-errors
  ;; §5.1: after both sides ended a stream, DATA or HEADERS on it is a
  ;; connection error STREAM_CLOSED (h2spec 5.1/11).
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (testing "DATA"
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (end-stream-on 1))))
        (write-frame! conn frame-data 0 1 (.getBytes "late"))
        (is (= 0x5 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code)))))
    (testing "HEADERS"
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (end-stream-on 1))))
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (= 0x5 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code)))))))

(deftest h2-frames-on-long-forgotten-reset-streams-ignored
  ;; Streams the server reset are remembered well beyond a fixed handful:
  ;; trailers on one of many refused streams are ignored rather than
  ;; mistaken for a reused stream id.
  (let [release (CountDownLatch. 1)
        blocking (CountDownLatch. 1)]
    (with-server (fn [req]
                   (when (= "/block" (:uri req))
                     (.countDown blocking)
                     (.await release 10 TimeUnit/SECONDS))
                   {:status 200 :body "ok"})
      {:http2-max-concurrent-streams 1}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/block") true)
        (.await blocking 5 TimeUnit/SECONDS)
        (doseq [sid (range 3 403 2)]
          (send-request! conn sid (request-headers "POST" "/") false))
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 3
                      (header-block conn [["x-trailer" "t"]]))
        (.countDown release)
        (let [seen (atom [])]
          (read-until conn (end-stream-on 1) seen)
          (is (not-any? #(= frame-goaway (:type %)) @seen) "no GOAWAY")
          (is (= "200" (some #(get-in % [:headers ":status"]) (filter (frame-on 1 frame-headers) @seen)))))))))

;; ---- Header list size ----------------------------------------------------------

(deftest h2-oversized-header-list-is-431
  ;; RFC 9113 §10.5.1: a field section over SETTINGS_MAX_HEADER_LIST_SIZE
  ;; is decoded (HPACK stays in sync) and answered 431 on its stream; the
  ;; connection is kept. Only a block over the hard ceiling (4x, at least
  ;; 64 KiB) is a connection error.
  (let [called (atom 0)]
    (with-server (fn [req] (swap! called inc) {:status 200 :body (str (get-in req [:headers "x-a"]))})
      {:max-header-bytes 8192}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/" [["x-big" (apply str (repeat 10000 "a"))]
                                                          ["x-a" "kept"]])
                       true)
        (is (= "431" (get (response-on conn 1) ":status")))
        (is (zero? @called) "handler not run")
        (send-request! conn 3 (request-headers "GET" "/" [["x-a" "kept"]]) true)
        (let [seen (atom [])]
          (read-until conn (end-stream-on 3) seen)
          (is (= "kept" (String. ^bytes (byte-array (mapcat :payload (filter (frame-on 3 frame-data) @seen)))))
              "HPACK in sync after the oversized block")))
      (with-conn [conn]
        (send-split-headers! conn 1 (header-block conn (request-headers "GET" "/" [["x-huge" (apply str (repeat 100000 "a"))]]))
                             true)
        (is (= 0xb (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))
            "over the hard ceiling: GOAWAY(ENHANCE_YOUR_CALM)")))))

(deftest h2-hpack-bomb-hits-hard-ceiling
  ;; A small block expanding to a huge decoded list (one big dynamic-table
  ;; entry referenced thousands of times) stops at the hard ceiling
  ;; instead of building it.
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (with-conn [conn]
      (let [base (header-block conn (request-headers "GET" "/"))
            ;; Literal with incremental indexing, new name "x-a", a 4000-byte
            ;; value: its length is 127 + 3873 in a 7-bit prefixed integer.
            literal (byte-array (concat (raw-bytes [0x40 3]) (.getBytes "x-a")
                                        (raw-bytes [0x7F (bit-or 0x80 (bit-and 3873 0x7F)) (bit-shift-right 3873 7)])
                                        (byte-array 4000 (byte 97))))
            ;; index 62 is the newest dynamic entry: x-a
            refs (byte-array 5000 (unchecked-byte 0xBE))]
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                      (byte-array (concat base literal refs)))
        (is (= 0xb (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code)))))))

;; ---- Stream versus connection errors (RFC 9113 §5.4) ---------------------------

(deftest h2-stream-level-errors-keep-the-connection
  (let [release (CountDownLatch. 1)]
    (with-server (fn [req]
                   (when (= "/hold" (:uri req)) (.await release 5 TimeUnit/SECONDS))
                   {:status 200 :body "ok"})
      {}
      (with-conn [conn]
        (testing "WINDOW_UPDATE with a zero increment on a stream"
          (send-request! conn 1 (request-headers "GET" "/hold") true)
          (write-frame! conn frame-window-update 0 1 (u32-bytes 0))
          (is (= 0x1 (some-> (read-until conn (frame-on 1 frame-rst)) rst-code))))
        (testing "pseudo-header in trailers"
          (send-request! conn 3 (request-headers "POST" "/hold") false)
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 3
                        (header-block conn [[":path" "/x"]]))
          (is (= 0x1 (some-> (read-until conn (frame-on 3 frame-rst)) rst-code))))
        (testing "second HEADERS without END_STREAM on an open stream"
          (send-request! conn 5 (request-headers "POST" "/hold") false)
          (write-frame! conn frame-headers flag-end-headers 5 (header-block conn [["x-t" "t"]]))
          (is (= 0x1 (some-> (read-until conn (frame-on 5 frame-rst)) rst-code))))
        (testing "HEADERS without END_STREAM on a half-closed (remote) stream"
          (send-request! conn 7 (request-headers "GET" "/hold") true)
          (write-frame! conn frame-headers flag-end-headers 7 (header-block conn [["x-t" "t"]]))
          (is (= 0x5 (some-> (read-until conn (frame-on 7 frame-rst)) rst-code))))
        (.countDown release)
        (send-request! conn 9 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (read-until conn (frame-on 9 frame-headers) seen)
          (is (not-any? #(= frame-goaway (:type %)) @seen))
          (is (= "200" (get-in (last @seen) [:headers ":status"]))))))))

(deftest h2-window-update-on-even-stream-is-connection-error
  ;; The server never opens even-numbered streams: they are idle, and
  ;; WINDOW_UPDATE on an idle stream is a connection error (§5.1).
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (with-conn [conn]
      (send-request! conn 3 (request-headers "GET" "/") true)
      (is (some? (read-until conn (end-stream-on 3))))
      (write-frame! conn frame-window-update 0 2 (u32-bytes 100))
      (is (= 0x1 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))))))

;; ---- Response policy (shared ResponseHead) --------------------------------------

(deftest h2-no-body-statuses-send-no-data
  ;; 204 and 304 never carry content (RFC 9110 §15.3.5, §15.4.5), whatever
  ;; the handler returned as body.
  (with-server (fn [req] {:status (parse-long (subs (:uri req) 1)) :body "content"}) {}
    (with-conn [conn]
      (doseq [[sid status] [[1 204] [3 304]]]
        (send-request! conn sid (request-headers "GET" (str "/" status)) true)
        (let [f (read-until conn (frame-on sid frame-headers))]
          (is (= (str status) (get (:headers f) ":status")))
          (is (pos? (bit-and flag-end-stream (:flags f))) "END_STREAM on HEADERS")
          (is (nil? (get (:headers f) "content-length"))))))))

(deftest h2-response-framing-follows-the-shared-policy
  (let [file (doto (java.io.File/createTempFile "enso-h2" ".txt") (.deleteOnExit))]
    (spit file "0123456789")
    (with-server (fn [req]
                   (case (:uri req)
                     "/file" {:status 200 :body file}
                     "/te" {:status 200 :headers {"Transfer-Encoding" "chunked" "X-Mixed" "v"} :body "ok"}
                     "/short" {:status 200 :headers {"content-length" "100"}
                               :body (java.io.ByteArrayInputStream. (.getBytes "only-this"))}))
      {}
      (with-conn [conn]
        (testing "HEAD of a file reports its length"
          (send-request! conn 1 (request-headers "HEAD" "/file") true)
          (is (= "10" (get (response-on conn 1) "content-length"))))
        (testing "Transfer-Encoding dropped, names lowercased"
          (send-request! conn 3 (request-headers "GET" "/te") true)
          (let [h (response-on conn 3)]
            (is (nil? (get h "transfer-encoding")))
            (is (= "v" (get h "x-mixed")))))
        (testing "a stream body shorter than its declared length is reset"
          (send-request! conn 5 (request-headers "GET" "/short") true)
          (is (= "100" (get (response-on conn 5) "content-length")))
          (is (= 0x2 (some-> (read-until conn (frame-on 5 frame-rst)) rst-code)) "RST_STREAM(INTERNAL_ERROR)"))))))

;; ---- Reset accounting (CVE-2025-8671 MadeYouReset) ------------------------------

(deftest h2-server-resets-count-against-the-reset-budget
  ;; Resets the server sends because of what the peer did (here malformed
  ;; requests) are charged to the same budget as the peer's own.
  (with-server (fn [_] {:status 200 :body "ok"}) {:http2-stream-reset-limit 10}
    (with-conn [conn]
      (try (doseq [sid (range 1 41 2)]
             (send-request! conn sid (request-headers "GET" "relative") true))
           (catch java.io.IOException _))
      (is (= 0xb (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))))))

;; ---- Timeouts and events ---------------------------------------------------------

(deftest h2-header-timeout-bounds-continuation
  ;; A header block left open (no END_HEADERS) blocks the whole connection:
  ;; :header-timeout (wall clock from its HEADERS) closes it.
  (with-server (fn [_] {:status 200 :body "ok"}) {:header-timeout 300 :idle-timeout 30000}
    (with-conn [conn]
      (let [block (header-block conn (request-headers "GET" "/"))]
        (write-frame! conn frame-headers flag-end-stream 1 block)
        (let [ga (read-until conn #(= frame-goaway (:type %)) nil 3000)]
          (is (some? ga) "GOAWAY")
          (is (eof-within? conn 2000) "connection closed"))))))

(deftest h2-read-timeout-bounds-body-reads
  ;; :read-timeout: a handler waiting on body bytes that never come gets a
  ;; failed read; the request is answered 408.
  (let [failure (promise)]
    (with-server (fn [req]
                   (try (slurp (:body req))
                        (catch java.io.IOException e (deliver failure e) (throw e)))
                   {:status 200 :body "ok"})
      {:read-timeout 300}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (is (= "408" (get (response-on conn 1) ":status")))
        (is (instance? java.io.IOException (deref failure 1000 nil)))))))

(deftest h2-server-events-and-protocol-errors
  (let [completed (atom [])
        errors (atom [])]
    (with-server (fn [_] {:status 201 :body "12345"})
      {:server-events {:request-completed (fn [p m s rb b _] (swap! completed conj [p m s rb b]))
                       :protocol-error (fn [p k] (swap! errors conj [p k]))}}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (end-stream-on 1))))
        (send-request! conn 3 (request-headers "GET" "relative") true)
        (is (some? (read-until conn (frame-on 3 frame-rst))))
        (ping-round-trip! conn)
        (is (= [["h2" "GET" 201 0 5]] @completed))
        (is (= [["h2" "bad-request"]] @errors))))))

;; ---- Graceful shutdown -----------------------------------------------------------

(deftest h2-graceful-shutdown-is-two-phase
  ;; §6.8: GOAWAY(2^31-1) + PING first, so requests already in flight are
  ;; still served; the real last stream id follows the PING ACK.
  (let [started (CountDownLatch. 1)
        release (CountDownLatch. 1)
        srv (enso/run-server
             (fn [req]
               (when (= "/slow" (:uri req))
                 (.countDown started)
                 (.await release 5 TimeUnit/SECONDS))
               {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context) :shutdown-timeout 5000})]
    (binding [*port* (enso/port srv)]
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/slow") true)
        (.await started 5 TimeUnit/SECONDS)
        (let [stopped (future (enso/stop srv))
              ga1 (read-until conn #(= frame-goaway (:type %)))
              ping (read-until conn #(and (= frame-ping (:type %)) (zero? (:flags %))))]
          (is (= 0x7FFFFFFF (some-> ga1 :payload (u32 0))) "first GOAWAY names no last stream")
          (is (= 0 (some-> ga1 goaway-code)))
          (is (some? ping) "PING to time the second GOAWAY")
          (send-request! conn 3 (request-headers "GET" "/") true)
          (is (= "200" (get (response-on conn 3) ":status")) "in-flight request still served")
          (write-frame! conn frame-ping 0x1 0 (:payload ping))
          (is (= 3 (some-> (read-until conn #(= frame-goaway (:type %))) :payload (u32 0)))
              "second GOAWAY names the last stream served")
          (.countDown release)
          (is (= "200" (get (response-on conn 1) ":status")))
          (is (eof-within? conn 3000) "closed once drained")
          (deref stopped 6000 nil))))))

;; ---- Allocation budgets -----------------------------------------------------------

(def ^:private ^com.sun.management.ThreadMXBean thread-mx
  (java.lang.management.ManagementFactory/getThreadMXBean))

(defn- total-allocated ^long []
  (.getTotalThreadAllocatedBytes thread-mx))

(deftest h2-tiny-data-frames-cost-no-heap-per-frame
  ;; One-byte DATA frames must not each cost a heap object (frame payload,
  ;; queue node): buffered request bytes are bounded by the window, not by
  ;; ~50x the window. Measured over every thread of this JVM, client
  ;; included, so the bound is loose.
  (let [n 20000
        release (CountDownLatch. 1)]
    (with-server (fn [_] (.await release 10 TimeUnit/SECONDS) {:status 200 :body "ok"}) {}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/") false)
        (ping-round-trip! conn)
        (let [one (frame-bytes frame-data 0 1 (byte-array 1))
              burst (byte-array (* n (alength one)))
              _ (dotimes [i n] (System/arraycopy one 0 burst (* i (alength one)) (alength one)))
              ping (frame-bytes frame-ping 0 0 (byte-array 8))
              before (total-allocated)]
          (write-raw! conn burst)
          (write-raw! conn ping)
          (read-until conn ping-ack?)
          (let [per-frame (/ (double (- (total-allocated) before)) n)]
            (println "h2 one-byte DATA frame:" per-frame "bytes/frame")
            (is (< per-frame 16) (str per-frame " bytes per one-byte DATA frame"))))
        (.countDown release)))))

(def ^:private alloc-get-block
  "HPACK block of the measured GET, encoded by a fresh encoder per connection."
  [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "localhost"]
   ["user-agent" "h2load"] ["accept" "*/*"]])

(defn- h2-alloc-input
  "Preface, SETTINGS and `n` GET HEADERS frames (END_STREAM) as one array."
  ^bytes [n]
  (let [enc (com.s_exp.enso.http2.Hpack$Encoder. 4096)
        block (fn [] (let [l (java.util.ArrayList.)]
                       (doseq [[k v] alloc-get-block] (.add l (com.s_exp.enso.http2.Hpack$HeaderField. k v)))
                       (.encode enc l)))
        out (java.io.ByteArrayOutputStream.)]
    (.write out (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1))
    (.write out (frame-bytes frame-settings 0 0 (byte-array 0)))
    (dotimes [i n]
      (.write out (frame-bytes frame-headers (bit-or flag-end-headers flag-end-stream) (inc (* 2 i)) (block))))
    (.toByteArray out)))

(defn- h2-connection-alloc-bytes
  "Bytes allocated by every thread while one in-memory Http2Connection,
  run on this thread, serves `n` GETs: framing, HPACK, Ring request,
  handler call, response head and DATA, handler threads, plus the
  connection's own buffers amortized over `n`."
  [srv handler ^bytes input n current]
  (let [latch (CountDownLatch. (int n))
        _ (reset! current latch)
        tail (proxy [java.io.InputStream] []
               (read
                 ([] -1)
                 ([b off len]
                  ;; End of input once every response is out.
                  (.await latch 10 TimeUnit/SECONDS)
                  -1)))
        in (java.io.SequenceInputStream. (java.io.ByteArrayInputStream. input) tail)
        out (java.io.OutputStream/nullOutputStream)
        addr (java.net.InetAddress/getLoopbackAddress)
        local (java.net.InetSocketAddress. addr 8443)
        sock (proxy [java.net.Socket] []
               (getInputStream [] in)
               (getOutputStream [] out)
               (setSoTimeout [_])
               (getInetAddress [] addr)
               (getLocalSocketAddress [] local)
               (getLocalPort [] 8443)
               (close []))
        c (com.s_exp.enso.http2.Http2Connection. sock handler srv 0)
        before (total-allocated)]
    (.run c)
    (- (total-allocated) before)))

(deftest h2-get-allocation-budget
  ;; A GET with 6 request fields, answered 200 with a String body, through
  ;; the whole HTTP/2 path. Measured over all threads (handler threads are
  ;; virtual, their allocation lands on carriers), with the connection
  ;; reading from memory and writing to a null stream so no client or TLS
  ;; cost is counted. See doc/architecture.md for what remains per request.
  (let [current (atom nil)
        ->response @#'enso/->response
        resp {:status 200 :headers {"content-type" "text/plain"} :body "Hello, World!"}
        handler (reify com.s_exp.enso.api.RingHandler
                  (handle [_ _] (->response resp)))
        events (reify com.s_exp.enso.api.ServerEvents
                 (requestCompleted [_ _ _ _ _ _ _] (.countDown ^CountDownLatch @current)))
        n 2000
        input (h2-alloc-input n)
        srv (enso/run-server (fn [_] resp) {:port 0 :http2 true :ssl-context (gen-server-context)
                                            :http2-max-concurrent-streams 4096
                                            :server-events events})]
    (try
      (dotimes [_ 20] (h2-connection-alloc-bytes srv handler input n current))
      (let [per-request (/ (double (apply min (repeatedly 3 #(h2-connection-alloc-bytes srv handler input n current)))) n)]
        (println "h2 GET:" per-request "bytes/request")
        (is (< per-request 1000) (str per-request " bytes/request")))
      (finally (enso/stop srv)))))

(deftest h2-stream-slot-free-once-response-ends
  ;; A client may open its next stream as soon as it sees END_STREAM:
  ;; the finished stream must no longer count against
  ;; MAX_CONCURRENT_STREAMS by then, however the response was produced.
  (with-server (fn [req]
                 (if (= "/stream" (:uri req))
                   {:status 200 :body (java.io.ByteArrayInputStream. (.getBytes "streamed"))}
                   {:status 200 :body "fixed"}))
    {:http2-max-concurrent-streams 1}
    (with-conn [conn]
      (let [seen (atom [])]
        (doseq [sid (range 1 801 2)]
          (send-request! conn sid (request-headers "GET" (if (zero? (mod sid 4)) "/stream" "/")) true)
          (read-until conn #(or (and (= sid (:sid %)) (= frame-rst (:type %)))
                                ((end-stream-on sid) %))
                      seen))
        (is (not-any? #(= frame-rst (:type %)) @seen) "no stream refused")))))

(deftest h2-bodiless-request-has-nil-body
  ;; Ring: :body is present only when the request has one, as on HTTP/1.1.
  (with-server (fn [req]
                 {:status 200 :body (if-let [^java.io.InputStream in (:body req)]
                                      (slurp in)
                                      "nil")})
    {}
    (with-conn [conn]
      (send-request! conn 1 (request-headers "GET" "/") true)
      (let [seen (atom [])]
        (read-until conn (end-stream-on 1) seen)
        (is (= "nil" (String. ^bytes (byte-array (mapcat :payload (filter (frame-on 1 frame-data) @seen)))))))
      (send-request! conn 3 (request-headers "POST" "/") false)
      (send-data! conn 3 3 true)
      (let [seen (atom [])]
        (read-until conn (end-stream-on 3) seen)
        (is (= 3 (count (String. ^bytes (byte-array (mapcat :payload (filter (frame-on 3 frame-data) @seen))))))
            "a body that is present is readable")))))

(deftest h2-control-flood-from-non-reading-peer-is-cut-off
  ;; A peer sending PINGs without reading the ACKs makes the server queue
  ;; control frames. The framer keeps reading, and past a cap (nghttp2's
  ;; outbound flood rule) the connection ends with ENHANCE_YOUR_CALM rather
  ;; than buffering every ACK. The peer never reads, so the error is
  ;; observed through :protocol-error. The client's write can complete
  ;; while the server still has PINGs buffered to read (Linux kernel
  ;; buffers hold a good part of the burst), so the error is waited for.
  (let [errors (atom [])]
    (with-server (fn [_] {:status 200 :body "ok"})
      ;; A small send buffer so the kernel can't absorb every ACK.
      {:so-snd-buf-bytes 8192
       :server-events {:protocol-error (fn [_ kind] (swap! errors conj kind))}}
      (with-conn [conn]
        (reset! (:paused conn) true)
        (let [ping (frame-bytes frame-ping 0 0 (byte-array 8))
              n 100000
              burst (byte-array (* n (alength ping)))
              _ (dotimes [i n] (System/arraycopy ping 0 burst (* i (alength ping)) (alength ping)))
              sent (future (try (write-raw! conn burst) :sent (catch java.io.IOException _ :closed)))]
          (is (not= ::blocked (deref sent 10000 ::blocked)) "the server kept reading")
          (let [deadline (+ (System/currentTimeMillis) 10000)]
            (while (and (not (some #{"enhance-your-calm"} @errors))
                        (< (System/currentTimeMillis) deadline))
              (Thread/sleep 10)))
          (is (some #{"enhance-your-calm"} @errors) (str "protocol errors: " @errors))
          (reset! (:paused conn) false)
          (is (eof-within? conn 5000) "connection closed"))))))
;; ---- Behaviour shared with the other protocols ---------------------------------

(defn- body-on [seen sid]
  (String. ^bytes (byte-array (mapcat :payload (filter (frame-on sid frame-data) seen)))))

(deftest h2-expect-100-continue-sent-on-first-body-read
  ;; RFC 9113 §8.6 / RFC 9110 §10.1.1, as on HTTP/1.1: the interim 100
  ;; goes out when the handler first reads the body, before the client
  ;; sends it; a handler that never reads gets no 100.
  (with-server (fn [req]
                 (if (= "/read" (:uri req))
                   {:status 200 :body (slurp (:body req))}
                   {:status 200 :body "unread"}))
    {}
    (with-conn [conn]
      (send-request! conn 1 (request-headers "POST" "/read" [["expect" "100-continue"]]) false)
      (let [f (read-until conn (frame-on 1 frame-headers))]
        (is (= "100" (get (:headers f) ":status")) "interim response first")
        (is (zero? (bit-and flag-end-stream (:flags f)))))
      (write-frame! conn frame-data flag-end-stream 1 (.getBytes "abc"))
      (let [seen (atom [])
            f (read-until conn (frame-on 1 frame-headers) seen)]
        (is (= "200" (get (:headers f) ":status")))
        (read-until conn (end-stream-on 1) seen)
        (is (= "abc" (body-on @seen 1))))
      (send-request! conn 3 (request-headers "POST" "/unread" [["expect" "100-continue"]]) false)
      (is (= "200" (get (response-on conn 3) ":status")) "no 100 for a body never read"))))

(deftest h2-unknown-expectation-is-417
  (let [called (atom 0)]
    (with-server (fn [_] (swap! called inc) {:status 200 :body "ok"}) {}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/" [["expect" "teapot"]]) false)
        (is (= "417" (get (response-on conn 1) ":status")))
        (is (zero? @called) "handler not run")))))

(deftest h2-repeated-content-length-is-malformed
  ;; One rule on every protocol: a repeated Content-Length is rejected
  ;; even when the values agree (HTTP/1.1 answers 400).
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (with-conn [conn]
      (send-request! conn 1 (request-headers "POST" "/" [["content-length" "3"] ["content-length" "3"]]) false)
      (is (= 0x1 (some-> (read-until conn (frame-on 1 frame-rst)) rst-code)) "RST_STREAM(PROTOCOL_ERROR)"))))

(deftest h2-header-field-count-is-capped
  (let [called (atom 0)]
    (with-server (fn [_] (swap! called inc) {:status 200 :body "ok"}) {:max-header-fields 5}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/" (for [i (range 5)] [(str "x-h" i) "v"])) true)
        (is (= "200" (get (response-on conn 1) ":status")))
        (send-request! conn 3 (request-headers "GET" "/" (for [i (range 6)] [(str "x-h" i) "v"])) true)
        (is (= "431" (get (response-on conn 3) ":status")))
        (is (= 1 @called))))))

(deftest h2-many-distinct-headers-build-a-hash-map-in-bounded-time
  (let [seen (promise)]
    (with-server (fn [req]
                   (deliver seen [(class (:headers req)) (count (:headers req)) (get-in req [:headers "x-h1999"])])
                   {:status 200 :body "ok"})
      {:max-header-fields 3000 :max-header-bytes (* 1024 1024)}
      (with-conn [conn]
        (let [t0 (System/nanoTime)]
          (send-split-headers! conn 1 (header-block conn (request-headers "GET" "/" (for [i (range 2000)] [(str "x-h" i) "v"])))
                               true)
          (is (= "200" (get (response-on conn 1) ":status")))
          (is (< (/ (- (System/nanoTime) t0) 1e6) 2000.0) "bounded time"))
        (is (= [clojure.lang.PersistentHashMap 2001 "v"] (deref seen 1000 nil)))))))

(defn- await-ignoring-interrupts
  "Waits on `latch` like a handler that never checks its interrupt."
  [^CountDownLatch latch]
  (loop []
    (when-not (try (.await latch 10 TimeUnit/SECONDS) (catch InterruptedException _ false))
      (when (pos? (.getCount latch)) (recur)))))

(deftest h2-closed-connection-keeps-its-slot-while-handlers-run
  ;; Closing TCP interrupts the connection's handlers; one that ignores
  ;; the interrupt keeps the connection counted (limiter slot, registry),
  ;; so dropping connections can't leave unbounded handlers running.
  (let [release (CountDownLatch. 1)
        started (CountDownLatch. 1)
        interrupted (promise)]
    (with-server (fn [req]
                   (if (= "/interruptible" (:uri req))
                     (try (.await (CountDownLatch. 1)) (catch InterruptedException _ (deliver interrupted true)))
                     (do (.countDown started) (await-ignoring-interrupts release)))
                   {:status 200 :body "ok"})
      {:max-connections 1 :shutdown-timeout 1000}
      (let [conn (h2-connect!)]
        (send-request! conn 1 (request-headers "GET" "/interruptible") true)
        (send-request! conn 3 (request-headers "GET" "/stubborn") true)
        (is (.await started 5 TimeUnit/SECONDS))
        (close-conn! conn))
      (is (deref interrupted 2000 false) "teardown interrupts the handlers")
      (Thread/sleep 200)
      (is (thrown? Exception (let [c (h2-connect!)]
                               (try (send-request! c 1 (request-headers "GET" "/") true)
                                    (when-not (response-on c 1) (throw (Exception. "refused")))
                                    (finally (close-conn! c)))))
          "still at :max-connections while the stubborn handler runs")
      (.countDown release)
      (Thread/sleep 300)
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (= "200" (get (response-on conn 1) ":status")) "slot freed once the handler returned")))))

(deftest h2-timed-out-handler-still-counts-against-concurrency
  ;; After the 503 the handler is interrupted; one ignoring it keeps its
  ;; stream slot until its thread exits.
  (let [release (CountDownLatch. 1)]
    (with-server (fn [_] (await-ignoring-interrupts release) {:status 200 :body "late"})
      {:handler-timeout 200 :http2-max-concurrent-streams 1 :shutdown-timeout 1000}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (= "503" (get (response-on conn 1) ":status")))
        (send-request! conn 3 (request-headers "GET" "/") true)
        (is (= 0x7 (some-> (read-until conn (frame-on 3 frame-rst) nil 1000) rst-code))
            "REFUSED_STREAM while the timed-out handler runs")
        (.countDown release)
        (Thread/sleep 300)
        (send-request! conn 5 (request-headers "GET" "/") true)
        (is (contains? #{"503" "200"} (get (response-on conn 5) ":status")) "slot back once it returned")))))

(deftest h2-memory-budget-holds-back-credit
  ;; Past :max-buffered-bytes, bytes a handler reads earn no WINDOW_UPDATE
  ;; until the budget has room again: backpressure through flow control.
  (let [release-a (CountDownLatch. 1)
        b-read (promise)]
    (with-server (fn [req]
                   (if (= "/a" (:uri req))
                     (do (.await release-a 10 TimeUnit/SECONDS) {:status 200 :body (str (count (slurp (:body req))))})
                     (let [buf (byte-array 65535)
                           in ^java.io.InputStream (:body req)]
                       ;; Reads what was sent without waiting for the end.
                       (loop [n 0] (if (< n 65535) (recur (+ n (.read in buf n (- 65535 n)))) n))
                       (deliver b-read true)
                       {:status 200 :body (str (count (slurp in)))})))
      {:max-buffered-bytes 60000 :http2-initial-window-bytes 65535}
      (with-conn [conn]
        (send-request! conn 1 (request-headers "POST" "/a") false)
        (send-data! conn 1 65535 false)
        (send-request! conn 3 (request-headers "POST" "/b") false)
        (send-data! conn 3 65535 false)
        (is (deref b-read 5000 false))
        (let [seen (drain-frames conn 300)]
          (is (empty? (window-updates seen 3)) "budget exhausted: stream 3's credit held back"))
        (.countDown release-a)
        (write-frame! conn frame-data flag-end-stream 1 (byte-array 0))
        (let [seen (atom [])]
          (read-until conn #(seq (window-updates [%] 3)) seen 3000)
          (is (seq (window-updates @seen 3)) "credit granted once A's body was read"))
        (write-frame! conn frame-data flag-end-stream 3 (byte-array 0))))))

(deftest h2-stop-interrupts-and-joins-handlers-within-the-timeout
  ;; stop drains until the last part of :shutdown-timeout, then closes
  ;; what is left: running handlers are interrupted and stop returns once
  ;; they exited, within the timeout.
  (let [started (CountDownLatch. 1)
        exited (promise)
        srv (enso/run-server (fn [_]
                               (.countDown started)
                               (try (.await (CountDownLatch. 1))
                                    (catch InterruptedException _ (Thread/sleep 50) (deliver exited :interrupted)))
                               {:status 200 :body "late"})
                             {:port 0 :http2 true :ssl-context (gen-server-context) :shutdown-timeout 1000})]
    (binding [*port* (enso/port srv)]
      (let [conn (h2-connect!)]
        (try
          (send-request! conn 1 (request-headers "GET" "/") true)
          (is (.await started 5 TimeUnit/SECONDS))
          (let [t0 (System/nanoTime)]
            (enso/stop srv)
            (is (< (/ (- (System/nanoTime) t0) 1e6) 1500.0) "within the timeout")
            (is (= :interrupted (deref exited 0 :still-running)) "the handler exited before stop returned"))
          (finally (close-conn! conn)))))))

(deftest h2-cancelling-a-writing-handler-keeps-the-connection
  ;; Handler threads also write for the whole connection. Cancelling a
  ;; stream interrupts its handler, which may be blocked in that socket
  ;; write: the interrupt must wait for the write (an interrupt inside a
  ;; blocking write closes the socket for every stream).
  (let [payload (byte-array (* 32 1024 1024))]
    (with-server (fn [req] (if (= "/big" (:uri req)) {:status 200 :body payload} {:status 200 :body "small"}))
      {}
      (with-conn [conn [[0x4 0x7FFFFFFF]]]
        (open-windows! conn)
        (reset! (:paused conn) true)
        (send-request! conn 1 (request-headers "GET" "/big") true)
        ;; The handler thread hands its body over and writes until the
        ;; socket buffers are full: it is blocked in the write.
        (Thread/sleep 500)
        (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
        (Thread/sleep 200)
        (send-request! conn 3 (request-headers "GET" "/small") true)
        (reset! (:paused conn) false)
        (let [seen (atom [])]
          (is (some? (read-until conn (end-stream-on 3) seen 10000)) "the connection still serves")
          (is (= "small" (body-on @seen 3))))))))

;; ---- Receive-side accounting -----------------------------------------------------

(def ^:private flag-padded 0x8)

(deftest h2-padding-of-a-length-mismatch-is-credited
  ;; A DATA frame ending a body shorter than its Content-Length is a
  ;; stream error, but its padding still counted against the connection
  ;; window (§6.9.1) and must come back: otherwise every such frame shrinks
  ;; the window for good until uploads on the connection stall.
  (let [release (CountDownLatch. 1)
        n 130]
    (with-server (fn [_]
                   (try (.await release 10 TimeUnit/SECONDS) (catch InterruptedException _))
                   {:status 200 :body "ok"})
      {:http2-initial-window-bytes 65535 :http2-stream-reset-limit 0
       :http2-max-concurrent-streams 200}
      (with-conn [conn]
        (drain-frames conn 300)
        ;; n x 256 octets of padding passes the 32767-octet credit threshold.
        (let [padding (byte-array 256)
              _ (aset-byte padding 0 (unchecked-byte 255))
              seen (atom [])]
          (doseq [sid (range 1 (inc (* 2 n)) 2)]
            (send-request! conn sid (request-headers "POST" "/" [["content-length" "1"]]) false)
            (write-frame! conn frame-data (bit-or flag-padded flag-end-stream) sid padding))
          (write-frame! conn frame-ping 0 0 (byte-array 8))
          (read-until conn ping-ack? seen)
          (swap! seen into (drain-frames conn 300))
          (is (= n (count (filter #(and (= frame-rst (:type %)) (= 0x1 (rst-code %))) @seen)))
              "every mismatch is a stream error")
          (is (seq (window-updates @seen 0)) "the padding is credited back to the connection"))
        (.countDown release)))))

(deftest h2-trailer-fields-are-validated
  ;; §8.2.1 / §8.2.2: a trailer section follows the field rules of a head
  ;; (lowercase token names, no CTL in values, no connection-specific
  ;; fields); breaking them makes the request malformed, a stream error
  ;; PROTOCOL_ERROR, even though Ring drops trailers.
  (with-server (fn [req] {:status 200 :body (slurp (:body req))}) {}
    (with-conn [conn]
      (doseq [[sid trailer] [[1 ["X-Upper" "t"]]
                             [3 ["x-ctl" "a\u0001b"]]
                             [5 ["connection" "close"]]
                             [7 ["x-space" " padded"]]
                             [9 ["bad name" "t"]]]]
        (send-request! conn sid (request-headers "POST" "/") false)
        (write-frame! conn frame-data 0 sid (.getBytes "body"))
        (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) sid
                      (header-block conn [trailer]))
        (is (= 0x1 (some-> (read-until conn (frame-on sid frame-rst)) rst-code))
            (str "trailer " (pr-str trailer) " resets the stream")))
      (send-request! conn 11 (request-headers "POST" "/") false)
      (write-frame! conn frame-data 0 11 (.getBytes "body"))
      (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 11
                    (header-block conn [["x-checksum" "abc"]]))
      (let [seen (atom [])]
        (read-until conn (end-stream-on 11) seen)
        (is (= "body" (body-on @seen 11)) "valid trailers end the body")
        (is (not-any? #(= frame-goaway (:type %)) @seen) "the connection is kept")))))

(deftest h2-aborted-fixed-responses-are-reported
  ;; Every request the handler answered ends in requestCompleted, as on
  ;; HTTP/1.1, including a fixed body handed to the writer that never
  ;; finished: reset by the peer while it waited for credit, or cut by the
  ;; connection closing.
  (let [completed (atom [])]
    (with-server (fn [_] {:status 200 :body (byte-array 100000)})
      {:server-events {:request-completed (fn [p m s _ b _] (swap! completed conj [p m s b]))}}
      (with-conn [conn [[0x4 0]]]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (frame-on 1 frame-headers))))
        (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
        (ping-round-trip! conn)
        (is (= [["h2" "GET" 200 0]] @completed) "reset while blocked on credit"))
      (reset! completed [])
      (let [conn (h2-connect! [[0x4 0]])]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (frame-on 1 frame-headers))))
        (close-conn! conn)
        (let [deadline (+ (System/currentTimeMillis) 5000)]
          (while (and (empty? @completed) (< (System/currentTimeMillis) deadline))
            (Thread/sleep 10)))
        (is (= [["h2" "GET" 200 0]] @completed) "connection closed while blocked on credit")))))

(deftest h2-request-on-a-forgotten-stream-id-is-a-connection-error
  ;; §5.1.1: a new request must use a stream id above every earlier one.
  ;; One reusing an id the closed-stream ring has forgotten is still a
  ;; PROTOCOL_ERROR (a trailer section on such a stream, which a request
  ;; the server reset may legitimately still send, stays ignored).
  (with-server (fn [_] {:status 200 :body "ok"}) {:http2-max-concurrent-streams 1}
    (with-conn [conn]
      (doseq [sid (range 1 161 2)]
        (send-request! conn sid (request-headers "GET" "/") true)
        (read-until conn (end-stream-on sid)))
      (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                    (header-block conn [["x-trailer" "t"]]))
      (ping-round-trip! conn)
      (send-request! conn 3 (request-headers "GET" "/") true)
      (is (= 0x1 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))
          "GOAWAY(PROTOCOL_ERROR)"))))

(deftest h2-closed-stream-history-across-many-streams
  ;; The closed-stream memory (2x the concurrency limit, here 64 streams)
  ;; after it wrapped: DATA on a recently ended stream or on an id the peer
  ;; skipped is a connection error STREAM_CLOSED (§5.1); on one older
  ;; than the memory it is ignored (it may be in flight after our reset).
  (with-server (fn [_] {:status 200 :body "ok"}) {:http2-max-concurrent-streams 1}
    (let [serve! (fn [conn sids]
                   (doseq [sid sids]
                     (send-request! conn sid (request-headers "GET" "/") true)
                     (read-until conn (end-stream-on sid))))]
      (testing "forgotten"
        (with-conn [conn]
          (serve! conn (range 1 301 2))
          (write-frame! conn frame-data 0 1 (.getBytes "late"))
          (let [seen (atom [])]
            (write-frame! conn frame-ping 0 0 (byte-array 8))
            (read-until conn ping-ack? seen)
            (is (not-any? #(= frame-goaway (:type %)) @seen)))))
      (testing "recently ended"
        (with-conn [conn]
          (serve! conn (range 1 301 2))
          (write-frame! conn frame-data 0 297 (.getBytes "late"))
          (is (= 0x5 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code)))))
      (testing "skipped"
        (with-conn [conn]
          (serve! conn (concat (range 1 201 2) (range 203 301 2)))
          (write-frame! conn frame-data 0 201 (.getBytes "late"))
          (is (= 0x5 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))))))))

(defn- settings-payload ^bytes [pairs]
  (byte-array (mapcat (fn [[id v]]
                        (concat [(unchecked-byte (bit-shift-right id 8)) (unchecked-byte id)]
                                (u32-bytes v)))
                      pairs)))

(deftest h2-initial-window-settings-apply-in-order
  ;; §6.5.3: values of one SETTINGS frame apply in order. Many
  ;; INITIAL_WINDOW_SIZE values in a frame end at the last one; one of them
  ;; overflowing a stream window on the way is a FLOW_CONTROL_ERROR
  ;; (§6.9.2) even when the last value would fit. A frame full of them
  ;; costs one pass over the streams, not one per value.
  (with-server (fn [_] {:status 200 :body (byte-array 1000)}) {}
    (testing "the last value wins"
      (with-conn [conn [[0x4 0]]]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (frame-on 1 frame-headers))))
        (write-frame! conn frame-settings 0 0
                      (settings-payload (concat (repeat 2000 [0x4 0]) [[0x4 1000]])))
        (let [seen (atom [])]
          (read-until conn (end-stream-on 1) seen)
          (is (= 1000 (data-bytes-on @seen 1))))))
    (testing "an overflow on the way"
      (with-conn [conn [[0x4 0]]]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (is (some? (read-until conn (frame-on 1 frame-headers))))
        (write-frame! conn frame-window-update 0 1 (u32-bytes 1))
        (write-frame! conn frame-settings 0 0
                      (settings-payload [[0x4 0x7FFFFFFF] [0x4 0]]))
        (is (= 0x3 (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code))
            "GOAWAY(FLOW_CONTROL_ERROR)")))))

;; ---- Memory held per connection ----------------------------------------------------
;; White-box: the server-side objects are reached by reflection, so the
;; buffers a connection keeps can be checked exactly.

(defn- field-of
  "Value of the field named `fname` declared by `obj`'s class or a superclass."
  [obj ^String fname]
  (loop [^Class c (class obj)]
    (if-let [^java.lang.reflect.Field f (try (.getDeclaredField c fname)
                                             (catch NoSuchFieldException _ nil))]
      (.get (doto f (.setAccessible true)) obj)
      (if-let [s (.getSuperclass c)]
        (recur s)
        (throw (NoSuchFieldException. fname))))))

(defn- server-h2-connection
  "The server's only live HTTP/2 connection."
  [srv]
  (let [live (field-of (field-of srv "registry") "live")]
    (first (keep #(let [d (field-of % "driver")]
                    (when (instance? com.s_exp.enso.http2.Http2Connection d) d))
                 live))))

(defn- capacity [^java.nio.ByteBuffer b] (.capacity b))

(defmacro ^:private with-server-instance
  "Like with-server, binding `srv` to the running server."
  [[srv handler opts] & body]
  `(let [~srv (enso/run-server ~handler (merge {:port 0 :http2 true :ssl-context (gen-server-context)} ~opts))]
     (try
       (binding [*port* (enso/port ~srv)] ~@body)
       (finally (enso/stop ~srv)))))

(deftest h2-idle-connection-gives-back-its-buffers
  ;; A connection quiet for a second keeps only what it needs to wait:
  ;; TLS record buffers swapped for small ones, the framer's input and
  ;; header-block buffers and the writer's encoder buffer back to their
  ;; initial size, closed streams forgotten. The next request regrows them.
  (with-server-instance [srv
                         (fn [req]
                           (some-> (:body req) slurp)
                           {:status 200 :headers {"x-big" (apply str (repeat 10000 "v"))} :body "ok"})
                         {:max-header-bytes 65536}]
    (with-conn [conn]
      (send-split-headers! conn 1 (header-block conn (request-headers "POST" "/" [["x-in" (apply str (repeat 30000 "i"))]])) false)
      (send-data! conn 1 16384 true)
      (is (some? (read-until conn (end-stream-on 1))))
      (Thread/sleep 1500)
      (let [c (server-h2-connection srv)
            tls (.tls ^com.s_exp.enso.core.TlsSocket$AdapterSocket (field-of c "socket"))
            writer (field-of c "writer")]
        (is (= 512 (capacity (field-of tls "peerNetData"))) "TLS input record buffer")
        (is (= 512 (capacity (field-of tls "myNetData"))) "TLS output record buffer")
        (is (>= 64 (alength ^bytes (field-of c "inBuf"))) "framer input buffer")
        (is (nil? (field-of c "pendingHeaderBytes")) "header block buffer")
        (is (nil? (field-of c "retired")) "closed streams forgotten")
        (is (zero? (field-of (field-of c "streams") "size")) "stream table empty")
        (is (>= 256 (alength ^bytes (field-of (field-of writer "encoder") "buf"))) "encoder buffer"))
      (send-request! conn 3 (request-headers "GET" "/") true)
      (is (= "200" (get (response-on conn 3) ":status")) "served after the release"))))

(deftest h2-finished-stream-keeps-no-response-ring
  ;; A streamed response's ring (up to 64 KiB) is dropped once END_STREAM
  ;; is packed, not when the stream object is collected.
  (with-server-instance [srv (fn [_] {:status 200 :body (ByteArrayInputStream. (byte-array 100000))}) {}]
    (with-conn [conn [[0x4 0x7FFFFFFF]]]
      (open-windows! conn)
      (send-request! conn 1 (request-headers "GET" "/") true)
      (is (some? (read-until conn (end-stream-on 1))))
      (let [s (field-of (server-h2-connection srv) "retired")]
        (is (some? s) "the finished stream, not yet forgotten")
        (is (nil? (some-> s (field-of "ring"))) "its ring is gone")))))

(deftest h2-drained-request-body-gives-back-its-buffer
  ;; The request body ring grows with what the peer sends ahead of the
  ;; handler (up to the stream window, 1 MiB by default). Once the handler
  ;; has read it all it is given back, while the upload goes on.
  (let [ready (CountDownLatch. 1)
        drained (CountDownLatch. 1)
        finish (CountDownLatch. 1)]
    (with-server-instance [srv (fn [req]
                                 (.await ready 5 TimeUnit/SECONDS)
                                 (let [in ^java.io.InputStream (:body req)]
                                   (.readNBytes in (* 512 1024))
                                   (.countDown drained)
                                   (.await finish 5 TimeUnit/SECONDS)
                                   {:status 200 :body (str (alength (.readAllBytes in)))}))
                           {}]
      (with-conn [conn]
        (open-windows! conn)
        (send-request! conn 1 (request-headers "POST" "/") false)
        (send-data! conn 1 (* 512 1024) false)
        (ping-round-trip! conn)
        (.countDown ready)
        (is (.await drained 5 TimeUnit/SECONDS))
        (let [streams (field-of (server-h2-connection srv) "streams")
              s (first (filter some? (field-of streams "values")))
              ring (field-of (field-of s "body") "ring")]
          (is (or (nil? ring) (>= 16384 (alength ^bytes ring))) "the grown ring was given back"))
        (.countDown finish)
        (send-data! conn 1 1000 true)
        (is (= "1000" (body-on (let [seen (atom [])] (read-until conn (end-stream-on 1) seen) @seen) 1))
            "the body goes on")))))

(deftest h2-pooled-response-heads-stay-small
  ;; Response heads are pooled server-wide; one grown by a response with
  ;; many header fields isn't kept, so the pool can't pin large arrays.
  (with-server (fn [_] {:status 200 :headers (into {} (for [i (range 200)] [(str "x-h" i) "v"])) :body "ok"}) {}
    (with-conn [conn]
      (send-request! conn 1 (request-headers "GET" "/") true)
      (is (some? (read-until conn (end-stream-on 1))))
      (let [^java.util.concurrent.atomic.AtomicReferenceArray heads
            (let [f (doto (.getDeclaredField (Class/forName "com.s_exp.enso.http2.Http2Exchange") "HEADS")
                      (.setAccessible true))]
              (.get f nil))]
        (is (not-any? (fn [h] (and h (> (alength ^objects (field-of h "names")) 64)))
                      (map #(.get heads %) (range (.length heads)))))))))

(deftest h2-invalid-fields-stay-invalid-when-indexed
  ;; Field characters are checked once per HPACK table entry, but an entry
  ;; that failed the check is never trusted: referencing it again from the
  ;; dynamic table is malformed every time.
  (with-server (fn [_] {:status 200 :body "ok"}) {}
    (with-conn [conn]
      (doseq [sid [1 3]]
        (send-request! conn sid (request-headers "GET" "/" [["x-bad" "a\u0001b"]]) true)
        (is (= 0x1 (some-> (read-until conn (frame-on sid frame-rst)) rst-code))))
      (doseq [sid [5 7]]
        (send-request! conn sid (request-headers "GET" "/" [["x-good" "v"]]) true)
        (is (= "200" (get (response-on conn sid) ":status")))))))

(deftest h2-small-streamed-bodies-leave-in-one-batch
  ;; A body that is read without waiting (a file, an in-memory stream)
  ;; goes out with its head and END_STREAM in one batch: one write, one
  ;; TLS record, not three. Another stream may be slow, so its head leaves
  ;; first; when its Content-Length says the last bytes were read,
  ;; END_STREAM goes with them.
  (let [f (doto (java.io.File/createTempFile "enso-h2" ".txt") (.deleteOnExit))]
    (spit f "file body")
    (with-server-instance [srv (fn [req]
                                 (case (:uri req)
                                   "/file" {:status 200 :body f}
                                   "/bytes" {:status 200 :body (ByteArrayInputStream. (.getBytes "in memory"))}
                                   "/declared" {:status 200 :headers {"content-length" "8"}
                                                :body (java.io.BufferedInputStream.
                                                       (ByteArrayInputStream. (.getBytes "declared")))}))
                           {}]
      (with-conn [conn]
        (ping-round-trip! conn)
        (let [writer (field-of (server-h2-connection srv) "writer")]
          (doseq [[sid path body batches] [[1 "/file" "file body" 1] [3 "/bytes" "in memory" 1]
                                           [5 "/declared" "declared" 2]]]
            (let [before (field-of writer "batchSeq")
                  seen (atom [])]
              (send-request! conn sid (request-headers "GET" path) true)
              (read-until conn (end-stream-on sid) seen)
              (is (= body (body-on @seen sid)))
              (is (= batches (- (field-of writer "batchSeq") before)) (str path " batches")))))))))

(deftest h2-credit-starved-stream-buffers-little
  ;; A peer that grants a stream little credit (or reads it slowly) keeps
  ;; its producer waiting with at most one frame's worth buffered, not the
  ;; full 64 KiB ring: slow readers can't pin much memory per stream.
  (with-server-instance [srv (fn [_] {:status 200
                                      :body (java.io.BufferedInputStream.
                                             (ByteArrayInputStream. (byte-array 200000)))})
                         {}]
    (with-conn [conn [[0x4 1000]]]
      (open-windows! conn)
      (send-request! conn 1 (request-headers "GET" "/") true)
      (is (some? (read-until conn (frame-on 1 frame-data))))
      (Thread/sleep 300)
      (let [streams (field-of (server-h2-connection srv) "streams")
            s (first (filter some? (field-of streams "values")))]
        (is (>= 16384 (field-of s "ringCount")) "buffered bytes")
        (is (>= 16384 (alength ^bytes (field-of s "ring"))) "ring size"))
      (write-frame! conn frame-window-update 0 1 (u32-bytes (- 200000 1000)))
      (let [seen (atom [])]
        (read-until conn (end-stream-on 1) seen)
        (is (= 199000 (data-bytes-on @seen 1)) "the rest follows the credit")))))

(deftest h2-ring-shrinks-when-credit-stops
  ;; A ring grown while credit flowed is cut down once the stream waits on
  ;; a shut window with less left than the window would let it buffer.
  (let [go (CountDownLatch. 1)]
    (with-server-instance [srv (fn [_] {:status 200
                                        :body (fn [w]
                                                (enso/write! w (byte-array 60000))
                                                (.await go 5 TimeUnit/SECONDS)
                                                (enso/write! w (byte-array 1000)))})
                           {}]
      (with-conn [conn [[0x4 50000]]]
        (open-windows! conn)
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (read-until conn (constantly false) seen 500)
          (is (= 50000 (data-bytes-on @seen 1)) "the window is used up")
          (let [streams (field-of (server-h2-connection srv) "streams")
                s (first (filter some? (field-of streams "values")))]
            (is (= 10000 (field-of s "ringCount")))
            (is (>= 16384 (alength ^bytes (field-of s "ring"))) "ring cut down"))
          (.countDown go)
          (write-frame! conn frame-window-update 0 1 (u32-bytes 11000))
          (read-until conn (end-stream-on 1) seen)
          (is (= 61000 (data-bytes-on @seen 1))))))))

(deftest h2-response-rings-are-charged-to-the-memory-budget
  ;; Streamed response bytes waiting in a stream's ring are held for a peer
  ;; that hasn't taken them: they count against :max-buffered-bytes until
  ;; sent or dropped, and while the budget is exhausted a producer may only
  ;; buffer one frame.
  (testing "charged until dropped"
    (with-server-instance [srv (fn [_] {:status 200
                                        :body (java.io.BufferedInputStream.
                                               (ByteArrayInputStream. (byte-array 200000)))})
                           {}]
      (let [budget (.budget (.service ^com.s_exp.enso.EnsoServer srv))]
        (with-conn [conn [[0x4 1000]]]
          (open-windows! conn)
          (send-request! conn 1 (request-headers "GET" "/") true)
          (is (some? (read-until conn (frame-on 1 frame-data))))
          (Thread/sleep 300)
          (let [streams (field-of (server-h2-connection srv) "streams")
                s (first (filter some? (field-of streams "values")))]
            (is (pos? (.used budget)))
            (is (= (field-of s "ringCount") (.used budget)) "the ring's bytes"))
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          (ping-round-trip! conn)
          (is (zero? (.used budget)) "released when the stream is reset")))))
  (testing "one frame while exhausted"
    ;; The peer stops reading: the socket fills, the window stays open.
    (with-server-instance [srv (fn [_] {:status 200
                                        :body (java.io.BufferedInputStream.
                                               (ByteArrayInputStream. (byte-array (* 32 1024 1024))))})
                           {:max-buffered-bytes 1}]
      (with-conn [conn [[0x4 0x7FFFFFFF]]]
        (open-windows! conn)
        (reset! (:paused conn) true)
        (send-request! conn 1 (request-headers "GET" "/") true)
        (Thread/sleep 1000)
        (let [streams (field-of (server-h2-connection srv) "streams")
              s (first (filter some? (field-of streams "values")))]
          (is (>= 16384 (field-of s "ringCount"))))))))

;; ---- Cleartext HTTP/2 (h2c, prior knowledge) ----------------------------------------

(defn- h2c-server
  "A started plain-listener server with `:http2c` on, built from Config
  directly; `configure` adjusts the Config.Builder."
  (^com.s_exp.enso.EnsoServer [handler] (h2c-server handler identity))
  (^com.s_exp.enso.EnsoServer [handler configure]
   (let [->response @#'enso/->response
         b (doto (com.s_exp.enso.api.Config$Builder.) (.port 0) (.http2c true))
         _ (configure b)
         srv (com.s_exp.enso.EnsoServer.
              (reify com.s_exp.enso.api.RingHandler
                (handle [_ req] (->response (handler req))))
              (.build ^com.s_exp.enso.api.Config$Builder b))]
     (.start srv)
     srv)))

(defn- plain-socket ^java.net.Socket []
  (doto (java.net.Socket. "127.0.0.1" (int *port*)) (.setTcpNoDelay true)))

(defn- http1-exchange
  "Writes `request` on a fresh plain connection and returns everything the
  server sends until it closes or goes quiet for 2 s."
  ^String [^String request]
  (with-open [sock (plain-socket)]
    (.setSoTimeout sock 2000)
    (doto (.getOutputStream sock)
      (.write (.getBytes request StandardCharsets/ISO_8859_1))
      (.flush))
    (let [in (.getInputStream sock)
          out (java.io.ByteArrayOutputStream.)
          buf (byte-array 4096)]
      (try
        (loop []
          (let [n (.read in buf)]
            (when (pos? n)
              (.write out buf 0 n)
              (recur))))
        (catch java.net.SocketTimeoutException _))
      (.toString out "ISO-8859-1"))))

(deftest h2c-prior-knowledge-is-served
  ;; RFC 9113 §3.3: a client that knows the server speaks HTTP/2 sends the
  ;; preface straight away on a cleartext connection.
  (let [seen (promise)
        srv (h2c-server (fn [req] (deliver seen req) {:status 200 :body "h2c"}))]
    (try
      (binding [*port* (.port srv)]
        (let [conn (h2-connect-on! (plain-socket) [])]
          (try
            (send-request! conn 1 [[":method" "GET"] [":scheme" "http"] [":path" "/x"]
                                   [":authority" "localhost"]] true)
            (let [frames (atom [])]
              (read-until conn (end-stream-on 1) frames)
              (is (= "200" (some #(get-in % [:headers ":status"]) @frames)))
              (is (= "h2c" (body-on @frames 1))))
            (let [req (deref seen 1000 nil)]
              (is (= :http (:scheme req)) "cleartext")
              (is (= "HTTP/2.0" (:protocol req)))
              (is (= "/x" (:uri req))))
            (finally (close-conn! conn)))))
      (finally (.close srv)))))

(deftest h2c-listener-still-serves-http1
  ;; The listener tells the two apart by the first bytes: anything that
  ;; isn't the HTTP/2 preface is HTTP/1.1, with the bytes read to decide
  ;; handed to the HTTP/1.1 parser, however short the request (an
  ;; HTTP/1.0 GET is 18 bytes) or close its start is to "PRI".
  (let [srv (h2c-server (fn [req] {:status 200 :body (str (:request-method req) " " (some-> (:body req) slurp))}))]
    (try
      (binding [*port* (.port srv)]
        (is (str/includes? (http1-exchange "GET / HTTP/1.0\r\n\r\n") ":get"))
        (is (str/includes? (http1-exchange "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n") ":get"))
        (is (str/includes? (http1-exchange (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n"
                                                "Connection: close\r\n\r\nabc"))
                           ":post abc"))
        (is (str/includes? (http1-exchange "PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                           ":put"))
        (is (str/starts-with? (http1-exchange "PRI * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n") "HTTP/1.1 ")
            "a request that only starts like the preface gets an HTTP/1.1 answer"))
      (finally (.close srv)))))

(deftest h2c-preface-arriving-in-pieces
  ;; The preface may trickle in a few bytes at a time.
  (let [srv (h2c-server (fn [_] {:status 200 :body "ok"}))]
    (try
      (binding [*port* (.port srv)]
        (let [sock (plain-socket)
              out (.getOutputStream sock)
              preface (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1)]
          (doseq [i (range 0 24 5)]
            (.write out preface i (min 5 (- 24 i)))
            (.flush out)
            (Thread/sleep 20))
          (let [conn (h2-connect-on! sock [] false)]
            (try
              (send-request! conn 1 [[":method" "GET"] [":scheme" "http"] [":path" "/"]
                                     [":authority" "localhost"]] true)
              (is (= "200" (get (response-on conn 1) ":status")))
              (finally (close-conn! conn))))))
      (finally (.close srv)))))

(deftest h2c-is-off-by-default
  ;; Without :http2c the plain listener is HTTP/1.1 only: the preface is
  ;; answered as a (malformed) HTTP/1.1 request.
  (let [srv (h2c-server (fn [_] {:status 200 :body "ok"}) #(.http2c ^com.s_exp.enso.api.Config$Builder % false))]
    (try
      (binding [*port* (.port srv)]
        (is (str/starts-with? (http1-exchange "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") "HTTP/1.1 ")))
      (finally (.close srv)))))

(deftest h2c-reports-its-own-protocol
  ;; Events name cleartext HTTP/2 "h2c" (its ALPN-style identifier), so it
  ;; is told apart from h2 over TLS.
  (let [opened (promise)
        completed (promise)
        srv (h2c-server (fn [_] {:status 200 :body "ok"})
                        #(.serverEvents ^com.s_exp.enso.api.Config$Builder %
                                        (reify com.s_exp.enso.api.ServerEvents
                                          (connectionOpened [_ p _] (deliver opened p))
                                          (requestCompleted [_ p _ _ _ _ _] (deliver completed p)))))]
    (try
      (binding [*port* (.port srv)]
        (let [conn (h2-connect-on! (plain-socket) [])]
          (try
            (send-request! conn 1 [[":method" "GET"] [":scheme" "http"] [":path" "/"]
                                   [":authority" "localhost"]] true)
            (is (some? (read-until conn (end-stream-on 1))))
            (is (= "h2c" (deref opened 1000 nil)))
            (is (= "h2c" (deref completed 1000 nil)))
            (finally (close-conn! conn)))))
      (finally (.close srv)))))

(deftest h2c-needs-a-plain-listener
  ;; One TCP listener is either TLS or plain: cleartext HTTP/2 with an
  ;; SSLContext is a contradiction (h2 over TLS is :http2).
  (let [b (doto (com.s_exp.enso.api.Config$Builder.)
            (.http2c true)
            (.sslContext (gen-server-context)))]
    (is (thrown-with-msg? IllegalArgumentException #":http2c serves a plain listener"
                          (.build b))))
  (is (thrown-with-msg? IllegalArgumentException #":http2 needs :ssl-context \(cleartext HTTP/2 is :http2c\)"
                        (.build (doto (com.s_exp.enso.api.Config$Builder.) (.http2 true))))))

(deftest h2-closed-stream-memory-matches-a-model
  ;; ClosedStreams (ring + hash table with backward-shift deletion) against
  ;; a plain list of the last `capacity` closes, over random close orders.
  (let [cls (Class/forName "com.s_exp.enso.http2.ClosedStreams")
        ctor (doto (.getDeclaredConstructor cls (into-array Class [Integer/TYPE])) (.setAccessible true))
        add (doto (.getDeclaredMethod cls "add" (into-array Class [Integer/TYPE Integer/TYPE])) (.setAccessible true))
        reason-of (doto (.getDeclaredMethod cls "reasonOf" (into-array Class [Integer/TYPE])) (.setAccessible true))
        rnd (java.util.Random. 42)]
    (doseq [capacity [64 200]]
      (let [cs (.newInstance ctor (object-array [(int capacity)]))
            ids (vec (range 1 6001 2))
            ;; closes in a shuffled order within a sliding window, as streams overlap
            order (loop [pending [] [id & more :as left] ids out []]
                    (cond
                      (and (empty? left) (empty? pending)) out
                      (and (seq left) (< (count pending) 50)) (recur (conj pending id) more out)
                      :else (let [k (.nextInt rnd (count pending))]
                              (recur (into (subvec pending 0 k) (subvec pending (inc k))) left
                                     (conj out (nth pending k))))))
            model (atom [])
            floor (atom 0)]
        (doseq [id order]
          (let [reason (inc (.nextInt rnd 3))]
            (.invoke add cs (object-array [(int id) (int reason)]))
            (swap! model conj [id reason])
            (when (> (count @model) capacity)
              (swap! floor max (first (first @model)))
              (swap! model subvec 1)))
          (when (zero? (.nextInt rnd 20))
            (let [m (into {} @model)]
              (doseq [probe (repeatedly 20 #(inc (* 2 (.nextInt rnd 3100))))]
                (is (= (get m probe (if (> probe @floor) 0 -1))
                       (.invoke reason-of cs (object-array [(int probe)])))
                    (str "capacity " capacity " id " probe))))))))))

(defn- patterned-stream
  "An InputStream of `n` bytes, byte i = i mod 251, returning reads of
  random sizes (as a socket or a decompressor would)."
  ^java.io.InputStream [n seed]
  (let [pos (atom 0)
        rnd (java.util.Random. seed)]
    (proxy [java.io.InputStream] []
      (read
        ([] (let [p @pos]
              (if (>= p n) -1 (do (swap! pos inc) (mod p 251)))))
        ([^bytes b off len]
         (let [p @pos]
           (if (>= p n)
             -1
             (let [k (min len (- n p) (inc (.nextInt rnd 40000)))]
               (dotimes [i k] (aset b (+ off i) (unchecked-byte (mod (+ p i) 251))))
               (reset! pos (+ p k))
               k))))))))

(deftest h2-streamed-body-integrity-under-backpressure
  ;; A streamed body read in irregular chunks into a ring the writer drains
  ;; at the pace of a slow reader: every byte arrives once, in order.
  (let [n (* 4 1024 1024)]
    (with-server (fn [_] {:status 200 :body (patterned-stream n 7)}) {}
      (with-conn [conn [[0x4 0x7FFFFFFF]]]
        (open-windows! conn)
        (reset! (:read-delay-ms conn) 1)
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [seen (atom [])]
          (is (some? (read-until conn (end-stream-on 1) seen 30000)))
          (let [data (filter (frame-on 1 frame-data) @seen)
                body (byte-array (reduce + 0 (map #(alength ^bytes (:payload %)) data)))]
            (reduce (fn [off f] (let [^bytes p (:payload f)]
                                  (System/arraycopy p 0 body off (alength p))
                                  (+ off (alength p))))
                    0 data)
            (is (= n (alength body)))
            (is (loop [i 0]
                  (cond (= i (alength body)) true
                        (not= (mod i 251) (bit-and (aget body i) 0xFF)) false
                        :else (recur (inc i))))
                "byte-for-byte")))))))

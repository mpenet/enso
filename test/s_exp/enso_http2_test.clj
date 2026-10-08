(ns s-exp.enso-http2-test
  "HTTP/2 end-to-end tests via java.net.http. Server runs h2 over TLS
  (h2c is not supported). Covers session changes:
  #209 (HPACK size update — indirect via multiple requests reusing
  connection), #211 (trailers path — verified negatively: no crash),
  #237 (FrameSeg envelope refactor), #226/#236 (stream state races),
  plus baseline GET/POST/concurrent-stream shape."
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

(deftest h2-per-request-timeout-returns-408
  ;; Handler sleeps past the configured request-timeout. Server must
  ;; emit 408 + reset the stream. Handler interruption unblocks the
  ;; sleep so no zombie vthread lingers.
  (let [interrupted? (atom false)
        started (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [_]
                 (.countDown started)
                 (try (Thread/sleep 3000)
                      (catch InterruptedException _
                        (reset! interrupted? true)))
                 {:status 200 :body "late"})
               {:port 0
                :http2 true
                :ssl-context (gen-server-context)
                :request-timeout 300})]
      (try
        (binding [*port* (enso/port srv)]
          (let [resp (get! "/slow")]
            (is (= 408 (.statusCode resp))
                "expired handler → 408")
            (is (.await started 2 TimeUnit/SECONDS))
            (Thread/sleep 200)
            (is @interrupted? "handler vthread interrupted on timeout")))
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
    (.setApplicationProtocols params (into-array String ["h2"]))
    (.setSSLParameters sock params)
    (.startHandshake sock)
    sock))

(defn- h2-connect!
  "Opens a raw h2 connection: TLS + ALPN h2, preface, client SETTINGS
  (`settings` is a seq of [id value]). Returns a conn map; the server's
  SETTINGS / ACK frames are left on the wire."
  ([] (h2-connect! []))
  ([settings]
   (let [sock (tls-h2-socket)]
     (let [conn {:sock sock
                 :frames (java.util.concurrent.LinkedBlockingQueue.)
                 :paused (atom false)
                 :in (java.io.BufferedInputStream. (.getInputStream sock))
                 :out (java.io.BufferedOutputStream. (.getOutputStream sock))
                 :enc (com.s_exp.enso.http2.Hpack$Encoder. 4096)
                 :dec (com.s_exp.enso.http2.Hpack$Decoder. 4096)}
           ^java.io.OutputStream out (:out conn)]
       (.write out (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1))
       (write-frame! conn frame-settings 0 0
                     (byte-array (mapcat (fn [[id v]]
                                           (concat [(unchecked-byte (bit-shift-right id 8))
                                                    (unchecked-byte id)]
                                                   (u32-bytes v)))
                                         settings)))
       (.start (Thread. (fn [] (reader-loop conn))))
       conn))))

(defn- close-conn! [{:keys [^java.net.Socket sock]}]
  (.close sock))

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
                :http2-initial-window-size 65535})]
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
        seen-header (atom nil)]
    (let [srv (enso/run-server
               (fn [req]
                 (if (= "/block" (:uri req))
                   (.await release 10 TimeUnit/SECONDS)
                   (reset! seen-header (get-in req [:headers "x-a"])))
                 {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 1})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/block") true)
            (Thread/sleep 200)
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
                :http2-initial-window-size 65535})]
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
        (is (some? (read-until conn #(= frame-goaway (:type %)))))
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
  (let [release (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [req]
                 (when (= "/block" (:uri req))
                   (.await release 10 TimeUnit/SECONDS))
                 {:status 200 :body (slurp (:body req))})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 1
                :http2-initial-window-size 65535})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/block") true)
            (Thread/sleep 200)
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
          (is (instance? java.io.IOException (deref p 3000 nil))
              "handler write fails once the peer reset the stream"))))))

(deftest h2-peer-reset-fails-body-read
  ;; A body cut short by RST_STREAM is not a complete body: the handler's
  ;; read fails instead of reaching EOF.
  (let [p (promise)]
    (with-h2-server
      (fn [req]
        (deliver p (try (slurp (:body req)) :eof (catch java.io.IOException _ :error)))
        {:status 200 :body "ok"})
      (fn []
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (write-frame! conn frame-data 0 1 (.getBytes "partial"))
          (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
          (is (= :error (deref p 3000 :timeout))))))))

(defn- read-twice
  "Reads `in` to the end twice, returning how each attempt ended."
  [^java.io.InputStream in]
  (letfn [(attempt [] (try (slurp in) :eof (catch java.io.IOException e (class e))))]
    [(attempt) (deref (future (attempt)) 2000 :blocked)]))

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
            (let [too-large (Class/forName "com.s_exp.enso.http2.Http2Stream$BodyTooLargeException")]
              (is (= [too-large too-large] (deref p 5000 :timeout))))))
        (finally (enso/stop srv)))))
  (testing "body aborted by RST_STREAM"
    (let [p (promise)]
      (with-h2-server
        (fn [req] (deliver p (read-twice (:body req))) {:status 200 :body "ok"})
        (fn []
          (with-conn [conn]
            (send-request! conn 1 (request-headers "POST" "/") false)
            (write-frame! conn frame-rst 0 1 (u32-bytes 0x8))
            (is (= [java.io.IOException java.io.IOException] (deref p 5000 :timeout)))))))))

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
          (Thread/sleep 200)
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
  ;; A non-IO exception while writing the response (here a header value
  ;; whose toString throws) must reset the stream, not leave it hanging.
  (with-h2-server
    (fn [_] {:status 200
             :headers {"x-bad" (reify Object (toString [_] (throw (RuntimeException. "bad"))))}
             :body "ok"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (let [rst (read-until conn (frame-on 1 frame-rst))]
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
          (Thread/sleep 300)
          (doseq [i (range 10)]
            (send-request! conn (+ 3 (* 2 i)) (request-headers "GET" "/big") true))
          (Thread/sleep 300)
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
  ;; has been written for :idle-timeout the connection is aborted instead
  ;; of holding its handler, writer and socket forever.
  (let [payload (byte-array (* 32 1024 1024))]
    (let [srv (enso/run-server
               (fn [_] {:status 200 :body payload})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :idle-timeout 500})]
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
  (with-h2-server
    (fn [_] (Thread/sleep 300) {:status 200 :body "done"})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/") true)
        (Thread/sleep 50)
        (write-frame! conn frame-goaway 0 0 (byte-array 8))
        (let [seen (atom [])]
          (read-until conn #(and (= frame-data (:type %)) (= 1 (:sid %))
                                 (pos? (bit-and flag-end-stream (:flags %))))
                      seen)
          (is (= "200" (some #(get-in % [:headers ":status"]) @seen)))
          (is (= "done" (apply str (map #(String. ^bytes (:payload %))
                                        (filter #(= frame-data (:type %)) @seen))))))
        (is (nil? (read-frame conn 2000)) "server closes once drained")))))

;; ---- Rapid reset ---------------------------------------------------------

(deftest h2-reset-streams-still-count-while-handler-runs
  ;; CVE-2023-44487: resetting a stream doesn't stop its handler, so the
  ;; concurrency limit must count running handlers, not just open streams.
  (let [release (CountDownLatch. 1)]
    (let [srv (enso/run-server
               (fn [_] (.await release 10 TimeUnit/SECONDS) {:status 200 :body "ok"})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :http2-max-concurrent-streams 2})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (doseq [sid [1 3]]
              (send-request! conn sid (request-headers "GET" "/") true)
              (Thread/sleep 100)
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
              :idle-timeout 500 :request-timeout 0})]
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
            (is (= -1 (try (.read (.getInputStream sock))
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
          (is (nil? (read-frame conn 2000)) "server closes once drained")
          (is (< (deref stopped 6000 Double/MAX_VALUE) 3000) "stop doesn't wait out the timeout"))))))

;; ---- WebSocket over h2 ---------------------------------------------------

(deftest h2-websocket-response-is-501
  ;; RFC 9113 §8.6: 101 is not allowed over HTTP/2 (no RFC 8441 support),
  ;; so a WebSocket response is answered 501 without a body.
  (with-h2-server
    (fn [_] {:ring.websocket/listener {:on-open (fn [_])}})
    (fn []
      (with-conn [conn]
        (send-request! conn 1 (request-headers "GET" "/ws") true)
        (let [f (read-until conn (frame-on 1 frame-headers))]
          (is (= "501" (get (:headers f) ":status")))
          (is (pos? (bit-and flag-end-stream (:flags f))) "no body"))))))

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

(deftest h2-timeout-408-is-not-followed-by-internal-error
  ;; A complete 408 (END_STREAM) on a request that already ended needs no
  ;; RST_STREAM at all; RST(INTERNAL_ERROR) would turn it into a failure.
  (let [closed (promise)]
    (let [srv (enso/run-server
               (fn [_]
                 (try (Thread/sleep 1000) (catch InterruptedException _))
                 {:status 200
                  :body (proxy [java.io.ByteArrayInputStream] [(.getBytes "late")]
                          (close [] (deliver closed true)))})
               {:port 0 :http2 true :ssl-context (gen-server-context)
                :request-timeout 200})]
      (try
        (binding [*port* (enso/port srv)]
          (with-conn [conn]
            (send-request! conn 1 (request-headers "GET" "/") true)
            (let [seen (atom [])]
              (read-until conn (frame-on 1 frame-headers) seen)
              (swap! seen into (drain-frames conn 500))
              (is (= "408" (some #(get-in % [:headers ":status"]) @seen)))
              (is (not-any? #(and (= frame-rst (:type %)) (= 1 (:sid %))) @seen)
                  "no RST_STREAM after the complete 408"))
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
  (let [release (CountDownLatch. 1)
        srv (enso/run-server
             (fn [_] (.await release 5 TimeUnit/SECONDS) {:status 200 :body "ok"})
             {:port 0 :http2 true :ssl-context (gen-server-context)
              :http2-max-header-list-size 300})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (send-request! conn 1 (request-headers "POST" "/") false)
          (write-frame! conn frame-headers (bit-or flag-end-headers flag-end-stream) 1
                        (header-block conn [["x-trailer" (apply str (repeat 400 "t"))]]))
          (is (= 0xb (some-> (read-until conn #(= frame-goaway (:type %))) goaway-code)))
          (.countDown release)))
      (finally (enso/stop srv)))))

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

(deftest h2-zero-max-header-list-size-not-advertised
  ;; 0 means "no limit": advertising SETTINGS_MAX_HEADER_LIST_SIZE = 0
  ;; would tell clients no header may be sent at all.
  (let [srv (enso/run-server (fn [_] {:status 200 :body "ok"})
                             {:port 0 :http2 true :ssl-context (gen-server-context)
                              :http2-max-header-list-size 0})]
    (try
      (binding [*port* (enso/port srv)]
        (with-conn [conn]
          (let [settings (server-settings conn)]
            (is (contains? settings 0x3) "MAX_CONCURRENT_STREAMS still sent")
            (is (not (contains? settings 0x6)) "no MAX_HEADER_LIST_SIZE"))))
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
              :max-request-body-bytes 1000 :http2-initial-window-size 65535})]
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

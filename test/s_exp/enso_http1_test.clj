;; ABOUTME: HTTP/1.1 integration tests: request parsing and validation, response writing, pipelining,
;; ABOUTME: the timeout model, connection limits, server events, shutdown and per-request allocation.
(ns s-exp.enso-http1-test
  "HTTP/1.1 integration tests: request parsing (head buffer growth,
  duplicate headers, targets), response writing (flush ordering with
  sendfile, body kinds), pipelining edge cases, the timeout model,
  connection limits, shutdown, and the per-request allocation budget."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (com.s_exp.enso.api RingHandler)
           (com.s_exp.enso.http1 HttpConnection)
           (java.io ByteArrayInputStream OutputStream SequenceInputStream)
           (java.lang.management ManagementFactory)
           (java.net InetAddress Socket)
           (java.nio.charset StandardCharsets)))

(def ^:dynamic *server* nil)

(defn- with-server [handler opts f]
  (let [srv (enso/run-server handler (merge {:port 0} opts))]
    (try
      (binding [*server* {:server srv :port (enso/port srv)}]
        (f))
      (finally (enso/stop srv)))))

(defn- send-raw!
  "Send raw bytes to server, read all reply bytes, return as string."
  [^String raw]
  (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
    (let [out (.getOutputStream sock)
          in (.getInputStream sock)]
      (.write out (.getBytes raw StandardCharsets/ISO_8859_1))
      (.flush out)
      (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))))

(defn- status-of [^String resp]
  (Long/parseLong (second (clojure.string/split resp #" " 3))))

;; ---- header buffer compact-before-grow ------------------------------------

(deftest headers-near-max-fit-in-buffer-after-compact
  ;; The parse buffer is :max-header-bytes (2048) here. A pipelined second
  ;; request whose ~1950-byte head straddles the end of the buffer, behind
  ;; the first request's consumed bytes, must fit once those are
  ;; compacted away; without compact-before-grow it would hit 431.
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:max-header-bytes 2048}
    (fn []
      (let [big-header (apply str (repeat 1900 "a"))
            first-req "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
            second-req (str "GET /foo HTTP/1.1\r\n"
                            "Host: x\r\n"
                            "X-Big: " big-header "\r\n"
                            "Connection: close\r\n\r\n")
            resp (send-raw! (str first-req second-req))]
        (is (= 2 (count (re-seq #"HTTP/1\.1 200" resp)))
            "1900-byte header inside the 2048 cap must serve after compact")))))

(deftest headers-over-max-still-431
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:max-header-bytes 1024}
    (fn []
      (let [monster (apply str (repeat 2000 "a"))
            req (str "GET / HTTP/1.1\r\nHost: x\r\nX-Huge: " monster
                     "\r\nConnection: close\r\n\r\n")
            resp (try (send-raw! req) (catch java.net.SocketException _ ""))]
        ;; Server sends 431 then closes. Depending on peer TCP timing
        ;; the client can either read the 431 response cleanly or see
        ;; a connection reset before draining. Either outcome proves
        ;; the request was rejected — 200 would prove the opposite.
        (is (or (empty? resp) (= 431 (status-of resp)))
            (str "expected 431 or reset, got: "
                 (subs resp 0 (min 60 (count resp)))))))))

;; ---- BufferedOutputStream + sendfile ordering ----------------------------

(deftest small-response-hits-wire-before-close
  ;; Small responses live inside the BufferedOutputStream buffer;
  ;; flush at end-of-response must push them before socket close.
  (with-server
    (fn [_] {:status 200 :body "hi"})
    {}
    (fn []
      (let [resp (send-raw! "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "hi"))))))

(deftest sendfile-preserves-header-body-order
  ;; sendfile path uses SocketChannel.transferTo which bypasses the
  ;; BufferedOutputStream layer. We must flush the buffered headers
  ;; before transferTo, else the body arrives before headers.
  (let [f (java.io.File/createTempFile "enso-h1" ".bin")
        payload (byte-array (mapv byte (repeat 3000 (int \x))))]
    (try
      (java.nio.file.Files/write (.toPath f) payload
                                 ^"[Ljava.nio.file.OpenOption;" (make-array java.nio.file.OpenOption 0))
      (with-server
        (fn [_] {:status 200 :body f})
        {}
        (fn []
          (let [resp (send-raw! "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
            (is (= 200 (status-of resp)))
            (is (clojure.string/includes? resp "Content-Length: 3000"))
            ;; The body chars ("xxx...") must come AFTER the CRLF CRLF.
            (let [sep (clojure.string/index-of resp "\r\n\r\n")]
              (is (some? sep) "headers precede body")
              (is (= 3000 (- (count resp) (+ sep 4)))
                  "body length matches Content-Length")))))
      (finally (.delete f)))))

;; ---- Response-body coercion via Ring StreamableResponseBody --------------

(deftest inputstream-body-round-trip
  (with-server
    (fn [_]
      {:status 200
       :headers {"Content-Length" "5"}
       :body (ByteArrayInputStream. (.getBytes "abcde" StandardCharsets/UTF_8))})
    {}
    (fn []
      (let [resp (send-raw! "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "abcde"))))))

(deftest seq-body-streams
  ;; Seq body chunks arrive on the wire. Server may frame via chunked
  ;; encoding OR (when Connection: close) stream raw and rely on EOF.
  (with-server
    (fn [_] {:status 200 :body (list "chunk-1" "chunk-2" "chunk-3")})
    {}
    (fn []
      (let [resp (send-raw! "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
        (is (= 200 (status-of resp)))
        (doseq [c ["chunk-1" "chunk-2" "chunk-3"]]
          (is (clojure.string/includes? resp c) (str "missing " c)))))))

;; ---- Sanity via echo (single-byte scratch) -------------------------------

(deftest request-body-single-byte-read-path
  ;; Echo handler reads the body byte-by-byte via .read() — exercises
  ;; the reused oneByte scratch in RequestBody.
  (with-server
    (fn [req]
      (let [in (:body req)
            baos (java.io.ByteArrayOutputStream.)]
        (loop []
          (let [b (.read in)]
            (when (not (neg? b))
              (.write baos b)
              (recur))))
        {:status 200 :body (.toByteArray baos)}))
    {}
    (fn []
      (let [req (str "POST / HTTP/1.1\r\n"
                     "Host: x\r\n"
                     "Content-Length: 5\r\n"
                     "Connection: close\r\n\r\n"
                     "hello")
            resp (send-raw! req)]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "hello"))))))

;; ---- Pipelining sanity ---------------------------------------------------

(deftest three-pipelined-requests-served-in-order
  (with-server
    (fn [req] {:status 200 :body (:uri req)})
    {}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              req (str "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                       "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
                       "GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
          (.write out (.getBytes req StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [resp (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)]
            (is (< (clojure.string/index-of resp "/a")
                   (clojure.string/index-of resp "/b")))
            (is (< (clojure.string/index-of resp "/b")
                   (clojure.string/index-of resp "/c")))))))))

;; ---- HEAD method: no body but Content-Length present ---------------------

(deftest head-response-drops-body-keeps-content-length
  (with-server
    (fn [_] {:status 200 :body "would-be-body"})
    {}
    (fn []
      (let [resp (send-raw! "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "Content-Length: 13"))
        (let [sep (clojure.string/index-of resp "\r\n\r\n")]
          (is (= (+ sep 4) (count resp))
              "no body bytes emitted after CRLF CRLF for HEAD"))))))

;; ---- Malformed request line ----------------------------------------------

(deftest bad-request-line-400
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {}
    (fn []
      (let [resp (send-raw! "NOT-VALID\r\n\r\n")]
        (is (= 400 (status-of resp)))))))

(defn- read-until-quiet!
  "Reads from `sock` until EOF, reset, or no byte arrives for `timeout-ms`.
  Returns everything read as an ISO-8859-1 string; never blocks forever."
  [^Socket sock timeout-ms]
  (.setSoTimeout sock (int timeout-ms))
  (let [in (.getInputStream sock)
        baos (java.io.ByteArrayOutputStream.)
        buf (byte-array 8192)]
    (try
      (loop []
        (let [n (.read in buf)]
          (when (pos? n)
            (.write baos buf 0 n)
            (recur))))
      (catch java.net.SocketTimeoutException _)
      (catch java.net.SocketException _))
    (String. (.toByteArray baos) StandardCharsets/ISO_8859_1)))

(defn- send-and-read!
  "Writes `raw` on a fresh socket and returns what the server sends back
  before closing or going quiet for `timeout-ms`."
  ([raw] (send-and-read! raw 2000))
  ([^String raw timeout-ms]
   (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
     (let [out (.getOutputStream sock)]
       (.write out (.getBytes raw StandardCharsets/ISO_8859_1))
       (.flush out)
       (read-until-quiet! sock timeout-ms)))))

(def ^:private close-req "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

;; ---- Response header validation -----------------------------------------

(deftest response-header-value-non-latin1-rejected
  ;; U+010D / U+010A truncate to CR / LF when narrowed to a byte; they must
  ;; be rejected rather than split the response.
  (with-server
    (fn [_] {:status 200
             :headers {"x-evil" "ačĊInjected: yes"}
             :body "ok"})
    {}
    (fn []
      (let [resp (send-and-read! close-req)]
        (is (= 500 (status-of resp)))
        (is (not (clojure.string/includes? resp "Injected")))))))

(deftest response-header-value-ctl-rejected
  (with-server
    (fn [_] {:status 200 :headers {"x-evil" "a\u0001b"} :body "ok"})
    {}
    (fn []
      (is (= 500 (status-of (send-and-read! close-req)))))))

(deftest response-header-value-htab-and-obs-text-allowed
  (with-server
    (fn [_] {:status 200 :headers {"x-ok" "a\tbé"} :body "ok"})
    {}
    (fn []
      (let [resp (send-and-read! close-req)]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "x-ok: a\tbé"))))))

(deftest response-header-name-non-token-rejected
  (with-server
    (fn [_] {:status 200 :headers {"x evil" "v"} :body "ok"})
    {}
    (fn []
      (is (= 500 (status-of (send-and-read! close-req)))))))

;; ---- Response flushed before blocking on the next read -------------------

(deftest response-sent-when-trailing-crlf-follows-request
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {}
    (fn []
      (let [resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\n\r\n\r\n" 1500)]
        (is (clojure.string/starts-with? resp "HTTP/1.1 200"))))))

(deftest pipelined-response-sent-while-next-request-incomplete
  (with-server
    (fn [req] {:status 200 :body (:uri req)})
    {}
    (fn []
      (let [resp (send-and-read! "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHo" 1500)]
        (is (clojure.string/includes? resp "/a"))))))

(deftest drain-error-after-response-closes-cleanly
  ;; Handler ignores an oversized chunked body; draining it fails with 413
  ;; after the response went out. The connection must close without the
  ;; error escaping the connection thread.
  (let [uncaught (atom [])
        prev (Thread/getDefaultUncaughtExceptionHandler)]
    (Thread/setDefaultUncaughtExceptionHandler
     (reify Thread$UncaughtExceptionHandler
       (uncaughtException [_ _ e] (swap! uncaught conj e))))
    (try
      (with-server
        (fn [_] {:status 200 :body "ok"})
        {:max-request-body-bytes 10}
        (fn []
          (let [resp (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\n"
                                          "Transfer-Encoding: chunked\r\n\r\n"
                                          "20\r\n" (apply str (repeat 32 "a")) "\r\n0\r\n\r\n")
                                     1500)]
            (is (clojure.string/starts-with? resp "HTTP/1.1 200"))
            (is (= 1 (count (re-seq #"HTTP/1\.1" resp))) "no second response"))))
      ;; stop returned: every connection thread has ended.
      (is (empty? @uncaught))
      (finally (Thread/setDefaultUncaughtExceptionHandler prev)))))

;; ---- Request framing ------------------------------------------------------

(defn- echo-body [req]
  {:status 200 :body (if (:body req) (slurp (:body req)) "")})

(deftest request-content-length-must-be-digits
  (with-server echo-body {}
    (fn []
      (doseq [cl ["+3" "-0" "3 3" "3,3" "0x3" "" "99999999999999999999"]]
        (is (= 400 (status-of (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\n"
                                                   "Content-Length: " cl "\r\n"
                                                   "Connection: close\r\n\r\nabc"))))
            (str "Content-Length " (pr-str cl)))))))

(deftest request-content-length-leading-zeros-accepted
  (with-server echo-body {}
    (fn []
      (let [resp (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 003\r\n"
                                      "Connection: close\r\n\r\nabc"))]
        (is (= 200 (status-of resp)))
        (is (clojure.string/ends-with? resp "abc"))))))

(deftest request-transfer-encoding-codings
  (with-server echo-body {}
    (fn []
      (doseq [[te proto expected] [["gzip, chunked" "HTTP/1.1" 501]
                                   ["gzip" "HTTP/1.1" 400]
                                   ["chunked, gzip" "HTTP/1.1" 400]
                                   ["chunked, chunked" "HTTP/1.1" 400]
                                   ["chunked" "HTTP/1.0" 400]
                                   ["Chunked" "HTTP/1.1" 200]]]
        (is (= expected
               (status-of (send-and-read! (str "POST / " proto "\r\nHost: x\r\n"
                                               "Transfer-Encoding: " te "\r\n"
                                               "Connection: close\r\n\r\n"
                                               "3\r\nabc\r\n0\r\n\r\n"))))
            (str proto " Transfer-Encoding " (pr-str te)))))))

(deftest http-1-1-request-without-host-400
  (with-server echo-body {}
    (fn []
      (is (= 400 (status-of (send-and-read! "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"))))
      (is (= 200 (status-of (send-and-read! "GET / HTTP/1.0\r\n\r\n")))
          "HTTP/1.0 has no Host requirement"))))

(deftest request-line-validation
  (with-server echo-body {}
    (fn []
      (doseq [[line expected] [[" / HTTP/1.1" 400]
                               ["GET /a b HTTP/1.1" 400]
                               ["GET /a\u0001 HTTP/1.1" 400]
                               ["GET /a\u007f HTTP/1.1" 400]
                               ["GET  HTTP/1.1" 400]
                               ["GET / HTTPS/1.1" 400]
                               ["GET / HTTP/1.2" 505]
                               ["GET / HTTP/2.0" 505]
                               ["GET /a?b=c HTTP/1.1" 200]]]
        (is (= expected (status-of (send-and-read! (str line "\r\nHost: x\r\nConnection: close\r\n\r\n"))))
            (pr-str line))))))

(deftest expect-100-continue-ignored-for-http-1-0
  (with-server echo-body {}
    (fn []
      (let [resp (send-and-read! (str "POST / HTTP/1.0\r\nContent-Length: 5\r\n"
                                      "Expect: 100-continue\r\n\r\nhello"))]
        (is (not (clojure.string/includes? resp "100 Continue")))
        (is (= 200 (status-of resp)))))))

(deftest expect-100-continue-not-sent-without-body
  (with-server echo-body {}
    (fn []
      (let [resp (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\n"
                                      "Expect: 100-continue\r\nConnection: close\r\n\r\n"))]
        (is (not (clojure.string/includes? resp "100 Continue")))
        (is (= 200 (status-of resp)))))))

(deftest unknown-expectation-417
  (with-server echo-body {}
    (fn []
      (let [resp (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                                      "Expect: teapot\r\nConnection: close\r\n\r\nhello"))]
        (is (clojure.string/starts-with? resp "HTTP/1.1 417 Expectation Failed\r\n"))))))

(defn- chunked-post [chunks]
  (str "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
       "Connection: close\r\n\r\n" chunks))

(deftest chunk-size-overflowing-a-long-is-400
  ;; A 16th hex digit of 8 or more would make the size negative: a body
  ;; read returning 0 forever, or a negative copy length.
  (with-server echo-body {}
    (fn []
      (doseq [size ["8000000000000000" "8000000080000000" "FFFFFFFFFFFFFFFF" "10000000000000000"]]
        (let [resp (future (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                                                "Connection: close\r\n\r\n" size "\r\nabc")
                                           3000))]
          (is (= 400 (some-> (deref resp 5000 nil) status-of)) size))))))

(deftest chunk-extension-control-characters-rejected
  (with-server echo-body {}
    (fn []
      (doseq [ext [";a\nb" ";a\u0001" ";a\rb"]]
        (is (= 400 (status-of (send-and-read! (chunked-post (str "3" ext "\r\nabc\r\n0\r\n\r\n")))))
            (pr-str ext)))
      (let [resp (send-and-read! (chunked-post "3;name=\"v\\\"al\"\t;x\r\nabc\r\n0\r\n\r\n"))]
        (is (= 200 (status-of resp)))
        (is (clojure.string/ends-with? resp "abc"))))))

(deftest trailer-field-lines-validated
  (with-server echo-body {}
    (fn []
      (doseq [trailer ["X-T: a\nb" "nocolon" " X-T: folded" "X T: v" "X-T: a\u0000b"]]
        (is (= 400 (status-of (send-and-read! (chunked-post (str "3\r\nabc\r\n0\r\n" trailer "\r\n\r\n")))))
            (pr-str trailer)))
      (is (= 200 (status-of (send-and-read! (chunked-post "3\r\nabc\r\n0\r\nX-T: ok\r\n\r\n"))))))))

(deftest trailer-cap-counts-lines-after-buffer-compaction
  ;; Trailer section well past max-header-bytes; the buffer compacts while
  ;; scanning, which must not reset the running total.
  (with-server echo-body {:max-header-bytes 1024}
    (fn []
      (let [trailers (apply str (repeat 60 (str "X-T: " (apply str (repeat 40 "v")) "\r\n")))]
        (is (= 431 (status-of (send-and-read! (chunked-post (str "3\r\nabc\r\n0\r\n" trailers "\r\n"))))))))))

;; ---- Request header map ---------------------------------------------------

(defn- request-with-headers [n]
  (str "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
       (apply str (for [i (range (- n 2))] (str "X-H" i ": v\r\n")))
       "\r\n"))

(deftest header-count-capped
  (with-server echo-body {}
    (fn []
      (is (= 200 (status-of (send-and-read! (request-with-headers 100)))))
      (is (= 431 (status-of (send-and-read! (request-with-headers 101)))))
      (is (= 431 (status-of (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\n"
                                                 (apply str (repeat 10000 "a:\r\n"))
                                                 "\r\n"))))))))

(deftest header-count-follows-max-header-fields
  (with-server echo-body {:max-header-fields 5}
    (fn []
      (is (= 200 (status-of (send-and-read! (request-with-headers 5)))))
      (is (= 431 (status-of (send-and-read! (request-with-headers 6))))))))

(deftest many-distinct-headers-build-a-hash-map-in-bounded-time
  ;; Past 8 fields the header map is a hash map, so building and looking
  ;; up stay linear in the field count (same on every protocol).
  (let [seen (promise)]
    (with-server
      (fn [req]
        (deliver seen [(class (:headers req)) (count (:headers req)) (get-in req [:headers "x-h1999"])])
        {:status 200 :body "ok"})
      {:max-header-fields 3000 :max-header-bytes (* 1024 1024)}
      (fn []
        (let [t0 (System/nanoTime)
              resp (send-and-read! (request-with-headers 2002) 5000)]
          (is (= 200 (status-of resp)))
          (is (< (/ (- (System/nanoTime) t0) 1e6) 2000.0) "bounded time"))
        (is (= [clojure.lang.PersistentHashMap 2002 "v"] (deref seen 1000 nil)))))))

(deftest repeated-content-length-rejected-even-when-equal
  ;; One rule on every protocol (RFC 9110 §8.6 permits rejecting).
  (with-server echo-body {}
    (fn []
      (is (= 400 (status-of (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n"
                                                 "Content-Length: 3\r\nConnection: close\r\n\r\nabc"))))))))

(deftest duplicate-request-headers-merged-like-h2
  (let [captured (atom nil)]
    (with-server
      (fn [req] (reset! captured (:headers req)) {:status 200 :body ""})
      {}
      (fn []
        (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\nX-Repeat: a\r\nCookie: a=1\r\n"
                             "X-Repeat: b\r\nCookie: b=2\r\nConnection: close\r\n\r\n"))
        (is (= "a, b" (get @captured "x-repeat")))
        (is (= "a=1; b=2" (get @captured "cookie")))))))

;; ---- Connection management ------------------------------------------------

(deftest request-connection-close-token-in-list
  (with-server echo-body {}
    (fn []
      (let [t0 (System/nanoTime)
            resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n" 3000)
            ms (/ (- (System/nanoTime) t0) 1e6)]
        (is (clojure.string/includes? resp "Connection: close\r\n"))
        (is (< ms 2000) "server closed the connection")))))

(deftest handler-keep-alive-header-does-not-hide-close
  (with-server
    (fn [_] {:status 200 :headers {"Connection" "keep-alive"} :body "ok"})
    {}
    (fn []
      (let [resp (send-and-read! close-req)]
        (is (clojure.string/includes? resp "Connection: close\r\n"))))))

(deftest handler-close-token-in-list-closes
  (with-server
    (fn [_] {:status 200 :headers {"Connection" "foo, close"} :body "ok"})
    {}
    (fn []
      (let [t0 (System/nanoTime)
            resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\n\r\n" 3000)
            ms (/ (- (System/nanoTime) t0) 1e6)]
        (is (= 200 (status-of resp)))
        (is (< ms 2000) "server closed the connection")))))

(deftest handler-close-in-list-value-closes
  ;; A list-valued Connection header goes out as one field line per
  ;; element; a "close" among them must end the connection.
  (with-server
    (fn [_] {:status 200 :headers {"Connection" ["close"]} :body "ok"})
    {}
    (fn []
      (let [t0 (System/nanoTime)
            resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\n\r\n" 3000)
            ms (/ (- (System/nanoTime) t0) 1e6)]
        (is (= 200 (status-of resp)))
        (is (clojure.string/includes? resp "Connection: close\r\n"))
        (is (< ms 2000) "server closed the connection")))))

(deftest no-content-length-on-1xx-and-204
  ;; RFC 9110 §8.6: a server MUST NOT send Content-Length in a 1xx or
  ;; 204 response. 304 may carry the length of the selected representation.
  ;; (A handler can't send a 1xx at all: see invalid-response-status-is-500.)
  (doseq [[status expected] [[204 false] [304 true]]]
    (with-server
      (fn [_] {:status status :headers {"Content-Length" "5"} :body nil})
      {}
      (fn []
        (let [resp (send-and-read! close-req)]
          (is (= expected (boolean (re-find #"(?i)content-length:" resp)))
              (str status " " (pr-str resp))))))))

;; ---- Timeouts -------------------------------------------------------------

(defn- read-all-timed
  "Reads `sock` to EOF (or `limit-ms`); returns [response-string elapsed-ms]."
  [^Socket sock limit-ms]
  (.setSoTimeout sock (int limit-ms))
  (let [t0 (System/nanoTime)
        resp (try (String. (.readAllBytes (.getInputStream sock)) StandardCharsets/ISO_8859_1)
                  (catch java.net.SocketTimeoutException _ :timed-out)
                  (catch java.io.IOException _ ""))]
    [resp (/ (- (System/nanoTime) t0) 1e6)]))

(defn- write! [^Socket sock ^String s]
  (doto (.getOutputStream sock)
    (.write (.getBytes s StandardCharsets/ISO_8859_1))
    (.flush)))

(deftest idle-timeout-closes-between-requests
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:idle-timeout 200}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (write! sock "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        (let [[resp ms] (read-all-timed sock 3000)]
          (is (clojure.string/starts-with? resp "HTTP/1.1 200") (pr-str resp))
          (is (< ms 1500) "closed by the idle timeout after the response"))))))

(deftest idle-timeout-bounds-the-wait-for-a-first-request
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:idle-timeout 200}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[resp ms] (read-all-timed sock 3000)]
          (is (= "" resp) "closed without a response")
          (is (< ms 1500)))))))

(deftest header-timeout-is-wall-clock-from-the-first-byte
  ;; One byte every 100ms keeps every read well under the idle and read
  ;; timeouts; only the wall-clock head budget ends it.
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:header-timeout 400 :idle-timeout 5000 :read-timeout 5000}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [dripper (future
                        (try
                          (doseq [c "GET / HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
                            (write! sock (str c))
                            (Thread/sleep 100))
                          (catch java.io.IOException _)))
              [resp ms] (read-all-timed sock 4000)]
          (future-cancel dripper)
          (is (clojure.string/starts-with? resp "HTTP/1.1 408") (pr-str resp))
          (is (< ms 2000)))))))

(deftest read-timeout-is-progress-based
  (let [handler (fn [req] {:status 200 :body (str (count (slurp (:body req))))})]
    (testing "a stalled body fails after the read timeout"
      (with-server handler {:read-timeout 300}
        (fn []
          (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
            (write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
            (let [[resp ms] (read-all-timed sock 4000)]
              (is (clojure.string/starts-with? resp "HTTP/1.1 408") (pr-str resp))
              (is (< ms 2000)))))))
    (testing "a slow body that keeps progressing completes"
      (with-server handler {:read-timeout 300}
        (fn []
          (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
            (write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\nConnection: close\r\n\r\n")
            (dotimes [_ 8]
              (Thread/sleep 100)
              (write! sock "z"))
            (let [[resp] (read-all-timed sock 4000)]
              (is (clojure.string/starts-with? resp "HTTP/1.1 200") (pr-str resp))
              (is (clojure.string/ends-with? resp "\r\n\r\n8")))))))))

(defn- await-connections [srv n ms]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (cond
        (= n (.connectionCount ^com.s_exp.enso.EnsoServer srv)) true
        (> (System/currentTimeMillis) deadline) false
        :else (do (Thread/sleep 20) (recur))))))

(deftest write-timeout-closes-a-peer-that-stopped-reading
  (let [stalled (promise)]
    (with-server
      (fn [_] {:status 200 :body (byte-array (* 64 1024 1024))})
      {:write-timeout 300
       :server-events {:protocol-error (fn [_ kind] (when (= "write-timeout" kind) (deliver stalled true)))}}
      (fn []
        (with-open [sock (doto (Socket.) (.setReceiveBufferSize 4096))]
          (.connect sock (java.net.InetSocketAddress. "127.0.0.1" (int (:port *server*))))
          (write! sock "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          (is (true? (deref stalled 3000 false)) "write-timeout reported")
          (is (await-connections (:server *server*) 0 3000) "connection closed"))))))

(deftest handler-timeout-answers-503-and-interrupts
  (let [interrupted (promise)]
    (with-server
      (fn [req]
        (if (= "/slow" (:uri req))
          (try (Thread/sleep 5000) {:status 200 :body "late"}
               (catch InterruptedException _ (deliver interrupted true) (throw (InterruptedException.))))
          {:status 200 :body "fast"}))
      {:handler-timeout 300}
      (fn []
        (testing "fast handlers are unaffected, keep-alive included"
          (let [resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
            (is (= 2 (count (re-seq #"HTTP/1\.1 200" resp))) resp)))
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (write! sock "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
          (let [[resp ms] (read-all-timed sock 4000)]
            (is (clojure.string/starts-with? resp "HTTP/1.1 503") (pr-str resp))
            (is (clojure.string/includes? resp "Connection: close\r\n"))
            (is (not (clojure.string/includes? resp "late")))
            (is (< ms 2000))
            (is (true? (deref interrupted 2000 false)) "handler interrupted")))))))

;; ---- Request target, Host and method rules -------------------------------

(deftest absolute-form-target-replaces-host
  (let [seen (atom nil)]
    (with-server
      (fn [req] (reset! seen (select-keys req [:uri :query-string :headers :server-name])) {:status 200 :body "ok"})
      {}
      (fn []
        (is (= 200 (status-of (send-and-read! "GET http://example.com:8080/a/b?c=d HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n"))))
        (is (= "/a/b" (:uri @seen)))
        (is (= "c=d" (:query-string @seen)))
        (is (= "example.com:8080" (get-in @seen [:headers "host"])))
        (is (= "example.com" (:server-name @seen)))
        (doseq [bad ["ftp://x/ " "http://u@x/ " "http:/x " "x/y "]]
          (is (= 400 (status-of (send-and-read! (str "GET " bad "HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))) bad))))))

(deftest host-must-be-a-valid-authority
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {}
    (fn []
      (doseq [[host expected] [["example.com" 200] ["[::1]:80" 200] ["" 200]
                               ["a b" 400] ["user@x" 400] ["x/y" 400] ["[::1" 400]]]
        (is (= expected (status-of (send-and-read! (str "GET / HTTP/1.1\r\nHost: " host "\r\nConnection: close\r\n\r\n")))) host)))))

(deftest asterisk-form-only-for-options-and-connect-not-implemented
  (with-server
    (fn [req] {:status 200 :body (:uri req)})
    {}
    (fn []
      (is (= 200 (status-of (send-and-read! "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
      (is (= 400 (status-of (send-and-read! "GET * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
      (is (= 501 (status-of (send-and-read! "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n")))))))

(deftest control-characters-in-field-values-rejected
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {}
    (fn []
      (is (= 200 (status-of (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\nX-T: a\tb\r\nConnection: close\r\n\r\n"))))
      (doseq [c ["\u0001" "\u001f" "\u007f"]]
        (is (= 400 (status-of (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\nX-T: a" c "b\r\nConnection: close\r\n\r\n"))))
            (pr-str c))))))

(deftest invalid-response-status-is-500
  (with-server
    (fn [req] {:status (Long/parseLong (subs (:uri req) 1)) :body "x"})
    {}
    (fn []
      (doseq [s [99 100 103 101 600]]
        (is (= 500 (status-of (send-and-read! (str "GET /" s " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))) (str s))))))

(deftest responses-always-carry-date
  (with-server
    (fn [_] {:status 200 :headers {"x" "y"} :body "ok"})
    {}
    (fn []
      (is (re-find #"\r\nDate: [A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT\r\n"
                   (send-and-read! close-req))))))

;; ---- Events ---------------------------------------------------------------

(deftest server-events-report-connections-requests-and-errors
  (let [log (atom [])
        record (fn [& args] (swap! log conj (vec args)))]
    (with-server
      (fn [_] {:status 201 :body "hello"})
      {:server-events {:connection-opened (fn [p a] (record :opened p a))
                       :connection-closed (fn [p a nanos] (record :closed p a (pos? nanos)))
                       :request-completed (fn [p method status req-bytes bytes nanos]
                                            (record :request p method status req-bytes bytes (pos? nanos)))
                       :protocol-error (fn [p kind] (record :error p kind))}}
      (fn []
        (send-and-read! close-req)
        (send-and-read! "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
        (send-and-read! "GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        (let [deadline (+ (System/currentTimeMillis) 3000)]
          ;; connection-closed comes last, from each connection's thread
          (while (and (< (count (filter #(= :closed (first %)) @log)) 3)
                      (< (System/currentTimeMillis) deadline))
            (Thread/sleep 10)))
        (let [events @log]
          (is (some #{[:opened "http/1.1" "127.0.0.1"]} events))
          (is (some #{[:request "http/1.1" "GET" 201 0 5 true]} events) "method, status, bytes each way")
          (is (some #{[:request "http/1.1" "POST" 201 3 5 true]} events) "request body bytes received")
          (is (some #{[:closed "http/1.1" "127.0.0.1" true]} events))
          (is (some #{[:error "http/1.1" "bad-request"]} events)))))))

;; ---- A throwing :server-events listener -------------------------------------

(deftest throwing-event-listener-never-breaks-serving
  ;; Listener exceptions are swallowed once, at the source: the acceptor
  ;; reporting a refused connection and a connection reporting its open
  ;; both keep working.
  (let [entered (java.util.concurrent.CountDownLatch. 1)
        release (java.util.concurrent.CountDownLatch. 1)
        boom (fn [& _] (throw (RuntimeException. "listener bug")))]
    (with-server
      (fn [req]
        (when (= "/hold" (:uri req))
          (.countDown entered)
          (.await release 5 java.util.concurrent.TimeUnit/SECONDS))
        {:status 200 :body "ok"})
      {:max-connections 1
       :server-events {:connection-opened boom :connection-closed boom
                       :request-completed boom :protocol-error boom}}
      (fn []
        (is (= 200 (status-of (send-and-read! close-req))) "served despite connection-opened throwing")
        (is (await-connections (:server *server*) 0 2000))
        (with-open [holder (Socket. "127.0.0.1" (int (:port *server*)))]
          (write! holder "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n")
          (is (.await entered 2 java.util.concurrent.TimeUnit/SECONDS))
          ;; Refused at accept: the acceptor reports a protocol error.
          (is (= "" (send-and-read! close-req 2000)))
          (.countDown release)
          (is (clojure.string/starts-with? (read-until-quiet! holder 2000) "HTTP/1.1 200")))
        (is (await-connections (:server *server*) 0 2000))
        (is (= 200 (status-of (send-and-read! close-req 2000))) "the acceptor still accepts")))))

(deftest last-keep-alive-response-announces-close
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:max-keep-alive-requests 2}
    (fn []
      (let [req "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
            resp (send-and-read! (str req req) 3000)
            [first-resp second-resp] (clojure.string/split resp #"(?=HTTP/1\.1 )")]
        (is (some? second-resp) "both responses served")
        (is (not (clojure.string/includes? first-resp "Connection: close")))
        (is (clojure.string/includes? second-resp "Connection: close\r\n"))))))

(deftest numeric-response-header-values
  (with-server
    (fn [_] {:status 200
             :headers {"x-neg" -5
                       "x-int" (int -42)
                       "x-min" Long/MIN_VALUE
                       "x-max" Long/MAX_VALUE
                       "x-zero" 0}
             :body "ok"})
    {}
    (fn []
      (let [resp (send-and-read! close-req)]
        (is (clojure.string/includes? resp "x-neg: -5\r\n"))
        (is (clojure.string/includes? resp "x-int: -42\r\n"))
        (is (clojure.string/includes? resp "x-min: -9223372036854775808\r\n"))
        (is (clojure.string/includes? resp "x-max: 9223372036854775807\r\n"))
        (is (clojure.string/includes? resp "x-zero: 0\r\n"))))))

;; ---- Response bodies ------------------------------------------------------

(defn- tracked-stream
  "ByteArrayInputStream over `s` that flips `closed` when closed."
  [^String s closed]
  (proxy [ByteArrayInputStream] [(.getBytes s StandardCharsets/UTF_8)]
    (close [] (reset! closed true))))

(deftest stream-body-closed-when-headers-invalid
  (let [closed (atom false)]
    (with-server
      (fn [_] {:status 200 :headers {"x-evil" "a\r\nb"} :body (tracked-stream "abc" closed)})
      {}
      (fn []
        (is (= 500 (status-of (send-and-read! close-req))))
        (is @closed)))))

(def ^:private two-keep-alive-reqs
  "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")

(defn- status-line-count [resp]
  (count (re-seq #"HTTP/1\.1 \d{3} " resp)))

(deftest failing-streaming-body-aborts-without-terminal-chunk
  (with-server
    (fn [_] {:status 200
             :body (fn [w]
                     (enso/write! w "partial")
                     (enso/flush! w)
                     (throw (ex-info "boom" {})))})
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs)]
        (is (clojure.string/includes? resp "partial"))
        (is (not (clojure.string/includes? resp "0\r\n\r\n")) "no terminal chunk")
        (is (= 1 (status-line-count resp)) "connection closed after the failure")))))

(deftest streaming-body-illegal-argument-after-commit-sends-no-second-response
  (with-server
    (fn [_] {:status 200
             :body (fn [w]
                     (enso/write! w "x")
                     (enso/flush! w)
                     (throw (IllegalArgumentException. "bad")))})
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs)]
        (is (= 1 (status-line-count resp)))
        (is (not (clojure.string/includes? resp " 500 ")))))))

(deftest invalid-response-keeps-coalesced-previous-response
  (with-server
    (fn [req] (if (= "/b" (:uri req))
                {:status 200 :headers {"x-evil" "a\nb"} :body "b"}
                {:status 200 :body "body-a"}))
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs)]
        (is (clojure.string/starts-with? resp "HTTP/1.1 200 "))
        (is (clojure.string/includes? resp "body-a"))
        (is (clojure.string/includes? resp "HTTP/1.1 500 "))))))

(deftest known-length-body-ignores-handler-content-length
  (doseq [[body declared expected-len] [[(.getBytes "hello" StandardCharsets/UTF_8) "2" 5]
                                        ["hello" "99" 5]
                                        ["héllo" "1" 6]
                                        [nil "5" 0]]]
    (with-server
      (fn [_] {:status 200 :headers {"Content-Length" declared} :body body})
      {}
      (fn []
        (let [resp (send-and-read! two-keep-alive-reqs)]
          (is (= 2 (status-line-count resp)) (pr-str body))
          (is (= 2 (count (re-seq (re-pattern (str "(?i)content-length: " expected-len "\r\n")) resp)))
              (pr-str body))
          (is (not (clojure.string/includes? resp (str "Content-Length: " declared "\r\n")))
              (pr-str body)))))))

(deftest handler-transfer-encoding-ignored
  ;; The server owns message framing: a handler Transfer-Encoding would
  ;; announce chunked while the body goes out raw, desyncing keep-alive.
  (doseq [[body te] [["hello" "chunked"]
                     [(java.io.ByteArrayInputStream. (.getBytes "hello" StandardCharsets/UTF_8)) "gzip"]]]
    (with-server
      (fn [_] {:status 200 :headers {"Transfer-Encoding" te} :body body})
      {}
      (fn []
        (let [resp (send-and-read! two-keep-alive-reqs)]
          (is (= 2 (status-line-count resp)) te)
          (is (not (clojure.string/includes? (clojure.string/lower-case resp) (str "transfer-encoding: " te)))
              te))))))

(deftest file-body-ignores-handler-content-length
  (let [f (java.io.File/createTempFile "enso-h1" ".txt")]
    (try
      (spit f "file-body")
      (with-server
        (fn [_] {:status 200 :headers {"Content-Length" "1"} :body f})
        {}
        (fn []
          (let [resp (send-and-read! close-req)]
            (is (clojure.string/includes? resp "Content-Length: 9\r\n"))
            (is (clojure.string/ends-with? resp "\r\n\r\nfile-body")))))
      (finally (.delete f)))))

(deftest head-keeps-handler-content-length
  (with-server
    (fn [_] {:status 200 :headers {"Content-Length" "1234"} :body nil})
    {}
    (fn []
      (let [resp (send-and-read! "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")]
        (is (clojure.string/includes? resp "Content-Length: 1234\r\n"))))))

(deftest stream-body-invalid-declared-content-length-500
  (with-server
    (fn [_] {:status 200
             :headers {"Content-Length" "+3"}
             :body (ByteArrayInputStream. (.getBytes "abc" StandardCharsets/UTF_8))})
    {}
    (fn []
      (is (= 500 (status-of (send-and-read! close-req)))))))

(deftest streaming-body-longer-than-declared-content-length-aborts
  (with-server
    (fn [_] {:status 200
             :headers {"Content-Length" "2"}
             :body (fn [w] (enso/write! w "hello"))})
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs)]
        (is (not (clojure.string/includes? resp "hello")))
        (is (<= (status-line-count resp) 1))))))

(deftest streaming-body-shorter-than-declared-content-length-closes
  (with-server
    (fn [_] {:status 200
             :headers {"Content-Length" "10"}
             :body (fn [w] (enso/write! w "hello"))})
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs)]
        (is (clojure.string/ends-with? resp "hello"))
        (is (= 1 (status-line-count resp)))))))

(deftest streaming-body-exact-declared-content-length-keeps-alive
  (with-server
    (fn [_] {:status 200
             :headers {"Content-Length" "5"}
             :body (fn [w] (enso/write! w "hello"))})
    {}
    (fn []
      (let [resp (send-and-read! two-keep-alive-reqs 1000)]
        (is (= 2 (status-line-count resp)))
        (is (= 2 (count (re-seq #"hello" resp))))))))

;; ---- ChunkedWriter ----------------------------------------------------------

(defn- dechunk
  "Decodes HTTP/1.1 chunked bytes (ISO-8859-1 string) into the payload."
  [^String s]
  (loop [i 0 acc (StringBuilder.)]
    (let [crlf (.indexOf s "\r\n" (int i))
          size (Long/parseLong (subs s i crlf) 16)]
      (if (zero? size)
        (str acc)
        (let [start (+ crlf 2)]
          (.append acc (subs s start (+ start size)))
          (recur (+ start size 2) acc))))))

(deftest chunked-writer-emits-chunks-when-buffer-fills
  (let [baos (java.io.ByteArrayOutputStream.)
        w (com.s_exp.enso.api.ChunkedWriter. baos 512 true)
        piece (apply str (repeat 100 "a"))
        big (apply str (repeat 5000 "b"))]
    (dotimes [_ 20] (.write w (.getBytes piece StandardCharsets/ISO_8859_1)))
    (is (pos? (.size baos)) "full buffer emitted without an explicit flush")
    (is (<= (.buffered w) 512))
    (.write w (.getBytes big StandardCharsets/ISO_8859_1))
    (is (<= (.buffered w) 512))
    (.writeAscii w big)
    (is (<= (.buffered w) 512))
    (dotimes [_ 1000] (.write w (int 99)))
    (is (<= (.buffered w) 512))
    (com.s_exp.enso.core.ChunkedWriters/finish w)
    (is (= (str (apply str (repeat 20 piece)) big big (apply str (repeat 1000 "c")))
           (dechunk (String. (.toByteArray baos) StandardCharsets/ISO_8859_1))))))

(deftest chunked-writer-write-ascii-rejects-non-ascii-atomically
  (let [baos (java.io.ByteArrayOutputStream.)
        w (com.s_exp.enso.api.ChunkedWriter. baos 512 true)]
    (.writeAscii w "ok")
    (is (thrown? IllegalArgumentException (.writeAscii w "abcé")))
    (com.s_exp.enso.core.ChunkedWriters/finish w)
    (is (= "ok" (dechunk (String. (.toByteArray baos) StandardCharsets/ISO_8859_1))))))

;; ---- WebSocket upgrade ------------------------------------------------------

(defn- ws-request
  ([] (ws-request {}))
  ([{:keys [method protocol key version extra]
     :or {method "GET" protocol "HTTP/1.1" key "dGhlIHNhbXBsZSBub25jZQ==" version "13" extra ""}}]
   (str method " / " protocol "\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: " key "\r\nSec-WebSocket-Version: " version "\r\n" extra "\r\n")))

(defn- masked-frame
  "Client frame with FIN and a fixed zero mask (payload sent as-is)."
  ^bytes [opcode ^bytes payload]
  (let [baos (java.io.ByteArrayOutputStream.)
        len (alength payload)]
    (.write baos (bit-or 0x80 opcode))
    (cond
      (< len 126) (.write baos (bit-or 0x80 len))
      (< len 65536) (do (.write baos (bit-or 0x80 126))
                        (.write baos (bit-and (bit-shift-right len 8) 0xFF))
                        (.write baos (bit-and len 0xFF)))
      :else (do (.write baos (bit-or 0x80 127))
                (dotimes [i 8]
                  (.write baos (bit-and (bit-shift-right len (* 8 (- 7 i))) 0xFF)))))
    (.write baos (byte-array 4) 0 4)
    (.write baos payload 0 len)
    (.toByteArray baos)))

(defn- read-http-head
  "Reads up to and including CRLF CRLF; returns it as a string."
  [^java.io.InputStream in]
  (let [sb (StringBuilder.)]
    (loop []
      (let [b (.read in)]
        (when (neg? b)
          (throw (java.io.EOFException. (str "closed after: " sb))))
        (.append sb (char b))
        (if (.endsWith (str sb) "\r\n\r\n")
          (str sb)
          (recur))))))

(defn- read-small-text-frame
  "Reads one unmasked server frame with a payload under 126 bytes."
  [^java.io.InputStream in]
  (let [dis (java.io.DataInputStream. in)
        _ (.readUnsignedByte dis)
        len (bit-and (.readUnsignedByte dis) 0x7F)
        payload (byte-array len)]
    (.readFully dis payload)
    (String. payload StandardCharsets/UTF_8)))

(defn- echo-ws-handler [_]
  {:ring.websocket/listener
   {:on-message (fn [^com.s_exp.enso.api.WebSocketSocket s msg]
                  (.sendText s (str msg)))}})

(deftest ws-outlives-header-timeout-when-idle-timeout-disabled
  (with-server echo-ws-handler {:idle-timeout 0 :header-timeout 300}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (.setSoTimeout sock 3000)
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          ;; Two writes: the second read is bounded by the remaining
          ;; request budget, which must not carry over into the WebSocket.
          (let [req (ws-request)]
            (.write out (.getBytes (subs req 0 10) StandardCharsets/ISO_8859_1))
            (.flush out)
            (Thread/sleep 50)
            (.write out (.getBytes (subs req 10) StandardCharsets/ISO_8859_1))
            (.flush out))
          (is (clojure.string/starts-with? (read-http-head in) "HTTP/1.1 101"))
          (Thread/sleep 800)
          (.write out (masked-frame 0x1 (.getBytes "hi" StandardCharsets/UTF_8)))
          (.flush out)
          (is (= "hi" (read-small-text-frame in))))))))

(deftest ws-frame-sent-with-handshake-is-delivered
  (with-server echo-ws-handler {}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (.setSoTimeout sock 3000)
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              hs (.getBytes (ws-request) StandardCharsets/ISO_8859_1)
              frame (masked-frame 0x1 (.getBytes "early" StandardCharsets/UTF_8))]
          (.write out (byte-array (concat hs frame)))
          (.flush out)
          (is (clojure.string/starts-with? (read-http-head in) "HTTP/1.1 101"))
          (is (= "early" (read-small-text-frame in))))))))

(deftest ws-handshake-validation
  (with-server echo-ws-handler {}
    (fn []
      (doseq [[opts expected] [[{:method "POST"} 400]
                               [{:protocol "HTTP/1.0"} 400]
                               [{:key "c2hvcnQ="} 400]
                               [{:key "not base64!!"} 400]]]
        (is (= expected (status-of (send-and-read! (ws-request opts)))) (pr-str opts)))
      (let [resp (send-and-read! (ws-request {:version "8"}))]
        (is (= 426 (status-of resp)))
        (is (clojure.string/includes? resp "Sec-WebSocket-Version: 13\r\n"))))))

(deftest ws-subprotocol-must-be-offered
  (doseq [[picked expected] [["superchat" 101] ["other" 500]]]
    (with-server
      (fn [_] {:ring.websocket/listener {}
               :ring.websocket/protocol picked})
      {}
      (fn []
        (let [resp (send-and-read! (ws-request {:extra "Sec-WebSocket-Protocol: chat, superchat\r\n"}) 1000)]
          (is (= expected (status-of resp)) picked)
          (when (= 101 expected)
            (is (clojure.string/includes? resp "Sec-WebSocket-Protocol: superchat\r\n"))))))))

(deftest ws-message-cap-falls-back-when-body-cap-disabled
  ;; WebSocket messages are buffered whole, so :max-request-body-bytes 0
  ;; still caps them at 10 MiB; a larger message gets CLOSE 1009.
  (let [received (promise)
        size (* 11 1024 1024)]
    (with-server
      (fn [_] {:ring.websocket/listener
               {:on-message (fn [_ msg] (deliver received (count (str msg))))}})
      {:max-request-body-bytes 0}
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (.setSoTimeout sock 10000)
          (let [out (.getOutputStream sock)
                in (java.io.DataInputStream. (.getInputStream sock))]
            (.write out (.getBytes (ws-request) StandardCharsets/ISO_8859_1))
            (.flush out)
            (read-http-head in)
            (future
              (try
                (.write out (masked-frame 0x1 (byte-array size (byte 97))))
                (.flush out)
                (catch java.io.IOException _)))
            (is (= 0x88 (.readUnsignedByte in)))
            (.readUnsignedByte in)
            (is (= 1009 (.readUnsignedShort in)))
            (is (not (realized? received)))))))))

(deftest ws-upgrade-response-carries-handler-headers
  (let [listener (reify com.s_exp.enso.api.WebSocketListener
                   (onOpen [_ _]) (onMessage [_ _ _]) (onPing [_ _ _]) (onPong [_ _ _])
                   (onError [_ _ _]) (onClose [_ _ _ _]))
        run (fn [headers]
              (let [srv (com.s_exp.enso.EnsoServer.
                         (reify com.s_exp.enso.api.RingHandler
                           (handle [_ _]
                             (com.s_exp.enso.api.Response. 101 headers nil listener nil)))
                         (.build (doto (com.s_exp.enso.api.Config/builder) (.port 0))))]
                (.start srv)
                (try
                  (binding [*server* {:port (.port srv)}]
                    (send-and-read! (ws-request) 1000))
                  (finally (.close srv)))))]
    (let [resp (run {"Set-Cookie" ["a=1" "b=2"]
                     "X-Extra" "yes"
                     "Content-Length" "5"
                     "Connection" "close"
                     "Sec-WebSocket-Accept" "forged"})]
      (is (clojure.string/starts-with? resp "HTTP/1.1 101"))
      (is (clojure.string/includes? resp "Set-Cookie: a=1\r\n"))
      (is (clojure.string/includes? resp "Set-Cookie: b=2\r\n"))
      (is (clojure.string/includes? resp "X-Extra: yes\r\n"))
      (is (not (clojure.string/includes? resp "Content-Length")))
      (is (not (clojure.string/includes? resp "forged")))
      (is (not (clojure.string/includes? resp "Connection: close"))))
    (let [resp (run {"X-Evil" "a\r\nInjected: 1"})]
      (is (= 500 (status-of resp)))
      (is (not (clojure.string/includes? resp "Injected"))))))

;; ---- Body / header paths kept allocation-light ---------------------------

(deftest large-ascii-body-round-trip
  (let [body (apply str (repeat 50000 "ab"))]
    (with-server (fn [_] {:status 200 :body body}) {}
      (fn []
        (let [resp (send-and-read! close-req)]
          (is (clojure.string/includes? resp "Content-Length: 100000\r\n"))
          (is (clojure.string/ends-with? resp (str "\r\n\r\n" body))))))))

(deftest chunked-stream-body-round-trip
  (let [body (apply str (repeat 30000 "xyz"))]
    (with-server
      (fn [_] {:status 200 :body (ByteArrayInputStream. (.getBytes body StandardCharsets/ISO_8859_1))})
      {}
      (fn []
        (let [resp (send-and-read! "GET / HTTP/1.1\r\nHost: x\r\n\r\n" 1000)
              sep (clojure.string/index-of resp "\r\n\r\n")]
          (is (clojure.string/includes? resp "Transfer-Encoding: chunked\r\n"))
          (is (= body (dechunk (subs resp (+ sep 4))))))))))

(deftest unknown-header-names-lowercased
  (let [captured (atom nil)]
    (with-server (fn [req] (reset! captured (:headers req)) {:status 200 :body ""}) {}
      (fn []
        (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\nX-Mixed-Case: 1\r\nx-already-lower: 2\r\n"
                             "Connection: close\r\n\r\n"))
        (is (= "1" (get @captured "x-mixed-case")))
        (is (= "2" (get @captured "x-already-lower")))))))

(deftest status-lines-for-uncommon-codes
  (with-server (fn [req] {:status (Long/parseLong (subs (:uri req) 1)) :body ""}) {}
    (fn []
      (is (clojure.string/starts-with? (send-and-read! "GET /299 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                                       "HTTP/1.1 299 \r\n"))
      (is (clojure.string/starts-with? (send-and-read! "GET /418 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                                       "HTTP/1.1 418 \r\n")))))

;; ---- Shutdown -------------------------------------------------------------

(deftest stop-waits-for-in-flight-requests-then-force-closes
  ;; Shutdown waits for the in-flight request until the last quarter of
  ;; :shutdown-timeout, then closes its socket, interrupts the handler and
  ;; returns once it exited, within the timeout.
  (let [entered (java.util.concurrent.CountDownLatch. 1)
        release (java.util.concurrent.CountDownLatch. 1)
        srv (enso/run-server
             (fn [_]
               (.countDown entered)
               (.await release 10 java.util.concurrent.TimeUnit/SECONDS)
               {:status 200 :body "late"})
             {:port 0 :shutdown-timeout 400})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
          (.flush out))
        (is (.await entered 2 java.util.concurrent.TimeUnit/SECONDS))
        (let [t0 (System/nanoTime)
              _ (enso/stop srv)
              stop-ms (/ (- (System/nanoTime) t0) 1e6)
              t1 (System/nanoTime)
              resp (read-until-quiet! sock 3000)
              closed-ms (/ (- (System/nanoTime) t1) 1e6)]
          (is (>= stop-ms 290) (str "stop returned after " stop-ms "ms without waiting"))
          (is (< stop-ms 450) (str "stop took " stop-ms "ms"))
          (is (= "" resp))
          (is (< closed-ms 2000) "in-flight socket force-closed")))
      (finally
        (.countDown release)))))

(deftest stop-lets-a-finishing-request-complete
  (let [entered (java.util.concurrent.CountDownLatch. 1)
        srv (enso/run-server
             (fn [_]
               (.countDown entered)
               (Thread/sleep 200)
               {:status 200 :body "done"})
             {:port 0 :shutdown-timeout 3000})]
    (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
      (let [out (.getOutputStream sock)]
        (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
        (.flush out))
      (is (.await entered 2 java.util.concurrent.TimeUnit/SECONDS))
      (let [stopper (future (enso/stop srv))
            resp (read-until-quiet! sock 3000)]
        @stopper
        (is (clojure.string/starts-with? resp "HTTP/1.1 200") resp)
        (is (clojure.string/includes? resp "Connection: close\r\n") "last response announces close")
        (is (clojure.string/ends-with? resp "done"))))))

;; ---- Lifecycle and acceptor ------------------------------------------------

(deftest constructor-binds-nothing-and-failed-start-releases-everything
  (with-open [taken (java.net.ServerSocket. 0)]
    (let [port (.getLocalPort taken)
          srv (com.s_exp.enso.EnsoServer.
               (reify com.s_exp.enso.api.RingHandler (handle [_ _] nil))
               (.build (doto (com.s_exp.enso.api.Config/builder) (.port (int port)))))]
      (is (some? srv) "constructing doesn't bind")
      (is (thrown? java.io.IOException (.start srv)))))
  (testing "an HTTP/3 setup failure releases the bound TCP port"
    (let [port (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s))]
      (is (thrown? Exception (enso/run-server (fn [_] {:status 200})
                                              {:port port :http3 true :http3-cert-path "/nonexistent.pem"
                                               :http3-key-path "/nonexistent.key"})))
      (with-open [again (java.net.ServerSocket. port)]
        (is (= port (.getLocalPort again)) "port free again")))))

(deftest max-connections-refuses-over-the-limit
  (let [entered (java.util.concurrent.CountDownLatch. 1)
        release (java.util.concurrent.CountDownLatch. 1)]
    (with-server
      (fn [req]
        (when (= "/hold" (:uri req))
          (.countDown entered)
          (.await release 5 java.util.concurrent.TimeUnit/SECONDS))
        {:status 200 :body "ok"})
      {:max-connections 1}
      (fn []
        (with-open [holder (Socket. "127.0.0.1" (int (:port *server*)))]
          (write! holder "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n")
          (is (.await entered 2 java.util.concurrent.TimeUnit/SECONDS))
          (is (= "" (send-and-read! close-req 2000)) "second connection closed at accept")
          (.countDown release)
          (is (clojure.string/starts-with? (read-until-quiet! holder 2000) "HTTP/1.1 200")))
        (is (await-connections (:server *server*) 0 2000))
        (is (= 200 (status-of (send-and-read! close-req))) "slot released")))))

(deftest max-connections-per-ip-refuses-over-the-limit
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:max-connections-per-ip 1}
    (fn []
      (with-open [first-conn (Socket. "127.0.0.1" (int (:port *server*)))]
        (is (await-connections (:server *server*) 1 2000))
        (is (= "" (send-and-read! close-req 2000)))
        (write! first-conn close-req)
        (is (clojure.string/starts-with? (read-until-quiet! first-conn 2000) "HTTP/1.1 200")))
      (is (await-connections (:server *server*) 0 2000))
      (is (= 200 (status-of (send-and-read! close-req)))))))

(deftest string-and-seq-bodies-use-content-type-charset
  ;; Ring encodes String and seq bodies with the Content-Type charset.
  (doseq [body ["\u00e9t\u00e9" (list "\u00e9" "t\u00e9")]]
    (with-server
      (fn [_] {:status 200 :headers {"Content-Type" "text/plain; charset=ISO-8859-1"} :body body})
      {}
      (fn []
        (let [resp (send-and-read! close-req)
              payload (subs resp (+ 4 (.indexOf ^String resp "\r\n\r\n")))]
          (is (clojure.string/includes? payload "\u00e9t\u00e9") (pr-str body))
          (when (string? body)
            (is (clojure.string/includes? resp "Content-Length: 3\r\n"))))))))

(deftest unknown-response-charset-is-500
  (with-server
    (fn [_] {:status 200 :headers {"content-type" "text/plain; charset=no-such"} :body "x"})
    {}
    (fn []
      (is (= 500 (status-of (send-and-read! close-req)))))))

;; ---- Allocation budget -----------------------------------------------------

(def ^:private ^com.sun.management.ThreadMXBean thread-mx
  (ManagementFactory/getThreadMXBean))

(def ^:private alloc-request
  (.getBytes (str "GET /plaintext?x=1 HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: bench\r\n"
                  "Accept: */*\r\n\r\n")
             StandardCharsets/ISO_8859_1))

(defn- connection-alloc-bytes
  "Bytes allocated by the current thread serving `n` GETs on one
  in-memory HttpConnection run on this thread: Ring adapter, parsing,
  handler call and response writing, plus the connection's own buffers
  (amortized over `n`). `pipelined`: all requests arrive in one read,
  else one per read with a flush per response."
  ^long [srv handler n pipelined]
  (let [^bytes req alloc-request
        in (if pipelined
             (ByteArrayInputStream. (byte-array (mapcat seq (repeat n req))))
             (SequenceInputStream. (java.util.Collections/enumeration
                                    (vec (repeatedly n #(ByteArrayInputStream. req))))))
        out (OutputStream/nullOutputStream)
        addr (InetAddress/getLoopbackAddress)
        sock (proxy [Socket] []
               (getInputStream [] in)
               (getOutputStream [] out)
               (setSoTimeout [_])
               (getInetAddress [] addr)
               (getLocalPort [] 8080)
               (close []))
        c (HttpConnection. sock handler srv)
        before (.getCurrentThreadAllocatedBytes thread-mx)]
    (.run c)
    (- (.getCurrentThreadAllocatedBytes thread-mx) before)))

(deftest h1-get-allocation-budget
  ;; A plain GET (3 request headers and a query, String body) through the whole
  ;; HTTP/1.1 path, measured on the calling thread, so it is exact and
  ;; free of other threads' noise. What is allocated per request is the
  ;; Ring request (Request and header map; value, uri and query Strings
  ;; only when they differ from the previous request's), the handler's
  ;; Response, and Clojure's response coercion; see
  ;; doc/architecture.md. The bound catches anything new per request
  ;; (a lambda, an iterator, a buffer).
  (let [served (java.util.concurrent.atomic.AtomicLong.)
        ->response @#'enso/->response
        resp {:status 200 :headers {"content-type" "text/plain"} :body "hello world"}
        handler (reify RingHandler
                  (handle [_ _]
                    (.incrementAndGet served)
                    (->response resp)))
        srv (enso/run-server (fn [_] resp) {:port 0 :max-keep-alive-requests 0})
        n 2000]
    (try
      (doseq [pipelined [true false]]
        (dotimes [_ 30] (connection-alloc-bytes srv handler n pipelined))
        (let [before (.get served)
              per-request (/ (double (apply min (repeatedly 3 #(connection-alloc-bytes srv handler n pipelined))))
                             n)]
          (is (= (* 3 n) (- (.get served) before)) "every request was served")
          (is (< per-request 300) (str (if pipelined "pipelined" "one request per read")
                                       ": " per-request " bytes/request"))
          (println "h1 GET," (if pipelined "pipelined:" "one request per read:") per-request "bytes/request")))
      (finally (enso/stop srv)))))

(defn- collected? [^java.lang.ref.WeakReference ref ms]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (System/gc)
      (cond
        (nil? (.get ref)) true
        (> (System/currentTimeMillis) deadline) false
        :else (do (Thread/sleep 20) (recur))))))

(deftest closed-connections-leave-the-timer
  ;; The connection's timer nodes (write watchdog, handler timeout) are
  ;; retired at close: the timer wheel doesn't keep a closed connection
  ;; and its buffers reachable until their slot comes around.
  (let [resp {:status 200 :body "ok"}
        ->response @#'enso/->response
        handler (reify RingHandler (handle [_ _] (->response resp)))
        srv (enso/run-server (fn [_] resp) {:port 0 :write-timeout 60000 :handler-timeout 60000})]
    (try
      (let [in (ByteArrayInputStream. alloc-request)
            out (OutputStream/nullOutputStream)
            addr (InetAddress/getLoopbackAddress)
            sock (proxy [Socket] []
                   (getInputStream [] in)
                   (getOutputStream [] out)
                   (setSoTimeout [_])
                   (getInetAddress [] addr)
                   (getLocalPort [] 8080)
                   (close []))
            ref (java.lang.ref.WeakReference. (doto (HttpConnection. sock handler srv) (.run)))]
        (is (collected? ref 1000)))
      (finally (enso/stop srv)))))

;; ---- Request head and body bounds -----------------------------------------

(deftest max-header-bytes-bounds-the-whole-head
  ;; :max-header-bytes caps request line + field lines + CRLFs, not each
  ;; line on its own: many short lines that together exceed it get 431.
  (with-server echo-body {:max-header-bytes 1024}
    (fn []
      (let [line (str "X-Pad: " (apply str (repeat 50 "p")) "\r\n")]
        (is (= 200 (status-of (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                                                   (apply str (repeat 15 line)) "\r\n")))))
        (is (= 431 (status-of (send-and-read! (str "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                                                   (apply str (repeat 30 line)) "\r\n")))))
        (is (= 431 (status-of (send-and-read! (str (apply str (repeat 600 "\r\n"))
                                                   "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
            "empty lines before the request line count too")))))

(deftest chunk-size-line-capped
  ;; A chunk-size line (with its extensions) is bounded on its own, far
  ;; below :max-header-bytes, and extension bytes count against the body cap.
  (with-server echo-body {:max-request-body-bytes 1000}
    (fn []
      (is (= 400 (status-of (send-and-read! (chunked-post (str "3;e=" (apply str (repeat 5000 "x"))
                                                               "\r\nabc\r\n0\r\n\r\n"))))))
      (is (= 413 (status-of (send-and-read! (chunked-post (str (apply str (repeat 40 (str "1;e=" (apply str (repeat 100 "x")) "\r\na\r\n")))
                                                               "0\r\n\r\n")))))
          "extension bytes count against :max-request-body-bytes")
      (is (= 200 (status-of (send-and-read! (chunked-post (str (apply str (repeat 5 (str "1;e=" (apply str (repeat 100 "x")) "\r\na\r\n")))
                                                               "0\r\n\r\n")))))))))

(deftest chunk-extension-bws-before-semicolon-accepted
  ;; RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name ...).
  (with-server echo-body {}
    (fn []
      (doseq [size-line ["3 ;a=b" "3\t;a" "3  ; a = b"]]
        (let [resp (send-and-read! (chunked-post (str size-line "\r\nabc\r\n0\r\n\r\n")))]
          (is (= 200 (status-of resp)) (pr-str size-line))
          (is (clojure.string/ends-with? resp "abc") (pr-str size-line))))
      (doseq [size-line ["3 " "3 a" " 3"]]
        (is (= 400 (status-of (send-and-read! (chunked-post (str size-line "\r\nabc\r\n0\r\n\r\n")))))
            (pr-str size-line))))))

(deftest malformed-chunked-body-is-400-and-skips-the-error-handler
  ;; Broken chunked framing found while the handler reads the body is the
  ;; client's error: 400, the connection closes, and neither the error
  ;; handler nor a handler that swallows the exception changes that.
  (let [error-handler-calls (atom 0)]
    (doseq [[label handler] [["throwing handler" echo-body]
                             ["wrapping handler" (fn [req]
                                                   (try (slurp (:body req))
                                                        (catch Exception e (throw (ex-info "wrapped" {} e)))))]
                             ["swallowing handler" (fn [req]
                                                     (try (slurp (:body req)) (catch Exception _))
                                                     {:status 200 :body "swallowed"})]]]
      (with-server handler
        {:error-handler (fn [_ _] (swap! error-handler-calls inc) {:status 500 :body "eh"})}
        (fn []
          (doseq [body ["zz\r\nabc\r\n0\r\n\r\n" "3\r\nabcXX0\r\n\r\n" "fffffffffffffffffffff\r\nx\r\n"]]
            (let [resp (send-and-read! (str "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" body))]
              (is (= 400 (status-of resp)) (str label " " (pr-str body)))
              (is (clojure.string/includes? resp "Connection: close\r\n") label)
              (is (= 1 (status-line-count resp)) label))))))
    (is (zero? @error-handler-calls))))

(deftest duplicate-content-length-response-keys-rejected
  (with-server
    (fn [_] {:status 200
             :headers {"Content-Length" "3" "content-length" "4"}
             :body (ByteArrayInputStream. (.getBytes "abcd" StandardCharsets/UTF_8))})
    {}
    (fn []
      (is (= 500 (status-of (send-and-read! close-req)))))))

;; ---- Pipelining, Expect, drain and close ----------------------------------

(deftest pipelined-response-not-held-behind-a-slow-handler
  ;; /fast's response must reach the client while /slow's handler still
  ;; runs, not wait to be coalesced with /slow's response.
  (let [release (java.util.concurrent.CountDownLatch. 1)]
    (with-server
      (fn [req]
        (when (= "/slow" (:uri req))
          (.await release 5 java.util.concurrent.TimeUnit/SECONDS))
        {:status 200 :body (:uri req)})
      {}
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (write! sock (str "GET /fast HTTP/1.1\r\nHost: x\r\n\r\n"
                            "GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
          (let [early (read-until-quiet! sock 1000)]
            (.countDown release)
            (is (clojure.string/ends-with? early "/fast") (pr-str early))
            (is (clojure.string/ends-with? (read-until-quiet! sock 2000) "/slow"))))))))

(defn- read-available!
  "Reads whatever arrives on `sock` within `ms` (at least one read)."
  [^Socket sock ms]
  (.setSoTimeout sock (int ms))
  (let [buf (byte-array 8192)]
    (try
      (let [n (.read (.getInputStream sock) buf)]
        (if (pos? n) (String. buf 0 n StandardCharsets/ISO_8859_1) ""))
      (catch java.net.SocketTimeoutException _ ""))))

(deftest expect-100-continue-sent-on-first-body-read
  (let [release (java.util.concurrent.CountDownLatch. 1)]
    (with-server
      (fn [req]
        (.await release 5 java.util.concurrent.TimeUnit/SECONDS)
        {:status 200 :body (slurp (:body req))})
      {}
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
          (is (= "" (read-available! sock 300)) "no 100 before the handler reads")
          (.countDown release)
          (is (= "HTTP/1.1 100 Continue\r\n\r\n" (read-available! sock 2000)))
          (write! sock "hello")
          (let [resp (read-until-quiet! sock 2000)]
            (is (clojure.string/starts-with? resp "HTTP/1.1 200"))
            (is (clojure.string/ends-with? resp "hello"))))))))

(deftest expect-100-continue-skipped-when-the-body-is-never-read
  (with-server
    (fn [_] {:status 200 :body "ignored"})
    {}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        (let [[resp ms] (read-all-timed sock 3000)]
          (is (clojure.string/starts-with? resp "HTTP/1.1 200") (pr-str resp))
          (is (not (clojure.string/includes? resp "100 Continue")))
          (is (clojure.string/includes? resp "Connection: close\r\n"))
          (is (< ms 1500) "closed instead of waiting for the body"))))))

(deftest unread-body-too-large-to-drain-announces-close
  ;; The handler ignores a body whose remaining length is above what the
  ;; server drains: the response says Connection: close and the
  ;; connection closes without reading the body.
  (with-server
    (fn [_] {:status 200 :body "ignored"})
    {}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (write! sock "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\nabc")
        (let [[resp ms] (read-all-timed sock 3000)]
          (is (clojure.string/starts-with? resp "HTTP/1.1 200") (pr-str resp))
          (is (clojure.string/includes? resp "Connection: close\r\n"))
          (is (< ms 1500)))))))

(deftest unread-small-body-keeps-the-connection
  (with-server
    (fn [req] {:status 200 :body (:uri req)})
    {}
    (fn []
      (let [resp (send-and-read! (str "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
                                      "POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                                      "GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))]
        (is (= 3 (status-line-count resp)) resp)
        (is (clojure.string/ends-with? resp "/c"))))))

(deftest error-response-survives-an-unread-upload
  ;; The client keeps uploading a body the server refused (413 at the
  ;; head): the server half-closes and discards input for a while
  ;; (lingering close) instead of resetting the connection, so the
  ;; client's upload completes and it reads the 413.
  (with-server echo-body {:max-request-body-bytes 1000}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              writer (future
                       (try
                         (.write out (.getBytes "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n"
                                                StandardCharsets/ISO_8859_1))
                         (dotimes [_ 100] (.write out (byte-array 40000)))
                         :uploaded
                         (catch java.io.IOException e e)))
              resp (read-until-quiet! sock 3000)]
          (is (clojure.string/starts-with? resp "HTTP/1.1 413") (pr-str (subs resp 0 (min 40 (count resp)))))
          (is (= :uploaded (deref writer 5000 :timed-out))))))))

(deftest server-events-cover-failed-requests
  (let [log (atom [])]
    (with-server
      (fn [req]
        (case (:uri req)
          "/throw" (throw (ex-info "boom" {}))
          "/read" {:status 200 :body (slurp (:body req))}))
      {:read-timeout 200
       :server-events {:request-completed (fn [_ _ status _ _ _] (swap! log conj [:request status]))
                       :protocol-error (fn [_ kind] (swap! log conj [:error kind]))}}
      (fn []
        (is (= 500 (status-of (send-and-read! "GET /throw HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
        (is (= 408 (status-of (send-and-read! "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\nabc"))))
        (let [deadline (+ (System/currentTimeMillis) 3000)]
          (while (and (< (count @log) 3) (< (System/currentTimeMillis) deadline))
            (Thread/sleep 10)))
        (is (= #{[:request 500] [:request 408] [:error "read-timeout"]} (set @log)))))))

(deftest file-transfer-falls-back-when-transfer-to-makes-no-progress
  ;; FileChannel.transferTo returning 0 is not the end of the file: the
  ;; rest is copied through the output stream instead.
  (let [f (java.io.File/createTempFile "enso-h1" ".txt")
        written (java.io.ByteArrayOutputStream.)]
    (try
      (spit f "0123456789")
      (let [resp {:status 200 :body f}
            ->response @#'enso/->response
            handler (reify RingHandler (handle [_ _] (->response resp)))
            srv (enso/run-server (fn [_] resp) {:port 0})
            stuck-channel (proxy [java.nio.channels.SocketChannel] [(java.nio.channels.spi.SelectorProvider/provider)]
                            (write
                              ([_] 0)
                              ([_ _ _] 0))
                            (implCloseSelectableChannel [])
                            (implConfigureBlocking [_]))
            in (ByteArrayInputStream. (.getBytes "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                                                 StandardCharsets/ISO_8859_1))
            addr (InetAddress/getLoopbackAddress)
            sock (proxy [Socket] []
                   (getInputStream [] in)
                   (getOutputStream [] written)
                   (getChannel [] stuck-channel)
                   (setSoTimeout [_])
                   (getInetAddress [] addr)
                   (getLocalPort [] 8080)
                   (close []))]
        (try
          (.run (HttpConnection. sock handler srv))
          (is (clojure.string/ends-with? (String. (.toByteArray written) StandardCharsets/ISO_8859_1)
                                         "\r\n\r\n0123456789"))
          (finally (enso/stop srv))))
      (finally (.delete f)))))

(deftest authority-form-only-for-connect
  ;; RFC 9112 §3.2.3: authority-form is only for CONNECT (answered 501);
  ;; on any other method it is not a valid target.
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {}
    (fn []
      (doseq [target ["example.com:80" "example.com" "a?b"]]
        (is (= 400 (status-of (send-and-read! (str "GET " target " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))
            target)))))

(deftest keep-alive-request-after-idle-buffer-release
  ;; A connection idle past the buffer-release delay serves the next
  ;; request, including one larger than the initial buffers.
  (with-server
    (fn [req] {:status 200 :body (str (count (get-in req [:headers "x-big"])) "|" (slurp (:body req)))})
    {}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [big (apply str (repeat 9000 "b"))
              body (apply str (repeat 20000 "z"))]
          (write! sock (str "POST / HTTP/1.1\r\nHost: x\r\nX-Big: " big "\r\nContent-Length: 1\r\n\r\na"))
          (is (clojure.string/ends-with? (read-available! sock 2000) "9000|a"))
          (Thread/sleep 1300)
          (write! sock (str "POST / HTTP/1.1\r\nHost: x\r\nX-Big: " big "\r\nContent-Length: " (count body)
                            "\r\nConnection: close\r\n\r\n" body))
          (is (clojure.string/ends-with? (read-until-quiet! sock 2000) (str "9000|" body))))))))

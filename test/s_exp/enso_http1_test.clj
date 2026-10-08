(ns s-exp.enso-http1-test
  "Additional HTTP/1.1 integration tests covering session changes:
  #223 (parseHeaders compact-before-grow), #225 (BufferedOutputStream
  flush ordering with sendfile), #224 (RequestBody single-byte scratch
  reuse), #222 (duplicate-header dedup), and h1 pipelining edge cases."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (java.io ByteArrayInputStream)
           (java.net Socket)
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

;; ---- #223: header buffer compact-before-grow -----------------------------

(deftest headers-near-max-fit-in-buffer-after-compact
  ;; With request-buffer-size = 512 and max-header-bytes = 2048, a
  ;; request with headers totalling ~1600 bytes must fit. Without
  ;; compact-before-grow, the buffer would fill with the request-line
  ;; area and hit 431 spuriously.
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:request-buffer-size 512 :max-header-bytes 2048}
    (fn []
      (let [big-header (apply str (repeat 1500 "a"))
            req (str "GET /foo HTTP/1.1\r\n"
                     "Host: x\r\n"
                     "X-Big: " big-header "\r\n"
                     "Connection: close\r\n\r\n")
            resp (send-raw! req)]
        (is (= 200 (status-of resp))
            "1500-byte header inside 2048 cap must serve after compact")))))

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

;; ---- #225: BufferedOutputStream + sendfile ordering ----------------------

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

;; ---- #224 sanity via echo (single-byte scratch) --------------------------

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
      (Thread/sleep 100)
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
  (with-server echo-body {:max-header-bytes 1024 :request-buffer-size 1024}
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
  (doseq [[status expected] [[204 false] [103 false] [304 true]]]
    (with-server
      (fn [_] {:status status :headers {"Content-Length" "5"} :body nil})
      {}
      (fn []
        (let [resp (send-and-read! close-req)]
          (is (= expected (boolean (re-find #"(?i)content-length:" resp)))
              (str status " " (pr-str resp))))))))

(deftest keep-alive-timeout-applies-only-between-requests
  ;; A fresh connection waits for its first request under :idle-timeout;
  ;; :keep-alive-timeout only bounds the wait after a response.
  (with-server
    (fn [_] {:status 200 :body "ok"})
    {:keep-alive-timeout 200 :idle-timeout 3000}
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (Thread/sleep 600)
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
          (.flush out)
          (.setSoTimeout sock 2000)
          (let [t0 (System/nanoTime)
                resp (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)
                ms (/ (- (System/nanoTime) t0) 1e6)]
            (is (clojure.string/starts-with? resp "HTTP/1.1 200") (pr-str resp))
            (is (< ms 1500) "closed by the keep-alive timeout after the response")))))))

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
    (.closeInternal w)
    (is (= (str (apply str (repeat 20 piece)) big big (apply str (repeat 1000 "c")))
           (dechunk (String. (.toByteArray baos) StandardCharsets/ISO_8859_1))))))

(deftest chunked-writer-write-ascii-rejects-non-ascii-atomically
  (let [baos (java.io.ByteArrayOutputStream.)
        w (com.s_exp.enso.api.ChunkedWriter. baos 512 true)]
    (.writeAscii w "ok")
    (is (thrown? IllegalArgumentException (.writeAscii w "abcé")))
    (.closeInternal w)
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
   {:on-message (fn [^com.s_exp.enso.websocket.WebSocketSocket s msg]
                  (.sendText s (str msg)))}})

(deftest ws-outlives-request-timeout-when-idle-timeout-disabled
  (with-server echo-ws-handler {:idle-timeout 0 :request-timeout 300}
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
  (let [listener (reify com.s_exp.enso.websocket.WebSocketListener
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

(deftest stop-with-user-executor-waits-then-force-closes
  ;; With a user executor the server's own executor runs no tasks, so
  ;; shutdown must track connections: wait up to :shutdown-timeout for the
  ;; in-flight request, then close its socket.
  (let [pool (java.util.concurrent.Executors/newVirtualThreadPerTaskExecutor)
        entered (java.util.concurrent.CountDownLatch. 1)
        release (java.util.concurrent.CountDownLatch. 1)
        srv (enso/run-server
             (fn [_]
               (.countDown entered)
               (.await release 10 java.util.concurrent.TimeUnit/SECONDS)
               {:status 200 :body "late"})
             {:port 0 :worker-executor pool :shutdown-timeout 400})]
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
          (is (>= stop-ms 350) (str "stop returned after " stop-ms "ms without waiting"))
          (is (= "" resp))
          (is (< closed-ms 2000) "in-flight socket force-closed")))
      (finally
        (.countDown release)
        (.shutdown pool)))))

;; ---- Acceptor --------------------------------------------------------------

(deftest acceptor-survives-rejected-dispatch
  ;; The first dispatch is rejected: that socket must be closed (not leaked)
  ;; and the acceptor must keep serving later connections.
  (let [rejected (atom 0)
        pool (java.util.concurrent.Executors/newVirtualThreadPerTaskExecutor)
        executor (reify java.util.concurrent.Executor
                   (execute [_ r]
                     (if (= 1 (swap! rejected inc))
                       (throw (java.util.concurrent.RejectedExecutionException. "busy"))
                       (.execute pool r))))]
    (try
      (with-server
        (fn [_] {:status 200 :body "ok"})
        {:worker-executor executor}
        (fn []
          (let [t0 (System/nanoTime)
                first-resp (send-and-read! close-req 3000)]
            (is (= "" first-resp))
            (is (< (/ (- (System/nanoTime) t0) 1e6) 2000) "rejected socket closed promptly"))
          (is (= 200 (status-of (send-and-read! close-req))))))
      (finally (.shutdown pool)))))

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

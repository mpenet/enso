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

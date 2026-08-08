(ns s-exp.enso-test
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.string :as str]
            [ring.core.protocols]
            [s-exp.enso :as enso])
  (:import (com.s_exp.enso.websocket WebSocketSocket)
           (java.io ByteArrayInputStream IOException)
           (java.net Socket SocketException URI)
           (java.net.http HttpClient WebSocket WebSocket$Builder WebSocket$Listener)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.security KeyStore)
           (java.util.concurrent CompletableFuture CountDownLatch TimeUnit)
           (javax.net.ssl KeyManagerFactory SSLContext TrustManager X509TrustManager)))

(def ^:dynamic *server* nil)

(defn- with-server
  ([handler f] (with-server handler nil f))
  ([handler opts f]
   (let [srv (enso/run-server handler (merge {:port 0} opts))]
     (try
       (binding [*server* {:server srv :port (enso/port srv)}]
         (f))
       (finally
         (enso/stop srv))))))

(defn- request!
  "Sends a raw HTTP request string over a fresh socket, reads all response bytes,
  returns the response as a string."
  ([raw] (request! (:port *server*) raw))
  ([port raw]
   (with-open [sock (Socket. "127.0.0.1" (int port))]
     (let [out (.getOutputStream sock)
           in (.getInputStream sock)]
       (.write out (.getBytes ^String raw StandardCharsets/ISO_8859_1))
       (.flush out)
       (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)))))

(defn- parse-response
  "Splits an HTTP response string into {:status :headers :body}. Assumes ISO-8859-1
  header + optional body starting after the empty line."
  [^String resp]
  (let [sep (str/index-of resp "\r\n\r\n")
        head (subs resp 0 sep)
        body (subs resp (+ sep 4))
        [status-line & header-lines] (str/split head #"\r\n")
        [_ status _] (str/split status-line #" " 3)
        headers (into {}
                      (map (fn [^String line]
                             (let [colon (.indexOf line ":")]
                               [(-> line (subs 0 colon) str/lower-case)
                                (-> line (subs (inc colon)) str/trim)])))
                      header-lines)]
    {:status (Long/parseLong status)
     :headers headers
     :body body}))

(defn- get! [path]
  (parse-response
   (request! (str "GET " path " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))))

(defn- echo-handler [req]
  {:status 200
   :body (if (:body req) (slurp (:body req)) "")})

(deftest happy-path-get
  (with-server
    (fn [_] {:status 200 :body "hello"}) nil
    (fn []
      (let [r (get! "/")]
        (is (= 200 (:status r)))
        (is (= "hello" (:body r)))
        (is (= "5" (get-in r [:headers "content-length"])))))))

(deftest request-map-keys
  (let [captured (atom nil)]
    (with-server
      (fn [req] (reset! captured req) {:status 200 :body "ok"}) nil
      (fn []
        (request! (str "GET /path?a=1 HTTP/1.1\r\nHost: example:8080\r\n"
                       "X-Foo: bar\r\nConnection: close\r\n\r\n"))
        (let [req @captured]
          (is (= "/path" (:uri req)))
          (is (= "a=1" (:query-string req)))
          (is (= :get (:request-method req)))
          (is (= "HTTP/1.1" (:protocol req)))
          (is (= :http (:scheme req)))
          (is (= "example" (:server-name req)))
          (is (= "bar" (get-in req [:headers "x-foo"])))
          (is (string? (:remote-addr req))))))))

(deftest methods
  (with-server
    (fn [req] {:status 200 :body (name (:request-method req))}) nil
    (fn []
      (doseq [[m expected] [["GET" "get"] ["POST" "post"] ["PUT" "put"]
                            ["DELETE" "delete"] ["PATCH" "patch"] ["OPTIONS" "options"]
                            ["HEAD" "head"]]]
        (let [r (parse-response
                 (request! (str m " / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))]
          (is (= 200 (:status r)) m)
          (when-not (= "HEAD" m)
            (is (= expected (:body r)) m)))))))

(deftest post-body-content-length
  (with-server echo-handler nil
    (fn []
      (let [r (parse-response
               (request! (str "POST /e HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
                              "Connection: close\r\n\r\nhello world")))]
        (is (= 200 (:status r)))
        (is (= "hello world" (:body r)))))))

(deftest chunked-request-body
  (with-server echo-handler nil
    (fn []
      (let [r (parse-response
               (request! (str "POST /e HTTP/1.1\r\nHost: x\r\n"
                              "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                              "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")))]
        (is (= 200 (:status r)))
        (is (= "helloworld" (:body r)))))))

(deftest chunked-request-body-with-extensions-and-trailer
  (with-server echo-handler nil
    (fn []
      (let [r (parse-response
               (request! (str "POST /e HTTP/1.1\r\nHost: x\r\n"
                              "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                              "A;name=value\r\n0123456789\r\n0\r\nX-Trailer: yo\r\n\r\n")))]
        (is (= 200 (:status r)))
        (is (= "0123456789" (:body r)))))))

(defn- read-until [in ^String terminator]
  (let [sb (StringBuilder.)
        buf (byte-array 4096)]
    (loop []
      (let [n (.read in buf)]
        (when (pos? n)
          (.append sb (String. buf 0 n StandardCharsets/ISO_8859_1))
          (when-not (.contains (.toString sb) terminator)
            (recur)))))
    (.toString sb)))

(deftest chunked-response
  (with-server
    (fn [_] {:status 200 :body (ByteArrayInputStream. (.getBytes "streamed body" StandardCharsets/UTF_8))}) nil
    (fn []
      ;; keep-alive path triggers chunked encoding for unknown-length streams
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              _ (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
              _ (.flush out)
              raw (read-until in "0\r\n\r\n")]
          (is (str/includes? raw "Transfer-Encoding: chunked"))
          (is (str/includes? raw "streamed body")))))))

(deftest keep-alive-and-pipelining
  (with-server
    (fn [req] {:status 200 :body (:uri req)}) nil
    (fn []
      (let [pipelined (str "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                           "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
                           "GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            resp (request! pipelined)
            statuses (re-seq #"HTTP/1\.1 (\d{3})" resp)]
        (is (= 3 (count statuses)))
        (is (str/includes? resp "/a"))
        (is (str/includes? resp "/b"))
        (is (str/includes? resp "/c"))))))

(deftest duplicate-header-merge
  (let [captured (atom nil)]
    (with-server
      (fn [req] (reset! captured (get-in req [:headers "x-repeat"])) {:status 200 :body ""}) nil
      (fn []
        (request! (str "GET / HTTP/1.1\r\nHost: x\r\nX-Repeat: a\r\nX-Repeat: b\r\n"
                       "Connection: close\r\n\r\n"))
        (is (= "a,b" @captured))))))

(deftest expect-100-continue
  (with-server echo-handler nil
    (fn []
      (let [raw (request! (str "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                               "Expect: 100-continue\r\nConnection: close\r\n\r\nhello"))]
        (is (str/includes? raw "HTTP/1.1 100 Continue"))
        (is (str/includes? raw "HTTP/1.1 200 OK"))
        (is (str/ends-with? raw "hello"))))))

;; ---- HPACK (RFC 7541 Appendix C) ---------------------------------------

(defn- hex->bytes ^"[B" [s]
  (let [s (str/replace s #"\s" "")
        n (/ (count s) 2)
        out (byte-array n)]
    (dotimes [i n]
      (aset-byte out i (byte (- (Integer/parseInt (subs s (* i 2) (+ (* i 2) 2)) 16)
                                (if (>= (Integer/parseInt (subs s (* i 2) (+ (* i 2) 2)) 16) 128) 256 0)))))
    out))

(deftest hpack-decode-c-3-1
  ;; RFC 7541 C.3.1 — first request in the sequence, no Huffman.
  (let [^com.s_exp.enso.http2.Hpack$Decoder dec (com.s_exp.enso.http2.Hpack$Decoder. 4096)
        ^bytes block (hex->bytes "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")
        ^java.util.List fields (.decode dec block (int 0) (int (alength block)))]
    (is (= 4 (.size fields)))
    (let [entries (map (fn [i]
                         (let [^com.s_exp.enso.http2.Hpack$HeaderField hf (.get fields (int i))]
                           [(.name hf) (.value hf)]))
                       (range (.size fields)))]
      (is (= [[":method" "GET"]
              [":scheme" "http"]
              [":path" "/"]
              [":authority" "www.example.com"]]
             entries)))))

(deftest hpack-huffman-decode-c-4-1
  ;; RFC 7541 C.4.1 — Huffman-encoded "www.example.com" (from the same request).
  (let [^bytes encoded (hex->bytes "f1e3 c2e5 f23a 6ba0 ab90 f4ff")
        ^bytes decoded (com.s_exp.enso.http2.HpackHuffman/decode encoded (int 0) (int (alength encoded)))]
    (is (= "www.example.com" (String. decoded StandardCharsets/UTF_8)))))

(deftest hpack-integer-round-trip
  ;; RFC 7541 §5.1: single-byte and multi-byte integer encodings.
  (doseq [[v prefix expected-hex]
          [[10 5 "0a"]
           [1337 5 "1f9a0a"]
           [42 8 "2a"]]]
    (let [buf (byte-array 8)
          n (com.s_exp.enso.http2.Hpack/encodeInteger buf 0 prefix 0 v)
          hex (apply str (map #(format "%02x" (bit-and % 0xff))
                              (java.util.Arrays/copyOf buf n)))]
      (is (= expected-hex hex) (str "encode value=" v " prefix=" prefix)))
    ;; And round-trip through decode.
    (let [buf (byte-array 8)
          n (com.s_exp.enso.http2.Hpack/encodeInteger buf 0 prefix 0 v)
          cursor (com.s_exp.enso.http2.Hpack$Cursor. buf 0 n)
          out (com.s_exp.enso.http2.Hpack/decodeInteger cursor prefix)]
      (is (= v out) (str "roundtrip value=" v " prefix=" prefix)))))

(deftest response-header-crlf-rejected
  ;; Handler returning a header with embedded CRLF must not split the response.
  (with-server
    (fn [_] {:status 200
             :headers {"x-evil" "value\r\nInjected: yes"}
             :body "ok"}) nil
    (fn []
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 500 (:status r)))
        (is (nil? (get-in r [:headers "injected"])))))))

(deftest response-header-name-crlf-rejected
  (with-server
    (fn [_] {:status 200
             :headers {"x\r\nInjected" "yes"}
             :body "ok"}) nil
    (fn []
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 500 (:status r)))))))

(deftest server-name-ipv6-host
  (let [captured (atom nil)]
    (with-server
      (fn [req] (reset! captured (:server-name req)) {:status 200 :body ""}) nil
      (fn []
        (request! (str "GET / HTTP/1.1\r\nHost: [::1]:8080\r\nConnection: close\r\n\r\n"))
        (is (= "[::1]" @captured))
        (request! (str "GET / HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n"))
        (is (= "example.com" @captured))
        (request! (str "GET / HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n"))
        (is (= "[::1]" @captured))))))

(deftest obs-fold-header-rejected
  ;; RFC 7230 §3.2.4: continuation lines starting with SP or HTAB must be rejected.
  (with-server
    (fn [_] {:status 200 :body "ok"}) nil
    (fn []
      (let [r (parse-response
               (request! (str "GET / HTTP/1.1\r\nHost: x\r\n"
                              "X-Long: first line\r\n"
                              " continuation\r\n"
                              "Connection: close\r\n\r\n")))]
        (is (= 400 (:status r)))))))

(deftest duplicate-content-length-rejected
  (with-server echo-handler nil
    (fn []
      (let [r (parse-response
               (request! (str "POST / HTTP/1.1\r\nHost: x\r\n"
                              "Content-Length: 5\r\n"
                              "Content-Length: 5\r\n"
                              "Connection: close\r\n\r\nhello")))]
        (is (= 400 (:status r)))))))

(deftest expect-100-continue-with-chunked
  ;; Full protocol dance: client sends headers, waits for 100 Continue, then
  ;; ships chunked body. Verifies the interim response arrives before the body
  ;; is committed on the wire and that the chunked decoder handles the split.
  (with-server echo-handler nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes (str "POST / HTTP/1.1\r\nHost: x\r\n"
                                      "Transfer-Encoding: chunked\r\n"
                                      "Expect: 100-continue\r\n"
                                      "Connection: close\r\n\r\n")
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          ;; Read until we see the interim 100 response.
          (let [interim-buf (StringBuilder.)
                buf (byte-array 1024)]
            (loop []
              (let [n (.read in buf)]
                (when (pos? n)
                  (.append interim-buf (String. buf 0 n StandardCharsets/ISO_8859_1))
                  (when-not (.contains (.toString interim-buf) "100 Continue")
                    (recur)))))
            (is (str/includes? (.toString interim-buf) "HTTP/1.1 100 Continue")))
          ;; Now stream chunks.
          (.write out (.getBytes "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [raw (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)
                r (parse-response
                   ;; The response body follows the 200 OK response line; the
                   ;; earlier 100 Continue lives in the pre-response bytes we
                   ;; drained above. `raw` may still contain it if the server
                   ;; batched, so parse from the last 200 marker.
                   (if-let [i (str/last-index-of raw "HTTP/1.1 200")]
                     (subs raw i)
                     raw))]
            (is (= 200 (:status r)))
            (is (= "hello world" (:body r)))))))))

(deftest http-1-0-closes
  (with-server
    (fn [_] {:status 200 :body "ok"}) nil
    (fn []
      (let [raw (request! "GET / HTTP/1.0\r\nHost: x\r\n\r\n")]
        (is (str/includes? raw "Connection: close"))))))

(deftest head-omits-body
  (with-server
    (fn [_] {:status 200 :body "hello"}) nil
    (fn []
      (let [r (parse-response
               (request! "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))]
        (is (= 200 (:status r)))
        (is (= "5" (get-in r [:headers "content-length"])))
        (is (= "" (:body r)))))))

(deftest status-204-no-body
  (with-server
    (fn [_] {:status 204}) nil
    (fn []
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 204 (:status r)))
        (is (nil? (get-in r [:headers "content-length"])))
        (is (= "" (:body r)))))))

(deftest body-types
  (with-server
    (fn [req]
      (case (:uri req)
        "/str" {:status 200 :body "text"}
        "/bytes" {:status 200 :body (.getBytes "raw" StandardCharsets/UTF_8)}
        "/stream" {:status 200 :headers {"content-length" "6"}
                   :body (ByteArrayInputStream. (.getBytes "stream" StandardCharsets/UTF_8))}
        "/seq" {:status 200 :body (list "a" "b" "c")}
        {:status 404 :body ""})) nil
    (fn []
      (is (= "text" (:body (get! "/str"))))
      (is (= "raw" (:body (get! "/bytes"))))
      (is (= "stream" (:body (get! "/stream"))))
      (is (= "abc" (:body (get! "/seq")))))))

(deftest utf-8-body
  (with-server
    (fn [_] {:status 200 :body "café ☕"}) nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [all-bytes (.readAllBytes in)
                raw (String. all-bytes StandardCharsets/ISO_8859_1)
                sep (str/index-of raw "\r\n\r\n")
                body-bytes (java.util.Arrays/copyOfRange all-bytes (+ sep 4) (count all-bytes))
                body (String. ^bytes body-bytes StandardCharsets/UTF_8)]
            (is (= "café ☕" body))))))))

(deftest malformed-request-400
  (with-server
    (fn [_] {:status 200 :body ""}) nil
    (fn []
      (let [r (parse-response (request! "GARBAGE\r\n\r\n"))]
        (is (= 400 (:status r)))))))

(deftest chunked-with-content-length-400
  (with-server echo-handler nil
    (fn []
      (let [r (parse-response
               (request! (str "POST / HTTP/1.1\r\nHost: x\r\n"
                              "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n"
                              "Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")))]
        (is (= 400 (:status r)))))))

(deftest handler-throws-500
  (with-server
    (fn [_] (throw (RuntimeException. "boom"))) nil
    (fn []
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 500 (:status r)))))))

(deftest handler-returns-nil-500
  (with-server
    (fn [_] nil) nil
    (fn []
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 500 (:status r)))))))

(deftest oversized-headers-rejected
  (with-server
    (fn [_] {:status 200 :body "ok"}) nil
    (fn []
      ;; server sends 431 + closes; macOS may TCP-RST before client drains.
      ;; Race a reader against the write and accept either 431 or connection-close.
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [in (.getInputStream sock)
              out (.getOutputStream sock)
              got-431 (atom false)
              closed (atom false)
              reader (Thread/ofVirtual)
              _ (.start (.unstarted reader
                                    (fn []
                                      (try
                                        (let [buf (byte-array 8192)
                                              n (.read in buf)]
                                          (when (pos? n)
                                            (when (str/includes? (String. buf 0 n StandardCharsets/ISO_8859_1) "431")
                                              (reset! got-431 true))))
                                        (reset! closed true)
                                        (catch IOException _ (reset! closed true))))))
              big (.getBytes (apply str (repeat 70000 "a")) StandardCharsets/ISO_8859_1)]
          (try
            (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\nX-Big: " StandardCharsets/ISO_8859_1))
            (.write out big)
            (.write out (.getBytes "\r\n\r\n" StandardCharsets/ISO_8859_1))
            (.flush out)
            (catch IOException _))
          (Thread/sleep 200)
          (is (or @got-431 @closed)))))))

(deftest fragmented-header-read
  (with-server
    (fn [_] {:status 200 :body "ok"}) nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (doseq [chunk ["GET / HTT" "P/1.1\r\nHo" "st: x\r\nCon"
                         "nection: close" "\r\n\r\n"]]
            (.write out (.getBytes chunk StandardCharsets/ISO_8859_1))
            (.flush out)
            (Thread/sleep 10))
          (let [r (parse-response (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))]
            (is (= 200 (:status r)))
            (is (= "ok" (:body r)))))))))

(deftest date-header-emitted
  (with-server
    (fn [_] {:status 200 :body "ok"}) nil
    (fn []
      (is (contains? (:headers (get! "/")) "date")))))

(deftest response-numeric-header-value
  (with-server
    (fn [_] {:status 200 :headers {"x-num" 42 "x-long" (long 99)} :body ""}) nil
    (fn []
      (let [r (get! "/")]
        (is (= "42" (get-in r [:headers "x-num"])))
        (is (= "99" (get-in r [:headers "x-long"])))))))

(deftest graceful-stop-completes-inflight
  (let [start-latch (java.util.concurrent.CountDownLatch. 1)
        release-latch (java.util.concurrent.CountDownLatch. 1)
        srv (enso/run-server
             (fn [_]
               (.countDown start-latch)
               (.await release-latch 2 java.util.concurrent.TimeUnit/SECONDS)
               {:status 200 :body "done"})
             {:port 0 :shutdown-timeout 3000})
        port (enso/port srv)
        result (atom nil)
        client (Thread/ofVirtual)]
    (.start (.unstarted client
                        (fn []
                          (with-open [sock (Socket. "127.0.0.1" (int port))]
                            (let [out (.getOutputStream sock)
                                  in (.getInputStream sock)]
                              (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                                     StandardCharsets/ISO_8859_1))
                              (.flush out)
                              (reset! result (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)))))))
    (.await start-latch 2 java.util.concurrent.TimeUnit/SECONDS)
    ;; handler is blocked; stop() must wait for it to finish
    (let [stop-thread (Thread/ofVirtual)
          stopped (atom false)]
      (.start (.unstarted stop-thread
                          (fn []
                            (enso/stop srv)
                            (reset! stopped true))))
      (Thread/sleep 100)
      (is (not @stopped) "stop should be waiting for in-flight request")
      (.countDown release-latch)
      (Thread/sleep 500)
      (is @stopped "stop should complete after handler returned")
      (is (some-> @result (str/includes? "done")) "in-flight request should get its response"))))

(deftest request-timeout-slowloris
  ;; Drip-feeds 1 byte at a time. Server should time out via 408 before headers complete.
  ;; Concurrent reader avoids losing the 408 to a TCP RST when the server closes mid-write.
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :idle-timeout 5000 :request-timeout 500})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              got-408 (atom false)
              closed (atom false)
              t0 (System/nanoTime)
              reader (Thread/ofVirtual)]
          (.start (.unstarted reader
                              (fn []
                                (try
                                  (let [buf (byte-array 4096)]
                                    (loop []
                                      (let [n (.read in buf)]
                                        (when (pos? n)
                                          (when (str/includes?
                                                 (String. buf 0 n StandardCharsets/ISO_8859_1) "408")
                                            (reset! got-408 true))
                                          (recur)))))
                                  (reset! closed true)
                                  (catch IOException _ (reset! closed true))))))
          (try
            (doseq [b (.getBytes "GET / HTTP/1.1\r\nHost: x\r\nX-Foo: bar\r\n\r\n"
                                 StandardCharsets/ISO_8859_1)]
              (.write out (byte-array [b]))
              (.flush out)
              (Thread/sleep 30))
            (catch IOException _))
          (Thread/sleep 200)
          (let [elapsed-ms (/ (- (System/nanoTime) t0) 1e6)]
            (is @got-408)
            (is (< elapsed-ms 2000) (str "should time out ~500ms, took " elapsed-ms "ms")))))
      (finally (enso/stop srv)))))

(defn- generate-self-signed-context
  "Shells out to `keytool` to create a temp keystore with a self-signed cert,
  then loads it into an SSLContext. Avoids JDK-internal APIs blocked by module
  system in JDK 17+."
  ^SSLContext []
  (let [pass "changeit"
        ks-file (java.io.File/createTempFile "enso-tls" ".p12")
        _ (.delete ks-file)
        cmd ["keytool" "-genkeypair" "-alias" "enso" "-keyalg" "RSA" "-keysize" "2048"
             "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
             "-storepass" pass "-validity" "365"
             "-dname" "CN=localhost, OU=test, O=enso, L=x, S=x, C=US"
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
          _ (with-open [in (java.io.FileInputStream. ks-file)]
              (.load ks in (.toCharArray pass)))
          kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
          _ (.init kmf ks (.toCharArray pass))
          ctx (SSLContext/getInstance "TLS")]
      (.init ctx (.getKeyManagers kmf) nil nil)
      (.delete ks-file)
      ctx)))

(defn- trust-all-context ^SSLContext []
  (let [trust-all (reify X509TrustManager
                    (checkClientTrusted [_ _ _])
                    (checkServerTrusted [_ _ _])
                    (getAcceptedIssuers [_] (make-array java.security.cert.X509Certificate 0)))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx nil (into-array TrustManager [trust-all]) nil)
    ctx))

(deftest streaming-body-multi-flush
  (let [barrier (java.util.concurrent.CountDownLatch. 3)]
    (with-server
      (fn [_]
        {:status 200
         :headers {"content-type" "text/event-stream"}
         :body (fn [w]
                 (dotimes [i 3]
                   (enso/write! w (str "event " i "\n"))
                   (enso/flush! w)
                   (.countDown barrier)
                   (Thread/sleep 20)))})
      nil
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)]
            (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                   StandardCharsets/ISO_8859_1))
            (.flush out)
            (.await barrier 3 java.util.concurrent.TimeUnit/SECONDS)
            (let [raw (read-until in "0\r\n\r\n")]
              (is (str/includes? raw "Transfer-Encoding: chunked"))
              (is (str/includes? raw "content-type: text/event-stream"))
              (is (str/includes? raw "event 0"))
              (is (str/includes? raw "event 1"))
              (is (str/includes? raw "event 2"))
              (is (str/includes? raw "0\r\n\r\n")))))))))

(deftest streaming-body-flushes-happen-independently
  ;; Client should see the first chunk on the wire well before the handler returns.
  (let [second-write (java.util.concurrent.CountDownLatch. 1)]
    (with-server
      (fn [_]
        {:status 200
         :body (fn [w]
                 (enso/write! w "first\n")
                 (enso/flush! w)
                 (.await second-write 3 java.util.concurrent.TimeUnit/SECONDS)
                 (enso/write! w "second\n")
                 (enso/flush! w))})
      nil
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)]
            (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                   StandardCharsets/ISO_8859_1))
            (.flush out)
            (let [accumulated (StringBuilder.)
                  buf (byte-array 4096)]
              ;; Read until we see "first" — proves the client received it before
              ;; the handler proceeds (second-write latch still held).
              (loop []
                (let [n (.read in buf)]
                  (when (pos? n)
                    (.append accumulated (String. buf 0 n StandardCharsets/ISO_8859_1))
                    (when-not (.contains (.toString accumulated) "first")
                      (recur)))))
              (is (str/includes? (.toString accumulated) "first"))
              (is (not (str/includes? (.toString accumulated) "second")))
              (.countDown second-write)
              (loop []
                (let [n (.read in buf)]
                  (when (pos? n)
                    (.append accumulated (String. buf 0 n StandardCharsets/ISO_8859_1))
                    (when-not (.contains (.toString accumulated) "0\r\n\r\n")
                      (recur)))))
              (is (str/includes? (.toString accumulated) "second")))))))))

(deftest tls-basic-get
  (let [srv (enso/run-server
             (fn [req] {:status 200 :body (str "hello " (name (:request-method req)))})
             {:port 0 :ssl-context (generate-self-signed-context)})]
    (try
      (let [factory (.getSocketFactory (trust-all-context))]
        (with-open [sock (.createSocket factory "127.0.0.1" (int (enso/port srv)))]
          (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
          (.startHandshake sock)
          (let [out (.getOutputStream sock)
                in (.getInputStream sock)]
            (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                   StandardCharsets/ISO_8859_1))
            (.flush out)
            (let [raw (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)
                  r (parse-response raw)]
              (is (= 200 (:status r)))
              (is (= "hello get" (:body r)))))))
      (finally (enso/stop srv)))))

(deftest tls-file-body-fallback
  (let [f (java.io.File/createTempFile "enso-tls" ".bin")
        payload (byte-array (mapv byte (repeat 5000 (int \y))))]
    (try
      (java.nio.file.Files/write (.toPath f) payload
                                 ^"[Ljava.nio.file.OpenOption;" (make-array java.nio.file.OpenOption 0))
      (let [srv (enso/run-server
                 (fn [_] {:status 200 :body f})
                 {:port 0 :ssl-context (generate-self-signed-context)})]
        (try
          (let [factory (.getSocketFactory (trust-all-context))]
            (with-open [sock (.createSocket factory "127.0.0.1" (int (enso/port srv)))]
              (.startHandshake sock)
              (let [out (.getOutputStream sock)
                    in (.getInputStream sock)]
                (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                       StandardCharsets/ISO_8859_1))
                (.flush out)
                (let [all (.readAllBytes in)
                      raw (String. all StandardCharsets/ISO_8859_1)
                      sep (str/index-of raw "\r\n\r\n")
                      body-bytes (java.util.Arrays/copyOfRange all (+ sep 4) (count all))]
                  (is (str/includes? raw "Content-Length: 5000"))
                  (is (= 5000 (alength body-bytes)))))))
          (finally (enso/stop srv))))
      (finally (.delete f)))))

(deftest file-body-sendfile
  (let [f (java.io.File/createTempFile "enso-test" ".bin")
        payload (byte-array (mapv byte (repeat 100000 (int \x))))]
    (try
      (java.nio.file.Files/write (.toPath f) payload
                                 ^"[Ljava.nio.file.OpenOption;" (make-array java.nio.file.OpenOption 0))
      (with-server
        (fn [_] {:status 200 :body f}) nil
        (fn []
          (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
            (let [out (.getOutputStream sock)
                  in (.getInputStream sock)]
              (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                     StandardCharsets/ISO_8859_1))
              (.flush out)
              (let [all (.readAllBytes in)
                    raw (String. all StandardCharsets/ISO_8859_1)
                    sep (str/index-of raw "\r\n\r\n")
                    body-bytes (java.util.Arrays/copyOfRange all (+ sep 4) (count all))]
                (is (str/includes? raw "200 OK"))
                (is (str/includes? raw "Content-Length: 100000"))
                (is (= 100000 (alength body-bytes))))))))
      (finally (.delete f)))))

(deftest error-handler-custom-response
  (let [srv (enso/run-server
             (fn [_] (throw (ex-info "boom" {:code :bad-data})))
             {:port 0
              :error-handler (fn [req t]
                               {:status 502
                                :headers {"content-type" "text/plain"}
                                :body (str "err: " (ex-message t)
                                           " uri: " (:uri req))})})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET /oops HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [r (parse-response (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))]
            (is (= 502 (:status r)))
            (is (= "err: boom uri: /oops" (:body r))))))
      (finally (enso/stop srv)))))

(deftest error-handler-throws-falls-back-500
  (let [srv (enso/run-server
             (fn [_] (throw (RuntimeException. "orig")))
             {:port 0
              :error-handler (fn [_ _] (throw (RuntimeException. "eh boom")))})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [r (parse-response (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))]
            (is (= 500 (:status r))))))
      (finally (enso/stop srv)))))

(deftest error-handler-returns-nil-falls-back-500
  (let [srv (enso/run-server
             (fn [_] (throw (RuntimeException. "boom")))
             {:port 0 :error-handler (fn [_ _] nil)})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [r (parse-response (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))]
            (is (= 500 (:status r))))))
      (finally (enso/stop srv)))))

(deftest inputstream-body-exact-content-length
  (with-server
    (fn [_] {:status 200
             :headers {"content-length" "5"}
             :body (ByteArrayInputStream. (.getBytes "hello" StandardCharsets/UTF_8))}) nil
    (fn []
      (let [r (get! "/")]
        (is (= 200 (:status r)))
        (is (= "5" (get-in r [:headers "content-length"])))
        (is (= "hello" (:body r)))))))

(deftest inputstream-body-longer-than-declared-truncates
  ;; Stream has 10 bytes but user declares 5. Server ships only 5, keeps conn alive.
  (with-server
    (fn [_] {:status 200
             :headers {"content-length" "5"}
             :body (ByteArrayInputStream. (.getBytes "helloworld" StandardCharsets/UTF_8))}) nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              _ (.write out (.getBytes "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                                       StandardCharsets/ISO_8859_1))
              _ (.flush out)
              raw (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)]
          ;; both responses came through: the truncated body did not corrupt framing
          (is (= 2 (count (re-seq #"HTTP/1\.1 200" raw))))
          (is (str/includes? raw "hello")))))))

(deftest inputstream-body-shorter-than-declared-closes
  ;; Stream has 3 bytes, user declared 10. Server ships 3 then closes.
  (with-server
    (fn [_] {:status 200
             :headers {"content-length" "10"}
             :body (ByteArrayInputStream. (.getBytes "abc" StandardCharsets/UTF_8))}) nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [raw (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)]
            (is (str/includes? (str/lower-case raw) "content-length: 10"))
            (is (str/ends-with? raw "abc"))))))))

(deftest request-body-size-cap-content-length
  (let [srv (enso/run-server
             echo-handler
             {:port 0 :max-request-body-bytes 100})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 200\r\nConnection: close\r\n\r\n"
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [r (parse-response (String. (.readAllBytes in) StandardCharsets/ISO_8859_1))]
            (is (= 413 (:status r))))))
      (finally (enso/stop srv)))))

(deftest request-body-size-cap-chunked
  (let [srv (enso/run-server
             echo-handler
             {:port 0 :max-request-body-bytes 8})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes (str "POST / HTTP/1.1\r\nHost: x\r\n"
                                      "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                      "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
                                 StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [raw (try (String. (.readAllBytes in) StandardCharsets/ISO_8859_1)
                         (catch IOException _ ""))]
            (is (str/includes? raw "413")))))
      (finally (enso/stop srv)))))

(defrecord CountingBody [n]
  ring.core.protocols/StreamableResponseBody
  (write-body-to-stream [_ _ out]
    (dotimes [i n]
      (.write out (.getBytes (str "line " i "\n") StandardCharsets/UTF_8))
      (.flush out))
    (.close out)))

(deftest streamable-response-body-custom-type
  (with-server
    (fn [_] {:status 200
             :headers {"content-type" "text/plain"}
             :body (->CountingBody 3)}) nil
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)]
          (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [raw (read-until in "0\r\n\r\n")]
            (is (str/includes? raw "Transfer-Encoding: chunked"))
            (is (str/includes? raw "line 0"))
            (is (str/includes? raw "line 1"))
            (is (str/includes? raw "line 2"))))))))

(deftest websocket-echo
  (let [received (atom [])
        opened (CountDownLatch. 1)
        closed (CountDownLatch. 1)]
    (with-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [socket]
                     (.countDown opened))
          :on-message (fn [socket message]
                        (swap! received conj (str message))
                        (.sendText ^WebSocketSocket socket (str "echo: " message)))
          :on-close (fn [_ _ _]
                      (.countDown closed))}}) nil
      (fn []
        (let [seen (atom [])
              listener (reify WebSocket$Listener
                         (onOpen [_ ws]
                           (.request ws 1))
                         (onText [_ ws data last?]
                           (swap! seen conj (str data))
                           (.request ws 1)
                           nil)
                         (onClose [_ _ _ _]
                           nil))
              client (-> (HttpClient/newHttpClient)
                         (.newWebSocketBuilder)
                         (.buildAsync (URI/create (str "ws://127.0.0.1:" (:port *server*) "/"))
                                      listener)
                         (.get 2 TimeUnit/SECONDS))]
          (.await opened 2 TimeUnit/SECONDS)
          (-> (.sendText ^WebSocket client "hello" true) (.get 2 TimeUnit/SECONDS))
          (Thread/sleep 100)
          (-> (.sendClose ^WebSocket client WebSocket/NORMAL_CLOSURE "bye") (.get 2 TimeUnit/SECONDS))
          (is (.await closed 2 TimeUnit/SECONDS))
          (is (= ["hello"] @received))
          (is (= ["echo: hello"] @seen)))))))

(deftest websocket-concurrent-sends-are-serialised
  ;; Spawns N virtual threads all calling sendText concurrently. Server's
  ;; write lock must serialise the frames so each message arrives whole,
  ;; never interleaved with another sender's bytes.
  (let [n 20
        server-socket (atom nil)
        opened (CountDownLatch. 1)
        seen (java.util.concurrent.ConcurrentLinkedQueue.)
        all-received (CountDownLatch. n)]
    (with-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [socket]
                     (reset! server-socket socket)
                     (.countDown opened))
          :on-message (fn [_ _])
          :on-close (fn [_ _ _])}}) nil
      (fn []
        (let [listener (reify WebSocket$Listener
                         (onOpen [_ ws] (.request ws 1))
                         (onText [_ ws data last?]
                           (.offer seen (str data))
                           (.countDown all-received)
                           (.request ws 1)
                           nil))
              client (-> (HttpClient/newHttpClient)
                         (.newWebSocketBuilder)
                         (.buildAsync (URI/create (str "ws://127.0.0.1:" (:port *server*) "/"))
                                      listener)
                         (.get 2 TimeUnit/SECONDS))]
          (.await opened 2 TimeUnit/SECONDS)
          (let [socket ^WebSocketSocket @server-socket
                senders (mapv (fn [i]
                                (Thread/startVirtualThread
                                 (fn []
                                   (.sendText socket
                                              (apply str (repeat 200 (char (+ 65 i))))))))
                              (range n))]
            (doseq [t senders] (.join ^Thread t)))
          (is (.await all-received 3 TimeUnit/SECONDS))
          (doseq [msg seen]
            (is (= 200 (count msg)))
            (is (= 1 (count (into #{} msg)))
                (str "interleaved: " (subs msg 0 (min 40 (count msg))))))
          (-> (.sendClose ^WebSocket client WebSocket/NORMAL_CLOSURE "bye")
              (.get 2 TimeUnit/SECONDS)))))))

(deftest websocket-binary
  (let [received (atom nil)
        opened (CountDownLatch. 1)
        got-response (CountDownLatch. 1)]
    (with-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [_] (.countDown opened))
          :on-message (fn [socket message]
                        (reset! received message)
                        (.sendBinary ^WebSocketSocket socket
                                     (ByteBuffer/wrap (.getBytes "pong" StandardCharsets/UTF_8))))
          :on-close (fn [_ _ _])}}) nil
      (fn []
        (let [seen-bin (atom nil)
              listener (reify WebSocket$Listener
                         (onOpen [_ ws] (.request ws 1))
                         (onBinary [_ ws data last?]
                           (let [arr (byte-array (.remaining data))]
                             (.get data arr)
                             (reset! seen-bin (String. arr StandardCharsets/UTF_8)))
                           (.countDown got-response)
                           nil))
              client (-> (HttpClient/newHttpClient)
                         (.newWebSocketBuilder)
                         (.buildAsync (URI/create (str "ws://127.0.0.1:" (:port *server*) "/"))
                                      listener)
                         (.get 2 TimeUnit/SECONDS))]
          (.await opened 2 TimeUnit/SECONDS)
          (-> (.sendBinary ^WebSocket client
                           (ByteBuffer/wrap (.getBytes "ping" StandardCharsets/UTF_8))
                           true)
              (.get 2 TimeUnit/SECONDS))
          (is (.await got-response 2 TimeUnit/SECONDS))
          (is (instance? ByteBuffer @received))
          (is (= "ping" (let [buf ^ByteBuffer @received
                              arr (byte-array (.remaining buf))]
                          (.get buf arr)
                          (String. arr StandardCharsets/UTF_8))))
          (is (= "pong" @seen-bin))
          (-> (.sendClose ^WebSocket client WebSocket/NORMAL_CLOSURE "bye")
              (.get 2 TimeUnit/SECONDS)))))))

(deftest websocket-invalid-handshake-400
  (with-server
    (fn [_] {:ring.websocket/listener {:on-open (fn [_]) :on-message (fn [_ _]) :on-close (fn [_ _ _])}})
    nil
    (fn []
      ;; Missing Upgrade header → server should reject with 400
      (let [r (parse-response
               (request! "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))]
        (is (= 400 (:status r)))))))

(deftest custom-max-header-bytes
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :max-header-bytes 1024})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (let [out (.getOutputStream sock)
              in (.getInputStream sock)
              got-431 (atom false)
              done (atom false)
              _ (.start (.unstarted (Thread/ofVirtual)
                                    (fn []
                                      (try
                                        (let [buf (byte-array 4096)
                                              n (.read in buf)]
                                          (when (pos? n)
                                            (when (str/includes?
                                                   (String. buf 0 n StandardCharsets/ISO_8859_1) "431")
                                              (reset! got-431 true))))
                                        (reset! done true)
                                        (catch IOException _ (reset! done true))))))]
          (try
            (.write out (.getBytes (str "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "
                                        (apply str (repeat 2000 "a"))
                                        "\r\n\r\n") StandardCharsets/ISO_8859_1))
            (.flush out)
            (catch IOException _))
          (Thread/sleep 200)
          (is @got-431)))
      (finally (enso/stop srv)))))

(deftest graceful-stop-closes-idle-keepalive
  (let [srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0 :shutdown-timeout 3000})
        port (enso/port srv)]
    (with-open [sock (Socket. "127.0.0.1" (int port))]
      (let [out (.getOutputStream sock)
            in (.getInputStream sock)]
        (.write out (.getBytes "GET / HTTP/1.1\r\nHost: x\r\n\r\n" StandardCharsets/ISO_8859_1))
        (.flush out)
        ;; drain first response, socket now sits idle in keep-alive
        (let [buf (byte-array 4096)]
          (.read in buf))
        (let [t0 (System/nanoTime)]
          (enso/stop srv)
          (let [elapsed-ms (/ (- (System/nanoTime) t0) 1e6)]
            (is (< elapsed-ms 500) (str "stop should be fast on idle conn, took " elapsed-ms "ms"))))))))

;; ============================================================================
;; HTTP/3 unit tests — RetryToken, H3BodyPipe, Sockaddr, Config
;; ============================================================================

(deftest h3-retry-token-roundtrip
  (let [tok (com.s_exp.enso.quiche.RetryToken.)
        peer (java.net.InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array (map byte [1 2 3 4 5 6 7 8]))
        minted (.mint tok peer odcid)
        verified (.verify tok minted peer)]
    (is (some? verified) "valid token verifies")
    (is (= (seq odcid) (seq verified)) "verified odcid matches minted")))

(deftest h3-retry-token-wrong-peer-rejected
  (let [tok (com.s_exp.enso.quiche.RetryToken.)
        peer1 (java.net.InetSocketAddress. "127.0.0.1" 55555)
        peer2 (java.net.InetSocketAddress. "127.0.0.1" 55556)
        odcid (byte-array (map byte [1 2 3 4]))
        minted (.mint tok peer1 odcid)]
    (is (nil? (.verify tok minted peer2)) "same IP different port must fail")))

(deftest h3-retry-token-wrong-ip-rejected
  (let [tok (com.s_exp.enso.quiche.RetryToken.)
        peer1 (java.net.InetSocketAddress. "127.0.0.1" 55555)
        peer2 (java.net.InetSocketAddress. "10.0.0.1" 55555)
        odcid (byte-array (map byte [1 2 3 4]))
        minted (.mint tok peer1 odcid)]
    (is (nil? (.verify tok minted peer2)) "different IP must fail")))

(deftest h3-retry-token-tampered-rejected
  (let [tok (com.s_exp.enso.quiche.RetryToken.)
        peer (java.net.InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array (map byte [1 2 3 4 5 6 7 8]))
        ^bytes minted (.mint tok peer odcid)]
    (aset minted 40 (byte (bit-xor (aget minted 40) 0x01)))
    (is (nil? (.verify tok minted peer)) "byte-flip in odcid body rejected")))

(deftest h3-retry-token-truncated-rejected
  (let [tok (com.s_exp.enso.quiche.RetryToken.)
        peer (java.net.InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array (map byte [1 2 3 4]))
        ^bytes minted (.mint tok peer odcid)
        chopped (byte-array (- (alength minted) 10))]
    (System/arraycopy minted 0 chopped 0 (alength chopped))
    (is (some? (.verify tok minted peer)) "sanity: full token verifies")
    (is (nil? (.verify tok chopped peer)) "truncated token rejected")
    (is (nil? (.verify tok (byte-array 0) peer)) "empty token rejected")
    (is (nil? (.verify tok nil peer)) "nil token rejected")))

(deftest h3-retry-token-different-instances-mint-differently
  ;; Fresh HMAC key per RetryToken instance — a token minted by one
  ;; listener must not validate against another (server restart => rotate).
  (let [t1 (com.s_exp.enso.quiche.RetryToken.)
        t2 (com.s_exp.enso.quiche.RetryToken.)
        peer (java.net.InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array (map byte [1 2 3]))
        m1 (.mint t1 peer odcid)]
    (is (nil? (.verify t2 m1 peer)) "cross-instance verify must fail")))

(deftest h3-body-pipe-basic
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "hello" StandardCharsets/UTF_8))
    (.signalEnd pipe)
    (is (= "hello" (slurp in)))))

(deftest h3-body-pipe-multi-chunk
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "aaa" StandardCharsets/UTF_8))
    (.enqueue pipe (.getBytes "bbb" StandardCharsets/UTF_8))
    (.enqueue pipe (.getBytes "ccc" StandardCharsets/UTF_8))
    (.signalEnd pipe)
    (is (= "aaabbbccc" (slurp in)))))

(deftest h3-body-pipe-eof-only
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe.)
        in (.inputStream pipe)]
    (.signalEnd pipe)
    (is (= "" (slurp in)) "empty body streams to empty string")))

(deftest h3-body-pipe-cap-accepts-below-limit
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe. 100)]
    (is (.enqueueChecked pipe (byte-array 40)))
    (is (.enqueueChecked pipe (byte-array 40)))
    (is (.enqueueChecked pipe (byte-array 20)))))

(deftest h3-body-pipe-cap-rejects-above-limit
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe. 100)]
    (is (.enqueueChecked pipe (byte-array 90)))
    (is (not (.enqueueChecked pipe (byte-array 20))) "20-byte push over 100 cap rejected")))

(deftest h3-body-pipe-cap-disabled-with-zero
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe. 0)]
    (is (.enqueueChecked pipe (byte-array 1000000)) "cap=0 disables enforcement")))

(deftest h3-body-pipe-read-single-byte
  (let [pipe (com.s_exp.enso.http3.Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (byte-array [(byte 65) (byte 66)]))
    (.signalEnd pipe)
    (is (= 65 (.read in)) "A")
    (is (= 66 (.read in)) "B")
    (is (= -1 (.read in)) "EOF")))

;; Sockaddr encoding is exercised end-to-end by the h3 smoke tests when
;; opt-in integration runs. Direct-reflection unit test dropped — too
;; entangled with package-private inner Encoded record for negligible
;; value.

;; ============================================================================
;; HTTP/3 Config validation
;; ============================================================================

(deftest h3-config-requires-cert-and-key
  ;; Config.build() throws directly — no server startup involved so no
  ;; risk of a shutdown hang.
  (is (thrown-with-msg? IllegalArgumentException #"http3CertPath"
                        (-> (com.s_exp.enso.api.Config/builder)
                            (.http3 true)
                            (.build)))
      "http3 without cert path throws"))

(deftest h3-config-validates-udp-payload-size
  (is (thrown-with-msg? IllegalArgumentException #"http3MaxUdpPayloadSize"
                        (-> (com.s_exp.enso.api.Config/builder)
                            (.http3MaxUdpPayloadSize 500)
                            (.build)))
      "below 1200 rejected")
  (is (thrown-with-msg? IllegalArgumentException #"http3MaxUdpPayloadSize"
                        (-> (com.s_exp.enso.api.Config/builder)
                            (.http3MaxUdpPayloadSize 70000)
                            (.build)))
      "above 65527 rejected"))

(deftest h3-config-alt-svc-max-age-negative-rejected
  (is (thrown-with-msg? IllegalArgumentException #"altSvcMaxAge"
                        (-> (com.s_exp.enso.api.Config/builder)
                            (.altSvcMaxAge -1)
                            (.build)))))

(deftest h3-config-initial-max-streams-bidi-positive
  (is (thrown-with-msg? IllegalArgumentException #"http3InitialMaxStreamsBidi"
                        (-> (com.s_exp.enso.api.Config/builder)
                            (.http3InitialMaxStreamsBidi 0)
                            (.build)))))

;; ============================================================================
;; Alt-Svc emission — Config-level tests. Integration tests via a real
;; server would need Connection: close plumbing that varies with keep-alive
;; state; those got dropped after they intermittently hung on shutdown.
;; ============================================================================

(deftest alt-svc-computed-when-explicitly-enabled
  (let [cfg (-> (com.s_exp.enso.api.Config/builder)
                (.advertiseAltSvc true)
                (.port 9999)
                (.build))]
    (is (true? (.-advertiseAltSvc cfg)))
    (is (= "h3=\":9999\"; ma=86400" (.-altSvcValue cfg)))))

(deftest alt-svc-not-computed-by-default
  (let [cfg (-> (com.s_exp.enso.api.Config/builder) (.build))]
    (is (false? (.-advertiseAltSvc cfg)))
    (is (nil? (.-altSvcValue cfg))
        "no Alt-Svc header value when disabled")))

(deftest alt-svc-explicit-false-overrides-http3-auto
  ;; When http3 is on, Alt-Svc defaults to true; explicit false disables.
  ;; Skip the real http3 flag here (needs cert paths for validation), just
  ;; exercise the advertiseAltSvcExplicit override branch.
  (let [cfg (-> (com.s_exp.enso.api.Config/builder)
                (.advertiseAltSvc false)
                (.build))]
    (is (false? (.-advertiseAltSvc cfg)))
    (is (nil? (.-altSvcValue cfg)))))

(deftest alt-svc-custom-max-age
  (let [cfg (-> (com.s_exp.enso.api.Config/builder)
                (.advertiseAltSvc true)
                (.altSvcMaxAge 300)
                (.port 8443)
                (.build))]
    (is (= "h3=\":8443\"; ma=300" (.-altSvcValue cfg)))))

(deftest alt-svc-uses-http3-port-when-set
  (let [cfg (-> (com.s_exp.enso.api.Config/builder)
                (.advertiseAltSvc true)
                (.port 8080)
                (.http3Port 4433)
                (.build))]
    (is (= "h3=\":4433\"; ma=86400" (.-altSvcValue cfg))
        "explicit http3Port wins over :port for Alt-Svc target")))

;; ============================================================================
;; HTTP/3 end-to-end smoke — requires quiche-client + libquiche
;; ============================================================================

(defn- h3-integration-enabled? []
  ;; Opt-in via `-J-Denso.h3.integration=true` since these tests need
  ;; quiche-client + fresh UDP ports + libquiche, and can hang on process
  ;; lifecycle mismatches. Off by default so `clj -M:test` is fast + safe.
  (= "true" (System/getProperty "enso.h3.integration")))

(defn- quiche-client-available? []
  (try
    (let [proc (-> (ProcessBuilder. ^java.util.List ["which" "quiche-client"])
                   (.redirectErrorStream true)
                   (.start))]
      (.waitFor proc)
      (zero? (.exitValue proc)))
    (catch Throwable _ false)))

(defn- gen-cert-and-key
  "Writes a temp cert + key pair to disk for quiche to load via PEM. Returns
  [cert-path key-path]. Cleanup is caller responsibility."
  []
  (let [dir (java.nio.file.Files/createTempDirectory
             "enso-h3-test" (into-array java.nio.file.attribute.FileAttribute []))
        cert (.resolve dir "cert.pem")
        key (.resolve dir "key.pem")
        cmd ["openssl" "req" "-x509" "-newkey" "rsa:2048"
             "-keyout" (str key) "-out" (str cert)
             "-sha256" "-days" "1" "-nodes"
             "-subj" "/CN=localhost"
             "-addext" "subjectAltName=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true)
                 (.start))]
    (.waitFor proc)
    [(str cert) (str key)]))

(defn- quiche-client-get
  "Sends a single HTTP/3 GET via quiche-client, returns the decoded body
  string (or nil on failure). Uses --no-verify against self-signed."
  [port]
  (try
    (let [cmd ["quiche-client" "--no-verify" "--dump-json"
               (str "https://127.0.0.1:" port "/")]
          proc (-> (ProcessBuilder. ^java.util.List cmd)
                   (.redirectErrorStream false)
                   (.start))
          _ (.waitFor proc 5 TimeUnit/SECONDS)
          out (slurp (.getInputStream proc))
          ;; body appears as a JSON array of ints
          m (re-find #"\"body\":\s*\[([0-9,\s]*)\]" out)]
      (when m
        (let [nums (map #(Integer/parseInt (str/trim %))
                        (str/split (second m) #","))]
          (String. (byte-array (map byte nums)) StandardCharsets/UTF_8))))
    (catch Throwable _ nil)))

(deftest h3-smoke-get
  (if (and (h3-integration-enabled?) (quiche-client-available?))
    (let [[cert-path key-path] (gen-cert-and-key)
          ctx (generate-self-signed-context)
          ;; :port 0 gives different random TCP + UDP ports since the two
          ;; socket namespaces are independent — pin the UDP port so the
          ;; test client can reach the h3 listener.
          h3-port 18890
          srv (enso/run-server (fn [_] {:status 200 :body "h3-hello"})
                               {:port 0
                                :ssl-context ctx
                                :http3 true
                                :http3-port h3-port
                                :http3-cert-path cert-path
                                :http3-key-path key-path})]
      (try
        (Thread/sleep 200)
        (let [body (quiche-client-get h3-port)]
          (is (= "h3-hello" body) "GET body round-trips over h3"))
        (finally (enso/stop srv))))
    (do (println "SKIP h3-smoke-get: opt-in with -J-Denso.h3.integration=true")
        (is true))))

(deftest h3-smoke-with-retry
  (if (and (h3-integration-enabled?) (quiche-client-available?))
    (let [[cert-path key-path] (gen-cert-and-key)
          ctx (generate-self-signed-context)
          h3-port 18891
          srv (enso/run-server (fn [_] {:status 200 :body "h3-retry-ok"})
                               {:port 0
                                :ssl-context ctx
                                :http3 true
                                :http3-port h3-port
                                :http3-cert-path cert-path
                                :http3-key-path key-path
                                :http3-stateless-retry true})]
      (try
        (Thread/sleep 200)
        (let [body (quiche-client-get h3-port)]
          (is (= "h3-retry-ok" body)
              "retry-challenged handshake completes + response round-trips"))
        (finally (enso/stop srv))))
    (do (println "SKIP h3-smoke-with-retry: opt-in with -J-Denso.h3.integration=true")
        (is true))))

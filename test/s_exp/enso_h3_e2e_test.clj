;; ABOUTME: End-to-end HTTP/3 tests: a raw quiche client (s-exp.h3-client)
;; ABOUTME: exercises the Http3Listener over real QUIC on loopback.
(ns s-exp.enso-h3-e2e-test
  "End-to-end HTTP/3 behaviour that unit tests can't reach: request body
  framing, backpressure, response streaming, stream/connection error
  codes."
  (:require [clojure.test :refer [deftest is testing]]
            [s-exp.enso-test-support :as support]
            [s-exp.h3-client :as h3])
  (:import (com.s_exp.enso.api Request Response)))

(set! *warn-on-reflection* true)

(defn- ok [body] (Response. 200 {"content-type" "text/plain"} body))

(deftest get-round-trip
  (h3/with-server [srv (fn [_] (ok "hello"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 200 (:status r)))
        (is (= "hello" (h3/body-str r)))
        (is (:fin r))))))

(defn- stream-bytes ^bytes [c sid]
  (some-> (h3/stream-state c sid) ^java.io.ByteArrayOutputStream (:out) .toByteArray))

(deftest server-opens-control-and-qpack-streams
  ;; RFC 9114 §6.2.1: each side MUST open a control stream and send
  ;; SETTINGS as its first frame; RFC 9204 §4.2 encoder/decoder streams.
  (h3/with-server [srv (fn [_] (ok "x"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/pump-until! c #(and (stream-bytes c 3) (stream-bytes c 7) (stream-bytes c 11)) 2000)
      (let [ctrl (stream-bytes c 3)]
        (is (some? ctrl) "server control stream opened")
        (when ctrl
          (is (= 0x00 (aget ctrl 0)) "control stream type")
          (is (= 0x04 (aget ctrl 1)) "first frame is SETTINGS")))
      (is (= [0x02] (some-> (stream-bytes c 7) seq vec)) "QPACK encoder stream")
      (is (= [0x03] (some-> (stream-bytes c 11) seq vec)) "QPACK decoder stream"))))

(deftest oversized-field-section-is-431
  ;; RFC 9114 §4.2.2: :max-header-bytes is SETTINGS_MAX_FIELD_SECTION_SIZE,
  ;; bounding the decoded section (name + value + 32 per field). Over it
  ;; the request is answered 431 without the handler, as on HTTP/1.1 and
  ;; HTTP/2; over the hard ceiling (4x, at least 64 KiB) the stream is
  ;; reset with H3_EXCESSIVE_LOAD before anything is buffered.
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "fine"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxHeaderBytes b 1024))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/" ["x-big" (apply str (repeat 2000 "a"))]))]
          (is (= 431 (:status r)))
          (is (= "Request Header Fields Too Large" (h3/body-str r))))
        (is (zero? @called) "handler not run")
        (let [r (h3/request! c 4 (h3/request-headers "GET" "/" ["x-huge" (apply str (repeat 70000 "a"))]))]
          (is (= 0x107 (:reset r)) "H3_EXCESSIVE_LOAD stream reset"))
        (is (nil? (h3/peer-error c)) "connection still open")
        (is (= "fine" (h3/body-str (h3/request! c 8 (h3/request-headers "GET" "/")))))))))

(defn- echo-handler [^Request req]
  (ok (.readAllBytes ^java.io.InputStream (.-body req))))

(deftest request-body-spanning-several-data-frames
  ;; RFC 9114 §4.1: the body is the concatenation of all DATA frames up to
  ;; the stream FIN, not just the first frame.
  (h3/with-server [srv echo-handler]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/concat-bytes
                     (h3/headers-frame (h3/request-headers "POST" "/"))
                     (h3/data-frame (.getBytes "one-"))
                     (h3/data-frame (.getBytes "two-"))
                     (h3/data-frame (.getBytes "three")))
                true)
      (h3/pump-until! c #(h3/stream-done? c 0) 5000)
      (let [r (h3/response c 0)]
        (is (= 200 (:status r)))
        (is (= "one-two-three" (h3/body-str r))))
      (is (nil? (h3/peer-error c)) "connection still open"))))

(deftest peer-reset-truncates-request-body
  ;; A RESET_STREAM mid-body must not look like a complete body to the
  ;; handler: reading throws instead of returning EOF.
  (let [outcome (promise)]
    (h3/with-server [srv (fn [^Request req]
                           (deliver outcome
                                    (try (String. (.readAllBytes ^java.io.InputStream (.-body req)))
                                         (catch java.io.IOException _ :truncated)))
                           (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (.getBytes "partial")))
                  false)
        (h3/pump! c 200)
        (h3/reset-stream! c 0 0x10c)
        (h3/pump-until! c #(realized? outcome) 3000)
        (is (= :truncated (deref outcome 0 :handler-still-blocked)))))))

(deftest response-from-slow-handler-is-sent-promptly
  ;; The connection thread must wake as soon as a handler enqueues its
  ;; response, not at its next timer/ingress wakeup.
  (h3/with-server [srv (fn [_] (Thread/sleep 100) (ok "late"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/pump! c 300)
      (let [lat (for [sid [0 4 8 12 16]]
                  (let [t0 (System/nanoTime)
                        r (h3/request! c sid (h3/request-headers "GET" "/"))]
                    (is (= "late" (h3/body-str r)))
                    (quot (- (System/nanoTime) t0) 1000000)))
            worst (apply max lat)]
        (is (< worst 250) (str "per-request latency ms: " (vec lat)))))))

(deftest unread-request-body-does-not-stall-connection
  ;; A handler that hasn't read its (large) body yet must not freeze the
  ;; connection: other streams keep being served, and the body arrives
  ;; intact once the handler reads it (QUIC flow control backpressures).
  (let [gate (promise)
        size (* 2 1024 1024)]
    (h3/with-server [srv (fn [^Request req]
                           (if (= "/slow" (.-uri req))
                             (do @gate
                                 (ok (str (alength (.readAllBytes ^java.io.InputStream (.-body req))))))
                             (ok "fast")))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/slow"))
                                       (h3/data-frame (byte-array size (byte 7))))
                  true)
        (h3/pump! c 500)
        (let [r (h3/request! c 4 (h3/request-headers "GET" "/fast"))]
          (is (= "fast" (h3/body-str r)) "second stream served while first body is unread"))
        (deliver gate true)
        (h3/pump-until! c #(h3/stream-done? c 0) 10000)
        (is (= (str size) (h3/body-str (h3/response c 0))))))))

(deftest early-response-while-request-body-in-flight
  ;; RFC 9114 §4.1.2: a server may respond before the request is complete.
  ;; Body bytes still arriving afterwards (here: the tail of a DATA frame)
  ;; must not be parsed as new frames.
  (h3/with-server [srv (fn [_] (Response. 401 {} "denied"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [payload (byte-array 50000 (byte 1))
            head (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                  (h3/varint 0x00) (h3/varint (alength payload))
                                  (java.util.Arrays/copyOfRange payload 0 1000))]
        (h3/send! c 0 head false)
        (h3/pump-until! c #(h3/stream-done? c 0) 3000)
        (is (= 401 (:status (h3/response c 0))))
        (h3/send! c 0 (java.util.Arrays/copyOfRange payload 1000 (alength payload)) true)
        (h3/pump! c 300)
        (is (nil? (h3/peer-error c)) "connection survives the late body bytes")
        (is (= 401 (:status (h3/request! c 4 (h3/request-headers "GET" "/"))))
            "connection still usable")))))

(defn- gated-stream
  "InputStream yielding `prefix`, then blocking until `gate` is delivered,
  then `suffix` and EOF."
  ^java.io.InputStream [^String prefix gate ^String suffix]
  (java.io.SequenceInputStream.
   (java.io.ByteArrayInputStream. (.getBytes prefix))
   (proxy [java.io.InputStream] []
     (read
       ([] (throw (UnsupportedOperationException.)))
       ([^bytes b off len]
        @gate
        (if (realized? (:done (meta gate)))
          -1
          (let [s (.getBytes suffix)]
            (deliver (:done (meta gate)) true)
            (System/arraycopy s 0 b off (alength s))
            (alength s))))))))

(deftest blocking-response-body-source-does-not-stall-connection
  ;; Response body sources are read off the connection thread: a slow
  ;; InputStream on one stream can't block the others.
  (let [gate (with-meta (promise) {:done (promise)})]
    (h3/with-server [srv (fn [^Request req]
                           (if (= "/slow" (.-uri req))
                             (ok (gated-stream "head-" gate "tail"))
                             (ok "fast")))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/slow")) true)
        (h3/pump! c 300)
        (let [t0 (System/nanoTime)
              r (h3/request! c 4 (h3/request-headers "GET" "/fast"))]
          (is (= "fast" (h3/body-str r)))
          (is (< (quot (- (System/nanoTime) t0) 1000000) 1000) "served promptly"))
        (deliver gate true)
        (h3/pump-until! c #(h3/stream-done? c 0) 5000)
        (is (= "head-tail" (h3/body-str (h3/response c 0))))))))

(deftest streaming-body-response
  ;; StreamingBody (what s-exp.enso coerces fn / seq / StreamableResponseBody
  ;; bodies into) is written chunk by chunk as DATA frames.
  (h3/with-server [srv (fn [_]
                         (ok (reify com.s_exp.enso.api.StreamingBody
                               (write [_ w]
                                 (.write w "event-1;")
                                 (.flush w)
                                 (.write w "event-2;")
                                 (.flush w)
                                 (.write w "end")))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 200 (:status r)))
        (is (= "event-1;event-2;end" (h3/body-str r)))
        (is (:fin r))))))

(deftest streaming-body-failure-resets-stream
  ;; A body that fails midway must not end with a clean FIN.
  (h3/with-server [srv (fn [_]
                         (ok (reify com.s_exp.enso.api.StreamingBody
                               (write [_ w]
                                 (.write w "partial")
                                 (.flush w)
                                 (throw (java.io.IOException. "boom"))))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 0x102 (:reset r)) "H3_INTERNAL_ERROR reset")
        (is (not (:fin r)))))))

(deftest unsupported-response-body-is-500
  (h3/with-server [srv (fn [_] (ok (Object.)))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= 500 (:status (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

(deftest response-header-values
  ;; Ring header values may be a seq of strings, one field per value; an
  ;; illegal value is a 500, as on HTTP/1.1.
  (h3/with-server [srv (fn [^Request req]
                         (case (.-uri req)
                           "/multi" (Response. 200 {"set-cookie" ["a=1" "b=2"]} "x")
                           "/crlf" (Response. 200 {"x-bad" "a\r\nb"} "x")
                           "/name" (Response. 200 {"bad name" "v"} "x")))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/multi"))]
        (is (= [["set-cookie" "a=1"] ["set-cookie" "b=2"]]
               (filterv #(= "set-cookie" (first %)) (:fields r)))))
      (doseq [[sid path] [[4 "/crlf"] [8 "/name"]]]
        (let [r (h3/request! c sid (h3/request-headers "GET" path))]
          (is (= 500 (:status r)) path)
          (is (not-any? #(#{"x-bad" "bad name"} (first %)) (:fields r)) path))))))

(deftest string-body-uses-content-type-charset
  (h3/with-server [srv (fn [_] (Response. 200 {"content-type" "text/plain; charset=ISO-8859-1"} "\u00e9t\u00e9"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= [0xE9 0x74 0xE9] (mapv #(bit-and % 0xFF) (:body r))))))))

(deftest error-handler
  ;; :error-handler answers when the handler throws or returns nil, as on
  ;; HTTP/1.1.
  (let [srv (h3/start-server (fn [^Request req]
                               (when (= "/boom" (.-uri req)) (throw (ex-info "boom" {}))))
                             (fn [_])
                             (fn [_ t] (Response. 418 {} (.getSimpleName (class t)))))]
    (try
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (doseq [[sid path cls] [[0 "/boom" "ExceptionInfo"] [4 "/nil" "NullPointerException"]]]
          (let [r (h3/request! c sid (h3/request-headers "GET" path))]
            (is (= 418 (:status r)) path)
            (is (= cls (h3/body-str r)) path))))
      (finally (.close srv)))))

(deftest file-body-larger-than-flow-control-window
  ;; Multi-chunk File body; client stream window (10 MB) > file, but the
  ;; congestion window forces many partial sends.
  (let [f (doto (java.io.File/createTempFile "enso-h3" ".bin") (.deleteOnExit))
        data (byte-array (* 3 1024 1024))]
    (.nextBytes (java.util.Random. 42) data)
    (java.nio.file.Files/write (.toPath f) data ^"[Ljava.nio.file.OpenOption;" (make-array java.nio.file.OpenOption 0))
    (h3/with-server [srv (fn [_] (ok f))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
          (is (:fin r))
          (is (java.util.Arrays/equals data ^bytes (:body r))))
        (let [r (h3/request! c 4 (h3/request-headers "HEAD" "/"))]
          (is (= (str (alength data)) (get (:headers r) "content-length")))
          (is (zero? (alength ^bytes (:body r)))))))))

(defn- message-error?
  "Sends `frames` as a complete request on `sid`; true when the server
  answers with a H3_MESSAGE_ERROR stream reset and keeps the connection."
  [c sid ^bytes frames]
  (h3/send! c sid frames true)
  (h3/pump-until! c #(h3/stream-done? c sid) 3000)
  (let [r (h3/response c sid)]
    (and (= 0x10e (:reset r)) (nil? (:status r)) (nil? (h3/peer-error c)))))

(defn- uppercase-literal-name-section
  "Valid request pseudo-headers followed by a literal field line whose
  name ('X-A') bypasses the encoder's lowercasing."
  ^bytes []
  (h3/concat-bytes (h3/field-section (h3/request-headers "GET" "/"))
                   (byte-array (map int [0x23 \X \- \A 0x01 \v]))))

(deftest malformed-requests-are-stream-errors
  ;; RFC 9114 §4.1.2: malformed requests MUST be treated as a stream error
  ;; of type H3_MESSAGE_ERROR; §4.2 field names/values; §4.3.1 pseudo-headers.
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (testing "CR in a field value"
        (is (message-error? c 0 (h3/headers-frame (h3/request-headers "GET" "/" ["x-a" "a\rb"])))))
      (testing "LF in a field value"
        (is (message-error? c 4 (h3/headers-frame (h3/request-headers "GET" "/" ["x-a" "a\nb"])))))
      (testing "NUL in a field value"
        (is (message-error? c 8 (h3/headers-frame (h3/request-headers "GET" "/" ["x-a" "a\u0000b"])))))
      (testing "non-token field name"
        (is (message-error? c 12 (h3/headers-frame (h3/request-headers "GET" "/" ["bad name" "v"])))))
      (testing "empty field name"
        (is (message-error? c 16 (h3/headers-frame (h3/request-headers "GET" "/" ["" "v"])))))
      (testing "uppercase field name"
        (is (message-error? c 20 (h3/frame 0x01 (uppercase-literal-name-section)))))
      (testing ":authority and Host disagree"
        (is (message-error? c 24 (h3/headers-frame (h3/request-headers "GET" "/" ["host" "evil.example"])))))
      (testing ":path not starting with /"
        (is (message-error? c 28 (h3/headers-frame (h3/request-headers "GET" "foo")))))
      (testing "* :path on a non-OPTIONS request"
        (is (message-error? c 32 (h3/headers-frame (h3/request-headers "GET" "*")))))
      (testing "content-length larger than the body"
        (is (message-error? c 36 (h3/concat-bytes
                                  (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "10"]))
                                  (h3/data-frame (.getBytes "abc"))))))
      (testing "content-length smaller than the body"
        (is (message-error? c 40 (h3/concat-bytes
                                  (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "1"]))
                                  (h3/data-frame (.getBytes "abc"))))))
      (testing "invalid content-length"
        (is (message-error? c 44 (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "x1"])))))
      (testing "duplicate pseudo-header"
        (is (message-error? c 48 (h3/headers-frame (conj (h3/request-headers "GET" "/") [":method" "GET"])))))
      (testing "connection still serves valid requests"
        (is (= "ok" (h3/body-str (h3/request! c 52 (h3/request-headers "GET" "/")))))))))

(deftest well-formed-edge-requests-accepted
  (let [seen (atom [])]
    (h3/with-server [srv (fn [^Request req]
                           (swap! seen conj [(.-method req) (.-uri req)
                                             (get (.-headers req) "host")
                                             (if-let [^java.io.InputStream in (.-body req)]
                                               (alength (.readAllBytes in))
                                               0)])
                           (ok "ok"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/" ["host" "localhost"])))))
        (is (= "ok" (h3/body-str (h3/request! c 4 (h3/request-headers "OPTIONS" "*")))))
        (is (= "ok" (h3/body-str (h3/request! c 8 (h3/request-headers "POST" "/" ["content-length" "3"])
                                              (.getBytes "abc")))))
        (is (= "ok" (h3/body-str (h3/request! c 12 [[":method" "GET"] [":scheme" "https"]
                                                    [":path" "/"] ["host" "h.example"]]))))
        (is (= [["GET" "/" "localhost" 0] ["OPTIONS" "*" "localhost" 0]
                ["POST" "/" "localhost" 3] ["GET" "/" "h.example" 0]]
               @seen))))))

(deftest request-trailers
  ;; RFC 9114 §4.1: HEADERS, DATA*, then optional trailing HEADERS.
  (h3/with-server [srv echo-handler]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (testing "trailers after the body are accepted"
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (.getBytes "body"))
                                       (h3/headers-frame [["x-checksum" "abc"]]))
                  true)
        (h3/pump-until! c #(h3/stream-done? c 0) 3000)
        (is (= "body" (h3/body-str (h3/response c 0))))
        (is (nil? (h3/peer-error c))))
      (testing "pseudo-header in trailers is malformed"
        (is (message-error? c 4 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                                 (h3/headers-frame [[":path" "/x"]])))))
      (testing "DATA after trailers is a frame sequence error"
        (h3/send! c 8 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/headers-frame [["x-t" "1"]])
                                       (h3/data-frame (.getBytes "late")))
                  true)
        (is (= [true 0x105] (h3/await-peer-error c 3000)) "H3_FRAME_UNEXPECTED")))))

(defn- conn-error-after
  "Opens the client control/QPACK streams, runs `f`, returns the server's
  CONNECTION_CLOSE [app? code] (nil if it kept the connection open)."
  [f]
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/pump! c 100)
      (f c)
      (h3/await-peer-error c 1500))))

(deftest uni-stream-rules
  ;; RFC 9114 §6.2.1 / RFC 9204 §4.2: a second control / QPACK encoder /
  ;; QPACK decoder stream is H3_STREAM_CREATION_ERROR; §6.2.2 so is a
  ;; client-initiated push stream; closing or resetting a critical stream
  ;; is H3_CLOSED_CRITICAL_STREAM.
  (testing "second control stream"
    (is (= [true 0x103] (conn-error-after #(h3/send! % 14 (h3/concat-bytes (h3/varint 0x00) (h3/settings-frame)) false)))))
  (testing "second QPACK encoder stream"
    (is (= [true 0x103] (conn-error-after #(h3/send! % 14 (h3/varint 0x02) false)))))
  (testing "second QPACK decoder stream"
    (is (= [true 0x103] (conn-error-after #(h3/send! % 14 (h3/varint 0x03) false)))))
  (testing "client push stream"
    (is (= [true 0x103] (conn-error-after #(h3/send! % 14 (h3/varint 0x01) false)))))
  (testing "control stream reset"
    (is (= [true 0x104] (conn-error-after #(h3/reset-stream! % 2 0x100)))))
  (testing "QPACK encoder stream reset"
    (is (= [true 0x104] (conn-error-after #(h3/reset-stream! % 6 0x100)))))
  (testing "unknown stream type: later bytes are never re-parsed as a stream type"
    (is (nil? (conn-error-after (fn [c]
                                  (h3/send! c 14 (h3/varint 0x3f) false)
                                  (h3/pump! c 100)
                                  (h3/send! c 14 (h3/concat-bytes (h3/varint 0x00) (h3/settings-frame)) false))))))
  (testing "grease stream type is ignored"
    (is (nil? (conn-error-after #(h3/send! % 14 (h3/concat-bytes (h3/varint 0x21) (h3/varint 0x00)) false))))))

(deftest reserved-frames-settings-and-qpack-decoder-instructions
  (testing "RFC 9114 §7.2.8: HTTP/2-only frame types are H3_FRAME_UNEXPECTED"
    (doseq [t [0x02 0x06 0x08 0x09]]
      (is (= [true 0x105]
             (conn-error-after #(h3/send! % 0 (h3/concat-bytes
                                               (h3/headers-frame (h3/request-headers "GET" "/"))
                                               (h3/frame t (byte-array 4)))
                                          false)))
          (str "request stream, type " t))
      (is (= [true 0x105] (conn-error-after #(h3/send! % 2 (h3/frame t (byte-array 4)) false)))
          (str "control stream, type " t))))
  (testing "RFC 9114 §7.2.4: duplicate setting identifier is H3_SETTINGS_ERROR"
    (is (= [true 0x109]
           (h3/with-server [srv (fn [_] (ok "ok"))]
             (h3/with-client [c (.port srv)]
               (h3/open-control! c (h3/settings-frame 0x06 100 0x06 200))
               (h3/await-peer-error c 1500))))))
  (testing "RFC 9204 §4.4: no dynamic table, so Section Acknowledgment and Insert Count Increment are QPACK_DECODER_STREAM_ERROR"
    (is (= [true 0x202] (conn-error-after #(h3/send! % 10 (byte-array [(unchecked-byte 0x80)]) false))))
    (is (= [true 0x202] (conn-error-after #(h3/send! % 10 (byte-array [0x01]) false)))))
  (testing "Stream Cancellation is fine"
    (is (nil? (conn-error-after #(h3/send! % 10 (byte-array [0x40]) false))))))

(deftest control-stream-push-and-settings-rules
  (testing "RFC 9114 §7.2.3: CANCEL_PUSH for a push never promised is H3_ID_ERROR"
    (is (= [true 0x108] (conn-error-after #(h3/send! % 2 (h3/frame 0x03 (h3/varint 0)) false)))))
  (testing "RFC 9114 §7.2.7: MAX_PUSH_ID may not decrease (H3_ID_ERROR)"
    (is (nil? (conn-error-after #(h3/send! % 2 (h3/concat-bytes (h3/frame 0x0d (h3/varint 5))
                                                                (h3/frame 0x0d (h3/varint 5))
                                                                (h3/frame 0x0d (h3/varint 9)))
                                           false))))
    (is (= [true 0x108] (conn-error-after #(h3/send! % 2 (h3/concat-bytes (h3/frame 0x0d (h3/varint 9))
                                                                          (h3/frame 0x0d (h3/varint 5)))
                                                     false)))))
  (testing "malformed MAX_PUSH_ID is H3_FRAME_ERROR"
    (is (= [true 0x106] (conn-error-after #(h3/send! % 2 (h3/frame 0x0d (byte-array [0x01 0x02])) false)))))
  (testing "RFC 9114 §6.2.1: any frame before SETTINGS, a reserved one included, is H3_MISSING_SETTINGS"
    (is (= [true 0x10a]
           (h3/with-server [srv (fn [_] (ok "ok"))]
             (h3/with-client [c (.port srv)]
               (h3/open-control! c (h3/concat-bytes (h3/frame 0x21 (byte-array 2)) (h3/settings-frame)))
               (h3/await-peer-error c 1500))))))
  (testing "RFC 9114 §6.2.1: STOP_SENDING on our control stream is H3_CLOSED_CRITICAL_STREAM"
    (is (= [true 0x104] (conn-error-after #(h3/stop-sending! % 3 0x100)))))
  (testing "... and on our QPACK decoder stream"
    (is (= [true 0x104] (conn-error-after #(h3/stop-sending! % 11 0x100))))))

(deftest response-header-section-over-the-peer-limit-is-not-sent
  ;; RFC 9114 §4.2.2: a header section larger than the peer's
  ;; SETTINGS_MAX_FIELD_SECTION_SIZE isn't sent: the response becomes a
  ;; 500, or the stream is reset when even that doesn't fit.
  (let [big (apply str (repeat 400 "a"))]
    (h3/with-server [srv (fn [^Request req]
                           (if (= "/big" (.-uri req)) (Response. 200 {"x-big" big} "ok") (ok "ok")))]
      (testing "limit fits a 500"
        (h3/with-client [c (.port srv)]
          (h3/open-control! c (h3/settings-frame 0x06 300))
          (h3/pump! c 100)
          (is (= 200 (:status (h3/request! c 0 (h3/request-headers "GET" "/")))) "a small section is sent")
          (is (= 500 (:status (h3/request! c 4 (h3/request-headers "GET" "/big")))))))
      (testing "limit too small even for a 500"
        (h3/with-client [c (.port srv)]
          (h3/open-control! c (h3/settings-frame 0x06 50))
          (h3/pump! c 100)
          (let [r (h3/request! c 0 (h3/request-headers "GET" "/big"))]
            (is (nil? (:status r)))
            (is (= 0x102 (:reset r)) "H3_INTERNAL_ERROR"))
          (is (nil? (h3/peer-error c))))))))

(deftest response-header-encoded-size-budget
  ;; 3000 'ü' = 6000 UTF-8 bytes whose Huffman codes are 19-23 bits each:
  ;; the frame budget must follow the encoded size, not the char count.
  (let [v (apply str (repeat 3000 "ü"))]
    (h3/with-server [srv (fn [_] (Response. 200 {"x-u" v} "ok"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
          (is (= 200 (:status r)))
          (is (= v (get (:headers r) "x-u")))
          (is (nil? (h3/peer-error c))))))))

(deftest stateless-retry-handshake
  ;; RFC 9000 §8.1.2: the client echoes the Retry token (bound to the
  ;; Retry SCID) and the handshake proceeds on that connection ID.
  (h3/with-server [srv (fn [_] (ok "after-retry"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StatelessRetry b true))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "after-retry" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

;; ---- listener: datagrams for unknown connection IDs ------------------------

(defn- long-header-packet
  "QUIC long-header packet of `size` bytes: `type-bits` (0 Initial,
  1 0-RTT, 2 Handshake), `version`, random DCID (16 bytes unless
  `dcid-len`), 8-byte SCID, `token` (Initial; default empty), junk payload."
  (^bytes [type-bits version size] (long-header-packet type-bits version size (byte-array 0)))
  (^bytes [type-bits version size ^bytes token] (long-header-packet type-bits version size token 16))
  (^bytes [type-bits version size ^bytes token dcid-len]
   (let [out (java.io.ByteArrayOutputStream.)
         dcid (byte-array (int dcid-len))
         rnd (java.util.Random.)]
     (.nextBytes rnd dcid)
     (.write out (int (bit-or 0xC0 (bit-shift-left type-bits 4))))
     (.write out (.array (.putInt (java.nio.ByteBuffer/allocate 4) (unchecked-int version))) 0 4)
     (.write out (int dcid-len))
     (.write out dcid 0 (int dcid-len))
     (.write out 8)
     (.write out (byte-array 8 (byte 1)) 0 8)
     (when (zero? type-bits)
       (let [^bytes tl (h3/varint (alength token))]
         (.write out tl 0 (alength tl))
         (.write out token 0 (alength token))))
     (let [head (.toByteArray out)
           pkt (byte-array size)]
       (System/arraycopy head 0 pkt 0 (alength head))
      ;; length varint (2 bytes) covering the rest, then junk
       (let [rest-len (- size (alength head) 2)]
         (aset pkt (alength head) (unchecked-byte (bit-or 0x40 (bit-shift-right rest-len 8))))
         (aset pkt (inc (alength head)) (unchecked-byte rest-len)))
       pkt))))

(defn- short-header-packet ^bytes [size]
  (let [pkt (byte-array size)]
    (.nextBytes (java.util.Random.) pkt)
    (aset pkt 0 (unchecked-byte 0x41))
    pkt))

(defn- reply-to
  "Sends `pkt` to the listener; returns the first reply datagram's bytes
  or nil if none arrives within 300ms."
  [^long port ^bytes pkt]
  (with-open [s (java.net.DatagramSocket. 0 (java.net.InetAddress/getByName "127.0.0.1"))]
    (.setSoTimeout s 300)
    (.send s (java.net.DatagramPacket. pkt (alength pkt)
                                       (java.net.InetSocketAddress. "127.0.0.1" (int port))))
    (let [buf (byte-array 2048)
          p (java.net.DatagramPacket. buf 2048)]
      (try (.receive s p)
           (java.util.Arrays/copyOf buf (.getLength p))
           (catch java.net.SocketTimeoutException _ nil)))))

(defn- connection-count ^long [^com.s_exp.enso.http3.Http3Listener srv]
  (.connectionCount srv))

(defn- await-connection-count
  "Polls until the listener holds `n` connections or `ms` pass; returns
  the last count seen."
  [srv n ms]
  (let [deadline (+ (System/currentTimeMillis) (long ms))]
    (loop []
      (let [c (connection-count srv)]
        (if (or (= c n) (> (System/currentTimeMillis) deadline))
          c
          (do (Thread/sleep 10) (recur)))))))

(deftest unknown-cid-datagrams
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (testing "RFC 9000 §6: no Version Negotiation for a short header"
      (is (nil? (reply-to (.port srv) (short-header-packet 1300)))))
    (testing "RFC 9000 §5.2.2: Version Negotiation only for datagrams >= 1200 bytes"
      (is (nil? (reply-to (.port srv) (long-header-packet 0 0x1a2a3a4a 100))))
      (let [vn (reply-to (.port srv) (long-header-packet 0 0x1a2a3a4a 1200))]
        (is (some? vn))
        (when vn (is (zero? (.getInt (java.nio.ByteBuffer/wrap vn 1 4))) "version 0 = VN"))))
    (testing "RFC 9000 §14.1: Initial in a datagram < 1200 bytes is discarded"
      (is (nil? (reply-to (.port srv) (long-header-packet 0 1 1199))))
      (is (zero? (connection-count srv))))
    (testing "only an Initial can create a connection"
      (is (nil? (reply-to (.port srv) (long-header-packet 2 1 1300))) "Handshake")
      (is (nil? (reply-to (.port srv) (long-header-packet 1 1 1300))) "0-RTT")
      (is (zero? (connection-count srv))))))

(defn- vn-ids
  "The [dcid scid] a Version Negotiation packet carries, and its versions."
  [^bytes vn]
  (let [b (java.nio.ByteBuffer/wrap vn)
        _ (.position b 5)
        dcid (byte-array (bit-and (.get b) 0xFF))
        _ (.get b dcid)
        scid (byte-array (bit-and (.get b) 0xFF))
        _ (.get b scid)
        versions (loop [vs []] (if (>= (.remaining b) 4) (recur (conj vs (.getInt b))) vs))]
    {:dcid (vec dcid) :scid (vec scid) :versions versions :trailing (.remaining b)}))

(deftest version-negotiation-for-any-unknown-version-long-header
  ;; RFC 8999 §6 / RFC 9000 §5.2.2, §17.2.1: an unknown version's long
  ;; header may carry connection ids of up to 255 bytes (a zero-length
  ;; one included) and its type bits mean nothing; a full-size datagram
  ;; gets Version Negotiation echoing both ids. quic-interop-runner's
  ;; readiness probe is such a packet (version "WAIT", empty DCID).
  (doseq [loops [1 2]]
    (h3/with-server [srv (fn [_] (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b (int loops)))]
      (doseq [[what type-bits dcid-len] [["empty destination id" 0 0]
                                         ["255-byte destination id" 0 255]
                                         ["21-byte destination id" 0 21]
                                         ["type bits 0x20 set (RFC 8999: meaningless)" 2 8]
                                         ["type bits 0x30 set" 3 0]]]
        (testing (str loops " loop(s), " what)
          (let [^bytes pkt (long-header-packet type-bits 0x57414954 1207 (byte-array 0) dcid-len)
                ^bytes vn (reply-to (.port srv) pkt)]
            (is (some? vn))
            (when vn
              (is (= 0x80 (bit-and (aget vn 0) 0x80)) "long header")
              (is (zero? (.getInt (java.nio.ByteBuffer/wrap vn 1 4))) "version 0 = VN")
              (let [{:keys [dcid scid versions trailing]} (vn-ids vn)]
                (is (= (vec (java.util.Arrays/copyOfRange pkt (int (+ 7 dcid-len)) (int (+ 15 dcid-len)))) dcid)
                    "destination id = the client's source id")
                (is (= (vec (java.util.Arrays/copyOfRange pkt 6 (int (+ 6 dcid-len)))) scid)
                    "source id = the client's destination id")
                (is (= [1] versions) "QUIC v1")
                (is (zero? trailing)))))))
      (testing "a Version Negotiation packet (version 0) is never answered"
        (is (nil? (reply-to (.port srv) (long-header-packet 0 0 1300 (byte-array 0) 8)))))
      (is (zero? (connection-count srv))))))

(deftest retry-only-for-full-size-initials
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StatelessRetry b true))]
    (testing "RFC 9000 §8.1: no Retry (amplification) for a short datagram"
      (is (nil? (reply-to (.port srv) (long-header-packet 0 1 40)))))
    (testing "Retry for a full-size Initial without token"
      (let [^bytes r (reply-to (.port srv) (long-header-packet 0 1 1200))]
        (is (some? r))
        (when r (is (= 0xF0 (bit-and (aget r 0) 0xF0)) "long header, type Retry"))))))

;; ---- admission: Retry above the half-open threshold, caps ---------------

(deftest initials-with-short-destination-ids-are-dropped
  ;; RFC 9000 §7.2: a client's first Destination Connection ID is at least
  ;; 8 bytes; a shorter one gets nothing, not even a Retry.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StatelessRetry b true))]
    (is (nil? (reply-to (.port srv) (long-header-packet 0 1 1200 (byte-array 0) 7))) "7 bytes: dropped")
    (let [^bytes r (reply-to (.port srv) (long-header-packet 0 1 1200 (byte-array 0) 8))]
      (is (some? r) "8 bytes: answered")
      (when r (is (= 0xF0 (bit-and (aget r 0) 0xF0)) "with a Retry")))))

(defn- retry? [^bytes r]
  (and r (= 0xF0 (bit-and (aget r 0) 0xF0))))

(deftest retry-required-above-half-open-threshold
  ;; A spoofed Initial costs a quiche connection and a handshake; past
  ;; :http3-retry-threshold handshaking connections, Initials without a
  ;; valid token only get a stateless Retry (RFC 9000 §8.1.2).
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3RetryThreshold b 1))]
    (is (not (retry? (reply-to (.port srv) (long-header-packet 0 1 1200)))) "below the threshold: no Retry")
    (let [half-open (h3/start-handshake (.port srv))]
      (try
        (is (= 1 (await-connection-count srv 1 1000)) "a client that never completes its handshake")
        (is (retry? (reply-to (.port srv) (long-header-packet 0 1 1200))) "at the threshold: Retry")
        (is (= 1 (connection-count srv)) "no state for it")
        (testing "a real client still gets in (with one Retry round trip)"
          (h3/with-client [c (.port srv)]
            (h3/open-control! c)
            (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))))
        (finally (h3/close! half-open))))))

(deftest half-open-connections-are-capped
  (let [refused (atom 0)
        two-refused (promise)
        events (reify com.s_exp.enso.api.ServerEvents
                 (connectionOpened [_ _ _])
                 (connectionClosed [_ _ _ _])
                 (requestCompleted [_ _ _ _ _ _ _])
                 (protocolError [_ _ kind]
                   (when (and (= "handshake-limit" kind) (= 2 (swap! refused inc)))
                     (deliver two-refused true))))]
    (h3/with-server [srv (fn [_] (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3MaxHalfOpen b 2)
                       (.serverEvents b events))]
      (let [clients (vec (repeatedly 4 #(h3/start-handshake (.port srv))))]
        (try
          ;; Each of the last two clients' Initial was refused at least once.
          (is (deref two-refused 3000 false))
          (is (= 2 (connection-count srv)) "Initials past :http3-max-half-open are dropped")
          (is (= 2 (.halfOpenCount srv)))
          (finally (run! h3/close! clients)))))))

(deftest quic-connections-count-against-max-connections
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.maxConnections b 1))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
      (is (thrown? clojure.lang.ExceptionInfo (h3/connect (.port srv))) "second connection refused")
      (is (= 1 (connection-count srv))))
    (is (zero? (await-connection-count srv 0 3000)) "slot released at close")
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

(deftest quic-connections-count-against-max-connections-per-ip
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.maxConnectionsPerIp b 1))]
    (h3/with-client [c (.port srv)]
      (is (thrown? clojure.lang.ExceptionInfo (h3/connect (.port srv))) "same address refused")
      (is (= 1 (connection-count srv))))))

(deftest per-ip-limit-validates-addresses-first
  ;; A per-address slot taken for an Initial's source address would let a
  ;; spoofer lock that address out: with :max-connections-per-ip set, a
  ;; client proves its address (Retry) before it is counted.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.maxConnectionsPerIp b 1))]
    (is (retry? (reply-to (.port srv) (long-header-packet 0 1 1200))) "tokenless Initial: Retry")
    (is (zero? (connection-count srv)) "no state, no slot for an unvalidated address")
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

(defn- minted-looking-token
  "A token with our Retry token's shape (length, magic) but a forged tag."
  ^bytes []
  (let [t (byte-array (+ 32 4 8 4 2 1 16 1 16))]
    (System/arraycopy (.getBytes "en30" "US-ASCII") 0 t 32 4)
    t))

(deftest invalid-retry-token-closes-with-invalid-token
  ;; RFC 9000 §8.1.2: an Initial whose Retry token doesn't validate gets
  ;; CONNECTION_CLOSE(INVALID_TOKEN) in a small server Initial; no state.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StatelessRetry b true))]
    (let [^bytes r (reply-to (.port srv) (long-header-packet 0 1 1200 (minted-looking-token)))]
      (is (some? r))
      (when r
        (is (= 0xC0 (bit-and (aget r 0) 0xF0)) "long header, type Initial")
        (is (< (alength r) 100) "far below the triggering datagram")))
    (is (zero? (connection-count srv)))
    (testing "a token of unknown shape counts as absent: Retry"
      (is (retry? (reply-to (.port srv) (long-header-packet 0 1 1200 (byte-array 40 (byte 7)))))))))

(deftest unestablished-connection-is-reaped
  ;; A client that sends its first Initial and vanishes: with the idle
  ;; timeout disabled quiche never gives up on the handshake, so the
  ;; server must drop the connection at its :handshake-timeout.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b]
                     (.idleTimeoutMillis b 0)
                     (.handshakeTimeoutMillis b 1500))]
    (let [c (h3/start-handshake (.port srv))
          t0 (System/nanoTime)]
      (try
        (is (= 1 (await-connection-count srv 1 1000)) "half-open connection created")
        (is (zero? (await-connection-count srv 0 4000)) "reaped")
        (is (>= (- (System/nanoTime) t0) 1400000000) "not before the handshake timeout")
        (finally (h3/close! c))))))

(deftest websocket-upgrade-response-is-501
  ;; HTTP/3 has no 101 / Upgrade (RFC 9114 §4.5): a handler answering with
  ;; a WebSocket listener gets the server's own 501, none of its headers.
  (h3/with-server [srv (fn [_]
                         (Response. 101 {"upgrade" "websocket" "x-a" "1"} "ignored"
                                    (reify com.s_exp.enso.api.WebSocketListener
                                      (onOpen [_ _])
                                      (onMessage [_ _ _])
                                      (onClose [_ _ _ _]))
                                    nil))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/ws"))]
        (is (= 501 (:status r)))
        (is (= {"content-type" "text/plain; charset=utf-8" "content-length" "15"} (dissoc (:headers r) "date"))
            "none of the handler's headers")
        (is (= "Not Implemented" (h3/body-str r)))
        (is (:fin r))))))

(defn- private-field [obj ^String name]
  (.get (doto (.getDeclaredField (class obj) name) (.setAccessible true)) obj))

(deftest listener-close-stops-loops-before-freeing-config
  ;; The event loops call quiche_accept with the shared config: every loop
  ;; must have exited before the config is freed, and a freed config must
  ;; never hand out its dangling pointer.
  (let [srv (h3/start-server (fn [_] (ok "ok")) (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 2)))
        loops (vec (private-field srv "loops"))
        threads (mapv #(private-field % "thread") loops)
        ^com.s_exp.enso.quiche.QuicheConfig cfg (private-field srv "currentConfig")]
    (is (= 2 (count threads)))
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))
    (.close srv)
    (is (not-any? #(.isAlive ^Thread %) threads) "loops joined by close")
    (is (thrown? IllegalStateException (.setInitialMaxData cfg 1)) "closed config refuses use")))

(deftest nat-rebinding
  ;; RFC 9000 §9: after the peer's address changes (NAT rebinding), the
  ;; server must send to the new address (quiche's send_info.to).
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
      (h3/rebind! c)
      (is (= "ok" (h3/body-str (h3/request! c 4 (h3/request-headers "GET" "/"))))))))

(deftest large-byte-array-body
  (let [data (byte-array (* 4 1024 1024))]
    (.nextBytes (java.util.Random. 7) data)
    (h3/with-server [srv (fn [_] (ok data))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
          (is (:fin r))
          (is (java.util.Arrays/equals data ^bytes (:body r))))))))

(deftest handler-timeout-503
  (h3/with-server [srv (fn [_] (Thread/sleep 3000) (ok "too late"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.handlerTimeoutMillis b 200))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 503 (:status r)))
        (is (= "Service Unavailable" (h3/body-str r)) "the shared error body")))))

(deftest client-initial-larger-than-advertised-payload-size
  ;; RFC 9000 §14.1: the client sizes its Initial datagrams before it has
  ;; seen our transport parameters, so they may exceed our
  ;; max_udp_payload_size (Chrome pads to 1250+). Truncating them on
  ;; receive would fail the handshake.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxUdpPayloadBytes b 1200))]
    (h3/with-client [c (.port srv) {:initial-size 1350}]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

(deftest request-body-chunks-larger-than-field-section-limit
  ;; SETTINGS_MAX_FIELD_SECTION_SIZE bounds HEADERS only (RFC 9114
  ;; §4.2.2): body bytes arriving in 16 KiB reads must not count against it.
  (let [body (byte-array (* 64 1024) (byte 9))]
    (h3/with-server [srv echo-handler
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxHeaderBytes b 8192))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "POST" "/") body)]
          (is (= 200 (:status r)))
          (is (java.util.Arrays/equals body ^bytes (:body r))))
        (is (nil? (h3/peer-error c)) "connection still open")))))

(deftest large-field-section-limit-accepts-large-headers
  ;; A :max-header-bytes above the 64 KiB default admits larger sections.
  (let [v (apply str (repeat 150000 "a"))]
    (h3/with-server [srv (fn [^Request req] (ok (str (count (get (.-headers req) "x-big")))))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxHeaderBytes b 200000))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/" ["x-big" v]))]
          (is (= 200 (:status r)))
          (is (= "150000" (h3/body-str r))))))))

(defn- body-outcome-handler
  "Handler delivering to `outcome` what reading the request body gave:
  the body string, or :truncated when the read threw."
  [outcome]
  (fn [^Request req]
    (deliver outcome
             (try (String. (.readAllBytes ^java.io.InputStream (.-body req)))
                  (catch java.io.IOException _ :truncated)))
    (ok "x")))

(deftest stream-error-after-body-started-truncates-body
  ;; A stream error raised by the session once the body is flowing (here
  ;; malformed trailers, RFC 9114 §4.1.2) must end the handler's body read
  ;; with an error instead of leaving it blocked until the request timeout.
  (let [outcome (promise)]
    (h3/with-server [srv (body-outcome-handler outcome)]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (.getBytes "partial")))
                  false)
        (h3/pump! c 200)
        (h3/send! c 0 (h3/headers-frame [[":path" "/x"]]) false)
        ;; The handler may see the truncation before the reset reaches us.
        (h3/pump-until! c #(and (realized? outcome) (:reset (h3/stream-state c 0))) 2000)
        (is (= 0x10e (:reset (h3/response c 0))) "H3_MESSAGE_ERROR reset")
        (is (= :truncated (deref outcome 0 :handler-still-blocked)))))))

(defn- await-ignoring-interrupts
  "Blocks until `p` is delivered, swallowing interrupts like a handler
  that never checks them."
  [p]
  (loop []
    (when-not (try @p true (catch InterruptedException _ false))
      (recur))))

(deftest body-over-cap-is-413-whatever-the-handler-does
  ;; A body growing past :max-request-body-bytes fails the handler's read
  ;; with a 413, answered as such even when the handler swallows it, as on
  ;; HTTP/1.1 and HTTP/2.
  (let [seen (promise)]
    (h3/with-server [srv (fn [^Request req]
                           (deliver seen (try (.readAllBytes ^java.io.InputStream (.-body req)) :read
                                              (catch java.io.IOException e (class e))))
                           (ok "swallowed"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxRequestBodyBytes b 10))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (byte-array 100)))
                  false)
        (h3/pump-until! c #(h3/stream-done? c 0) 3000)
        (is (= com.s_exp.enso.core.RequestBodyException (deref seen 2000 :none)))
        (is (= 413 (:status (h3/response c 0))))
        (is (= "Content Too Large" (h3/body-str (h3/response c 0))))
        (is (nil? (h3/peer-error c)) "connection kept")))))

(defn- reset-once-started!
  "Sends a request on `sid` the server will reset (body longer than its
  content-length), the offending body only once `started?` is true or the
  stream is done: a request reset before its handler starts never runs
  the handler at all."
  [c sid started?]
  (h3/send! c sid (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "1"])) false)
  (h3/pump-until! c #(or (started?) (h3/stream-done? c sid)) 2000)
  (when-not (h3/stream-done? c sid)
    (h3/send! c sid (h3/data-frame (.getBytes "abc")) true))
  (h3/pump-until! c #(h3/stream-done? c sid) 2000))

(deftest abandoned-request-interrupts-handler
  ;; A request the server resets is abandoned: its handler is interrupted
  ;; rather than left running until the request timeout.
  (let [exited (promise)
        started (promise)]
    (h3/with-server [srv (fn [_]
                           (deliver started true)
                           (try @(promise)
                                (catch InterruptedException _ (deliver exited :interrupted)))
                           (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (reset-once-started! c 0 #(realized? started))
        (is (= 0x10e (:reset (h3/response c 0))))
        (is (= :interrupted (deref exited 2000 :still-running)))))))

(deftest abandoned-handlers-are-bounded
  ;; Resetting requests frees their QUIC streams but not handlers that
  ;; ignore interrupts: once twice the stream limit of handlers is live,
  ;; new requests are refused with H3_REQUEST_REJECTED (RFC 9114 §8.1).
  (let [gate (promise)
        live (atom 0)
        peak (atom 0)]
    (h3/with-server [srv (fn [_]
                           (swap! peak max (swap! live inc))
                           (try (await-ignoring-interrupts gate)
                                (finally (swap! live dec)))
                           (ok "x"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.http3InitialMaxStreamsBidi b 3))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [codes (vec (for [i (range 20)
                               :let [sid (* 4 i)
                                     before @peak]]
                           (do (reset-once-started! c sid #(> @peak before))
                               (:reset (h3/response c sid)))))]
          (is (<= @peak 6) (str "live handlers peaked at " @peak))
          (is (some #{0x10b} codes) (str "reset codes " codes)))
        (deliver gate true)
        (h3/pump-until! c #(zero? @live) 2000)
        (is (= "x" (h3/body-str (h3/request! c 80 (h3/request-headers "GET" "/")))))))))

(deftest peer-reset-of-request-keeps-response
  ;; RESET_STREAM only ends the client's sending side (RFC 9000 §3.2): the
  ;; handler sees a truncated body, but its response still reaches the
  ;; client, completing the stream.
  (h3/with-server [srv (fn [^Request req]
                         (try (.readAllBytes ^java.io.InputStream (.-body req))
                              (ok "complete")
                              (catch java.io.IOException _
                                (Response. 400 {} "incomplete"))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                     (h3/data-frame (.getBytes "partial")))
                false)
      (h3/pump! c 200)
      (h3/reset-stream! c 0 0x10c)
      (h3/pump-until! c #(h3/stream-done? c 0) 3000)
      (let [r (h3/response c 0)]
        (is (= 400 (:status r)))
        (is (= "incomplete" (h3/body-str r)))
        (is (:fin r))))))

(deftest peer-reset-mid-response-keeps-queued-bytes
  ;; Response bytes queued behind congestion control when the peer resets
  ;; its request stream are still sent in order: a streamed response whose
  ;; 200 KB header section is only partly out must not continue with DATA
  ;; after dropping the rest of its HEADERS frame.
  (let [v (apply str (repeat 200000 "v"))]
    (h3/with-server [srv (fn [_]
                           (Response. 200 {"x-big" v}
                                      (reify com.s_exp.enso.api.StreamingBody
                                        (write [_ w] (.write w "body")))))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (.getBytes "partial")))
                  false)
        (h3/pump-until! c #(some? (h3/stream-state c 0)) 2000)
        (h3/reset-stream! c 0 0x10c)
        (h3/pump-until! c #(h3/stream-done? c 0) 5000)
        (let [r (try (h3/response c 0) (catch Exception e {:error e}))]
          (is (nil? (:error r)))
          (is (:fin r))
          (is (true? (= v (get (:headers r) "x-big"))) "header section intact")
          (is (= "body" (h3/body-str r))))))))

(deftest peer-cancel-abandons-request
  ;; RESET_STREAM plus STOP_SENDING cancels the request (RFC 9114 §4.1.1):
  ;; nobody will read the response, so the handler is interrupted.
  (let [exited (promise)]
    (h3/with-server [srv (fn [_]
                           (try @(promise)
                                (catch InterruptedException _ (deliver exited :interrupted)))
                           (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "POST" "/")) false)
        (h3/pump! c 200)
        (h3/stop-sending! c 0 0x10c)
        (h3/reset-stream! c 0 0x10c)
        (h3/pump-until! c #(realized? exited) 2000)
        (is (= :interrupted (deref exited 0 :still-running)))))))

(deftest handler-outliving-connection-does-not-hang
  ;; A handler that ignores the teardown interrupt and returns afterwards
  ;; must not block forever handing a streamed body to a dead connection
  ;; (leaking its thread and body source): its response is dropped. Until
  ;; it returns the closed connection still counts (its limiter slot), so
  ;; closing connections can't leave unbounded handlers running.
  (let [gate (promise)
        returned (promise)
        started (promise)
        finished (promise)]
    (h3/with-server [srv (fn [_]
                           (await-ignoring-interrupts gate)
                           (deliver returned true)
                           (ok (reify com.s_exp.enso.api.StreamingBody
                                 (write [_ w]
                                   (deliver started true)
                                   (try (.write w "x") (.flush w)
                                        (finally (deliver finished true)))))))]
      (let [c (h3/connect (.port srv))]
        (h3/open-control! c)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (h3/pump! c 200)
        (h3/close! c))
      (Thread/sleep 500)
      (is (= 1 (.connectionCount srv)) "counted while its handler runs")
      (deliver gate true)
      (is (deref returned 2000 false))
      (is (zero? (await-connection-count srv 0 3000)) "released once the handler returned")
      ;; If the body started, its write must fail promptly (not block).
      (when (deref started 300 false)
        (is (deref finished 2000 false) "streamed body blocked on a closed connection")))))

(deftest unread-request-body-is-bounded-by-stream-window
  ;; While the handler doesn't read, QUIC flow control is what bounds the
  ;; body bytes buffered for it: the default per-stream window is 1 MiB.
  (let [gate (promise)]
    (h3/with-server [srv (fn [_] @gate (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (byte-array (* 8 1024 1024))))
                  true)
        (h3/pump! c 1000)
        (let [[_ accepted] (get @(:pending c) 0)]
          (is (some? accepted) "body not fully accepted")
          (is (< (long (or accepted Long/MAX_VALUE)) (* 2 1024 1024))
              (str "server accepted " accepted " bytes")))
        (deliver gate true)))))

(deftest idle-streamed-body-notices-client-cancel
  ;; An event stream waiting for its next event must learn that the client
  ;; stopped reading (STOP_SENDING) without having to write first.
  (let [outcome (promise)]
    (h3/with-server [srv (fn [_]
                           (ok (reify com.s_exp.enso.api.StreamingBody
                                 (write [_ w]
                                   (.write w "event-1")
                                   (.flush w)
                                   (try @(promise)
                                        (catch InterruptedException _ (deliver outcome :cancelled)))))))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/events")) true)
        (h3/pump-until! c #(= "event-1" (h3/body-str (h3/response c 0))) 2000)
        (h3/stop-sending! c 0 0x10c)
        (h3/pump-until! c #(realized? outcome) 2000)
        (is (= :cancelled (deref outcome 0 :still-waiting)))))))

;; ---- Shared response and request-head policy -------------------------------

(deftest responses-carry-date
  (h3/with-server [srv (fn [^Request req]
                         (if (= "/own" (.-uri req))
                           (Response. 200 {"Date" "Tue, 15 Nov 1994 08:12:31 GMT"} "x")
                           (ok "x")))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (re-matches #"\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT"
                      (str (get (:headers (h3/request! c 0 (h3/request-headers "GET" "/"))) "date"))))
      (is (= [["date" "Tue, 15 Nov 1994 08:12:31 GMT"]]
             (filterv #(= "date" (first %)) (:fields (h3/request! c 4 (h3/request-headers "GET" "/own")))))
          "a handler Date wins"))))

(deftest invalid-response-status-is-500
  ;; 200-599 only: 1xx can't be a final response, and HTTP/3 has no 101.
  (h3/with-server [srv (fn [^Request req] (Response. (int (parse-long (subs (.-uri req) 1))) {} "x"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (doseq [[sid status] [[0 99] [4 101] [8 103] [12 600] [16 1000]]]
        (is (= 500 (:status (h3/request! c sid (h3/request-headers "GET" (str "/" status))))) (str status)))
      (is (= 599 (:status (h3/request! c 20 (h3/request-headers "GET" "/599"))))))))

(deftest request-head-rules
  ;; The shared request-head rules (RFC 9114 §4.2-4.3, RFC 9110 §5.5).
  (let [called (atom [])]
    (h3/with-server [srv (fn [^Request req] (swap! called conj (.-uri req)) (ok "ok"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (testing "unsupported :scheme"
          (is (message-error? c 0 (h3/headers-frame [[":method" "GET"] [":scheme" "ftp"]
                                                     [":authority" "localhost"] [":path" "/0"]]))))
        (testing "userinfo in :authority"
          (is (message-error? c 4 (h3/headers-frame [[":method" "GET"] [":scheme" "https"]
                                                     [":authority" "u@localhost"] [":path" "/4"]]))))
        (testing "control char in value"
          (is (message-error? c 8 (h3/headers-frame (h3/request-headers "GET" "/8" ["x-a" "a\u0001b"])))))
        (testing "TE other than trailers"
          (is (message-error? c 12 (h3/headers-frame (h3/request-headers "GET" "/12" ["te" "gzip"])))))
        (testing "CONNECT is well-formed but not served"
          (is (= 501 (:status (h3/request! c 16 [[":method" "CONNECT"] [":authority" "example.org:443"]])))))
        (testing "a repeated content-length is malformed even when the values agree, as on HTTP/1.1"
          (is (message-error? c 20 (h3/headers-frame (h3/request-headers "POST" "/20" ["content-length" "3"]
                                                                         ["content-length" "3"])))))
        (testing "host matches :authority ignoring case"
          (let [seen (promise)]
            (h3/with-server [srv2 (fn [^Request req] (deliver seen (.-headers req)) (ok "ok"))]
              (h3/with-client [c2 (.port srv2)]
                (h3/open-control! c2)
                (is (= 200 (:status (h3/request! c2 0 (h3/request-headers "POST" "/" ["host" "LOCALHOST"]
                                                                          ["content-length" "3"])
                                                 (.getBytes "abc")))))
                (is (= "3" (get (deref seen 1000 nil) "content-length")))))))
        (is (empty? @called) "no invalid request reached the handler")))))

;; ---- timeouts and peer-controlled resources --------------------------------

(defn- partial-headers
  "A HEADERS frame header announcing `announced` payload bytes followed by
  only `sent` of them."
  ^bytes [announced sent]
  (h3/concat-bytes (h3/varint 0x01) (h3/varint announced) (byte-array sent (byte 0x41))))

(deftest header-timeout-refuses-slow-header-sections
  ;; :header-timeout: a request whose header section isn't complete in time
  ;; is refused (H3_REQUEST_REJECTED); the connection lives on.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.headerTimeoutMillis b 300))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [t0 (System/nanoTime)]
        (h3/send! c 0 (partial-headers 200 20) false)
        (is (h3/pump-until! c #(h3/stream-done? c 0) 3000))
        (is (= 0x10b (:reset (h3/response c 0))))
        (is (>= (- (System/nanoTime) t0) 250000000) "not before the timeout"))
      (is (nil? (h3/peer-error c)))
      (is (= "ok" (h3/body-str (h3/request! c 4 (h3/request-headers "GET" "/"))))))))

(deftest partial-header-sections-share-a-connection-budget
  ;; Header bytes buffered for incomplete sections are bounded per
  ;; connection (the hard field-section ceiling: 4x :max-header-bytes, at
  ;; least 64 KiB): past it, streams are refused instead of growing the
  ;; buffer.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.maxHeaderBytes b 1000))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      ;; 30000 bytes each arrive over many packets, interleaved: which
      ;; stream crosses the budget first depends on delivery order, but two
      ;; fit (60000 < 65536) and the three don't.
      (doseq [sid [0 4 8]] (h3/send! c sid (partial-headers 60000 30000) false))
      (h3/pump-until! c #(some (fn [sid] (h3/stream-done? c sid)) [0 4 8]) 2000)
      (h3/pump! c 200)
      (is (= [0x10b] (keep #(:reset (h3/response c %)) [0 4 8])) "exactly one refused: over budget")
      (is (nil? (h3/peer-error c))))))

(deftest read-timeout-ends-stalled-body-reads
  ;; :read-timeout: a handler waiting for body bytes that don't come gets
  ;; a SocketTimeoutException.
  (let [outcome (promise)]
    (h3/with-server [srv (fn [^Request req]
                           (deliver outcome
                                    (try (.readAllBytes ^java.io.InputStream (.-body req)) :read
                                         (catch java.net.SocketTimeoutException _ :timed-out)
                                         (catch java.io.IOException e e)))
                           (Response. 408 {} "slow"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.readTimeoutMillis b 300))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (.getBytes "partial")))
                  false)
        (h3/pump-until! c #(h3/stream-done? c 0) 3000)
        (is (= :timed-out (deref outcome 0 :still-blocked)))
        (is (= 408 (:status (h3/response c 0))))))))

(deftest min-data-rate-bounds-trickled-bodies
  ;; :min-data-rate-bytes: a body trickled below the rate (one byte every
  ;; 100 ms, each resetting :read-timeout) fails once the grace period is
  ;; over; the request is answered 408.
  (h3/with-server [srv (fn [^Request req]
                         (.readAllBytes ^java.io.InputStream (.-body req))
                         (ok "read"))
                   (fn [^com.s_exp.enso.api.Config$Builder b]
                     (.readTimeoutMillis b 30000)
                     (.minDataRateBytes b 100)
                     (.minDataRateGraceMillis b 300))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/headers-frame (h3/request-headers "POST" "/")) false)
      (let [t0 (System/nanoTime)]
        (loop [i 0]
          (when (and (< i 40) (not (h3/stream-done? c 0)))
            (h3/send! c 0 (h3/data-frame (byte-array 1)) false)
            (h3/pump! c 100)
            (recur (inc i))))
        (is (= 408 (:status (h3/response c 0))))
        (is (< (/ (- (System/nanoTime) t0) 1e6) 2500.0) "well before :read-timeout")))))

(deftest write-timeout-resets-stalled-streamed-responses
  ;; :write-timeout: a client that stops reading a streamed response (its
  ;; flow-control window stays full) gets the stream reset; the producer's
  ;; blocked write fails instead of pinning the response forever.
  (let [failed (promise)
        chunk (byte-array 16384 (byte 1))]
    (h3/with-server [srv (fn [_]
                           (ok (reify com.s_exp.enso.api.StreamingBody
                                 (write [_ w]
                                   (try (dotimes [_ 1000] (.write w chunk) (.flush w))
                                        (catch java.io.IOException e (deliver failed :io) (throw e)))))))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.writeTimeoutMillis b 400))]
      (h3/with-client [c (.port srv) {:configure #(.setInitialMaxStreamDataBidiLocal ^com.s_exp.enso.quiche.QuicheConfig % 65536)}]
        (h3/open-control! c)
        (h3/pause-stream! c 0)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (is (= :io (deref failed 5000 :still-blocked)) "producer released")
        (h3/resume-stream! c 0)
        (h3/pump-until! c #(h3/stream-done? c 0) 3000)
        (is (= 0x10c (:reset (h3/response c 0))) "H3_REQUEST_CANCELLED")
        (is (nil? (h3/peer-error c)))))))

(deftest write-timeout-resets-responses-starved-by-dribbled-credit
  ;; A client that hands out credit a little at a time (2 KiB every
  ;; 200 ms here) makes progress on every grant: progress only counts once
  ;; 16 KiB went out, so the stream is still reset within :write-timeout.
  (let [chunk (byte-array 16384 (byte 1))]
    (h3/with-server [srv (fn [_]
                           (ok (reify com.s_exp.enso.api.StreamingBody
                                 (write [_ w]
                                   (dotimes [_ 1000] (.write w chunk) (.flush w))))))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.writeTimeoutMillis b 1000))]
      (h3/with-client [c (.port srv) {:configure #(.setInitialMaxStreamDataBidiLocal ^com.s_exp.enso.quiche.QuicheConfig % 2048)}]
        (h3/open-control! c)
        (h3/pause-stream! c 0)
        (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (loop [i 0]
          (when (and (< i 30) (not (:reset (h3/stream-state c 0))))
            (h3/resume-stream! c 0)
            (h3/pause-stream! c 0)
            (h3/pump! c 200)
            (recur (inc i))))
        (is (= 0x10c (:reset (h3/response c 0))) "H3_REQUEST_CANCELLED")))))

(deftest idle-connection-closes-despite-pings
  ;; :idle-timeout with no request in flight closes the connection (GOAWAY,
  ;; then H3_NO_ERROR) even while the client keeps the path alive.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.idleTimeoutMillis b 600))]
    (h3/with-client [c (.port srv) {:idle-timeout 0}]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
      (let [deadline (+ (System/currentTimeMillis) 4000)]
        (while (and (nil? (h3/peer-error c)) (< (System/currentTimeMillis) deadline))
          (h3/ping! c)
          (h3/pump! c 100)))
      (is (= [true 0x100] (h3/peer-error c)) "closed with H3_NO_ERROR")
      (let [ctrl ^bytes (some-> (h3/stream-state c 3) ^java.io.ByteArrayOutputStream (:out) .toByteArray)]
        (is (some? ctrl))
        (is (some #(= 0x07 %) (map #(bit-and % 0xff) ctrl)) "GOAWAY sent on the control stream")))))

(deftest rapid-reset-closes-the-connection
  ;; CVE-2023-44487 style: past :http3-stream-reset-limit peer resets per
  ;; 30 s, the connection closes with H3_EXCESSIVE_LOAD.
  (h3/with-server [srv (fn [_] @(promise))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StreamResetLimit b 5))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (doseq [i (range 20)
              :let [sid (* 4 i)]
              :while (nil? (h3/peer-error c))]
        (h3/send! c sid (h3/headers-frame (h3/request-headers "GET" "/")) false)
        (h3/pump! c 10)
        (h3/reset-stream! c sid 0x10c)
        (h3/pump! c 10))
      (is (= [true 0x107] (h3/await-peer-error c 2000))))))

(deftest resets-answering-our-stop-sending-are-not-rapid-resets
  ;; A request answered early (413) gets STOP_SENDING, and a client
  ;; answers that with RESET_STREAM (RFC 9000 §3.5) after the exchange is
  ;; over: quiche reports the stream readable again, which must neither
  ;; start a new exchange nor count against the reset budget.
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3StreamResetLimit b 2)
                       (.maxRequestBodyBytes b 1000))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (doseq [i (range 6)
                :let [sid (* 4 i)]]
          (h3/send! c sid (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "5000"])) false)
          (h3/pump-until! c #(h3/stream-done? c sid) 2000)
          (is (= 413 (:status (h3/response c sid))) (str "stream " sid))
          (h3/pump! c 50))
        (is (nil? (h3/peer-error c)) "connection still open")
        (is (= "ok" (h3/body-str (h3/request! c 24 (h3/request-headers "GET" "/")))))
        (is (= 1 @called))))))

(deftest stream-ending-without-request-is-reset
  ;; RFC 9114 §4.1.2: a request stream that ends (or is reset) before its
  ;; header section is complete gets its server side reset with
  ;; H3_REQUEST_INCOMPLETE, so the stream and the client's credit are freed.
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (testing "FIN with no HEADERS"
        (h3/send! c 0 (byte-array 0) true)
        (h3/pump-until! c #(h3/stream-done? c 0) 2000)
        (is (= 0x10d (:reset (h3/response c 0)))))
      (testing "RESET_STREAM mid-header"
        (h3/send! c 4 (partial-headers 100 10) false)
        (h3/pump! c 50)
        (h3/reset-stream! c 4 0x10c)
        (h3/pump-until! c #(h3/stream-done? c 4) 2000)
        (is (= 0x10d (:reset (h3/response c 4)))))
      (is (nil? (h3/peer-error c)))
      (is (= "ok" (h3/body-str (h3/request! c 8 (h3/request-headers "GET" "/"))))))))

(deftest request-target-and-field-validation
  ;; RFC 9114 §4.2-4.3 / RFC 9110 §5.5 / RFC 3986: what the shared request
  ;; head rules and the h3 driver reject.
  (let [called (atom [])
        cases [["space in :path" (h3/request-headers "GET" "/a b")]
               ["non-ASCII :path" (h3/request-headers "GET" "/\u00e9")]
               ["control character in :path" (h3/request-headers "GET" "/a\u0001")]
               [":method not a token" (h3/request-headers "GE T" "/")]
               ["leading whitespace in a value" (h3/request-headers "GET" "/" ["x-a" " v"])]
               ["trailing whitespace in a value" (h3/request-headers "GET" "/" ["x-a" "v\t"])]
               ["empty :authority without host" [[":method" "GET"] [":scheme" "https"]
                                                 [":authority" ""] [":path" "/"]]]
               ["unsupported :scheme with a bad :path" [[":method" "GET"] [":scheme" "ws"]
                                                        [":authority" "localhost"] [":path" "x"]]]]]
    (h3/with-server [srv (fn [^Request req] (swap! called conj (.-uri req)) (ok "ok"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (doseq [[i [what pairs]] (map-indexed vector cases)]
          (testing what
            (is (message-error? c (* 4 i) (h3/headers-frame pairs)))))
        (is (empty? @called))
        (is (= "ok" (h3/body-str (h3/request! c (* 4 (count cases)) (h3/request-headers "GET" "/ok")))))))))

;; ---- graceful shutdown (RFC 9114 §5.2) -----------------------------------------

(defn- goaway-ids
  "Stream ids of the GOAWAY frames the server sent on its control stream."
  [c]
  (let [^bytes ctrl (or (some-> (h3/stream-state c 3) ^java.io.ByteArrayOutputStream (:out) .toByteArray)
                        (byte-array 0))
        r (com.s_exp.enso.http3.Http3FrameReader.)]
    (when (pos? (alength ctrl))
      (.feed r ctrl 1 (dec (alength ctrl))))
    (loop [ids []]
      (if-let [^com.s_exp.enso.http3.Http3FrameReader$Frame f (.poll r)]
        (recur (if (= 0x07 (.-type f))
                 (conj ids (com.s_exp.enso.http3.Http3Varint/decode (java.nio.ByteBuffer/wrap (.-payload f))))
                 ids))
        ids))))

(deftest close-drains-in-flight-requests
  ;; Closing the listener sends GOAWAY, refuses newer requests
  ;; (H3_REQUEST_REJECTED), lets the in-flight one complete, then closes
  ;; the connection with H3_NO_ERROR.
  (let [gate (promise)
        entered (promise)
        srv (h3/start-server (fn [^Request req]
                               (when (= "/slow" (.-uri req)) (deliver entered true) @gate)
                               (ok (.-uri req))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/slow")) true)
      (h3/pump-until! c #(realized? entered) 2000)
      (let [closing (future (.close srv))]
        (is (h3/pump-until! c #(= 2 (count (goaway-ids c))) 2000) "two GOAWAYs")
        (is (= [(- (bit-shift-left 1 62) 4) 4] (goaway-ids c))
            "first the largest id (requests in flight still processed), then: from stream 4 on, not processed")
        (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/late")) true)
        (h3/pump-until! c #(h3/stream-done? c 4) 2000)
        (is (= 0x10b (:reset (h3/response c 4))) "refused after GOAWAY")
        (is (not (realized? closing)) "waits for the in-flight request")
        (deliver gate true)
        (h3/pump-until! c #(h3/stream-done? c 0) 2000)
        (is (= "/slow" (h3/body-str (h3/response c 0))) (str "in-flight response completed " (dissoc (h3/response c 0) :body)))
        (is (= [true 0x100] (h3/await-peer-error c 3000)) "then H3_NO_ERROR")
        (is (not= ::timeout (deref closing 5000 ::timeout)) "close returned")))))

(deftest drain-serves-requests-below-the-goaway-id-that-arrive-late
  ;; Stream 4 arrived, stream 0 not yet (reordered, or lost and resent):
  ;; the GOAWAY (id 8) promised stream 0 would be processed, so the
  ;; connection waits for it instead of closing as soon as it is idle.
  (let [srv (h3/start-server (fn [^Request req] (ok (.-uri req))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "/four" (h3/body-str (h3/request! c 4 (h3/request-headers "GET" "/four")))))
      (let [closing (future (.close srv))]
        (is (h3/pump-until! c #(= 2 (count (goaway-ids c))) 2000) "both GOAWAYs")
        (is (= 8 (last (goaway-ids c))))
        (h3/pump! c 200)
        (is (nil? (h3/peer-error c)) "still open: stream 0 is due")
        (is (= "/zero" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/zero")))))
        (is (= [true 0x100] (h3/await-peer-error c 3000)) "then H3_NO_ERROR")
        (is (not= ::timeout (deref closing 5000 ::timeout)) "close returned")))))

(deftest close-forces-connections-at-the-shutdown-timeout
  (let [srv (h3/start-server (fn [_] @(promise) (ok "never"))
                             (fn [^com.s_exp.enso.api.Config$Builder b] (.shutdownTimeoutMillis b 300)))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
      (h3/pump! c 100)
      (let [t0 (System/nanoTime)
            closing (future (.close srv))]
        (is (some? (h3/await-peer-error c 3000)) "connection closed")
        (is (not= ::timeout (deref closing 3000 ::timeout)))
        (is (< (- (System/nanoTime) t0) 2500000000) "bounded by the shutdown timeout")
        (is (zero? (.connectionCount srv)))))))

(deftest close-returns-at-the-shutdown-timeout-even-with-a-stuck-loop
  ;; A loop that can't stop (here: an event listener blocking it while it
  ;; closes its connections) is left behind at the deadline instead of
  ;; being waited for past :shutdown-timeout.
  (let [release (promise)
        events (reify com.s_exp.enso.api.ServerEvents
                 (connectionOpened [_ _ _])
                 (connectionClosed [_ _ _ _] (deref release 10000 nil))
                 (requestCompleted [_ _ _ _ _ _ _])
                 (protocolError [_ _ _]))
        srv (h3/start-server (fn [_] (ok "ok"))
                             (fn [^com.s_exp.enso.api.Config$Builder b]
                               (.shutdownTimeoutMillis b 1000)
                               (.serverEvents b events)))]
    (try
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
        (let [t0 (System/nanoTime)]
          (.close srv)
          (is (< (- (System/nanoTime) t0) 2000000000)
              (str "close took " (quot (- (System/nanoTime) t0) 1000000) " ms"))))
      (finally (deliver release true)))))

;; ---- observability ------------------------------------------------------------

(deftest server-events-and-protocol-errors
  (let [events (atom [])
        listener (reify com.s_exp.enso.api.ServerEvents
                   (connectionOpened [_ p _] (swap! events conj [:opened p]))
                   (connectionClosed [_ p _ _] (swap! events conj [:closed p]))
                   (requestCompleted [_ p method status _ bytes _] (swap! events conj [:request p method status bytes]))
                   (protocolError [_ p kind] (swap! events conj [:error p kind])))]
    (h3/with-server [srv (fn [_] (ok "hello"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.serverEvents b listener))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= "hello" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
        (is (message-error? c 4 (h3/headers-frame (h3/request-headers "GET" "no-slash")))))
      (await-connection-count srv 0 3000))
    (is (= [[:opened "h3"] [:request "h3" "GET" 200 5] [:error "h3" "bad-request"] [:closed "h3"]]
           @events))))

;; ---- response details ------------------------------------------------------------

(deftest file-bodies-carry-content-length
  (let [f (doto (java.io.File/createTempFile "enso-h3" ".txt") (.deleteOnExit))]
    (spit f "file body")
    (h3/with-server [srv (fn [_] (ok f))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
          (is (= "file body" (h3/body-str r)))
          (is (= "9" (get (:headers r) "content-length"))))))))

(deftest unsent-response-bodies-are-closed
  ;; A body that is never sent (501 for a WebSocket answer, HEAD) is closed.
  (let [closed (atom 0)
        body #(proxy [java.io.ByteArrayInputStream] [(.getBytes "x")]
                (close [] (swap! closed inc)))]
    (h3/with-server [srv (fn [^Request req]
                           (if (= "/ws" (.-uri req))
                             (Response. 101 {} (body)
                                        (reify com.s_exp.enso.api.WebSocketListener
                                          (onOpen [_ _]) (onMessage [_ _ _]) (onClose [_ _ _ _]))
                                        nil)
                             (ok (body))))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= 501 (:status (h3/request! c 0 (h3/request-headers "GET" "/ws")))))
        (is (= 200 (:status (h3/request! c 4 (h3/request-headers "HEAD" "/")))))
        (is (= 2 @closed))))))

(deftest nothing-is-dispatched-after-a-connection-error
  ;; Frames read in the same pass after a connection error are dropped.
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/pump! c 50)
        ;; Both streams leave in one flight: a SETTINGS frame on request
        ;; stream 0 (H3_FRAME_UNEXPECTED) and a valid request on stream 4.
        (swap! (:pending c) assoc
               0 [(h3/settings-frame) 0 false]
               4 [(h3/headers-frame (h3/request-headers "GET" "/")) 0 true])
        (h3/pump! c 10)
        (is (= [true 0x105] (h3/await-peer-error c 2000)))
        (is (zero? @called))))))

;; ---- sharding ----------------------------------------------------------------------

(def ^:private linux? (.contains (.toLowerCase (System/getProperty "os.name")) "linux"))

(deftest connections-spread-across-event-loops
  ;; Each connection lives on the loop its connection id names. On Linux
  ;; every loop has its own SO_REUSEPORT socket and the kernel steers each
  ;; datagram to its loop by connection id (nothing is forwarded);
  ;; elsewhere loop 0 receives for all and hands datagrams over.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 4))]
    (is (= 4 (.eventLoops srv)))
    (is (.steersByConnectionId srv))
    (let [clients (vec (repeatedly 12 #(h3/connect (.port srv))))]
      (try
        (doseq [c clients]
          (h3/open-control! c)
          (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))
        (let [per-loop (mapv #(.invoke (doto (.getDeclaredMethod (class %) "connectionCount" (make-array Class 0))
                                         (.setAccessible true))
                                       % (object-array 0))
                             (private-field srv "loops"))]
          (is (= 12 (reduce + per-loop)))
          (is (<= 2 (count (filter pos? per-loop))) (str "connections per loop " per-loop))
          (if linux?
            (is (zero? (.forwardedDatagrams srv)) "steered by the kernel")
            (is (pos? (.forwardedDatagrams srv)) "handed over by loop 0")))
        (finally (run! h3/close! clients))))))

(defn- loop-connection-counts [srv]
  (mapv #(.invoke (doto (.getDeclaredMethod (class %) "connectionCount" (make-array Class 0))
                    (.setAccessible true))
                  % (object-array 0))
        (private-field srv "loops")))

(deftest a-loop-allocates-its-inbox-on-first-use
  ;; The inbox (datagrams other loops hand over: 1 MiB of direct memory)
  ;; only exists once something was handed over; a single loop never needs it.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))
    (is (nil? (private-field (private-field (first (private-field srv "loops")) "inbox") "slab")))))

(deftest client-chosen-ids-dont-steer-handshakes
  ;; A client picks its first Initial's destination id: steering by it
  ;; would let one client aim every handshake at one loop (and spreads
  ;; unevenly when 256 isn't a multiple of the loop count). Initials and
  ;; 0-RTT go by the kernel's 4-tuple hash instead (Linux, per-loop
  ;; sockets); the loop that receives one accepts it.
  (when linux?
    (h3/with-server [srv (fn [_] (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3EventLoops b 4)
                       (.handshakeTimeoutMillis b 10000))]
      ;; Real client Initials, each re-addressed to an id naming loop 0.
      (let [clients (vec (repeatedly 16 #(h3/start-handshake (.port srv)
                                                             {:initial-size 1200
                                                              :initial-dcid-fn (fn [^bytes d]
                                                                                 (doto (aclone d) (aset 0 (byte 0))))})))]
        (try
          (is (= 16 (await-connection-count srv 16 3000)))
          (let [per-loop (loop-connection-counts srv)]
            (is (<= 2 (count (filter pos? per-loop))) (str "handshakes per loop " per-loop)))
          (is (zero? (.forwardedDatagrams srv)) "accepted where they landed")
          (finally (run! h3/close! clients)))))
    (testing "after a Retry, the connection lives on the loop that named it"
      (h3/with-server [srv (fn [_] (ok "ok"))
                       (fn [^com.s_exp.enso.api.Config$Builder b]
                         (.http3EventLoops b 4)
                         (.http3StatelessRetry b true))]
        (dotimes [_ 8]
          (h3/with-client [c (.port srv)]
            (h3/open-control! c)
            (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))))))))

(defn- bindable? [^String ip]
  (try (with-open [_ (java.net.DatagramSocket. 0 (java.net.InetAddress/getByName ip))] true)
       (catch java.io.IOException _ false)))

(deftest wildcard-listener-answers-from-the-addressed-ip
  ;; Bound to the wildcard address on a multi-homed host, replies must leave
  ;; from the address the client used (IP_PKTINFO), or the client's QUIC
  ;; stack sees them come from elsewhere. Needs a second loopback address
  ;; (Linux has 127.0.0.0/8).
  (when (and linux? (bindable? "127.0.0.2"))
    (let [srv (h3/start-server (fn [_] (ok "ok"))
                               (fn [^com.s_exp.enso.api.Config$Builder b] (.host b "0.0.0.0")))]
      (try
        (h3/with-client [c (.port srv) {:server-ip "127.0.0.2"}]
          (h3/open-control! c)
          (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))
        (finally (.close srv))))))

;; ---- allocation budget ------------------------------------------------------------

(defn- compressed-oops? []
  (= "true" (.getValue (.getVMOption ^com.sun.management.HotSpotDiagnosticMXBean
                        (java.lang.management.ManagementFactory/getPlatformMXBean
                         com.sun.management.HotSpotDiagnosticMXBean)
                                     "UseCompressedOops"))))

(defn- server-thread-allocated-bytes
  "Bytes allocated so far by the server's threads: the event loops and the
  carriers of the handlers' virtual threads (the test client allocates on
  its own platform thread)."
  ^long []
  (let [mx ^com.sun.management.ThreadMXBean (java.lang.management.ManagementFactory/getThreadMXBean)
        ids (->> (keys (Thread/getAllStackTraces))
                 (filter (fn [^Thread t]
                           (let [n (.getName t)]
                             (or (.startsWith n "enso-h3-loop") (.startsWith n "ForkJoinPool")))))
                 (map #(.threadId ^Thread %))
                 long-array)]
    (reduce + 0 (filter pos? (.getThreadAllocatedBytes mx ids)))))

(defn- get-batch!
  "Sends `n` GETs on fresh streams from `sid` and waits for all of them;
  returns the next stream id."
  [c ^long sid ^long n ^bytes frame]
  (let [sids (range sid (+ sid (* 4 n)) 4)]
    (doseq [s sids] (h3/send! c s frame true))
    (h3/pump-until! c #(every? (fn [s] (h3/stream-done? c s)) sids) 10000)
    (swap! (:streams c) #(apply dissoc % sids))
    (+ sid (* 4 n))))

(deftest a-quick-response-carries-the-ack-of-its-request
  ;; quiche acknowledges a request at once; held back briefly, that ACK
  ;; leaves with the response: one datagram per request, not two.
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (dotimes [i 20] (h3/request! c (* 4 i) (h3/request-headers "GET" "/")))
      (h3/pump! c 50)
      (let [n 100
            before (h3/datagrams-received c)]
        (dotimes [i n] (h3/request! c (* 4 (+ 20 i)) (h3/request-headers "GET" "/")))
        (let [per-request (/ (double (- (h3/datagrams-received c) before)) n)]
          (is (< per-request 1.6) (str per-request " datagrams per request")))))))

(deftest h3-get-allocation-budget
  ;; Server-side bytes per GET (4 request headers, String body), whole path:
  ;; datagram, quiche, frame parsing, QPACK, the Ring request and handler
  ;; thread, response encoding. Measured after warm-up on the server's own
  ;; threads (exact, not sampled).
  (h3/with-server [srv (fn [_] (ok "Hello, World!"))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [frame (h3/headers-frame (h3/request-headers "GET" "/" ["accept" "*/*"]
                                                        ["user-agent" "enso-test"]
                                                        ["accept-encoding" "gzip"]
                                                        ["x-request-id" "abc"]))
            sid (reduce (fn [sid _] (get-batch! c sid 50 frame)) 0 (range 40))
            before (server-thread-allocated-bytes)
            n 2000
            _ (reduce (fn [sid _] (get-batch! c sid 50 frame)) sid (range (quot n 50)))
            per-request (quot (- (server-thread-allocated-bytes) before) n)]
        (println "h3 GET server allocation per request:" per-request "bytes")
        ;; ~730 measured with compressed oops (~1050 without, e.g. ZGC):
        ;; the per-request virtual thread (with its continuation and
        ;; thread-container node), the Exchange, the Ring request and header
        ;; map, the handler's Response.
        (is (< per-request (if (compressed-oops?) 900 1300)) (str per-request " bytes per request"))))))

(deftest small-stream-bodies-get-small-buffers
  ;; A streamed body's producer buffer is sized to what the body can need
  ;; (its Content-Length, or what a ByteArrayInputStream holds), not a
  ;; fixed 64 KiB per response.
  (doseq [[what handler] [["InputStream of known size" (fn [_] (ok (java.io.ByteArrayInputStream. (byte-array 100))))]
                          ["declared Content-Length" (fn [_] (Response. 200 {"content-length" "100"}
                                                                        (proxy [java.io.InputStream] []
                                                                          (read ([] 0)
                                                                            ([^bytes b off len] (java.util.Arrays/fill b (int off) (int (+ off (min len 100))) (byte 0))
                                                                                                (min len 100))))))]]]
    (testing what
      (h3/with-server [srv handler]
        (h3/with-client [c (.port srv)]
          (h3/open-control! c)
          (let [frame (h3/headers-frame (h3/request-headers "GET" "/"))
                sid (reduce (fn [sid _] (get-batch! c sid 20 frame)) 0 (range 10))
                before (server-thread-allocated-bytes)
                n 200
                _ (reduce (fn [sid _] (get-batch! c sid 20 frame)) sid (range (quot n 20)))
                per-request (quot (- (server-thread-allocated-bytes) before) n)]
            (is (< per-request 16384) (str per-request " bytes per request"))))))))

(deftest large-text-bodies-are-not-copied-whole
  ;; A 64 KiB ASCII String body is written to quiche in slices through the
  ;; loop's frame buffer, not turned into a 64 KiB byte[] per response.
  (let [body (apply str (repeat (* 64 1024) "a"))]
    (h3/with-server [srv (fn [_] (ok body))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= body (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
        (let [frame (h3/headers-frame (h3/request-headers "GET" "/"))
              sid (reduce (fn [sid _] (get-batch! c sid 4 frame)) 4 (range 10))
              before (server-thread-allocated-bytes)
              n 80
              _ (reduce (fn [sid _] (get-batch! c sid 4 frame)) sid (range (quot n 4)))
              per-request (quot (- (server-thread-allocated-bytes) before) n)]
          (is (< per-request (* 16 1024)) (str per-request " bytes per request")))))))

(deftest enso-server-drains-h3-connections
  ;; Through the server: QUIC connections count in its registry (and
  ;; connectionCount), drain with GOAWAY on close, and a handshaking one
  ;; is simply closed.
  (let [gate (promise)
        entered (promise)
        cfg (h3/server-config (fn [^com.s_exp.enso.api.Config$Builder b]
                                (.http3Port b (int (support/free-udp-port)))
                                (.shutdownTimeoutMillis b 5000)))
        server (doto (com.s_exp.enso.EnsoServer.
                      (reify com.s_exp.enso.api.RingHandler
                        (handle [_ req]
                          (deliver entered true)
                          @gate
                          (ok "done")))
                      cfg)
                 (.start))
        port (.-http3Port cfg)]
    (try
      (let [half-open (h3/start-handshake port)]
        (h3/with-client [c port]
          (h3/open-control! c)
          (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
          (h3/pump-until! c #(realized? entered) 2000)
          (is (= 2 (.connectionCount server)) "both QUIC connections registered")
          (let [closing (future (.close server))]
            (is (h3/pump-until! c #(seq (goaway-ids c)) 2000) "GOAWAY")
            (deliver gate true)
            (h3/pump-until! c #(h3/stream-done? c 0) 2000)
            (is (= "done" (h3/body-str (h3/response c 0))))
            (is (= [true 0x100] (h3/await-peer-error c 3000)))
            (is (not= ::timeout (deref closing 5000 ::timeout)))
            (is (zero? (.connectionCount server)))))
        (h3/close! half-open))
      (finally (.close server)))))

(defn- open-fds ^long []
  (.getOpenFileDescriptorCount ^com.sun.management.UnixOperatingSystemMXBean
   (java.lang.management.ManagementFactory/getOperatingSystemMXBean)))

(deftest failed-start-releases-sockets-and-config
  ;; A listener whose start fails (port taken, here) releases what it
  ;; opened before failing: sockets, wake-up channels, the quiche config.
  (with-open [taken (java.net.DatagramSocket. 0 (java.net.InetAddress/getByName "127.0.0.1"))]
    (let [port (.getLocalPort taken)
          attempt #(let [l (com.s_exp.enso.http3.Http3Listener.
                            (h3/server-config (fn [^com.s_exp.enso.api.Config$Builder b]
                                                (.http3Port b (int port))
                                                (.http3EventLoops b 2)))
                            (reify com.s_exp.enso.api.RingHandler (handle [_ _] (ok "x")))
                            nil)]
                     (try (.start l) :started
                          (catch java.io.IOException _ :failed)
                          (finally (.close l))))]
      (attempt)
      (let [before (open-fds)]
        (is (every? #{:failed} (repeatedly 20 attempt)))
        (is (<= (open-fds) (+ before 2)) "no descriptor leaked per failed start")))))

(deftest small-socket-buffers-still-deliver-large-bodies
  ;; A small UDP send buffer may fill (EAGAIN) or drop (ENOBUFS, treated as
  ;; loss): either way a large body completes. Loopback rarely reports
  ;; EAGAIN, so the resume-on-writable path itself is covered by reasoning,
  ;; not asserted.
  (let [data (byte-array (* 4 1024 1024))]
    (.nextBytes (java.util.Random. 11) data)
    (h3/with-server [srv (fn [_] (ok data))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3SoSndBufBytes b 65536)
                       (.http3EventLoops b 1))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [t0 (System/nanoTime)
              r (h3/request! c 0 (h3/request-headers "GET" "/"))]
          (is (java.util.Arrays/equals data ^bytes (:body r)))
          (is (< (- (System/nanoTime) t0) 10000000000)))))))

(deftest invalid-client-transport-parameters-close-the-handshake
  ;; RFC 9000 §7.4 / §18.2: a max_udp_payload_size below 1200 is a
  ;; TRANSPORT_PARAMETER_ERROR (0x08), sent before any state is kept.
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (let [c (h3/start-handshake (.port srv) {:configure #(.setMaxRecvUdpPayloadSize ^com.s_exp.enso.quiche.QuicheConfig % 1199)})]
      (try
        (is (= [false 0x08] (h3/await-peer-error c 3000)) (str (h3/peer-error c)))
        (is (zero? (await-connection-count srv 0 3000)))
        (finally (h3/close! c))))))

(deftest bodiless-request-has-nil-body
  ;; Ring: :body is present only when the request has one, as on HTTP/1.1
  ;; and HTTP/2.
  (h3/with-server [srv (fn [^Request req]
                         (ok (if-let [^java.io.InputStream in (.-body req)]
                               (String. (.readAllBytes in) "UTF-8")
                               "nil")))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= "nil" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))
      (is (= "abc" (h3/body-str (h3/request! c 4 (h3/request-headers "POST" "/") (.getBytes "abc" "UTF-8"))))))))

;; ---- behaviour shared with the other protocols ---------------------------------

(deftest declared-body-over-cap-is-413-without-the-handler
  ;; As on HTTP/1.1 and HTTP/2: a Content-Length over
  ;; :max-request-body-bytes is answered 413 before any handler runs.
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "ran"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxRequestBodyBytes b 10))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "POST" "/" ["content-length" "100"]) (byte-array 100))]
          (is (= 413 (:status r)))
          (is (= "Content Too Large" (h3/body-str r))))
        (is (zero? @called) "handler not run")
        (is (nil? (h3/peer-error c)))))))

(deftest expect-100-continue-sent-on-first-body-read
  ;; RFC 9114 §4.1 / RFC 9110 §10.1.1, as on HTTP/1.1: the interim 100
  ;; goes out when the handler first reads the body.
  (h3/with-server [srv (fn [^Request req]
                         (if (= "/read" (.-uri req))
                           (ok (String. (.readAllBytes ^java.io.InputStream (.-body req))))
                           (ok "unread")))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (h3/send! c 0 (h3/headers-frame (h3/request-headers "POST" "/read" ["expect" "100-continue"])) false)
      (h3/pump-until! c #(= [100] (:interim (h3/response c 0))) 2000)
      (is (= [100] (:interim (h3/response c 0))) "100 before the body was sent")
      (h3/send! c 0 (h3/data-frame (.getBytes "abc")) true)
      (h3/pump-until! c #(h3/stream-done? c 0) 3000)
      (let [r (h3/response c 0)]
        (is (= 200 (:status r)))
        (is (= "abc" (h3/body-str r))))
      (let [r (h3/request! c 4 (h3/request-headers "POST" "/unread" ["expect" "100-continue"]) (.getBytes "x"))]
        (is (= [] (:interim r)) "no 100 for a body never read")
        (is (= 200 (:status r)))))))

(deftest unknown-expectation-is-417
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "ran"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= 417 (:status (h3/request! c 0 (h3/request-headers "POST" "/" ["expect" "teapot"]) (.getBytes "x")))))
        (is (zero? @called))))))

(deftest header-field-count-is-capped
  (let [called (atom 0)]
    (h3/with-server [srv (fn [_] (swap! called inc) (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxHeaderFields b 5))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (= 200 (:status (h3/request! c 0 (apply h3/request-headers "GET" "/" (for [i (range 5)] [(str "x-h" i) "v"]))))))
        (is (= 431 (:status (h3/request! c 4 (apply h3/request-headers "GET" "/" (for [i (range 6)] [(str "x-h" i) "v"]))))))
        (is (= 1 @called))))))

(deftest many-distinct-headers-build-a-hash-map-in-bounded-time
  (let [seen (promise)]
    (h3/with-server [srv (fn [^Request req]
                           (let [h (.-headers req)]
                             (deliver seen [(class h) (count h) (get h "x-h1999")]))
                           (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.maxHeaderFields b 3000)
                       (.maxHeaderBytes b (* 1024 1024)))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [t0 (System/nanoTime)
              r (h3/request! c 0 (apply h3/request-headers "GET" "/" (for [i (range 2000)] [(str "x-h" i) "v"])))]
          (is (= 200 (:status r)))
          (is (< (/ (- (System/nanoTime) t0) 1e6) 2000.0) "bounded time"))
        (is (= [clojure.lang.PersistentHashMap 2001 "v"] (deref seen 1000 nil)))))))

;; ---- failure containment ---------------------------------------------------------

(defn- set-private-field! [obj ^String name v]
  (.set (doto (.getDeclaredField (class obj) name) (.setAccessible true)) obj v))

(defn- loop-connections
  "The connections owned by `srv`'s event loops."
  [srv]
  (vec (mapcat (fn [l]
                 (let [m (doto (.getDeclaredMethod (class l) "connections" (make-array Class 0))
                           (.setAccessible true))]
                   (seq (.invoke m l (object-array 0)))))
               (private-field srv "loops"))))

(defn- served? [c sid]
  (= "ok" (h3/body-str (h3/request! c sid (h3/request-headers "GET" "/")))))

(deftest a-failing-connection-closes-alone
  ;; An exception while processing one connection closes that connection
  ;; (H3_INTERNAL_ERROR); the loop and its other connections carry on.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
    (h3/with-client [a (.port srv)]
      (h3/with-client [b (.port srv)]
        (h3/open-control! a)
        (h3/open-control! b)
        (is (served? a 0))
        (is (served? b 0))
        ;; Corrupt one connection: its next stream read throws.
        (set-private-field! (first (loop-connections srv)) "reader" nil)
        (h3/send! a 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (h3/send! b 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (h3/pump-until! a #(or (h3/peer-error a) (h3/stream-done? a 4)) 3000)
        (h3/pump-until! b #(or (h3/peer-error b) (h3/stream-done? b 4)) 3000)
        (let [[victim survivor] (if (h3/peer-error a) [a b] [b a])]
          (is (= [true 0x102] (h3/peer-error victim)) "H3_INTERNAL_ERROR for the broken connection")
          (is (nil? (h3/peer-error survivor)))
          (is (served? survivor 8) "the loop still serves the others"))))))

(deftest a-connection-whose-teardown-fails-is-still-freed
  ;; Teardown that throws half-way (here: abandoning its requests) must
  ;; still free the quiche connection and give back its configuration.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (served? c 0))
      (let [conn (first (loop-connections srv))
            ^com.s_exp.enso.quiche.QuicheConnection q (private-field conn "quiche")]
        (set-private-field! conn "writer" nil)
        (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (is (support/await-condition #(do (h3/pump! c 20) (.isFreed q)) 3000 1)
            "the quiche connection was freed")
        (is (= 1 (.liveQuicheConfigs srv)) "its configuration reference was given back")
        (is (empty? (loop-connections srv)))))))

(deftest a-failing-event-loop-is-restarted
  ;; A failure escaping the loop's own guards is reported, the loop's
  ;; connections are closed and the loop restarts: new connections are
  ;; served again.
  (let [errors (atom [])
        listener (reify com.s_exp.enso.api.ServerEvents
                   (protocolError [_ _ kind] (swap! errors conj kind)))]
    (h3/with-server [srv (fn [_] (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3EventLoops b 1)
                       (.serverEvents b listener))]
      (let [l (first (private-field srv "loops"))
            ready (private-field l "ready")]
        (h3/with-client [c (.port srv)]
          (h3/open-control! c)
          (is (served? c 0))
          (set-private-field! l "ready" nil)
          (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
          (is (h3/await-peer-error c 3000) "the failed loop's connections are closed"))
        ;; Events are delivered from their own thread.
        (is (support/await-condition #(some #{"event-loop-failure"} @errors) 3000 10) (str "events: " @errors))
        (set-private-field! l "ready" ready)
        (h3/with-client [c (.port srv)]
          (h3/open-control! c)
          (is (served? c 0) "the restarted loop serves new connections"))))))

;; Leaves the loop's logger with a handler that throws on every record,
;; as a broken logging setup would, for the duration of `f`.
(defn- with-throwing-log-handler [^String logger-name f]
  (let [logger (java.util.logging.Logger/getLogger logger-name)
        handler (proxy [java.util.logging.Handler] []
                  (publish [_] (throw (IllegalStateException. "log handler broke")))
                  (flush [])
                  (close []))]
    (.addHandler logger handler)
    (try (f) (finally (.removeHandler logger handler)))))

(deftest a-failing-event-loop-is-restarted-even-when-reporting-fails
  ;; Reporting the failure (logging here) can fail too; the supervisor
  ;; still restarts the loop.
  (with-throwing-log-handler
    (.getName com.s_exp.enso.http3.Http3Loop)
    (fn []
      (h3/with-server [srv (fn [_] (ok "ok"))
                       (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
        (let [l (first (private-field srv "loops"))
              ready (private-field l "ready")]
          (h3/with-client [c (.port srv)]
            (h3/open-control! c)
            (is (served? c 0))
            (set-private-field! l "ready" nil)
            (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
            (is (h3/await-peer-error c 3000) "the failed loop's connections are closed"))
          (set-private-field! l "ready" ready)
          (is (.isHealthy srv) "the loop thread is alive")
          (h3/with-client [c (.port srv)]
            (h3/open-control! c)
            (is (served? c 0) "the restarted loop serves new connections")))))))

(deftest a-restarted-loop-frees-connections-whose-teardown-fails
  ;; The loop's own state can't be trusted after a failure: a connection
  ;; whose timer entry is broken (removing it throws) is still freed (its
  ;; quiche state and limiter slot given back), and the
  ;; restarted loop starts from fresh timers and tables.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
    (let [l (first (private-field srv "loops"))
          ready (private-field l "ready")
          timers (private-field l "timers")]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (served? c 0))
        (let [conn (first (loop-connections srv))]
          (set-private-field! conn "heapIndex" (int 100000)))
        (set-private-field! l "ready" nil)
        (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (is (h3/await-peer-error c 3000) "the failed loop's connections are closed"))
      (set-private-field! l "ready" ready)
      (is (zero? (await-connection-count srv 0 3000)) "freed despite its broken timer entry")
      (is (empty? (loop-connections srv)))
      (is (not (identical? timers (private-field l "timers"))) "fresh timers")
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (is (served? c 0) "the restarted loop serves new connections")))))

(deftest a-handler-thread-that-fails-to-start-is-not-counted
  ;; A handler counted as live but never started would keep its
  ;; connection's slot forever (the count only drops when a handler
  ;; returns): the request gets a 503 and the connection is released.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3EventLoops b 1))]
    (set-private-field! srv "handlerThreads"
                        (reify java.util.concurrent.ThreadFactory
                          (newThread [_ _] (Thread/startVirtualThread (fn [])))))
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (is (= 503 (:status (h3/request! c 0 (h3/request-headers "GET" "/"))))))
    (is (zero? (await-connection-count srv 0 3000)) "the connection's slot was given back")))

(deftest a-stuck-event-listener-never-stalls-the-event-loop
  ;; connectionOpened / Closed and protocol errors are reported from the
  ;; loop; a listener that blocks must not hold it up.
  (let [gate (java.util.concurrent.CountDownLatch. 1)
        listener (reify com.s_exp.enso.api.ServerEvents
                   (connectionOpened [_ _ _] (.await gate))
                   (connectionClosed [_ _ _ _] (.await gate))
                   (protocolError [_ _ _] (.await gate)))]
    (try
      (h3/with-server [srv (fn [_] (ok "ok"))
                       (fn [^com.s_exp.enso.api.Config$Builder b]
                         (.http3EventLoops b 1)
                         (.serverEvents b listener))]
        (h3/with-client [c (.port srv)]
          (h3/open-control! c)
          (is (served? c 0) "served while the listener is stuck"))
        (h3/with-client [c (.port srv)]
          (h3/open-control! c)
          (is (served? c 0) "and the next connection too")))
      (finally
        (.countDown gate)))))

(deftest datagram-from-an-undecodable-address-is-dropped
  ;; A source address in a family the shim doesn't decode is dropped at
  ;; admission rather than crashing the loop with a null address.
  (h3/with-server [srv (fn [_] (ok "ok"))]
    (let [admit (doto (.getDeclaredMethod com.s_exp.enso.http3.Http3Listener "admit"
                                          (into-array Class [java.nio.ByteBuffer Integer/TYPE java.nio.ByteBuffer
                                                             Integer/TYPE (class (byte-array 0))]))
                  (.setAccessible true))
          meta (java.nio.ByteBuffer/allocate 256)
          verdict (.invoke admit srv (object-array [(java.nio.ByteBuffer/allocate 64) (int 0) meta (int 0)
                                                    (byte-array 8)]))]
      (is (= 1 (private-field verdict "verdict")) "Admission/DROP"))))

;; ---- certificate reloading -------------------------------------------------

(defn- write-cert-pair!
  "Generates an ECDSA P-256 certificate for `cn` and moves it over
  `cert` / `key` (each replaced in one rename, as deploy tools do).
  Returns the certificate's DER bytes."
  ^bytes [^String cert ^String key ^String cn]
  (let [dir (java.nio.file.Files/createTempDirectory "enso-h3-cert" (make-array java.nio.file.attribute.FileAttribute 0))
        c (str (.resolve dir "c.pem"))
        k (str (.resolve dir "k.pem"))
        run (fn [& args] (let [p (.start (doto (ProcessBuilder. ^java.util.List (vec args)) (.redirectErrorStream true)))]
                           (slurp (.getInputStream p))
                           (assert (zero? (.waitFor p)) (str args))))]
    (run "openssl" "ecparam" "-name" "prime256v1" "-genkey" "-noout" "-out" k)
    (run "openssl" "req" "-new" "-x509" "-key" k "-out" c "-days" "1" "-subj" (str "/CN=" cn))
    (java.nio.file.Files/move (java.nio.file.Path/of k (make-array String 0)) (java.nio.file.Path/of key (make-array String 0))
                              (into-array java.nio.file.CopyOption [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (java.nio.file.Files/move (java.nio.file.Path/of c (make-array String 0)) (java.nio.file.Path/of cert (make-array String 0))
                              (into-array java.nio.file.CopyOption [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (with-open [in (java.io.FileInputStream. cert)]
      (.getEncoded (.generateCertificate (java.security.cert.CertificateFactory/getInstance "X.509") in)))))

(defn- presented-certificate
  "DER of the certificate a new connection to `port` is shown."
  ^bytes [port]
  (h3/with-client [c port]
    (h3/peer-certificate c)))

(deftest changed-certificate-files-are-loaded-for-new-connections
  (let [dir (java.nio.file.Files/createTempDirectory "enso-h3-rotate" (make-array java.nio.file.attribute.FileAttribute 0))
        cert (str (.resolve dir "cert.pem"))
        key (str (.resolve dir "key.pem"))
        first-der (write-cert-pair! cert key "first")]
    (h3/with-server [srv (fn [_] (ok "ok"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3CertPath b cert)
                       (.http3KeyPath b key)
                       (.http3CertReloadIntervalMillis b 50))]
      (let [old (h3/connect (.port srv))]
        (try
          (h3/open-control! old)
          (is (java.util.Arrays/equals first-der (h3/peer-certificate old)))
          (let [second-der (write-cert-pair! cert key "second")]
            (is (support/await-condition #(java.util.Arrays/equals second-der (presented-certificate (.port srv))) 5000 50)
                "new connections get the new certificate")
            (is (= "ok" (h3/body-str (h3/request! old 0 (h3/request-headers "GET" "/"))))
                "an existing connection keeps working on the configuration it was accepted with")
            (is (= 2 (.liveQuicheConfigs srv)) "the old configuration lives while a connection uses it")
            (testing "a broken pair is refused and the current one kept"
              (spit cert "not a certificate")
              (Thread/sleep 300)
              (is (java.util.Arrays/equals second-der (presented-certificate (.port srv))))))
          (finally (h3/close! old))))
      (is (support/await-condition #(= 1 (.liveQuicheConfigs srv)) 5000 50)
          "the old configuration is freed once its last connection is gone"))))

(deftest certificate-reloads-keep-no-trace-of-freed-configurations
  ;; Each reload builds a configuration; one freed (no connection uses it)
  ;; must not stay listed, or a long-running server's list grows with
  ;; every rotation.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3CertReloadIntervalMillis b 0))]
    (dotimes [_ 20] (.reloadCertificates srv))
    (is (<= (count (private-field srv "configs")) 2))))

;; ---- request-body memory -----------------------------------------------------

(defn- start-with-service
  "A listener on its own Service (so the test can watch its memory budget).
  Returns [listener service timer]."
  [handler configure]
  (let [cfg (h3/server-config configure)
        timer (com.s_exp.enso.core.Timer. "h3-test-timer" 10 512)
        service (com.s_exp.enso.core.Service. (reify com.s_exp.enso.api.RingHandler (handle [_ req] (handler req)))
                                              nil cfg timer)
        l (com.s_exp.enso.http3.Http3Listener. service nil nil)]
    (.start l)
    [l service timer]))

(defn- budget-used ^long [^com.s_exp.enso.core.Service service]
  (.used ^com.s_exp.enso.core.MemoryBudget (.-budget service)))

(deftest response-bytes-held-for-the-peer-are-charged-to-the-budget
  ;; Response bytes waiting for the client's flow-control credit (deferred
  ;; writes, a streamed body's slice) are held for the peer: charged to
  ;; :max-buffered-bytes through the connection's share, given back as
  ;; they are sent, when the stream is reset and when the connection goes.
  (doseq [[what body] [["byte[] body" (fn [] (byte-array (* 256 1024) (byte 7)))]
                       ["InputStream body" (fn [] (java.io.ByteArrayInputStream. (byte-array (* 512 1024) (byte 7))))]]]
    (testing what
      (let [[^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
            (start-with-service (fn [_] (ok (body))) (fn [_]))
            small-window {:configure #(.setInitialMaxStreamDataBidiLocal ^com.s_exp.enso.quiche.QuicheConfig % 32768)}]
        (try
          (testing "sent once the client reads"
            (h3/with-client [c (.port l) small-window]
              (h3/open-control! c)
              (h3/pause-stream! c 0)
              (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
              (is (support/await-condition #(do (h3/pump! c 20) (>= (budget-used service) 16384)) 5000 1)
                  (str "held while blocked: " (budget-used service)))
              (h3/resume-stream! c 0)
              (h3/pump-until! c #(h3/stream-done? c 0) 5000)
              (is (:fin (h3/response c 0)))
              (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 5000 1)
                  (str "still charged: " (budget-used service)))))
          (testing "given back when the client stops the stream"
            (h3/with-client [c (.port l) small-window]
              (h3/open-control! c)
              (h3/pause-stream! c 0)
              (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
              (is (support/await-condition #(do (h3/pump! c 20) (pos? (budget-used service))) 5000 1))
              (h3/stop-sending! c 0 0x10c)
              (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 5000 1)
                  (str "still charged: " (budget-used service)))))
          (testing "given back when the connection goes"
            (let [c (h3/connect (.port l) small-window)]
              (h3/open-control! c)
              (h3/pause-stream! c 0)
              (h3/send! c 0 (h3/headers-frame (h3/request-headers "GET" "/")) true)
              (is (support/await-condition #(do (h3/pump! c 20) (pos? (budget-used service))) 5000 1))
              (h3/close! c)
              (is (support/await-condition #(zero? (budget-used service)) 5000 20)
                  (str "still charged: " (budget-used service)))))
          (finally
            (.close l)
            (.close timer)))))))

(deftest header-timeout-spares-streams-the-server-stopped-reading
  ;; A request stream the loop doesn't read (its connection's body pipes
  ;; hold the whole window) can't complete its header section: that's the
  ;; server's backpressure, not a slow client. :header-timeout counts
  ;; from when reading resumes.
  (let [gate (promise)
        errors (atom [])
        events (reify com.s_exp.enso.api.ServerEvents
                 (protocolError [_ _ kind] (swap! errors conj kind)))
        window (* 256 1024)]
    (h3/with-server [srv (fn [^Request req]
                           (when (= "/hold" (.-uri req)) @gate)
                           (ok "x"))
                     (fn [^com.s_exp.enso.api.Config$Builder b]
                       (.http3InitialMaxDataBytes b window)
                       (.headerTimeoutMillis b 400)
                       (.serverEvents b events))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (doseq [sid [0 4 8 12]]
          (h3/send! c sid (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/hold"))
                                           (h3/data-frame (byte-array (* 64 1024))))
                    false))
        (h3/pump! c 300)
        (h3/send! c 16 (h3/headers-frame (h3/request-headers "GET" "/")) true)
        (h3/pump! c 1500)
        (is (nil? (:reset (h3/stream-state c 16))) "not refused while the server held it")
        (is (not-any? #{"header-timeout"} @errors) (str @errors))
        (deliver gate true)
        (h3/pump-until! c #(h3/stream-done? c 16) 5000)
        (is (= 200 (:status (h3/response c 16))))))))

(deftest unread-body-bytes-are-released-when-the-connection-goes
  ;; A handler that never reads its body (and ignores interrupts) can't
  ;; give the buffered bytes back: closing the connection must.
  (let [gate (promise)
        [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] (while (not (realized? gate))
                                      (try (deref gate) (catch InterruptedException _)))
                              (ok "x"))
                            (fn [_]))]
    (try
      (let [c (h3/connect (.port l))]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (byte-array (* 40 1024))))
                  false)
        (is (support/await-condition #(do (h3/pump! c 20) (pos? (budget-used service))) 5000 1)
            "body bytes buffered for the handler")
        (h3/close! c))
      (is (support/await-condition #(zero? (budget-used service)) 5000 20)
          (str "budget still charged: " (budget-used service)))
      (finally
        (deliver gate true)
        (.close l)
        (.close timer)))))

(deftest unread-bodies-of-a-connection-are-bounded-by-its-window
  ;; Body bytes the loop moves out of quiche into pipes return flow-control
  ;; credit to the peer, so the pipes, not quiche, must bound what one
  ;; connection's unread bodies hold: at most its connection window, on
  ;; top of the window itself, charged while bodies are read.
  (let [gate (promise)
        window (* 256 1024)
        [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] @gate (ok "x"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.http3InitialMaxDataBytes b window)
                              (.http3InitialMaxStreamsBidi b 8)))]
    (try
      (h3/with-client [c (.port l)]
        (h3/open-control! c)
        (doseq [sid (range 0 32 4)]
          (h3/send! c sid (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                           (h3/data-frame (byte-array (* 96 1024))))
                    true))
        (let [peak (loop [deadline (+ (System/currentTimeMillis) 2000) peak 0]
                     (if (> (System/currentTimeMillis) deadline)
                       peak
                       (do (h3/pump! c 20)
                           (recur deadline (max peak (budget-used service))))))]
          (is (pos? peak))
          (is (<= peak (* 2 window)) (str "peak charged " peak " bytes, window " window))))
      (finally
        (deliver gate true)
        (.close l)
        (.close timer)))))

(deftest connection-window-is-charged-while-a-body-is-read
  ;; quiche holds, or was promised, up to a connection window of request
  ;; data natively: charged to :max-buffered-bytes while a request body
  ;; of the connection is being read, given back once no body is (here:
  ;; the body was read to its end while the handler still runs).
  (let [window (* 256 1024)
        start (promise)
        body-read (promise)
        respond (promise)
        [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [^Request req]
                              @start
                              (.readAllBytes ^java.io.InputStream (.-body req))
                              (deliver body-read true)
                              @respond
                              (ok "x"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.http3InitialMaxDataBytes b window)))]
    (try
      (h3/with-client [c (.port l)]
        (h3/open-control! c)
        (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 2000 1)
            "an idle connection costs nothing")
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (byte-array (* 16 1024))))
                  false)
        (is (support/await-condition #(do (h3/pump! c 20) (>= (budget-used service) (+ window (* 16 1024)))) 5000 1)
            (str "window and buffered body charged: " (budget-used service)))
        (deliver start true)
        (h3/send! c 0 (h3/data-frame (byte-array 100)) true)
        (is (deref body-read 5000 false))
        (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 5000 1)
            (str "nothing in play while the handler runs: " (budget-used service)))
        (deliver respond true)
        (h3/pump-until! c #(h3/stream-done? c 0) 5000)
        (is (= 200 (:status (h3/response c 0))))
        (testing "charged again by the next body, once"
          (h3/send! c 4 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                         (h3/data-frame (byte-array 10)))
                    false)
          (h3/send! c 8 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                         (h3/data-frame (byte-array 10)))
                    false)
          (is (support/await-condition #(do (h3/pump! c 20) (= window (budget-used service))) 5000 1)
              (str "one window for the connection (the handlers read the bytes): " (budget-used service)))
          (h3/send! c 4 (byte-array 0) true)
          (h3/send! c 8 (byte-array 0) true)
          (h3/pump-until! c #(and (h3/stream-done? c 4) (h3/stream-done? c 8)) 5000)
          (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 5000 1)
              (str "still charged: " (budget-used service)))))
      (finally
        (deliver start true)
        (deliver respond true)
        (.close l)
        (.close timer)))))

(deftest connection-window-charge-is-released-on-reset-and-close
  ;; A body that never completes gives the window back when its stream is
  ;; reset (the bytes already buffered stay charged until the exchange
  ;; ends), or when the connection goes.
  (let [window (* 256 1024)
        gate (promise)
        [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] @gate (ok "x"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.http3InitialMaxDataBytes b window)))
        post! (fn [c sid]
                (h3/send! c sid (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                                 (h3/data-frame (byte-array 1000)))
                          false)
                (is (support/await-condition #(do (h3/pump! c 20) (>= (budget-used service) window)) 5000 1)
                    (str "window charged: " (budget-used service))))]
    (try
      (testing "peer reset"
        (h3/with-client [c (.port l)]
          (h3/open-control! c)
          (post! c 0)
          (h3/reset-stream! c 0 0x10c)
          (is (support/await-condition #(do (h3/pump! c 20) (= 1000 (budget-used service))) 5000 1)
              (str "only the unread body left: " (budget-used service)))))
      (testing "connection closed"
        (let [c (h3/connect (.port l))]
          (h3/open-control! c)
          (post! c 0)
          (h3/close! c)
          (is (support/await-condition #(zero? (budget-used service)) 5000 20)
              (str "still charged: " (budget-used service)))))
      (finally
        (deliver gate true)
        (.close l)
        (.close timer)))))

;; ---- receive-window autotuning (patched libquiche) ----------------------------

(def ^:private recv-window-control com.s_exp.enso.quiche.Quiche/RECV_WINDOW_CONTROL)

(defn- skip-without-recv-window-control
  "Skips (or fails, with ENSO_H3_REQUIRE_RECV_WINDOW_CONTROL set, as in CI)
  a test that needs the patched libquiche."
  []
  (when-not recv-window-control
    (is (nil? (System/getenv "ENSO_H3_REQUIRE_RECV_WINDOW_CONTROL"))
        "ENSO_H3_REQUIRE_RECV_WINDOW_CONTROL is set but the shim's libquiche lacks the patches")
    (println "SKIP: the loaded libquiche lacks receive-window control (native/enso_quiche/patches/);"
             "build the shim against build-libquiche.sh's libquiche to run this test")))

(defn- the-connection [l]
  (first (loop-connections l)))

(defn- connection-window
  "[the window quiche autotunes to at most, quiche's current connection window]"
  [conn]
  [(private-field conn "connectionWindowMax")
   (.connectionWindow ^com.s_exp.enso.quiche.QuicheConnection (private-field conn "quiche"))])

(defn- upload!
  "POSTs `n` bytes on stream `sid` of `c`, pumping until the response."
  [c sid n]
  (h3/send! c sid (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                   (h3/data-frame (byte-array n)))
            true)
  (h3/pump-until! c #(h3/stream-done? c sid) 20000)
  (h3/response c sid))

(deftest receive-window-grows-while-drained-and-stops-at-the-max
  ;; With receive-window control the connection window autotunes like
  ;; quiche's own, from :http3-initial-max-data-bytes up to twice
  ;; :http3-max-window-bytes, each step reserved from the connection's
  ;; account before quiche may use it; given back when the connection goes.
  (if-not recv-window-control
    (skip-without-recv-window-control)
    (let [initial (* 16 1024)
          max-window (* 128 1024)
          [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
          (start-with-service (fn [^Request req]
                                (ok (str (.transferTo ^java.io.InputStream (.-body req)
                                                      (java.io.OutputStream/nullOutputStream)))))
                              (fn [^com.s_exp.enso.api.Config$Builder b]
                                (.http3InitialMaxDataBytes b initial)
                                (.http3MaxWindowBytes b max-window)))]
      (try
        (let [c (h3/connect (.port l))]
          (h3/open-control! c)
          (is (= [initial initial] (connection-window (the-connection l))) "starts at the initial window")
          (doseq [sid [0 4 8]]
            (is (= (str (* 4 1024 1024)) (h3/body-str (upload! c sid (* 4 1024 1024))))))
          (let [[window-max window] (connection-window (the-connection l))]
            (is (= (* 2 max-window) window-max) "grown to twice :http3-max-window-bytes, no further")
            (is (< initial window) (str "quiche's window grew: " window))
            (is (<= window window-max))
            (is (= (- window-max initial) (budget-used service)) "the growth stays reserved, nothing else"))
          (h3/close! c))
        (is (support/await-condition #(zero? (budget-used service)) 5000 20)
            (str "given back with the connection: " (budget-used service)))
        (finally
          (.close l)
          (.close timer))))))

(deftest receive-window-does-not-grow-when-the-budget-cannot-pay
  ;; A step the account can't reserve isn't granted: quiche keeps the
  ;; window it has, and the upload goes on within it.
  (if-not recv-window-control
    (skip-without-recv-window-control)
    (let [initial (* 256 1024)
          [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
          (start-with-service (fn [^Request req]
                                (ok (str (.transferTo ^java.io.InputStream (.-body req)
                                                      (java.io.OutputStream/nullOutputStream)))))
                              (fn [^com.s_exp.enso.api.Config$Builder b]
                                (.maxBufferedBytes b (* 1024 1024))
                                (.http3InitialMaxDataBytes b initial)))
          budget ^com.s_exp.enso.core.MemoryBudget (.-budget ^com.s_exp.enso.core.Service service)]
      (try
        ;; Below the low-water mark with the window charged, but no room
        ;; for one more window.
        (.charge budget (* 520 1024))
        (h3/with-client [c (.port l)]
          (h3/open-control! c)
          (is (= (str (* 4 1024 1024)) (h3/body-str (upload! c 0 (* 4 1024 1024)))))
          (let [[window-max window] (connection-window (the-connection l))]
            (is (= initial window-max))
            (is (<= window initial)))
          (is (= (* 520 1024) (budget-used service)) "nothing reserved"))
        (.release budget (* 520 1024))
        (finally
          (.close l)
          (.close timer))))))

(deftest receive-window-stays-fixed-without-recv-window-control
  ;; On a stock libquiche the windows stay where they start.
  (if recv-window-control
    (println "SKIP: the loaded libquiche has receive-window control; this covers a stock one")
    (let [initial (* 64 1024)
          [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
          (start-with-service (fn [^Request req]
                                (ok (str (.transferTo ^java.io.InputStream (.-body req)
                                                      (java.io.OutputStream/nullOutputStream)))))
                              (fn [^com.s_exp.enso.api.Config$Builder b]
                                (.http3InitialMaxDataBytes b initial)))]
      (try
        (h3/with-client [c (.port l)]
          (h3/open-control! c)
          (is (= (str (* 1024 1024)) (h3/body-str (upload! c 0 (* 1024 1024)))))
          (is (= [initial -1] (connection-window (the-connection l))))
          (is (support/await-condition #(do (h3/pump! c 20) (zero? (budget-used service))) 5000 1)))
        (finally
          (.close l)
          (.close timer))))))

(deftest idle-connections-cost-no-budget
  ;; No connection reserves anything at admission: far more connections
  ;; than :max-buffered-bytes could hold windows for are admitted and
  ;; served, and while idle they cost nothing.
  (let [[^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] (ok "ok"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.maxBufferedBytes b (* 1024 1024))
                              (.http3InitialMaxDataBytes b (* 1024 1024))))
        clients (atom [])]
    (try
      (dotimes [_ 16]
        (let [c (h3/connect (.port l))]
          (swap! clients conj c)
          (h3/open-control! c)
          (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))))
      (is (= 16 (count @clients)))
      (is (zero? (budget-used service)))
      (finally
        (run! h3/close! @clients)
        (.close l)
        (.close timer)))))

(deftest default-max-connections-idle-connections-fit-a-small-heap
  ;; With a 1 GiB heap's budget (a quarter of it) every connection
  ;; :max-connections allows (10000) is admitted and, idle, costs nothing.
  (let [[^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] (ok "ok"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.maxBufferedBytes b (* 256 1024 1024))))
        n (.-maxConnections ^com.s_exp.enso.api.Config (.-config ^com.s_exp.enso.core.Service service))]
    (try
      (is (= 10000 n))
      (let [{:keys [established close!]} (h3/storm (.port l) n {})]
        (try
          (is (= n established))
          (is (= n (await-connection-count l n 5000)))
          (is (zero? (budget-used service)))
          (finally (close!))))
      (finally
        (.close l)
        (.close timer)))))

(deftest new-connections-are-refused-while-the-budget-is-exhausted
  ;; At the :max-buffered-bytes limit the server is overloaded: a new
  ;; connection's Initial is dropped before any state ("connection-limit");
  ;; connections are admitted again once the budget has room.
  (let [errors (atom [])
        events (reify com.s_exp.enso.api.ServerEvents
                 (protocolError [_ _ kind] (swap! errors conj kind)))
        [^com.s_exp.enso.http3.Http3Listener l service ^com.s_exp.enso.core.Timer timer]
        (start-with-service (fn [_] (ok "ok"))
                            (fn [^com.s_exp.enso.api.Config$Builder b]
                              (.maxBufferedBytes b (* 1024 1024))
                              (.serverEvents b events)))
        budget ^com.s_exp.enso.core.MemoryBudget (.-budget ^com.s_exp.enso.core.Service service)]
    (try
      (.charge budget (* 3 256 1024))
      (testing "under pressure, below the limit: admitted"
        (h3/with-client [c (.port l)]
          (h3/open-control! c)
          (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))))))
      (.charge budget (* 256 1024))
      (let [refused (h3/start-handshake (.port l))]
        (try
          (is (support/await-condition #(some #{"connection-limit"} @errors) 3000 10) (str @errors))
          (finally (h3/close! refused))))
      (.release budget (* 4 256 1024))
      (h3/with-client [c (.port l)]
        (h3/open-control! c)
        (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/")))) "room again"))
      (finally
        (.close l)
        (.close timer)))))

(deftest stream-body-longer-than-content-length-is-truncated
  ;; As on HTTP/1.1 and HTTP/2: a declared Content-Length bounds what an
  ;; InputStream body sends; the rest is dropped and the response ends
  ;; cleanly.
  (h3/with-server [srv (fn [_] (Response. 200 {"content-length" "3"}
                                          (java.io.ByteArrayInputStream. (.getBytes "hello" "UTF-8"))))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 200 (:status r)))
        (is (= "hel" (h3/body-str r)))
        (is (:fin r))
        (is (nil? (:reset r)))))))

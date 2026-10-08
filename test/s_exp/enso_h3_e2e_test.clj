;; ABOUTME: End-to-end HTTP/3 tests: a raw quiche client (s-exp.h3-client)
;; ABOUTME: exercises the Http3Listener over real QUIC on loopback.
(ns s-exp.enso-h3-e2e-test
  "End-to-end HTTP/3 behaviour that unit tests can't reach: request body
  framing, backpressure, response streaming, stream/connection error
  codes."
  (:require [clojure.test :refer [deftest is testing]]
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

(deftest oversized-field-section-is-stream-error
  ;; RFC 9114 §4.2.2: SETTINGS_MAX_FIELD_SECTION_SIZE bounds the decoded
  ;; section (name + value + 32 per field). Exceeding it resets only
  ;; the offending stream.
  (h3/with-server [srv (fn [_] (ok "fine"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxFieldSectionSize b 1024))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/" ["x-big" (apply str (repeat 2000 "a"))]))]
        (is (= 0x107 (:reset r)) "H3_EXCESSIVE_LOAD stream reset"))
      (is (nil? (h3/peer-error c)) "connection still open")
      (is (= "fine" (h3/body-str (h3/request! c 4 (h3/request-headers "GET" "/"))))))))

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
                                             (alength (.readAllBytes ^java.io.InputStream (.-body req)))])
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
  1 0-RTT, 2 Handshake), `version`, 16-byte random DCID, 8-byte SCID,
  empty token (Initial), junk payload."
  ^bytes [type-bits version size]
  (let [out (java.io.ByteArrayOutputStream.)
        dcid (byte-array 16)
        rnd (java.util.Random.)]
    (.nextBytes rnd dcid)
    (.write out (int (bit-or 0xC0 (bit-shift-left type-bits 4))))
    (.write out (.array (.putInt (java.nio.ByteBuffer/allocate 4) (unchecked-int version))) 0 4)
    (.write out 16)
    (.write out dcid 0 16)
    (.write out 8)
    (.write out (byte-array 8 (byte 1)) 0 8)
    (when (zero? type-bits) (.write out 0))
    (let [head (.toByteArray out)
          pkt (byte-array size)]
      (System/arraycopy head 0 pkt 0 (alength head))
      ;; length varint (2 bytes) covering the rest, then junk
      (let [rest-len (- size (alength head) 2)]
        (aset pkt (alength head) (unchecked-byte (bit-or 0x40 (bit-shift-right rest-len 8))))
        (aset pkt (inc (alength head)) (unchecked-byte rest-len)))
      pkt)))

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

(defn- connection-count [srv]
  (let [f (doto (.getDeclaredField (class srv) "conns") (.setAccessible true))]
    (count (distinct (vals (.get f srv))))))

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

(deftest retry-only-for-full-size-initials
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3StatelessRetry b true))]
    (testing "RFC 9000 §8.1: no Retry (amplification) for a short datagram"
      (is (nil? (reply-to (.port srv) (long-header-packet 0 1 40)))))
    (testing "Retry for a full-size Initial without token"
      (let [^bytes r (reply-to (.port srv) (long-header-packet 0 1 1200))]
        (is (some? r))
        (when r (is (= 0xF0 (bit-and (aget r 0) 0xF0)) "long header, type Retry"))))))

(deftest unestablished-connection-is-reaped
  ;; A client that sends its first Initial and vanishes: with the idle
  ;; timeout disabled quiche never gives up on the handshake, so the
  ;; server must drop the connection at its handshake deadline (10s).
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxIdleTimeoutMs b 0))]
    (let [c (h3/start-handshake (.port srv))]
      (try
        (Thread/sleep 300)
        (is (= 1 (connection-count srv)))
        (Thread/sleep 11000)
        (is (zero? (connection-count srv)))
        (finally (h3/close! c))))))

(deftest websocket-upgrade-response-is-501
  ;; HTTP/3 has no 101 / Upgrade (RFC 9114 §4.5): a handler answering with
  ;; a WebSocket listener gets 501, empty headers, no body.
  (h3/with-server [srv (fn [_]
                         (Response. 101 {"upgrade" "websocket" "x-a" "1"} "ignored"
                                    (reify com.s_exp.enso.websocket.WebSocketListener
                                      (onOpen [_ _])
                                      (onMessage [_ _ _])
                                      (onClose [_ _ _ _]))
                                    nil))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/ws"))]
        (is (= 501 (:status r)))
        (is (= {} (:headers r)))
        (is (zero? (alength ^bytes (:body r))))
        (is (:fin r))))))

(deftest listener-close-stops-demux-before-freeing-config
  ;; The demux thread calls quiche_accept/retry with the shared config:
  ;; it must be gone before the config is freed, and a freed config must
  ;; never hand out its dangling pointer.
  (let [srv (h3/start-server (fn [_] (ok "ok")))
        demux-f (doto (.getDeclaredField (class srv) "demux") (.setAccessible true))
        cfg-f (doto (.getDeclaredField (class srv) "quicheConfig") (.setAccessible true))
        ^Thread demux (.get demux-f srv)
        ^com.s_exp.enso.quiche.QuicheConfig cfg (.get cfg-f srv)]
    (.close srv)
    (is (not (.isAlive demux)) "demux joined by close")
    (is (thrown? IllegalStateException (.handle cfg)) "closed config refuses its handle")))

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

(deftest request-timeout-408
  (h3/with-server [srv (fn [_] (Thread/sleep 3000) (ok "too late"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.requestTimeoutMillis b 200))]
    (h3/with-client [c (.port srv)]
      (h3/open-control! c)
      (let [r (h3/request! c 0 (h3/request-headers "GET" "/"))]
        (is (= 408 (:status r)))
        (is (= "408 request timeout" (h3/body-str r)))))))

(deftest client-initial-larger-than-advertised-payload-size
  ;; RFC 9000 §14.1: the client sizes its Initial datagrams before it has
  ;; seen our transport parameters, so they may exceed our
  ;; max_udp_payload_size (Chrome pads to 1250+). Truncating them on
  ;; receive would fail the handshake.
  (h3/with-server [srv (fn [_] (ok "ok"))
                   (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxUdpPayloadSize b 1200))]
    (h3/with-client [c (.port srv) {:initial-size 1350}]
      (h3/open-control! c)
      (is (= "ok" (h3/body-str (h3/request! c 0 (h3/request-headers "GET" "/"))))))))

(deftest request-body-chunks-larger-than-field-section-limit
  ;; SETTINGS_MAX_FIELD_SECTION_SIZE bounds HEADERS only (RFC 9114
  ;; §4.2.2): body bytes arriving in 16 KiB reads must not count against it.
  (let [body (byte-array (* 64 1024) (byte 9))]
    (h3/with-server [srv echo-handler
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxFieldSectionSize b 8192))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (let [r (h3/request! c 0 (h3/request-headers "POST" "/") body)]
          (is (= 200 (:status r)))
          (is (java.util.Arrays/equals body ^bytes (:body r))))
        (is (nil? (h3/peer-error c)) "connection still open")))))

(deftest unlimited-field-section-size-accepts-large-headers
  ;; :http3-max-field-section-size 0 omits the setting: the peer may send
  ;; field sections larger than the 64 KiB default.
  (let [v (apply str (repeat 150000 "a"))]
    (h3/with-server [srv (fn [^Request req] (ok (str (count (get (.-headers req) "x-big")))))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.http3MaxFieldSectionSize b 0))]
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
        (h3/pump-until! c #(realized? outcome) 2000)
        (is (= 0x10e (:reset (h3/response c 0))) "H3_MESSAGE_ERROR reset")
        (is (= :truncated (deref outcome 0 :handler-still-blocked)))))))

(defn- await-ignoring-interrupts
  "Blocks until `p` is delivered, swallowing interrupts like a handler
  that never checks them."
  [p]
  (loop []
    (when-not (try @p true (catch InterruptedException _ false))
      (recur))))

(defn- recording-body
  "StreamingBody delivering true to `started` when the server runs it."
  [started]
  (reify com.s_exp.enso.api.StreamingBody
    (write [_ w]
      (deliver started true)
      (.write w "x"))))

(deftest body-cap-reset-drops-handler-response
  ;; Once the stream was reset for exceeding :max-request-body-bytes, the
  ;; handler's response is never produced (its streamed body never runs).
  (let [gate (promise)
        returned (promise)
        started (promise)]
    (h3/with-server [srv (fn [_]
                           (await-ignoring-interrupts gate)
                           (deliver returned true)
                           (ok (recording-body started)))
                     (fn [^com.s_exp.enso.api.Config$Builder b] (.maxRequestBodyBytes b 10))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/"))
                                       (h3/data-frame (byte-array 100)))
                  false)
        (h3/pump-until! c #(h3/stream-done? c 0) 2000)
        (is (= 0x10e (:reset (h3/response c 0))))
        (deliver gate true)
        (is (deref returned 2000 false))
        (h3/pump! c 300)
        (is (not (realized? started)) "response body produced for a reset stream")))))

(defn- content-length-mismatch
  "A request that the server resets (body longer than content-length)."
  ^bytes []
  (h3/concat-bytes (h3/headers-frame (h3/request-headers "POST" "/" ["content-length" "1"]))
                   (h3/data-frame (.getBytes "abc"))))

(deftest abandoned-request-interrupts-handler
  ;; A request the server resets is abandoned: its handler is interrupted
  ;; rather than left running until the request timeout.
  (let [exited (promise)]
    (h3/with-server [srv (fn [_]
                           (try @(promise)
                                (catch InterruptedException _ (deliver exited :interrupted)))
                           (ok "x"))]
      (h3/with-client [c (.port srv)]
        (h3/open-control! c)
        (h3/send! c 0 (content-length-mismatch) true)
        (h3/pump-until! c #(h3/stream-done? c 0) 2000)
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
                               :let [sid (* 4 i)]]
                           (do (h3/send! c sid (content-length-mismatch) true)
                               (h3/pump-until! c #(h3/stream-done? c sid) 2000)
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
  ;; (leaking its thread and body source): its response is dropped.
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
      (let [deadline (+ (System/currentTimeMillis) 3000)]
        (while (and (pos? (connection-count srv)) (< (System/currentTimeMillis) deadline))
          (Thread/sleep 20)))
      (is (zero? (connection-count srv)))
      (deliver gate true)
      (is (deref returned 2000 false))
      (Thread/sleep 300)
      (is (or (not (realized? started)) (realized? finished))
          "streamed body blocked on a closed connection"))))

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

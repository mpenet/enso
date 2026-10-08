(ns s-exp.enso-websocket-test
  "Raw-socket WebSocket protocol tests. Uses low-level frame writing so
  we can inject wire-level cases the java.net.http.WebSocket client
  won't produce: control-frame interleave between fragments (#215),
  invalid UTF-8 in text frames (#216), truncated multi-byte at frame
  boundary, unmasked client frame, oversized control frame."
  (:require [clojure.test :refer [deftest testing is]]
            [ring.websocket.protocols :as wsp]
            [s-exp.enso :as enso])
  (:import (com.s_exp.enso.api Response)
           (com.s_exp.enso.websocket WebSocketConnection WebSocketListener WebSocketSocket)
           (java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream EOFException
                    FilterInputStream InputStream)
           (java.lang.management ManagementFactory)
           (java.net Socket SocketTimeoutException)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.util.concurrent CountDownLatch TimeUnit)))

(def ^:dynamic *server* nil)

(defn- with-ws-server [handler f]
  (let [srv (enso/run-server handler {:port 0})]
    (try
      (binding [*server* {:server srv :port (enso/port srv)}]
        (f))
      (finally (enso/stop srv)))))

;; ---- Raw frame helpers ---------------------------------------------------

(def ^:private client-mask
  ;; Fixed mask so tests are deterministic. Server unmasks against
  ;; whatever we send — value doesn't affect correctness.
  (byte-array [(unchecked-byte 0xAA) (unchecked-byte 0xBB)
               (unchecked-byte 0xCC) (unchecked-byte 0xDD)]))

(defn- mask-frame
  "Build one WebSocket client-to-server frame. `opcode` low 4 bits.
  `fin` sets FIN bit. Payload is masked in place per RFC 6455 §5.3.
  Server enforces MASK bit set on all client frames."
  ^bytes [opcode fin ^bytes payload]
  (let [baos (ByteArrayOutputStream.)
        len (alength payload)]
    (.write baos (bit-or (if fin 0x80 0) opcode))
    (cond
      (< len 126) (.write baos (bit-or 0x80 len))
      (< len 65536) (do (.write baos (bit-or 0x80 126))
                        (.write baos (bit-and (bit-shift-right len 8) 0xFF))
                        (.write baos (bit-and len 0xFF)))
      :else (do (.write baos (bit-or 0x80 127))
                (dotimes [i 8]
                  (.write baos (bit-and (bit-shift-right len (* 8 (- 7 i))) 0xFF)))))
    (.write baos client-mask 0 4)
    (dotimes [i len]
      (.write baos (bit-xor (aget payload i) (aget client-mask (bit-and i 3)))))
    (.toByteArray baos)))

(defn- ws-handshake!
  "Perform WS opening handshake on `sock`. Reads response headers into a
  string; asserts 101. Returns the (already-connected) socket streams."
  [^Socket sock]
  (let [out (.getOutputStream sock)
        in (.getInputStream sock)
        req (str "GET / HTTP/1.1\r\n"
                 "Host: 127.0.0.1\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                 "Sec-WebSocket-Version: 13\r\n\r\n")]
    (.write out (.getBytes req StandardCharsets/ISO_8859_1))
    (.flush out)
    ;; Drain response headers until CRLF CRLF.
    (let [rd (StringBuilder.)]
      (loop [prev-cr false prev-crlf false prev-crlfcr false]
        (let [b (.read in)]
          (when (neg? b)
            (throw (EOFException. "handshake closed early")))
          (.append rd (char b))
          (cond
            (and prev-crlfcr (= b 10)) nil
            (and prev-crlf (= b 13)) (recur false false true)
            (and prev-cr (= b 10)) (recur false true false)
            (= b 13) (recur true false false)
            :else (recur false false false))))
      (let [resp (.toString rd)]
        (assert (re-find #"HTTP/1.1 101" resp)
                (str "expected 101, got: " (subs resp 0 (min 200 (count resp)))))))
    [in out]))

(defn- read-frame
  "Read one server-to-client frame. Server frames are unmasked.
  Returns {:opcode :fin? :payload byte[]}. Blocks."
  [^java.io.InputStream in]
  (let [dis (DataInputStream. in)
        b0 (.readUnsignedByte dis)
        b1 (.readUnsignedByte dis)
        opcode (bit-and b0 0x0F)
        fin? (not (zero? (bit-and b0 0x80)))
        len7 (bit-and b1 0x7F)
        len (cond
              (< len7 126) len7
              (= len7 126) (.readUnsignedShort dis)
              :else (.readLong dis))
        payload (byte-array len)]
    (.readFully dis payload)
    {:opcode opcode :fin? fin? :payload payload}))

;; ---- Tests ---------------------------------------------------------------

(deftest ws-control-frame-interleaved-between-fragments
  ;; RFC 6455 §5.4: control frames MAY be interjected between fragments
  ;; of a data message. Server should PONG the interjected PING and then
  ;; accept the following CONTINUATION, delivering the assembled
  ;; message to the listener.
  (let [msg-received (atom nil)
        pong-payload (.getBytes "ping-me" StandardCharsets/UTF_8)]
    (with-ws-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [_])
          :on-message (fn [_ msg] (reset! msg-received (str msg)))
          :on-close (fn [_ _ _])}})
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (let [[in out] (ws-handshake! sock)]
            ;; Fragment 1 of text message.
            (.write ^java.io.OutputStream out
                    (mask-frame 0x1 false (.getBytes "hel" StandardCharsets/UTF_8)))
            ;; PING between fragments — must be processed inline.
            (.write ^java.io.OutputStream out (mask-frame 0x9 true pong-payload))
            ;; Fragment 2: CONTINUATION with FIN.
            (.write ^java.io.OutputStream out
                    (mask-frame 0x0 true (.getBytes "lo" StandardCharsets/UTF_8)))
            (.flush ^java.io.OutputStream out)
            ;; Expect server PONG first (echo of PING payload).
            (let [pong (read-frame in)]
              (is (= 0xA (:opcode pong)) "server auto-pongs PING")
              (is (= (seq pong-payload) (seq (:payload pong)))))
            (Thread/sleep 100)
            (is (= "hello" @msg-received)
                "text message assembled across interleaved PING")))))))

(deftest ws-text-invalid-utf8-closes-1007
  ;; RFC 6455 §5.6 + §8.1: text frame with invalid UTF-8 → CLOSE(1007).
  ;; Autobahn §6.4 requires detection at the offending frame, not at
  ;; end-of-message.
  (with-ws-server
    (fn [_]
      {:ring.websocket/listener
       {:on-open (fn [_])
        :on-message (fn [_ _])
        :on-close (fn [_ _ _])}})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[in out] (ws-handshake! sock)
              ;; 0xC3 0x28 = invalid UTF-8 (continuation byte doesn't
              ;; follow lead byte pattern).
              bad (byte-array [(unchecked-byte 0xC3) (byte 0x28)])]
          (.write ^java.io.OutputStream out (mask-frame 0x1 true bad))
          (.flush ^java.io.OutputStream out)
          (let [close (read-frame in)]
            (is (= 0x8 (:opcode close)) "server sent CLOSE")
            (let [p (:payload close)
                  code (bit-or (bit-shift-left (bit-and (aget p 0) 0xFF) 8)
                               (bit-and (aget p 1) 0xFF))]
              (is (= 1007 code) "close code 1007 = invalid UTF-8"))))))))

(deftest ws-truncated-utf8-at-message-end-closes-1007
  ;; Text frame ends mid-sequence (e.g., 0xC3 without continuation).
  ;; Should CLOSE(1007) on finish() UTF-8 check.
  (with-ws-server
    (fn [_]
      {:ring.websocket/listener
       {:on-open (fn [_])
        :on-message (fn [_ _])
        :on-close (fn [_ _ _])}})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[in out] (ws-handshake! sock)]
          (.write ^java.io.OutputStream out
                  (mask-frame 0x1 true (byte-array [(unchecked-byte 0xC3)])))
          (.flush ^java.io.OutputStream out)
          (let [close (read-frame in)]
            (is (= 0x8 (:opcode close)))
            (let [p (:payload close)
                  code (bit-or (bit-shift-left (bit-and (aget p 0) 0xFF) 8)
                               (bit-and (aget p 1) 0xFF))]
              (is (= 1007 code)))))))))

(deftest ws-utf8-split-across-fragments-accepted
  ;; Multi-byte codepoint split across fragments MUST decode correctly
  ;; (Autobahn §6.4.1-6.4.4). Send "€" (0xE2 0x82 0xAC) as two fragments.
  (let [msg (atom nil)
        got (CountDownLatch. 1)]
    (with-ws-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [_])
          :on-message (fn [_ m]
                        (reset! msg (str m))
                        (.countDown got))
          :on-close (fn [_ _ _])}})
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (let [[in out] (ws-handshake! sock)]
            (.write ^java.io.OutputStream out
                    (mask-frame 0x1 false (byte-array [(unchecked-byte 0xE2)])))
            (.write ^java.io.OutputStream out
                    (mask-frame 0x0 true (byte-array [(unchecked-byte 0x82) (unchecked-byte 0xAC)])))
            (.flush ^java.io.OutputStream out)
            (is (.await got 2 TimeUnit/SECONDS) "message delivered")
            (is (= "€" @msg) "codepoint split across 2 fragments assembles")))))))

(deftest ws-unmasked-client-frame-rejected
  ;; RFC 6455 §5.1: client-to-server frames MUST be masked. Unmasked
  ;; text frame → protocol error, connection dropped.
  (with-ws-server
    (fn [_]
      {:ring.websocket/listener
       {:on-open (fn [_])
        :on-message (fn [_ _])
        :on-close (fn [_ _ _])}})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[in out] (ws-handshake! sock)
              ;; hand-built unmasked frame: FIN+text, len=2, "ab".
              frame (byte-array [(unchecked-byte 0x81) (byte 0x02) (byte 0x61) (byte 0x62)])]
          (.write ^java.io.OutputStream out frame)
          (.flush ^java.io.OutputStream out)
          ;; Server drops the connection — read may return EOF, send a
          ;; CLOSE frame first, or the socket-reset may surface as
          ;; SocketException. Any of those = correct rejection.
          (Thread/sleep 100)
          (let [outcome (try
                          (let [b (.read ^java.io.InputStream in)]
                            (cond (neg? b) :eof
                                  (= 0x88 b) :close-frame
                                  :else :other))
                          (catch java.io.IOException _ :reset))]
            (is (contains? #{:eof :close-frame :reset} outcome)
                (str "unmasked frame → rejected, got " outcome))))))))

(deftest ws-oversized-control-frame-rejected
  ;; RFC 6455 §5.5: control frames MUST have payload ≤ 125 bytes.
  ;; 200-byte PING → protocol error.
  (with-ws-server
    (fn [_]
      {:ring.websocket/listener
       {:on-open (fn [_])
        :on-message (fn [_ _])
        :on-close (fn [_ _ _])}})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[in out] (ws-handshake! sock)
              big (byte-array 200)]
          (.write ^java.io.OutputStream out (mask-frame 0x9 true big))
          (.flush ^java.io.OutputStream out)
          (Thread/sleep 100)
          (let [outcome (try
                          (let [b (.read ^java.io.InputStream in)]
                            (cond (neg? b) :eof
                                  (= 0x88 b) :close-frame
                                  :else :other))
                          (catch java.io.IOException _ :reset))]
            (is (contains? #{:eof :close-frame :reset} outcome)
                (str "oversized PING → rejected, got " outcome))))))))

(deftest ws-close-invalid-utf8-in-reason-rejected
  ;; RFC 6455 §7.1.6: CLOSE reason MUST be UTF-8. Client CLOSE with
  ;; invalid UTF-8 in reason → server responds with CLOSE(1007).
  (with-ws-server
    (fn [_]
      {:ring.websocket/listener
       {:on-open (fn [_])
        :on-message (fn [_ _])
        :on-close (fn [_ _ _])}})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (let [[in out] (ws-handshake! sock)
              ;; 2-byte code (1000) + invalid UTF-8 payload.
              payload (byte-array [(byte 0x03) (unchecked-byte 0xE8)
                                   (unchecked-byte 0xC3) (byte 0x28)])]
          (.write ^java.io.OutputStream out (mask-frame 0x8 true payload))
          (.flush ^java.io.OutputStream out)
          (let [close (read-frame in)]
            (is (= 0x8 (:opcode close)))
            (let [p (:payload close)
                  code (bit-or (bit-shift-left (bit-and (aget p 0) 0xFF) 8)
                               (bit-and (aget p 1) 0xFF))]
              (is (= 1007 code) "invalid UTF-8 in CLOSE reason → 1007"))))))))

;; ---- In-memory connection harness -----------------------------------------
;;
;; Drives a WebSocketConnection directly over byte streams on the calling
;; thread: the client side is a pre-built byte[] of masked frames, the
;; server's writes land in a ByteArrayOutputStream. Deterministic, no
;; network, and lets us measure the reader thread's allocations.

(defn- frames
  "Concatenates masked client frames. Each spec is [opcode fin payload]."
  ^bytes [& specs]
  (let [baos (ByteArrayOutputStream.)]
    (doseq [[opcode fin payload] specs]
      (.write baos ^bytes (mask-frame opcode fin payload)))
    (.toByteArray baos)))

(defn- utf8 ^bytes [^String s] (.getBytes s StandardCharsets/UTF_8))

(defn- close-payload
  ^bytes [code ^String reason]
  (let [r (utf8 reason)
        p (byte-array (+ 2 (alength r)))]
    (aset p 0 (unchecked-byte (bit-shift-right code 8)))
    (aset p 1 (unchecked-byte (bit-and code 0xFF)))
    (System/arraycopy r 0 p 2 (alength r))
    p))

(defn- parse-frames
  "Parses server (unmasked) frames from `bs` into [{:opcode :fin? :payload}]."
  [^bytes bs]
  (let [in (ByteArrayInputStream. bs)]
    (loop [acc []]
      (if (pos? (.available in))
        (let [f (read-frame in)]
          (recur (conj acc (update f :payload vec))))
        acc))))

(defn- close-code [{:keys [payload]}]
  (when (>= (count payload) 2)
    (bit-or (bit-shift-left (bit-and (nth payload 0) 0xFF) 8)
            (bit-and (nth payload 1) 0xFF))))

(defn- thread-allocated-bytes ^long []
  (.getCurrentThreadAllocatedBytes
   ^com.sun.management.ThreadMXBean (ManagementFactory/getThreadMXBean)))

(defn- buffer->vec [^ByteBuffer bb]
  (let [a (byte-array (.remaining bb))]
    (.get (.duplicate bb) a)
    (vec a)))

(defn- run-ws
  "Runs a WebSocketConnection to completion over `in` on the calling
  thread. `on-open` is called with the WebSocketSocket. Returns
  {:frames :events}."
  [^InputStream in {:keys [max-message on-open on-message out]
                    :or {max-message 1048576}}]
  (let [events (atom [])
        ^ByteArrayOutputStream out (or out (ByteArrayOutputStream.))
        listener (reify WebSocketListener
                   (onOpen [_ s] (when on-open (on-open s)))
                   (onMessage [_ s m]
                     (if on-message
                       (on-message s m)
                       (swap! events conj [:message (if (instance? ByteBuffer m)
                                                      (buffer->vec m)
                                                      m)])))
                   (onError [_ _ t] (swap! events conj [:error t]))
                   (onClose [_ _ code reason] (swap! events conj [:close code reason])))
        conn (WebSocketConnection. (Socket.) in out listener (int max-message))]
    (.run conn)
    {:frames (parse-frames (.toByteArray out))
     :events @events}))

(defn- run-ws-bytes [^bytes input opts]
  (run-ws (ByteArrayInputStream. input) opts))

(defn- server-close-codes [result]
  (mapv close-code (filter #(= 0x8 (:opcode %)) (:frames result))))

(defn- close-event [result]
  (some #(when (= :close (first %)) %) (:events result)))

(deftest ws-empty-close-echoed-empty
  ;; RFC 6455 §7.4.1: 1005 MUST NOT be sent on the wire. An empty CLOSE
  ;; is answered with an empty CLOSE; the listener sees 1005.
  (let [r (run-ws-bytes (frames [0x8 true (byte-array 0)]) {})
        [f :as fs] (:frames r)]
    (is (= 1 (count fs)))
    (is (= 0x8 (:opcode f)))
    (is (= [] (:payload f)) "echoed CLOSE has empty payload")
    (is (= [:close 1005 ""] (close-event r)))))

(deftest ws-received-close-code-validation
  ;; RFC 6455 §7.4: codes outside the allowed ranges are a protocol error.
  (testing "invalid codes fail with 1002"
    (doseq [code [0 999 1004 1005 1006 1015 1016 2999 5000 65535]]
      (let [r (run-ws-bytes (frames [0x8 true (close-payload code "")]) {})]
        (is (= [1002] (server-close-codes r)) (str "code " code))
        (is (= 1002 (second (close-event r))) (str "code " code)))))
  (testing "valid codes are echoed"
    (doseq [code [1000 1001 1002 1003 1007 1008 1009 1010 1011 1012 1013 1014 3000 4999]]
      (let [r (run-ws-bytes (frames [0x8 true (close-payload code "x")]) {})]
        (is (= [code] (server-close-codes r)) (str "code " code))
        (is (= [:close code "x"] (close-event r)) (str "code " code))))))

(deftest ws-protocol-violations-send-close
  ;; RFC 6455 §7.1.7: failing the connection sends CLOSE with the
  ;; matching status code before dropping TCP.
  (let [unmasked (byte-array [(unchecked-byte 0x81) (byte 0x02) (byte 0x61) (byte 0x62)])
        rsv (let [f (mask-frame 0x1 true (utf8 "ab"))]
              (aset f 0 (unchecked-byte (bit-or 0x40 (aget f 0))))
              f)
        huge-len-msb (byte-array [(unchecked-byte 0x82) (unchecked-byte 0xFF)
                                  (unchecked-byte 0x80) 0 0 0 0 0 0 1
                                  0 0 0 0])]
    (doseq [[label input expected]
            [["rsv bit" rsv 1002]
             ["unmasked" unmasked 1002]
             ["reserved data opcode" (frames [0x3 true (byte-array 0)]) 1002]
             ["reserved control opcode" (frames [0xB true (byte-array 0)]) 1002]
             ["fragmented control" (frames [0x9 false (byte-array 0)]) 1002]
             ["oversized control" (frames [0x9 true (byte-array 126)]) 1002]
             ["continuation without start" (frames [0x0 true (utf8 "x")]) 1002]
             ["data frame mid-fragment" (frames [0x1 false (utf8 "a")] [0x1 true (utf8 "b")]) 1002]
             ["1-byte close payload" (frames [0x8 true (byte-array 1)]) 1002]
             ["64-bit length with MSB set" huge-len-msb 1002]
             ["single frame too big" (frames [0x2 true (byte-array 2000)]) 1009]
             ["fragments too big" (frames [0x2 false (byte-array 600)] [0x0 true (byte-array 600)]) 1009]
             ["invalid utf-8" (frames [0x1 true (byte-array [(unchecked-byte 0xC3) 0x28])]) 1007]]]
      (let [r (run-ws-bytes input {:max-message 1024})]
        (is (= [expected] (server-close-codes r)) label)
        (is (= expected (second (close-event r))) label)
        (is (some #(= :error (first %)) (:events r)) label)))))

(deftest ws-frame-length-overflow-rejected
  ;; Fragment lengths summing past Integer/MAX_VALUE must not wrap the
  ;; accumulator's bounds check.
  (let [hdr (byte-array [(unchecked-byte 0x00) (unchecked-byte 0xFF)
                         0 0 0 0 (unchecked-byte 0x7F) (unchecked-byte 0xFF)
                         (unchecked-byte 0xFF) (unchecked-byte 0xFF)
                         0 0 0 0])
        input (byte-array (concat (frames [0x2 false (byte-array 10)]) hdr))
        r (run-ws-bytes input {:max-message Integer/MAX_VALUE})]
    (is (= [1009] (server-close-codes r)))))

(deftest ws-claimed-length-not-preallocated
  ;; A header claiming a large payload must not allocate it before the
  ;; bytes arrive: 14-byte header claiming 8 MiB, then 100 bytes, then EOF.
  (let [hdr (byte-array [(unchecked-byte 0x82) (unchecked-byte 0xFF)
                         0 0 0 0 0 (unchecked-byte 0x80) 0 0
                         0 0 0 0])
        input (byte-array (concat hdr (repeat 100 (byte 1))))
        before (thread-allocated-bytes)
        r (run-ws-bytes input {:max-message (* 16 1024 1024)})
        allocated (- (thread-allocated-bytes) before)]
    (is (= 1006 (second (close-event r))))
    (is (< allocated (* 1024 1024)) (str "allocated " allocated " bytes"))))

(deftest ws-messages-roundtrip-across-chunks
  ;; Unmasking must keep the mask phase across buffered reads, for odd
  ;; frame sizes and payloads larger than any internal read chunk.
  (let [payloads (concat (map #(byte-array (map unchecked-byte (range %))) (range 0 40))
                         [(byte-array (map unchecked-byte (range 200001)))])
        input (apply frames (map #(vector 0x2 true %) payloads))
        r (run-ws-bytes input {:max-message (* 1024 1024)})]
    (is (= (map vec payloads)
           (keep #(when (= :message (first %)) (second %)) (:events r))))
    (testing "fragmented text with codepoints split at every offset"
      (let [s "a€b😀c"
            bs (utf8 s)
            n (alength bs)]
        (doseq [i (range 1 n)]
          (let [r (run-ws-bytes (frames [0x1 false (java.util.Arrays/copyOfRange bs 0 (int i))]
                                        [0x0 true (java.util.Arrays/copyOfRange bs (int i) n)])
                                {})]
            (is (= [[:message s]] (filterv #(= :message (first %)) (:events r)))
                (str "split at " i))))))))

(deftest ws-frame-headers-read-buffered
  ;; Frame headers must not be read one byte at a time off the stream.
  (let [single-reads (atom 0)
        reads (atom 0)
        input (apply frames (repeat 100 [0x1 true (utf8 "hi")]))
        in (proxy [FilterInputStream] [(ByteArrayInputStream. input)]
             (read
               ([] (swap! single-reads inc) (proxy-super read))
               ([b off len] (swap! reads inc) (proxy-super read b off len))))
        r (run-ws in {})]
    (is (= 100 (count (filter #(= :message (first %)) (:events r)))))
    (is (zero? @single-reads))
    (is (< @reads 10) (str @reads " bulk reads"))))

(deftest ws-text-message-allocation
  ;; A single-frame text message should cost about one String, not extra
  ;; intermediate copies of the payload.
  (let [n 100
        size 20000
        msg (byte-array size (byte 0x61))
        input (apply frames (repeat n [0x1 true msg]))
        in (ByteArrayInputStream. input)
        before (thread-allocated-bytes)
        r (run-ws in {:on-message (fn [_ _])})
        allocated (- (thread-allocated-bytes) before)]
    (is (= 1006 (second (close-event r))))
    (is (< allocated (* 1.5 n size)) (str "allocated " allocated " bytes"))))

(deftest ws-send-binary-does-not-copy
  (let [n 100
        size 20000
        bb (ByteBuffer/wrap (byte-array size))
        allocated (atom nil)
        r (run-ws-bytes (byte-array 0)
                        {:out (ByteArrayOutputStream. (int (* 2 n size)))
                         :on-open (fn [^WebSocketSocket s]
                                    (let [before (thread-allocated-bytes)]
                                      (dotimes [_ n] (.sendBinary s bb))
                                      (reset! allocated (- (thread-allocated-bytes) before))))})]
    (is (= n (count (:frames r))))
    (is (= 0 (.position bb)) "caller's buffer position untouched")
    (is (< @allocated (* 0.5 n size)) (str "allocated " @allocated " bytes"))))

(deftest ws-send-validation
  (let [errors (atom {})
        try! (fn [k f] (try (f) (swap! errors assoc k :ok)
                            (catch IllegalArgumentException _ (swap! errors assoc k :iae))))
        r (run-ws-bytes (byte-array 0)
                        {:on-open (fn [^WebSocketSocket s]
                                    (try! :ping-126 #(.sendPing s (ByteBuffer/allocate 126)))
                                    (try! :pong-126 #(.sendPong s (ByteBuffer/allocate 126)))
                                    (try! :ping-125 #(.sendPing s (ByteBuffer/allocate 125)))
                                    (try! :reason-124 #(.close s 1000 (apply str (repeat 124 "a"))))
                                    (try! :reason-multibyte #(.close s 1000 (apply str (repeat 62 "é"))))
                                    (try! :code-1005 #(.close s 1005 ""))
                                    (try! :code-1006 #(.close s 1006 ""))
                                    (try! :code-1015 #(.close s 1015 ""))
                                    (try! :code-999 #(.close s 999 ""))
                                    (try! :code-5000 #(.close s 5000 "")))})]
    (is (= {:ping-126 :iae :pong-126 :iae :ping-125 :ok :reason-124 :iae
            :reason-multibyte :iae :code-1005 :iae :code-1006 :iae :code-1015 :iae
            :code-999 :iae :code-5000 :iae}
           @errors))
    (is (= [0x9] (mapv :opcode (:frames r))) "only the valid ping was written")))

(deftest ws-server-close-waits-for-peer-close
  ;; RFC 6455 §7.1.2-7.1.4: server-initiated close sends CLOSE, keeps
  ;; reading until the peer's CLOSE, then closes TCP. The listener sees
  ;; the peer's close code and no error.
  (testing "in-memory"
    (let [r (run-ws-bytes (frames [0x1 true (utf8 "late")]
                                  [0x8 true (close-payload 4000 "bye")])
                          {:on-open (fn [^WebSocketSocket s] (.close s 4000 "bye"))})]
      (is (= [4000] (server-close-codes r)) "exactly one CLOSE sent")
      (is (= [[:close 4000 "bye"]] (:events r)) "no error, no late message")))
  (testing "over TCP"
    (let [events (atom [])
          closed (CountDownLatch. 1)]
      (with-ws-server
        (fn [_]
          {:ring.websocket/listener
           {:on-open (fn [^WebSocketSocket s] (.close s 4000 "bye"))
            :on-error (fn [_ t] (swap! events conj [:error t]))
            :on-close (fn [_ code reason]
                        (swap! events conj [:close code reason])
                        (.countDown closed))}})
        (fn []
          (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
            (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
                  f (read-frame in)]
              (is (= 0x8 (:opcode f)))
              (is (= 4000 (close-code (update f :payload vec))))
              (.setSoTimeout sock 300)
              (is (thrown? SocketTimeoutException (.read ^InputStream in))
                  "TCP stays open until the peer's CLOSE")
              (.setSoTimeout sock 2000)
              (.write out (mask-frame 0x8 true (close-payload 4000 "bye")))
              (.flush out)
              (is (= -1 (.read ^InputStream in)) "server closes TCP after peer CLOSE")
              (is (.await closed 2 TimeUnit/SECONDS))
              (is (= [[:close 4000 "bye"]] @events)))))))))

(deftest ws-close-not-blocked-by-stalled-writer
  ;; A writer blocked on a peer that stopped reading holds the write lock.
  ;; close from another thread must still complete in bounded time and
  ;; unblock that writer.
  (let [sock-p (promise)
        writer-done (promise)]
    (with-ws-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [^WebSocketSocket s]
                     (deliver sock-p s)
                     (Thread/startVirtualThread
                      (fn []
                        (try
                          (let [chunk (ByteBuffer/allocate (* 1024 1024))]
                            (while (.isOpen s)
                              (.sendBinary s (.duplicate chunk))))
                          (deliver writer-done :closed)
                          (catch java.io.IOException _ (deliver writer-done :io-error))))))
          :on-close (fn [_ _ _])}})
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (ws-handshake! sock)
          (let [^WebSocketSocket s (deref sock-p 2000 nil)]
            (is s)
            ;; Let the writer fill the socket buffers and block.
            (Thread/sleep 500)
            (let [closer (future (.close s 1000 "") :returned)]
              (is (= :returned (deref closer 10000 :timed-out))
                  "close returns despite the stalled writer")
              (is (contains? #{:closed :io-error} (deref writer-done 10000 :timed-out))
                  "stalled writer is released"))))))))

(deftest ws-on-open-failure-reaches-on-close-when-on-error-throws
  ;; A throwing onOpen and a throwing onError must still end with CLOSE
  ;; 1011 and onClose, without the exception escaping run().
  (let [events (atom [])
        out (ByteArrayOutputStream.)
        listener (reify WebSocketListener
                   (onOpen [_ _] (throw (RuntimeException. "open failed")))
                   (onError [_ _ _] (swap! events conj :error) (throw (RuntimeException. "error failed")))
                   (onClose [_ _ code _] (swap! events conj [:close code])))
        conn (WebSocketConnection. (Socket.) (ByteArrayInputStream. (byte-array 0)) out listener (int 1024))]
    (is (nil? (.run conn)))
    (is (= [1011] (mapv close-code (parse-frames (.toByteArray out)))))
    (is (= [:error [:close 1011]] @events))))

(deftest ws-server-stop-sends-close-1001
  ;; Graceful stop runs the closing handshake on open WebSockets instead
  ;; of waiting out :shutdown-timeout and dropping TCP.
  (let [closed (promise)
        srv (enso/run-server
             (fn [_]
               {:ring.websocket/listener
                {:on-close (fn [_ code reason] (deliver closed [code reason]))}})
             {:port 0 :shutdown-timeout 5000})]
    (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
      (.setSoTimeout sock 8000)
      (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
            t0 (System/nanoTime)
            stopped (future (enso/stop srv) :stopped)
            f (update (read-frame in) :payload vec)]
        (is (= 0x8 (:opcode f)))
        (is (= 1001 (close-code f)))
        (.write out (mask-frame 0x8 true (close-payload 1001 "")))
        (.flush out)
        (is (= :stopped (deref stopped 8000 :timed-out)))
        (is (< (/ (- (System/nanoTime) t0) 1e6) 2000) "stop did not wait out the shutdown timeout")
        (is (= [1001 ""] (deref closed 1000 :timed-out)))))))

;; ---- Ring websocket protocols ---------------------------------------------

(defrecord EchoListener [events]
  wsp/Listener
  (on-open [_ socket]
    (swap! events conj [:open (wsp/-open? socket)]))
  (on-message [_ socket message]
    (swap! events conj [:message message])
    (case message
      "bin" (wsp/-send socket (ByteBuffer/wrap (utf8 "bytes")))
      "ping" (wsp/-ping socket (utf8 "p"))
      "pong" (wsp/-pong socket (ByteBuffer/wrap (utf8 "q")))
      "async" (wsp/-send-async socket "async-ok"
                               #(swap! events conj [:sent])
                               #(swap! events conj [:failed %]))
      "close" (wsp/-close socket 4001 "done")
      (wsp/-send socket (str "echo: " message))))
  (on-pong [_ _ data]
    (swap! events conj [:pong (buffer->vec data)]))
  (on-error [_ _ t]
    (swap! events conj [:error t]))
  (on-close [_ _ code reason]
    (swap! events conj [:close code reason]))
  wsp/PingListener
  (on-ping [_ _ data]
    (swap! events conj [:ping (buffer->vec data)])))

(defn- frame-text [{:keys [payload]}]
  (String. (byte-array payload) StandardCharsets/UTF_8))

(deftest ws-ring-protocol-listener-and-socket
  ;; ring.websocket.protocols/Listener implementations (not just maps)
  ;; receive events, and the socket they get satisfies Socket and
  ;; AsyncSocket.
  (let [events (atom [])]
    (with-ws-server
      (fn [_] {:ring.websocket/listener (->EchoListener events)})
      (fn []
        (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
          (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
                roundtrip (fn [^String msg]
                            (.write out (mask-frame 0x1 true (utf8 msg)))
                            (.flush out)
                            (update (read-frame in) :payload vec))]
            (is (= [0x1 "echo: hi"] ((juxt :opcode frame-text) (roundtrip "hi"))))
            (is (= [0x2 "bytes"] ((juxt :opcode frame-text) (roundtrip "bin"))))
            (is (= [0x9 "p"] ((juxt :opcode frame-text) (roundtrip "ping"))))
            (is (= [0xA "q"] ((juxt :opcode frame-text) (roundtrip "pong"))))
            (is (= [0x1 "async-ok"] ((juxt :opcode frame-text) (roundtrip "async"))))
            (.write out (mask-frame 0x9 true (utf8 "cp")))
            (.write out (mask-frame 0xA true (utf8 "cq")))
            (.flush out)
            (let [f (roundtrip "close")]
              (is (= 0x8 (:opcode f)))
              (is (= 4001 (close-code f))))
            (.write out (mask-frame 0x8 true (close-payload 4001 "")))
            (.flush out)
            (is (= -1 (.read ^InputStream in)))
            (Thread/sleep 100)
            (is (= [[:open true]
                    [:message "hi"] [:message "bin"] [:message "ping"]
                    [:message "pong"] [:message "async"] [:sent]
                    [:ping (vec (utf8 "cp"))] [:pong (vec (utf8 "cq"))]
                    [:message "close"] [:close 4001 ""]]
                   @events))))))))

(deftest ws-unsupported-listener-rejected
  ;; A listener that is neither a map nor a Listener implementation must
  ;; fail loudly rather than silently ignore every event.
  (with-ws-server
    (fn [_] {:ring.websocket/listener (Object.)})
    (fn []
      (with-open [sock (Socket. "127.0.0.1" (int (:port *server*)))]
        (is (thrown-with-msg? AssertionError #"HTTP/1.1 500"
                              (ws-handshake! sock)))))))

(deftest ws-response-keeps-headers
  ;; Upgrade responses may carry headers (e.g. Set-Cookie).
  (let [^Response r (#'enso/->response {:ring.websocket/listener {}
                                        :ring.websocket/protocol "chat"
                                        :headers {"set-cookie" "a=1"}})]
    (is (= 101 (.status r)))
    (is (= {"set-cookie" "a=1"} (.headers r)))
    (is (= "chat" (.webSocketProtocol r)))
    (is (some? (.webSocketListener r)))))

(deftest ws-send-large-frame-length-encoding
  ;; Frames of 64 KiB and more use the 8-byte extended length.
  (let [size 70000
        out (ByteArrayOutputStream.)
        r (run-ws-bytes (byte-array 0)
                        {:out out
                         :on-open (fn [^WebSocketSocket s]
                                    (.sendBinary s (ByteBuffer/wrap (byte-array size (byte 7)))))})
        [f :as fs] (:frames r)]
    (is (= [0x82 127 0 0 0 0 0 1 0x11 0x70]
           (take 10 (map #(bit-and % 0xFF) (.toByteArray out))))
        "FIN|binary, 127, 64-bit big-endian length 70000")
    (is (= 1 (count fs)))
    (is (= size (count (:payload f))))))

(deftest ws-idle-timeout-sends-close-1001
  ;; :idle-timeout bounds how long a WebSocket may stay quiet. When it
  ;; passes the server closes cleanly with 1001 instead of dropping TCP.
  (let [events (atom [])
        closed (CountDownLatch. 1)
        srv (enso/run-server
             (fn [_]
               {:ring.websocket/listener
                {:on-error (fn [_ t] (swap! events conj [:error t]))
                 :on-close (fn [_ code reason]
                             (swap! events conj [:close code reason])
                             (.countDown closed))}})
             {:port 0 :idle-timeout 300})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (.setSoTimeout sock 3000)
        (let [[in] (ws-handshake! sock)
              f (update (read-frame in) :payload vec)]
          (is (= 0x8 (:opcode f)))
          (is (= 1001 (close-code f)))
          (is (= "idle timeout" (String. (byte-array (drop 2 (:payload f))) StandardCharsets/UTF_8)))
          (is (.await closed 2 TimeUnit/SECONDS))
          (is (= [[:close 1001 "idle timeout"]] @events))))
      (finally (enso/stop srv)))))

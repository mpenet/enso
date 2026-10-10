;; ABOUTME: WebSocket protocol tests using raw frames to inject wire-level cases (fragmentation, UTF-8,
;; ABOUTME: masking, control frames), plus send queueing, timeouts, close handshake and permessage-deflate.
(ns s-exp.enso-websocket-test
  "Raw-socket WebSocket protocol tests. Uses low-level frame writing so
  we can inject wire-level cases the java.net.http.WebSocket client
  won't produce: control-frame interleave between fragments,
  invalid UTF-8 in text frames, truncated multi-byte at frame
  boundary, unmasked client frame, oversized control frame."
  (:require [clojure.test :refer [deftest testing is]]
            [ring.websocket.protocols :as wsp]
            [s-exp.enso :as enso]
            [s-exp.enso-test-support :as support])
  (:import (com.s_exp.enso.api Config Response WebSocketException WebSocketListener WebSocketSocket
                               WebSocketSocket$SendCallback)
           (com.s_exp.enso.core MemoryBudget Timer)
           (com.s_exp.enso.websocket PerMessageDeflate Utf8 WebSocketConnection ZlibPool)
           (java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream EOFException
                    FilterInputStream InputStream SequenceInputStream)
           (java.lang.management ManagementFactory)
           (java.lang.reflect Method)
           (java.net Socket SocketTimeoutException)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.util.concurrent CountDownLatch TimeUnit)
           (java.util.concurrent.locks ReentrantLock)))

(def ^:dynamic *server* nil)

;; Close timers of WebSocketConnections driven directly over byte streams.
(defonce ^:private test-timer (com.s_exp.enso.core.Timer.))

(defn- ws-config
  "Config for a WebSocketConnection driven over byte streams: no socket
  timeouts unless given."
  ^Config [{:keys [max-message idle-timeout read-timeout close-timeout max-queued]
            :or {max-message 1048576 idle-timeout 0 read-timeout 0 close-timeout 5000
                 max-queued 1048576}}]
  (-> (Config/builder)
      (.wsMaxMessageBytes (int max-message))
      (.idleTimeoutMillis (int idle-timeout))
      (.readTimeoutMillis (int read-timeout))
      (.wsCloseTimeoutMillis (int close-timeout))
      (.wsMaxQueuedBytes (int max-queued))
      (.build)))

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

(defn- ws-handshake-response
  "Sends a WS opening handshake on `sock` with `extra-headers` (a map) and
  reads the response head up to CRLF CRLF. Returns it as a string."
  ^String [^Socket sock extra-headers]
  (let [out (.getOutputStream sock)
        in (.getInputStream sock)
        req (str "GET / HTTP/1.1\r\n"
                 "Host: 127.0.0.1\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                 "Sec-WebSocket-Version: 13\r\n"
                 (apply str (for [[k v] extra-headers] (str k ": " v "\r\n")))
                 "\r\n")]
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
      (.toString rd))))

(defn- ws-handshake!
  "Perform WS opening handshake on `sock`. Reads response headers into a
  string; asserts 101. Returns the (already-connected) socket streams."
  ([sock] (ws-handshake! sock {}))
  ([^Socket sock extra-headers]
   (let [resp (ws-handshake-response sock extra-headers)]
     (assert (re-find #"HTTP/1.1 101" resp)
             (str "expected 101, got: " (subs resp 0 (min 200 (count resp)))))
     [(.getInputStream sock) (.getOutputStream sock)])))

(defn- read-frame
  "Read one server-to-client frame. Server frames are unmasked.
  Returns {:opcode :fin? :rsv1? :payload byte[]}. Blocks."
  [^java.io.InputStream in]
  (let [dis (DataInputStream. in)
        b0 (.readUnsignedByte dis)
        b1 (.readUnsignedByte dis)
        opcode (bit-and b0 0x0F)
        fin? (not (zero? (bit-and b0 0x80)))
        rsv1? (not (zero? (bit-and b0 0x40)))
        len7 (bit-and b1 0x7F)
        len (cond
              (< len7 126) len7
              (= len7 126) (.readUnsignedShort dis)
              :else (.readLong dis))
        payload (byte-array len)]
    (.readFully dis payload)
    {:opcode opcode :fin? fin? :rsv1? rsv1? :payload payload}))

(defn- close-code [{:keys [payload]}]
  (when (>= (count payload) 2)
    (bit-or (bit-shift-left (bit-and (nth payload 0) 0xFF) 8)
            (bit-and (nth payload 1) 0xFF))))

(defn- field-value
  "Value of the (private) field `field` declared by `obj`'s class or a superclass."
  [obj ^String field]
  (loop [^Class c (class obj)]
    (if-let [f (try (.getDeclaredField c field) (catch NoSuchFieldException _ nil))]
      (.get (doto ^java.lang.reflect.Field f (.setAccessible true)) obj)
      (recur (.getSuperclass c)))))

;; ---- Tests ---------------------------------------------------------------

(deftest ws-control-frame-interleaved-between-fragments
  ;; RFC 6455 §5.4: control frames MAY be interjected between fragments
  ;; of a data message. Server should PONG the interjected PING and then
  ;; accept the following CONTINUATION, delivering the assembled
  ;; message to the listener.
  (let [msg-received (promise)
        pong-payload (.getBytes "ping-me" StandardCharsets/UTF_8)]
    (with-ws-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [_])
          :on-message (fn [_ msg] (deliver msg-received (str msg)))
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
            (is (= "hello" (deref msg-received 2000 :timed-out))
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
          ;; The server fails the connection with CLOSE 1002, half-closes
          ;; and drains, so the CLOSE arrives before EOF instead of being
          ;; lost to a reset.
          (.setSoTimeout sock 3000)
          (let [f (update (read-frame in) :payload vec)]
            (is (= 0x8 (:opcode f)))
            (is (= 1002 (close-code f))))
          (is (= -1 (.read ^java.io.InputStream in))))))))

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
          (.setSoTimeout sock 3000)
          (let [f (update (read-frame in) :payload vec)]
            (is (= 0x8 (:opcode f)))
            (is (= 1002 (close-code f))))
          (is (= -1 (.read ^java.io.InputStream in))))))))

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

(defn- thread-allocated-bytes ^long []
  (.getCurrentThreadAllocatedBytes
   ^com.sun.management.ThreadMXBean (ManagementFactory/getThreadMXBean)))

(defn- buffer->vec [^ByteBuffer bb]
  (let [a (byte-array (.remaining bb))]
    (.get (.duplicate bb) a)
    (vec a)))

(defn- run-ws
  "Runs a WebSocketConnection to completion over `in` on the calling
  thread. `on-open` is called with the WebSocketSocket. The server writes
  to `out`; frames are parsed from `sink` (default: `out` when it is a
  ByteArrayOutputStream). Returns {:frames :events}."
  [^InputStream in {:keys [on-open on-message out sink deflate budget] :as opts}]
  (let [events (atom [])
        ^java.io.OutputStream out (or out (ByteArrayOutputStream.))
        ^ByteArrayOutputStream sink (or sink (when (instance? ByteArrayOutputStream out) out))
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
        conn (WebSocketConnection. (Socket.) in out listener (ws-config opts) deflate test-timer
                                   (or budget (MemoryBudget. Long/MAX_VALUE)))]
    (.run conn)
    {:frames (if sink (parse-frames (.toByteArray sink)) [])
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

(deftest ws-fragmented-text-assembles-in-bytes
  ;; Text is assembled as UTF-8 bytes (validated as they arrive) and
  ;; decoded once: no char buffer twice the message size on the way.
  (let [size 200000
        part (byte-array (quot size 4) (byte 0x61))
        input (frames [0x1 false part] [0x0 false part] [0x0 false part] [0x0 true part])
        in (ByteArrayInputStream. input)
        before (thread-allocated-bytes)
        r (run-ws in {:on-message (fn [_ _])})
        allocated (- (thread-allocated-bytes) before)]
    (is (= 1006 (second (close-event r))))
    (is (< allocated (* 3 size)) (str "allocated " allocated " bytes"))))

(defn- jdk-valid-utf8? [^bytes bs]
  (try
    (-> (.newDecoder StandardCharsets/UTF_8)
        (.onMalformedInput java.nio.charset.CodingErrorAction/REPORT)
        (.onUnmappableCharacter java.nio.charset.CodingErrorAction/REPORT)
        (.decode (ByteBuffer/wrap bs)))
    true
    (catch java.nio.charset.CharacterCodingException _ false)))

(defn- utf8-valid?
  "Validates `bs` with Utf8 fed in pieces cut at `cuts`."
  [^bytes bs cuts]
  (loop [state Utf8/ACCEPT
         [from & more] (concat [0] cuts [(alength bs)])]
    (if (or (nil? more) (= state Utf8/REJECT))
      (= state Utf8/ACCEPT)
      (recur (Utf8/validate bs (int from) (int (first more)) (int state)) more))))

(deftest utf8-validator-agrees-with-the-jdk-decoder
  (testing "every 1- and 2-byte sequence, every 3-byte one from E0, 4-byte ones from F0"
    (doseq [a (range 256)]
      (let [bs (byte-array [(unchecked-byte a)])]
        (is (= (jdk-valid-utf8? bs) (utf8-valid? bs [])) (str [a]))))
    (let [mismatches (atom [])]
      (doseq [a (range 256) b (range 256)]
        (let [bs (byte-array [(unchecked-byte a) (unchecked-byte b)])]
          (when-not (= (jdk-valid-utf8? bs) (utf8-valid? bs []) (utf8-valid? bs [1]))
            (swap! mismatches conj [a b]))))
      (doseq [a (range 0xE0 0x100) b (range 0x80 0xC0) c (range 0x70 0xD0)]
        (let [bs (byte-array [(unchecked-byte a) (unchecked-byte b) (unchecked-byte c)])]
          (when-not (= (jdk-valid-utf8? bs) (utf8-valid? bs []) (utf8-valid? bs [1]) (utf8-valid? bs [2]))
            (swap! mismatches conj [a b c]))))
      (doseq [a (range 0xF0 0x100) b (range 0x70 0xD0) c [0x7F 0x80 0xBF 0xC0] d [0x7F 0x80 0xBF 0xC0]]
        (let [bs (byte-array (map unchecked-byte [a b c d]))]
          (when-not (= (jdk-valid-utf8? bs) (utf8-valid? bs []) (utf8-valid? bs [1]) (utf8-valid? bs [3]))
            (swap! mismatches conj [a b c d]))))
      (is (= [] (take 10 @mismatches)))))
  (testing "random mixes of ASCII runs and multi-byte sequences, cut anywhere"
    (let [rnd (java.util.Random. 42)
          pieces [(utf8 "abcdefghijklmnop") (utf8 "é") (utf8 "€") (utf8 "😀") (utf8 "\u0000")
                  (byte-array [(unchecked-byte 0xED) (unchecked-byte 0xA0) (unchecked-byte 0x80)])
                  (byte-array [(unchecked-byte 0xC0) (unchecked-byte 0x80)])
                  (byte-array [(unchecked-byte 0xF4) (unchecked-byte 0x90)])
                  (byte-array [(unchecked-byte 0x80)])
                  (byte-array [(unchecked-byte 0xE2) (unchecked-byte 0x82)])]
          mismatches (atom [])]
      (dotimes [_ 20000]
        (let [n (.nextInt rnd 12)
              ;; mostly valid pieces, sometimes a broken one
              chosen (repeatedly n #(nth pieces (if (< (.nextInt rnd 10) 8) (.nextInt rnd 4) (.nextInt rnd (count pieces)))))
              bs (byte-array (apply concat chosen))
              len (alength bs)
              cuts (sort (distinct (repeatedly (.nextInt rnd 4) #(if (pos? len) (.nextInt rnd (inc len)) 0))))]
          (when-not (= (jdk-valid-utf8? bs) (utf8-valid? bs cuts))
            (swap! mismatches conj [(vec bs) cuts]))))
      (is (= [] (take 5 @mismatches))))))

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

(deftest ws-large-frames-leave-header-and-payload-together
  ;; A frame's header goes out in the same write as (the start of) its
  ;; payload: no write, TCP segment or TLS record holding a lone header.
  (let [sink (ByteArrayOutputStream.)
        writes (atom [])
        out (proxy [java.io.OutputStream] []
              (write
                ([b] (swap! writes conj 1) (.write sink (int b)))
                ([b off len] (swap! writes conj len) (.write sink ^bytes b (int off) (int len))))
              (flush []))
        r (run-ws-bytes (byte-array 0)
                        {:out out
                         :sink sink
                         :on-open (fn [^WebSocketSocket s]
                                    (.sendBinary s (ByteBuffer/allocate 12000))
                                    (.sendBinary s (ByteBuffer/allocateDirect 12000))
                                    (.sendBinary s (ByteBuffer/allocate 100000))
                                    (.sendText s "small"))})]
    (is (= [12000 12000 100000 5] (mapv #(count (:payload %)) (:frames r))))
    (is (= [12004 12004 16384 (- 100000 (- 16384 10))]
           (take 4 @writes)))))

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
        writer-thread (promise)
        writer-done (promise)]
    (with-ws-server
      (fn [_]
        {:ring.websocket/listener
         {:on-open (fn [^WebSocketSocket s]
                     (deliver sock-p s)
                     (Thread/startVirtualThread
                      (fn []
                        (deliver writer-thread (Thread/currentThread))
                        (try
                          (let [chunk (ByteBuffer/allocate (* 1024 1024))]
                            (while (.isOpen s)
                              (.sendBinary s (.duplicate chunk))))
                          (deliver writer-done :closed)
                          (catch java.io.IOException _ (deliver writer-done :io-error))))))
          :on-close (fn [_ _ _])}})
      (fn []
        (with-open [sock (doto (Socket.) (.setReceiveBufferSize 4096))]
          (.connect sock (java.net.InetSocketAddress. "127.0.0.1" (int (:port *server*))))
          (ws-handshake! sock)
          (let [^WebSocketSocket s (deref sock-p 2000 nil)
                ^Thread writer (deref writer-thread 2000 nil)]
            (is s)
            ;; The writer fills the socket buffers and parks in a write.
            (is (support/await-condition
                 #(= Thread$State/WAITING (.getState writer)) 5000 10)
                "writer blocked")
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
        conn (WebSocketConnection. (Socket.) (ByteArrayInputStream. (byte-array 0)) out listener
                                   (ws-config {}) nil test-timer (MemoryBudget. Long/MAX_VALUE))]
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
            (is (support/await-condition #(some (fn [[k]] (= :close k)) @events) 2000 5)
                "on-close ran")
            ;; The async send's callback runs on the writer thread, so it
            ;; may land anywhere after the message that sent it.
            (is (= [[:open true]
                    [:message "hi"] [:message "bin"] [:message "ping"]
                    [:message "pong"] [:message "async"]
                    [:ping (vec (utf8 "cp"))] [:pong (vec (utf8 "cq"))]
                    [:message "close"] [:close 4001 ""]]
                   (remove #{[:sent]} @events)))
            (is (= 1 (count (filter #{[:sent]} @events))))))))))

(deftest ws-protocol-listener-without-ping-listener-protocol
  ;; ring-websocket-protocols versions without PingListener: a Listener
  ;; implementation still converts, and pings get the automatic pong.
  (with-redefs [enso/ws-ping-listener-var nil]
    (let [events (atom [])
          ^WebSocketListener l (#'enso/ring-listener->java (->EchoListener events))
          r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                          {:on-open (fn [s] (.onPing l s (ByteBuffer/wrap (utf8 "p"))))})]
      (is (= [0xA 0x8] (mapv :opcode (:frames r)))))))

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
  ;; passes the server starts the closing handshake with 1001 and waits
  ;; for the client's CLOSE before dropping TCP.
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
        (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
              f (update (read-frame in) :payload vec)]
          (is (= 0x8 (:opcode f)))
          (is (= 1001 (close-code f)))
          (is (= "idle timeout" (String. (byte-array (drop 2 (:payload f))) StandardCharsets/UTF_8)))
          (.setSoTimeout sock 100)
          (is (thrown? SocketTimeoutException (.read ^InputStream in))
              "TCP stays open until the client's CLOSE")
          (.setSoTimeout sock 3000)
          (.write out (mask-frame 0x8 true (close-payload 1001 "")))
          (.flush out)
          (is (= -1 (.read ^InputStream in)) "server closes TCP after the client's CLOSE")
          (is (.await closed 2 TimeUnit/SECONDS))
          (is (= [[:close 1001 ""]] @events))))
      (finally (enso/stop srv)))))

(deftest ws-ping-interval-keeps-a-silent-client-alive
  ;; With :ws-ping-interval the server pings a client that has sent
  ;; nothing for that long; the client's pongs are frames, so a live but
  ;; silent client outlasts :idle-timeout. One that stops answering is
  ;; closed with 1001 once :idle-timeout passes.
  (let [srv (enso/run-server (fn [_] {:ring.websocket/listener {}})
                             {:port 0 :ws-ping-interval 150 :idle-timeout 600})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (.setSoTimeout sock 3000)
        (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
              t0 (System/nanoTime)
              elapsed-ms #(/ (- (System/nanoTime) t0) 1e6)]
          ;; Answer pings for well past the idle timeout.
          (loop [pings 0]
            (if (< (elapsed-ms) 1500)
              (let [f (read-frame in)]
                (is (= 0x9 (:opcode f)) "only pings while the client answers")
                (.write out (mask-frame 0xA true (:payload f)))
                (.flush out)
                (recur (inc pings)))
              (is (<= 6 pings 12) (str pings " pings in 1.5 s"))))
          ;; Stop answering: pings go on, then the idle timeout closes.
          (let [silent-from (System/nanoTime)
                frames (loop [acc []]
                         (let [f (read-frame in)]
                           (if (= 0x8 (:opcode f)) (conj acc f) (recur (conj acc f)))))
                ms (/ (- (System/nanoTime) silent-from) 1e6)]
            (is (every? #(= 0x9 (:opcode %)) (butlast frames)))
            (is (= 1001 (close-code (last frames))))
            (is (< 450 ms 1500) (str "closed " ms " ms after the last pong")))))
      (finally (enso/stop srv)))))

(deftest ws-write-timeout-closes-a-peer-that-stopped-reading
  ;; The server keeps sending to a client that never reads: once its
  ;; writes make no progress for :write-timeout the connection is dropped
  ;; and the listener sees onClose.
  (let [closed (promise)
        srv (enso/run-server
             (fn [_]
               {:ring.websocket/listener
                {:on-open (fn [^WebSocketSocket s]
                            (Thread/startVirtualThread
                             (fn []
                               (try
                                 (let [chunk (ByteBuffer/allocate (* 256 1024))]
                                   (while (.isOpen s)
                                     (.sendBinary s (.duplicate chunk))))
                                 (catch java.io.IOException _)))))
                 :on-close (fn [_ code _] (deliver closed code))}})
             {:port 0 :write-timeout 300 :idle-timeout 0})]
    (try
      (with-open [sock (doto (Socket.) (.setReceiveBufferSize 4096))]
        (.connect sock (java.net.InetSocketAddress. "127.0.0.1" (int (enso/port srv))))
        (.setSoTimeout sock 3000)
        (ws-handshake! sock)
        (let [t0 (System/nanoTime)
              code (deref closed 5000 :timed-out)]
          (is (= 1006 code) "abnormal closure after the write stalled")
          (is (< (/ (- (System/nanoTime) t0) 1e6) 3000))))
      (finally (enso/stop srv)))))

;; ---- Sends: stalled writers, closed sockets, the async queue ----------------

(defn- gated-output
  "An OutputStream into `sink` whose writes, once `armed` is set, count
  down `blocked` and wait for `gate` to open."
  ^java.io.OutputStream [^ByteArrayOutputStream sink armed ^CountDownLatch blocked ^CountDownLatch gate]
  (let [wait! (fn [] (when @armed (.countDown blocked) (.await gate)))]
    (proxy [java.io.OutputStream] []
      (write
        ([b] (wait!) (if (bytes? b) (.write sink ^bytes b) (.write sink (int b))))
        ([b off len] (wait!) (.write sink ^bytes b (int off) (int len))))
      (flush []))))

(defn- callback
  "A SendCallback delivering :sent or the failure to promise `p`."
  [p]
  (reify WebSocketSocket$SendCallback
    (onSuccess [_] (deliver p :sent))
    (onFailure [_ t] (deliver p t))))

(defn- stall-writer!
  "Starts a virtual thread sending on `s` and waits until its write blocks
  in a gated output."
  [^WebSocketSocket s armed ^CountDownLatch blocked]
  (reset! armed true)
  (Thread/startVirtualThread
   (fn [] (try (.sendText s "stalled") (catch Exception _))))
  (is (.await blocked 2 TimeUnit/SECONDS) "writer stalled"))

(deftest ws-read-loop-not-blocked-by-stalled-writer
  ;; A writer stalled on a peer that stopped reading holds the write lock.
  ;; The read loop must keep dispatching: the automatic pong is queued
  ;; behind the stalled write instead of waiting for it.
  (let [armed (atom false)
        blocked (CountDownLatch. 1)
        gate (CountDownLatch. 1)
        messages (atom [])
        input (frames [0x9 true (utf8 "p")] [0x1 true (utf8 "after")])
        done (future
               (run-ws-bytes input
                             {:out (gated-output (ByteArrayOutputStream.) armed blocked gate)
                              :close-timeout 200
                              :on-open (fn [s] (stall-writer! s armed blocked))
                              :on-message (fn [_ m] (swap! messages conj m))}))]
    (try
      (is (not= :timed-out (deref done 3000 :timed-out)) "read loop ran to completion")
      (is (= ["after"] @messages))
      (finally (.countDown gate)))))

(deftest ws-sends-after-close-fail
  ;; Once the server's CLOSE is out every send fails instead of being
  ;; dropped silently; asynchronous sends call their failure callback.
  (let [results (atom {})
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:on-open
                         (fn [^WebSocketSocket s]
                           (.close s 1000 "bye")
                           (doseq [[k f] {:text #(.sendText s "x")
                                          :binary #(.sendBinary s (ByteBuffer/allocate 1))
                                          :ping #(.sendPing s (ByteBuffer/allocate 1))
                                          :pong #(.sendPong s (ByteBuffer/allocate 1))}]
                             (swap! results assoc k (try (f) :sent
                                                         (catch java.io.IOException e (.getMessage e)))))
                           (let [p (promise)]
                             (.sendTextAsync s "x" (callback p))
                             (swap! results assoc :async (let [v (deref p 1000 :no-callback)]
                                                           (if (instance? Throwable v) (ex-message v) v))))
                           (let [p (promise)]
                             (wsp/-send-async s "x" #(deliver p :sent) #(deliver p (ex-message %)))
                             (swap! results assoc :ring-async (deref p 1000 :no-callback))))})]
    (is (= {:text "WebSocket closed" :binary "WebSocket closed" :ping "WebSocket closed"
            :pong "WebSocket closed" :async "WebSocket closed" :ring-async "WebSocket closed"}
           @results))
    (is (= [0x8] (mapv :opcode (:frames r))) "nothing but the CLOSE was written")))

(deftest ws-async-sends-keep-call-order
  ;; Asynchronous and synchronous sends leave in call order; a callback
  ;; runs once its frame was written.
  (let [sink (ByteArrayOutputStream.)
        written (atom [])
        cb (fn [label done]
             (reify WebSocketSocket$SendCallback
               (onSuccess [_] (swap! written conj [label (pos? (.size sink))]) (.countDown ^CountDownLatch done))
               (onFailure [_ t] (swap! written conj [label t]) (.countDown ^CountDownLatch done))))
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:out sink
                         :on-open (fn [^WebSocketSocket s]
                                    (let [done (CountDownLatch. 3)]
                                      (.sendTextAsync s "a" (cb :a done))
                                      (.sendText s "b")
                                      (.sendBinaryAsync s (ByteBuffer/wrap (utf8 "c")) (cb :c done))
                                      (.sendTextAsync s "d" (cb :d done))
                                      (is (.await done 2 TimeUnit/SECONDS))))})]
    (is (= [[0x1 "a"] [0x1 "b"] [0x2 "c"] [0x1 "d"]]
           (mapv (juxt :opcode #(String. (byte-array (:payload %)) StandardCharsets/UTF_8))
                 (butlast (:frames r)))))
    (is (= [[:a true] [:c true] [:d true]] @written))))

(deftest ws-async-sends-do-not-block-and-are-bounded
  ;; With a writer stalled, asynchronous sends return at once and queue;
  ;; past :ws-max-queued-bytes they fail immediately. Releasing the
  ;; writer delivers the queued ones.
  (let [armed (atom false)
        blocked (CountDownLatch. 1)
        gate (CountDownLatch. 1)
        outcome (atom {})
        sink (ByteArrayOutputStream.)
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:out (gated-output sink armed blocked gate)
                         :sink sink
                         :max-queued 1000
                         :on-open (fn [^WebSocketSocket s]
                                    (stall-writer! s armed blocked)
                                    (let [first-p (promise)
                                          second-p (promise)
                                          t0 (System/nanoTime)]
                                      (.sendBinaryAsync s (ByteBuffer/allocate 600) (callback first-p))
                                      (.sendBinaryAsync s (ByteBuffer/allocate 600) (callback second-p))
                                      (swap! outcome assoc
                                             :returned-ms (/ (- (System/nanoTime) t0) 1e6)
                                             :first-before-release (realized? first-p)
                                             :second (some-> (deref second-p 1000 nil) ex-message))
                                      (reset! armed false)
                                      (.countDown gate)
                                      (swap! outcome assoc :first (deref first-p 2000 :timed-out))))})]
    (is (< (:returned-ms @outcome) 500) "async sends did not wait for the stalled writer")
    (is (false? (:first-before-release @outcome)))
    (is (= "WebSocket send queue full" (:second @outcome)))
    (is (= :sent (:first @outcome)))
    (is (= [0x1 0x2 0x8] (mapv :opcode (:frames r))))))

(deftest ws-writer-thread-ends-when-idle
  ;; The writer thread of asynchronous sends doesn't stay parked for the
  ;; connection's lifetime: it ends once idle, and the next asynchronous
  ;; send starts another.
  (let [outcome (atom {})
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:on-open (fn [^WebSocketSocket s]
                                    (let [writer (promise)
                                          sent (fn [] (reify WebSocketSocket$SendCallback
                                                        (onSuccess [_] (deliver writer (Thread/currentThread)))
                                                        (onFailure [_ t] (deliver writer t))))
                                          again (promise)]
                                      (.sendTextAsync s "a" (sent))
                                      (let [^Thread t (deref writer 2000 nil)]
                                        (swap! outcome assoc :ended
                                               (support/await-condition #(not (.isAlive t)) 5000 20)))
                                      (.sendTextAsync s "b" (callback again))
                                      (swap! outcome assoc :again (deref again 2000 :timed-out))))})]
    (is (= {:ended true :again :sent} @outcome))
    (is (= [0x1 0x1 0x8] (mapv :opcode (:frames r))))))

(deftest ws-pongs-to-a-ping-flood-are-coalesced
  ;; RFC 6455 §5.5.3: a pong for the most recent ping only. Pings that
  ;; arrive while a write is stalled leave one pending pong (the latest
  ;; payload) instead of a queue growing with the flood.
  (let [armed (atom false)
        blocked (CountDownLatch. 1)
        gate (CountDownLatch. 1)
        sink (ByteArrayOutputStream.)
        pings (for [i (range 200)] [0x9 true (utf8 (str "p" i))])
        input (apply frames (concat pings [[0x1 true (utf8 "done")]
                                           [0x8 true (close-payload 1000 "")]]))
        r (run-ws-bytes input
                        {:out (gated-output sink armed blocked gate)
                         :sink sink
                         :on-open (fn [s] (stall-writer! s armed blocked))
                         :on-message (fn [_ _] (reset! armed false) (.countDown gate))})]
    (is (= [[0x1 "stalled"] [0xA "p199"] [0x8 nil]]
           (mapv (fn [f] [(:opcode f) (when-not (= 0x8 (:opcode f)) (frame-text f))]) (:frames r))))))

(defn- flush-counting-output
  "An OutputStream into `sink` that calls `on-flush` on every flush."
  ^java.io.OutputStream [^ByteArrayOutputStream sink on-flush]
  (proxy [java.io.OutputStream] []
    (write
      ([b] (if (bytes? b) (.write sink ^bytes b) (.write sink (int b))))
      ([b off len] (.write sink ^bytes b (int off) (int len))))
    (flush [] (on-flush))))

(deftest ws-replies-to-buffered-messages-share-a-flush
  ;; Replies sent from onMessage while more of the client's frames are
  ;; already read join one write: a batch of messages costs one flush
  ;; (one syscall, one TCP segment), not one per message.
  (let [sink (ByteArrayOutputStream.)
        flushes (atom 0)
        msgs (mapv #(str "m" %) (range 8))
        r (run-ws-bytes (apply frames (map #(vector 0x1 true (utf8 %)) msgs))
                        {:out (flush-counting-output sink #(swap! flushes inc))
                         :sink sink
                         :on-message (fn [^WebSocketSocket s m] (.sendText s ^String m))})]
    (is (= msgs (mapv frame-text (:frames r))))
    (is (= 1 @flushes))))

(deftest ws-held-reply-does-not-wait-for-the-next-listener
  ;; A reply held for the next message's company goes out on its own
  ;; within about a timer tick when that message's listener takes long.
  (let [sink (ByteArrayOutputStream.)
        flushed (CountDownLatch. 1)
        seen (promise)
        r (run-ws-bytes (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")])
                        {:out (flush-counting-output sink #(.countDown flushed))
                         :sink sink
                         :on-message (fn [^WebSocketSocket s m]
                                       (if (= "a" m)
                                         (.sendText s "a")
                                         (deliver seen (.await flushed 2 TimeUnit/SECONDS))))})]
    (is (true? @seen) "the reply to a was flushed while b's listener ran")
    (is (= ["a"] (mapv frame-text (:frames r))))))

(deftest ws-held-reply-goes-out-when-the-lock-holder-releases
  ;; The read loop doesn't wait for the write lock to write the replies it
  ;; held. A holder with nothing of its own to write (the writer thread
  ;; finding its queue empty) writes them as it releases the lock, not
  ;; the hold timer, which never fires here. The test plays that holder:
  ;; the window is too short to hit through the public API.
  (let [timer (Timer. "ws-test-slow-timer" 60000 2)
        sink (ByteArrayOutputStream.)
        flushed (CountDownLatch. 1)
        lock-now (CountDownLatch. 1)
        locked (CountDownLatch. 1)
        reading (CountDownLatch. 1)
        release-now (CountDownLatch. 1)
        end (CountDownLatch. 1)
        blocking (proxy [InputStream] []
                   (read
                     ([] -1)
                     ([b off len] (.countDown reading) (.await end) -1)))
        in (SequenceInputStream. (ByteArrayInputStream. (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")]))
                                 ^InputStream blocking)
        listener (reify WebSocketListener
                   (onOpen [_ _])
                   (onMessage [_ s m]
                     (if (= "a" m)
                       (.sendText s "a")
                       (do (.countDown lock-now) (.await locked))))
                   (onError [_ _ _])
                   (onClose [_ _ _ _]))
        conn (WebSocketConnection. (Socket.) in (flush-counting-output sink #(.countDown flushed)) listener
                                   (ws-config {}) nil timer (MemoryBudget. Long/MAX_VALUE))
        ^ReentrantLock lock (.get (doto (.getDeclaredField WebSocketConnection "writeLock")
                                    (.setAccessible true))
                                  conn)
        ^Method unlock-writes (doto (.getDeclaredMethod WebSocketConnection "unlockWrites" (make-array Class 0))
                                (.setAccessible true))
        holder (Thread/startVirtualThread
                (fn []
                  (.await lock-now)
                  (.lock lock)
                  (.countDown locked)
                  (.await release-now)
                  (.invoke unlock-writes conn (object-array 0))))
        done (future (.run conn))]
    (try
      (is (.await reading 2 TimeUnit/SECONDS) "read loop waits for input")
      (is (= 1 (.getCount flushed)) "the reply is held while the lock is taken")
      (.countDown release-now)
      (is (.await flushed 1 TimeUnit/SECONDS) "the holder wrote the held reply")
      (is (= ["a"] (mapv frame-text (parse-frames (.toByteArray sink)))))
      (finally
        (.countDown release-now)
        (.countDown end)
        (deref done 2000 nil)
        (.join holder 2000)
        (.close timer)))))

(deftest ws-deferred-write-failure-is-reported-once-with-its-cause
  ;; A held reply whose write fails (here on the hold timer's flusher,
  ;; while the next listener runs) fails the connection: later sends throw
  ;; with that failure as cause, onError gets it once, the close is 1006.
  (let [boom (java.io.IOException. "boom")
        failed (CountDownLatch. 1)
        out (proxy [java.io.OutputStream] []
              (write ([_]) ([_ _ _]))
              (flush [] (.countDown failed) (throw boom)))
        later (promise)
        r (run-ws-bytes (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")])
                        {:out out
                         :on-message (fn [^WebSocketSocket s m]
                                       (if (= "a" m)
                                         (.sendText s "a")
                                         (do (.await failed 2 TimeUnit/SECONDS)
                                             (while (.isOpen s) (Thread/sleep 1))
                                             (deliver later (try (.sendText s "x") nil
                                                                 (catch java.io.IOException e e))))))})
        errors (keep #(when (= :error (first %)) (second %)) (:events r))]
    (is (instance? java.io.IOException (deref later 0 nil)) "a send after the failure throws")
    (is (identical? boom (some-> ^Throwable (deref later 0 nil) .getCause)) "with the failure as cause")
    (is (= 1 (count errors)) "onError is called once")
    (is (identical? boom (first errors)) "with the original failure")
    (is (= 1006 (second (close-event r))))
    (testing "written by the read loop before its next read"
      (let [r (run-ws-bytes (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")])
                            {:out out
                             :on-message (fn [^WebSocketSocket s m] (when (= "a" m) (.sendText s "a")))})
            errors (keep #(when (= :error (first %)) (second %)) (:events r))]
        (is (= [boom] errors))
        (is (identical? boom (first errors)))
        (is (= 1006 (second (close-event r))))))))

(deftest ws-held-replies-go-out-before-the-close
  ;; Replies held in the output buffer are written ahead of the CLOSE,
  ;; whether a listener closes or the server fails the connection.
  (let [summary (fn [r] (mapv (fn [f] (if (= 0x8 (:opcode f)) [0x8 (close-code f)] [(:opcode f) (frame-text f)]))
                              (:frames r)))]
    (testing "close from a listener"
      (let [r (run-ws-bytes (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")])
                            {:on-message (fn [^WebSocketSocket s m]
                                           (when (= "a" m)
                                             (.sendText s "a")
                                             (.close s 1000 "bye")))})]
        (is (= [[0x1 "a"] [0x8 1000]] (summary r)))))
    (testing "failing the connection"
      (let [unmasked (byte-array [(unchecked-byte 0x81) (byte 0x02) (byte 0x61) (byte 0x62)])
            r (run-ws-bytes (byte-array (concat (frames [0x1 true (utf8 "a")]) unmasked))
                            {:on-message (fn [^WebSocketSocket s m] (.sendText s ^String m))})]
        (is (= [[0x1 "a"] [0x8 1002]] (summary r)))))))

(deftest ws-async-callbacks-run-after-their-frames-are-flushed
  ;; An asynchronous send succeeds once its frame left the connection's
  ;; buffer, even when a synchronous reply is held right behind it.
  (let [sink (ByteArrayOutputStream.)
        flushed (atom [])
        seen (promise)
        r (run-ws-bytes (frames [0x1 true (utf8 "a")] [0x1 true (utf8 "b")])
                        {:out (flush-counting-output
                               sink #(reset! flushed (mapv frame-text (parse-frames (.toByteArray sink)))))
                         :sink sink
                         :on-message (fn [^WebSocketSocket s m]
                                       (when (= "a" m)
                                         (.sendTextAsync s "q" (reify WebSocketSocket$SendCallback
                                                                 (onSuccess [_] (deliver seen @flushed))
                                                                 (onFailure [_ t] (deliver seen t)))))
                                       (.sendText s ^String m))})]
    (is (some #{"q"} (deref seen 2000 nil)) "q was flushed when its callback ran")
    (is (= #{"q" "a" "b"} (set (mapv frame-text (:frames r)))))))

(deftest ws-queued-frames-count-their-overhead
  ;; Every queued frame counts against :ws-max-queued-bytes, empty ones
  ;; included, so a flood of empty sends can't queue without bound.
  (let [armed (atom false)
        blocked (CountDownLatch. 1)
        gate (CountDownLatch. 1)
        sink (ByteArrayOutputStream.)
        outcome (atom nil)
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:out (gated-output sink armed blocked gate)
                         :sink sink
                         :max-queued 1000
                         :on-open (fn [^WebSocketSocket s]
                                    (stall-writer! s armed blocked)
                                    (let [ps (vec (repeatedly 1000 promise))]
                                      (doseq [p ps] (.sendTextAsync s "" (callback p)))
                                      (let [rejected (filterv #(instance? Throwable (deref % 0 nil)) ps)
                                            ^Throwable t (deref (first rejected))]
                                        (reset! outcome {:rejected (count rejected)
                                                         :message (ex-message t)
                                                         :stack (count (.getStackTrace t))}))
                                      (reset! armed false)
                                      (.countDown gate)))})]
    (is (< 900 (:rejected @outcome) 1000) (str @outcome))
    (is (= "WebSocket send queue full" (:message @outcome)))
    (is (zero? (:stack @outcome)) "rejections carry no stack trace")
    (is (= 0x8 (:opcode (last (:frames r)))))))

(deftest ws-async-sends-are-bounded-by-the-server-budget
  ;; Queued sends count against :max-buffered-bytes across connections:
  ;; past it a send fails at once instead of buffering, and the bytes are
  ;; given back once written.
  (let [armed (atom false)
        blocked (CountDownLatch. 1)
        gate (CountDownLatch. 1)
        outcome (atom {})
        budget (MemoryBudget. 1000)
        sink (ByteArrayOutputStream.)
        r (run-ws-bytes (frames [0x8 true (close-payload 1000 "")])
                        {:out (gated-output sink armed blocked gate)
                         :sink sink
                         :max-queued 0
                         :budget budget
                         :on-open (fn [^WebSocketSocket s]
                                    (stall-writer! s armed blocked)
                                    (let [first-p (promise)
                                          second-p (promise)]
                                      (.sendBinaryAsync s (ByteBuffer/allocate 600) (callback first-p))
                                      (.sendBinaryAsync s (ByteBuffer/allocate 600) (callback second-p))
                                      (swap! outcome assoc
                                             :used-while-queued (.used budget)
                                             :second (some-> (deref second-p 1000 nil) ex-message))
                                      (reset! armed false)
                                      (.countDown gate)
                                      (swap! outcome assoc :first (deref first-p 2000 :timed-out))))})]
    (is (= (+ 600 64) (:used-while-queued @outcome)) "the payload and the frame's overhead")
    (is (some-> (:second @outcome) (clojure.string/includes? ":max-buffered-bytes")) (str (:second @outcome)))
    (is (= :sent (:first @outcome)))
    (is (zero? (.used budget)) "given back once written")
    (is (= [0x1 0x2 0x8] (mapv :opcode (:frames r))))))

(deftest ws-incoming-messages-are-charged-to-the-server-budget
  ;; Message bytes past the first 64 KiB count against :max-buffered-bytes
  ;; while the message is assembled. While the budget is exhausted the
  ;; read loop stops reading (TCP pushes back) until bytes are released,
  ;; within the message deadline.
  (testing "reading waits for room, then the message completes"
    (let [budget (MemoryBudget. 100000)
          size 200000
          input (frames [0x2 true (byte-array size)] [0x8 true (close-payload 1000 "")])
          delivered (promise)
          used-during (atom nil)
          _ (.charge budget 100000)
          done (future (run-ws-bytes input {:budget budget
                                            :on-message (fn [_ ^ByteBuffer m]
                                                          (reset! used-during (.used budget))
                                                          (deliver delivered (.remaining m)))}))]
      (is (= :waiting (deref delivered 300 :waiting)) "paused while the budget is exhausted")
      (.release budget 100000)
      (is (= size (deref delivered 2000 :timed-out)))
      (is (= (- size 65536) @used-during) "past the first 64 KiB, charged until the listener returns")
      (is (not= :timed-out (deref done 2000 :timed-out)))
      (is (zero? (.used budget)) "released once delivered")))
  (testing "a message that can't get room within :read-timeout fails with 1008"
    (let [budget (doto (MemoryBudget. 100000) (.charge 100000))
          r (run-ws-bytes (frames [0x2 true (byte-array 200000)]) {:budget budget :read-timeout 300})]
      (is (= [1008] (server-close-codes r)))
      (is (= 100000 (.used budget)) "what the message held was released"))))

(deftest ws-connection-events-use-protocol-websocket
  (let [log (atom [])
        closed (CountDownLatch. 2)]
    (let [srv (enso/run-server (fn [_] {:ring.websocket/listener {:on-open (fn [_])}})
                               {:port 0
                                :server-events {:connection-opened (fn [p _] (swap! log conj [:opened p]))
                                                :connection-closed (fn [p _ _] (swap! log conj [:closed p])
                                                                     (.countDown closed))}})]
      (try
        (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
          (ws-handshake! sock)
          (.write (.getOutputStream sock) (mask-frame 0x8 true (close-payload 1000 "")))
          (.flush (.getOutputStream sock))
          (read-frame (DataInputStream. (.getInputStream sock))))
        (is (.await closed 3 TimeUnit/SECONDS))
        (is (= [[:opened "http/1.1"] [:opened "websocket"] [:closed "websocket"] [:closed "http/1.1"]] @log))
        (finally (enso/stop srv))))))

;; ---- Closing handshake ------------------------------------------------------

(deftest ws-close-timeout-is-configurable
  ;; A server-initiated close waits :ws-close-timeout for the peer's CLOSE.
  (let [srv (enso/run-server
             (fn [_] {:ring.websocket/listener {:on-open (fn [^WebSocketSocket s] (.close s 4000 "bye"))}})
             {:port 0 :ws-close-timeout 300})]
    (try
      (with-open [sock (Socket. "127.0.0.1" (int (enso/port srv)))]
        (.setSoTimeout sock 5000)
        (let [[in] (ws-handshake! sock)
              f (read-frame in)
              t0 (System/nanoTime)
              end (try (.read ^InputStream in) (catch java.io.IOException _ :reset))
              ms (/ (- (System/nanoTime) t0) 1e6)]
          (is (= 0x8 (:opcode f)))
          (is (contains? #{-1 :reset} end))
          (is (< 150 ms 2000) (str "dropped after " ms " ms"))))
      (finally (enso/stop srv)))))

(deftest ws-close-timer-race-free-when-peer-answers-at-once
  ;; The close timer is armed before the CLOSE can be answered, so a fast
  ;; peer never leaves an armed timer behind a finished connection.
  (let [r (run-ws-bytes (frames [0x8 true (close-payload 4000 "")])
                        {:on-open (fn [^WebSocketSocket s] (.close s 4000 ""))})]
    (is (= [4000] (server-close-codes r)))
    (is (= [:close 4000 ""] (close-event r)))))

;; ---- Failures ---------------------------------------------------------------

(defn- close-reason [{:keys [payload]}]
  (String. (byte-array (drop 2 payload)) StandardCharsets/UTF_8))

(deftest ws-failure-close-carries-reason-and-public-exception
  ;; Failing the connection sends a CLOSE whose reason says why, and
  ;; onError receives a WebSocketException carrying that code.
  (doseq [[label input max code reason]
          [["too big" (frames [0x2 true (byte-array 2000)]) 1024 1009 "message exceeds 1024 bytes"]
           ["bad utf-8" (frames [0x1 true (byte-array [(unchecked-byte 0xC3) 0x28])]) 1024 1007
            "invalid UTF-8 in text message"]
           ["reserved opcode" (frames [0x3 true (byte-array 0)]) 1024 1002 "reserved opcode: 3"]]]
    (let [r (run-ws-bytes input {:max-message max})
          close (first (filter #(= 0x8 (:opcode %)) (:frames r)))
          [_ ^Throwable t] (first (filter #(= :error (first %)) (:events r)))]
      (is (= code (close-code close)) label)
      (is (= reason (close-reason close)) label)
      (is (instance? WebSocketException t) label)
      (is (= code (some-> ^WebSocketException t .code)) label)
      (is (= [:close code reason] (close-event r)) label))))

(deftest ws-close-reason-truncated-on-a-character-boundary
  (let [m (doto (.getDeclaredMethod WebSocketConnection "closeReasonBytes" (into-array Class [String]))
            (.setAccessible true))
        bytes-of (fn [s] (vec ^bytes (.invoke m nil (object-array [s]))))]
    (is (= (vec (utf8 "short")) (bytes-of "short")))
    (is (= 123 (count (bytes-of (apply str (repeat 200 "a"))))))
    ;; 2-byte characters: 61 fit (122 bytes), the 62nd would straddle 123.
    (is (= (vec (utf8 (apply str (repeat 61 "é")))) (bytes-of (apply str (repeat 100 "é")))))
    ;; 4-byte characters: 30 fit (120 bytes).
    (is (= (vec (utf8 (apply str (repeat 30 "😀")))) (bytes-of (apply str (repeat 40 "😀")))))))

(deftest ws-internal-error-reason-does-not-leak-exception-text
  (let [r (run-ws-bytes (frames [0x1 true (utf8 "boom")])
                        {:on-message (fn [_ _] (throw (RuntimeException. "secret detail")))})
        close (first (filter #(= 0x8 (:opcode %)) (:frames r)))]
    (is (= 1011 (close-code close)))
    (is (= "internal error" (close-reason close)))))

(deftest ws-listener-io-exceptions-are-listener-failures
  ;; What a listener callback throws is the listener's failure (1011),
  ;; whatever its type: an IOException or SocketTimeoutException from the
  ;; listener's own I/O isn't the connection dropping or a message
  ;; deadline, and a WebSocketException it throws doesn't pick the code.
  (doseq [[label ex] [["io" (java.io.IOException. "backend down")]
                      ["timeout" (SocketTimeoutException. "backend slow")]
                      ["ws exception" (WebSocketException. 1003 "listener's own")]]
          [cb input] [[:message (frames [0x1 true (utf8 "x")] [0x1 true (utf8 "y")]
                                        [0x8 true (close-payload 1000 "")])]
                      [:ping (frames [0x9 true (utf8 "p")] [0x8 true (close-payload 1000 "")])]
                      [:pong (frames [0xA true (utf8 "p")] [0x8 true (close-payload 1000 "")])]]]
    (let [events (atom [])
          out (ByteArrayOutputStream.)
          listener (reify WebSocketListener
                     (onOpen [_ _])
                     (onMessage [_ _ m] (swap! events conj [:message m]) (when (= cb :message) (throw ex)))
                     (onPing [_ _ _] (when (= cb :ping) (throw ex)))
                     (onPong [_ _ _] (when (= cb :pong) (throw ex)))
                     (onError [_ _ t] (swap! events conj [:error t]))
                     (onClose [_ _ code reason] (swap! events conj [:close code reason])))
          conn (WebSocketConnection. (Socket.) (ByteArrayInputStream. input) out listener
                                     (ws-config {}) nil test-timer (MemoryBudget. Long/MAX_VALUE))
          _ (.run conn)
          closes (filter #(= 0x8 (:opcode %)) (parse-frames (.toByteArray out)))]
      (is (= [1011] (mapv close-code closes)) [label cb])
      (is (= "internal error" (close-reason (first closes))) [label cb])
      (is (some #(= [:error ex] %) @events) [label cb])
      (is (= [:close 1011 "internal error"] (last @events)) [label cb])
      (is (not-any? #(= [:message "y"] %) @events) [label cb "nothing dispatched after the failure"]))))

;; ---- Limits and deadlines ---------------------------------------------------

(defn- with-server [handler opts f]
  (let [srv (enso/run-server handler (merge {:port 0} opts))]
    (try (f (enso/port srv)) (finally (enso/stop srv)))))

(def ^:private echo-handler
  (fn [_] {:ring.websocket/listener
           {:on-message (fn [^WebSocketSocket s m]
                          (if (string? m) (.sendText s ^String m) (.sendBinary s ^ByteBuffer m)))}}))

(deftest ws-max-message-bytes-option
  (with-server echo-handler {:ws-max-message-bytes 1024}
    (fn [port]
      (with-open [sock (Socket. "127.0.0.1" (int port))]
        (.setSoTimeout sock 3000)
        (let [[in ^java.io.OutputStream out] (ws-handshake! sock)]
          (.write out (mask-frame 0x2 true (byte-array 1024)))
          (.flush out)
          (is (= 1024 (count (:payload (read-frame in)))) "a message at the limit is echoed")
          (.write out (mask-frame 0x2 true (byte-array 1025)))
          (.flush out)
          (let [f (update (read-frame in) :payload vec)]
            (is (= 1009 (close-code f)))))))))

(deftest ws-oversized-message-close-reaches-a-client-still-sending
  ;; The client is still sending a message past the limit when the server
  ;; fails the connection: the server keeps reading (and discarding) so
  ;; its CLOSE 1009 isn't destroyed by a TCP reset, then finishes the
  ;; closing handshake.
  (with-server echo-handler {:ws-max-message-bytes 1024}
    (fn [port]
      (with-open [sock (Socket. "127.0.0.1" (int port))]
        (.setSoTimeout sock 5000)
        (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
              big (mask-frame 0x2 true (byte-array (* 4 1024 1024)))
              sender (future (try (.write out ^bytes big) (.flush out) :sent
                                  (catch java.io.IOException e e)))
              f (update (read-frame in) :payload vec)]
          (is (= 0x8 (:opcode f)))
          (is (= 1009 (close-code f)))
          (is (= :sent (deref sender 5000 :timed-out)) "the server drained the rest of the message")
          (.write out (mask-frame 0x8 true (close-payload 1009 "")))
          (.flush out)
          (is (= -1 (.read ^InputStream in)) "server closes TCP after the client's CLOSE"))))))

(deftest ws-message-must-complete-within-read-timeout
  ;; A message in progress must complete within :read-timeout (wall
  ;; clock from its first frame), even when bytes keep trickling in.
  (doseq [[label drip?] [["silent" false] ["dripping" true]]]
    (with-server echo-handler {:read-timeout 400 :idle-timeout 20000}
      (fn [port]
        (with-open [sock (Socket. "127.0.0.1" (int port))]
          (.setSoTimeout sock 5000)
          (let [[in ^java.io.OutputStream out] (ws-handshake! sock)
                frame (mask-frame 0x1 true (utf8 (apply str (repeat 100 "x"))))
                t0 (System/nanoTime)
                dripper (future
                          (try
                            (if drip?
                              (doseq [b frame]
                                (.write out (int b))
                                (.flush out)
                                (Thread/sleep 50))
                              (do (.write out (mask-frame 0x1 false (utf8 "part"))) (.flush out)))
                            (catch Exception _)))
                f (update (read-frame in) :payload vec)
                ms (/ (- (System/nanoTime) t0) 1e6)]
            (future-cancel dripper)
            (is (= 1008 (close-code f)) label)
            (is (= "message timeout" (close-reason f)) label)
            (is (< 300 ms 2500) (str label ": closed after " ms " ms"))))))))

;; ---- Handshake: Origin, extensions --------------------------------------------

(deftest ws-origin-is-checked
  (doseq [[opts origin expected]
          [[{} nil "101"]
           [{} "http://127.0.0.1" "101"]
           [{} "HTTP://127.0.0.1" "101"]
           [{} "http://evil.example" "403"]
           [{} "null" "403"]
           [{:ws-allowed-origins ["http://evil.example"]} "http://evil.example" "101"]
           [{:ws-allowed-origins ["http://evil.example"]} "http://127.0.0.1" "403"]
           [{:ws-allowed-origins ["*"]} "http://evil.example" "101"]
           [{:ws-allowed-origins #(= % "http://fn.example")} "http://fn.example" "101"]
           [{:ws-allowed-origins #(= % "http://fn.example")} "http://evil.example" "403"]]]
    (with-server echo-handler opts
      (fn [port]
        (with-open [sock (Socket. "127.0.0.1" (int port))]
          (.setSoTimeout sock 3000)
          (let [resp (ws-handshake-response sock (if origin {"Origin" origin} {}))]
            (is (= expected (second (re-find #"^HTTP/1.1 (\d+)" resp)))
                (str (pr-str opts) " " origin))))))))

(deftest ws-handler-extensions-header-is-not-sent
  ;; Only the server negotiates extensions: a handler's
  ;; Sec-WebSocket-Extensions would announce one the server doesn't speak.
  (with-server (fn [_] {:ring.websocket/listener {}
                        :headers {"Sec-WebSocket-Extensions" "permessage-deflate"}})
    {}
    (fn [port]
      (with-open [sock (Socket. "127.0.0.1" (int port))]
        (.setSoTimeout sock 3000)
        (let [resp (ws-handshake-response sock {"Sec-WebSocket-Extensions" "permessage-deflate"})]
          (is (re-find #"^HTTP/1.1 101" resp))
          (is (not (re-find #"(?i)sec-websocket-extensions" resp))))))))

;; ---- permessage-deflate -------------------------------------------------------

(deftest ws-deflate-negotiation
  (doseq [[offer expected]
          [[nil nil]
           ["" nil]
           ["foo" nil]
           ["permessage-deflate" "permessage-deflate"]
           ["Permessage-Deflate" "permessage-deflate"]
           ["permessage-deflate; client_max_window_bits" "permessage-deflate"]
           ["permessage-deflate; client_max_window_bits=10" "permessage-deflate"]
           ["permessage-deflate; client_max_window_bits=\"10\"" "permessage-deflate"]
           ["permessage-deflate; client_no_context_takeover" "permessage-deflate"]
           ["permessage-deflate;server_no_context_takeover"
            "permessage-deflate; server_no_context_takeover"]
           ["permessage-deflate; server_max_window_bits=15"
            "permessage-deflate; server_max_window_bits=15"]
           ["permessage-deflate; server_max_window_bits=10, permessage-deflate"
            "permessage-deflate; server_max_window_bits=10"]
           ["permessage-deflate; server_max_window_bits=9; server_no_context_takeover"
            "permessage-deflate; server_no_context_takeover; server_max_window_bits=9"]
           ["x-webkit-deflate-frame, permessage-deflate; client_max_window_bits" "permessage-deflate"]
           ["permessage-deflate; server_max_window_bits" nil]
           ["permessage-deflate; server_max_window_bits=7" nil]
           ["permessage-deflate; client_max_window_bits=7" nil]
           ["permessage-deflate; client_max_window_bits=16" nil]
           ["permessage-deflate; client_max_window_bits=09" nil]
           ["permessage-deflate; server_no_context_takeover=1" nil]
           ["permessage-deflate; server_no_context_takeover; server_no_context_takeover" nil]
           ["permessage-deflate; unknown_param" nil]
           ["permessage-deflate; client_max_window_bits=\"1" nil]]]
    (is (= expected (some-> (PerMessageDeflate/negotiate offer) .responseHeader)) (pr-str offer))))

(def ^:private deflate-tail
  (byte-array [0 0 (unchecked-byte 0xFF) (unchecked-byte 0xFF)]))

(defn- deflate-message
  "Compresses `data` as one permessage-deflate message with `deflater`
  (raw deflate, sync flush, the trailing 00 00 FF FF removed)."
  ^bytes [^java.util.zip.Deflater deflater ^bytes data]
  (.setInput deflater data)
  (let [out (ByteArrayOutputStream.)
        buf (byte-array 4096)]
    (loop []
      (let [n (.deflate deflater buf 0 (alength buf) java.util.zip.Deflater/SYNC_FLUSH)]
        (.write out buf 0 n)
        (when (= n (alength buf)) (recur))))
    (let [bs (.toByteArray out)]
      (java.util.Arrays/copyOf bs (- (alength bs) 4)))))

(defn- inflate-message ^bytes [^java.util.zip.Inflater inflater ^bytes data]
  (.setInput inflater (byte-array (concat data deflate-tail)))
  (let [out (ByteArrayOutputStream.)
        buf (byte-array 4096)]
    (loop []
      (let [n (.inflate inflater buf)]
        (.write out buf 0 n)
        (when (pos? n) (recur))))
    (.toByteArray out)))

(defn- client-deflater ^java.util.zip.Deflater []
  (java.util.zip.Deflater. java.util.zip.Deflater/DEFAULT_COMPRESSION true))

(defn- negotiated
  ([] (negotiated "permessage-deflate"))
  ([offer] (PerMessageDeflate/negotiate offer)))

(deftest ws-deflate-receives-compressed-messages
  (let [d (client-deflater)
        text (apply str (repeat 50 "hello deflate "))
        c1 (deflate-message d (utf8 text))
        ;; Context takeover: the second message refers back to the first.
        c2 (deflate-message d (utf8 text))
        bin (byte-array (map unchecked-byte (range 3000)))
        c3 (deflate-message d bin)
        half (quot (alength c3) 2)
        r (run-ws-bytes (frames [0x41 true c1]
                                [0x41 true c2]
                                [0x42 false (java.util.Arrays/copyOfRange c3 0 half)]
                                [0x0 true (java.util.Arrays/copyOfRange c3 half (alength c3))])
                        {:deflate (negotiated)})]
    (is (< (alength c2) (alength c1)) "second message used the shared window")
    (is (= [[:message text] [:message text] [:message (vec bin)]]
           (filterv #(= :message (first %)) (:events r))))))

(deftest ws-deflate-sends-compressed-messages
  (doseq [[offer same-size?] [["permessage-deflate" false]
                              ["permessage-deflate; server_no_context_takeover" true]]]
    (let [text (apply str (repeat 100 "abcdefgh"))
          r (run-ws-bytes (byte-array 0)
                          {:deflate (negotiated offer)
                           :on-open (fn [^WebSocketSocket s]
                                      (.sendText s text)
                                      (.sendText s text)
                                      (.sendText s "hi")
                                      (.sendBinary s (ByteBuffer/wrap (utf8 text))))})
          [f1 f2 f3 f4] (:frames r)
          inf (java.util.zip.Inflater. true)
          payload (fn [f] (byte-array (:payload f)))]
      (is (= [true true false true] (mapv :rsv1? [f1 f2 f3 f4])) offer)
      (is (= text (String. (inflate-message inf (payload f1)) StandardCharsets/UTF_8)) offer)
      (is (= text (String. (inflate-message inf (payload f2)) StandardCharsets/UTF_8)) offer)
      (is (= "hi" (String. ^bytes (payload f3) StandardCharsets/UTF_8)) "small messages go uncompressed")
      (is (= text (String. (inflate-message inf (payload f4)) StandardCharsets/UTF_8)) offer)
      (is (= same-size? (= (count (:payload f1)) (count (:payload f2))))
          (str offer ": context taken over unless server_no_context_takeover")))))

(defn- collected?
  "True once the referent of `ref` was garbage collected (a few full GCs)."
  [^java.lang.ref.WeakReference ref]
  (loop [i 0]
    (cond
      (nil? (.get ref)) true
      (= i 20) false
      :else (do (System/gc) (Thread/sleep 10) (recur (inc i))))))

(deftest ws-deflate-does-not-retain-sent-messages
  ;; The Deflater lives as long as the connection; it must not keep the
  ;; last message it compressed reachable (heap array or direct buffer).
  (let [results (atom {})]
    (run-ws-bytes (byte-array 0)
                  {:deflate (negotiated "permessage-deflate")
                   :on-open (fn [^WebSocketSocket s]
                              (let [heap (java.lang.ref.WeakReference. (byte-array 100000))
                                    direct (java.lang.ref.WeakReference. (ByteBuffer/allocateDirect 100000))]
                                (.sendBinary s (ByteBuffer/wrap ^bytes (.get heap)))
                                (.sendBinary s ^ByteBuffer (.get direct))
                                (swap! results assoc
                                       :heap (collected? heap)
                                       :direct (collected? direct))))})
    (is (= {:heap true :direct true} @results))))

(defn- final-block
  "`data` compressed as one raw deflate stream ending with a BFINAL block,
  as clients without a sync flush send it (RFC 7692 §7.2.3.4)."
  ^bytes [^bytes data]
  (let [d (java.util.zip.Deflater. java.util.zip.Deflater/DEFAULT_COMPRESSION true)
        out (ByteArrayOutputStream.)
        buf (byte-array 4096)]
    (.setInput d data)
    (.finish d)
    (while (not (.finished d))
      (.write out buf 0 (.deflate d buf)))
    (.end d)
    (.toByteArray out)))

(deftest ws-deflate-blocks-after-a-final-block
  ;; RFC 7692 §7.2.3.1: a message may hold blocks with BFINAL set; the
  ;; next block follows. With context takeover the window survives the
  ;; final block, so later data may still refer back to it.
  (let [hello (utf8 "Hello")
        text (apply str (repeat 40 "context takeover "))]
    (testing "a block after a final block in the same message"
      (let [payload (byte-array (concat (final-block hello)
                                        (deflate-message (client-deflater) (utf8 " world"))))
            r (run-ws-bytes (frames [0x41 true payload]) {:deflate (negotiated)})]
        (is (= [[:message "Hello world"]] (filterv #(= :message (first %)) (:events r))))))
    (testing "the RFC 7692 §7.2.3.4 example, then a message referring back past the final block"
      (let [rfc (byte-array (map unchecked-byte [0xf3 0x48 0xcd 0xc9 0xc9 0x07 0x00 0x00]))
            m1 (byte-array (concat (final-block (utf8 text)) [0]))
            d (doto (client-deflater) (.setDictionary (utf8 text)))
            m2 (deflate-message d (utf8 text))
            r (run-ws-bytes (frames [0x41 true rfc] [0x41 true m1] [0x41 true m2])
                            {:deflate (negotiated)})]
        (is (< (alength m2) 20) "the second message is back-references")
        (is (= [[:message "Hello"] [:message text] [:message text]]
               (filterv #(= :message (first %)) (:events r)))
            (pr-str (:events r)))))))

(deftest ws-deflate-large-messages-are-sent-as-fragments
  ;; A large compressed message leaves as a sequence of frames (RSV1 on
  ;; the first only), so compressing it holds a bounded buffer rather than
  ;; the whole compressed message.
  (let [size (* 2 1024 1024)
        data (let [b (byte-array size)] (.nextBytes (java.util.Random. 7) b) b)
        allocated (atom nil)
        r (run-ws-bytes (byte-array 0)
                        {:deflate (negotiated)
                         :out (ByteArrayOutputStream. (int (* 3 size)))
                         :on-open (fn [^WebSocketSocket s]
                                    (.sendText s (apply str (repeat 100 "warm up ")))
                                    (let [before (thread-allocated-bytes)]
                                      (.sendBinary s (ByteBuffer/wrap data))
                                      (reset! allocated (- (thread-allocated-bytes) before))))})
        [warm & fs] (:frames r)
        inf (java.util.zip.Inflater. true)]
    (inflate-message inf (byte-array (:payload warm)))
    (is (< 4 (count fs)) "several frames")
    (is (= (concat [[0x2 true false]] (repeat (- (count fs) 2) [0x0 false false]) [[0x0 false true]])
           (mapv (juxt :opcode :rsv1? :fin?) fs)))
    (is (= (vec data) (vec (inflate-message inf (byte-array (mapcat :payload fs))))))
    (is (< @allocated (quot size 4)) (str "allocated " @allocated " bytes"))))

(deftest zlib-pool-reuses-what-it-gets-back
  (let [d (ZlibPool/deflater)]
    (ZlibPool/give d)
    (is (identical? d (ZlibPool/deflater)) "a Deflater given back is handed out again")
    (ZlibPool/give d)))

(deftest ws-deflate-without-context-takeover-holds-no-deflater
  ;; Without the server's context takeover nothing survives a message on
  ;; the send side, so a connection borrows a Deflater from a server-wide
  ;; pool per message instead of holding ~256 KiB of native memory for its
  ;; lifetime.
  (let [deflate (negotiated "permessage-deflate; server_no_context_takeover")
        text (apply str (repeat 100 "abcdefgh"))
        held (atom [])
        r (run-ws-bytes (frames [0x41 true (deflate-message (client-deflater) (utf8 text))])
                        {:deflate deflate
                         :on-message (fn [^WebSocketSocket s m]
                                       (.sendText s ^String m)
                                       (.sendText s ^String m)
                                       (swap! held conj (some? (field-value deflate "deflater"))))})
        inf (java.util.zip.Inflater. true)]
    (is (= [false] @held))
    (is (= [text text] (mapv #(String. (inflate-message inf (byte-array (:payload %))) StandardCharsets/UTF_8)
                             (take 2 (:frames r)))))))

(deftest ws-deflate-client-context-takeover-despite-its-hint
  ;; A client's client_no_context_takeover offer is only a hint while the
  ;; response doesn't echo it, and clients (Autobahn's) do keep their
  ;; context: the server's Inflater keeps its window across messages.
  (let [deflate (negotiated "permessage-deflate; client_no_context_takeover; client_max_window_bits")
        d (client-deflater)
        text (apply str (repeat 50 "hello deflate "))
        r (run-ws-bytes (frames [0x41 true (deflate-message d (utf8 text))]
                                [0x41 true (deflate-message d (utf8 text))])
                        {:deflate deflate})]
    (is (= "permessage-deflate" (.responseHeader ^PerMessageDeflate deflate)))
    (is (= [[:message text] [:message text]] (filterv #(= :message (first %)) (:events r))))))

(deftest ws-deflate-violations
  (let [d (client-deflater)
        c (deflate-message d (utf8 "hello hello hello"))]
    (doseq [[label input code]
            [["rsv1 on a continuation" (frames [0x41 false c] [0x40 true c]) 1002]
             ["rsv1 on a control frame" (frames [0x49 true (byte-array 0)]) 1002]
             ["rsv2" (frames [0x21 true (utf8 "x")]) 1002]
             ["corrupt data" (frames [0x41 true (byte-array [(unchecked-byte 0xFF) 1 2 3 4 5])]) 1007]
             ["invalid utf-8 inside" (frames [0x41 true (deflate-message (client-deflater)
                                                                         (byte-array [(unchecked-byte 0xC3) 0x28]))])
              1007]]]
      (let [r (run-ws-bytes input {:deflate (negotiated)})]
        (is (= [code] (server-close-codes r)) label))))
  (testing "rsv1 without negotiation"
    (let [r (run-ws-bytes (frames [0x41 true (byte-array 3)]) {})]
      (is (= [1002] (server-close-codes r))))))

(deftest ws-deflate-bomb-is-bounded
  ;; 16 MiB of zeros compress to a few KiB; inflating stops at the
  ;; message limit (1009) without allocating the whole thing.
  (let [bomb (deflate-message (client-deflater) (byte-array (* 16 1024 1024)))
        input (frames [0x42 true bomb])
        before (thread-allocated-bytes)
        r (run-ws-bytes input {:deflate (negotiated) :max-message (* 1024 1024)})
        allocated (- (thread-allocated-bytes) before)]
    (is (< (alength bomb) (* 64 1024)))
    (is (= [1009] (server-close-codes r)))
    (is (< allocated (* 8 1024 1024)) (str "allocated " allocated " bytes"))))

(deftest ws-deflate-negotiated-over-tcp
  (with-server echo-handler {:ws-compression true}
    (fn [port]
      (with-open [sock (Socket. "127.0.0.1" (int port))]
        (.setSoTimeout sock 3000)
        (let [resp (ws-handshake-response sock {"Sec-WebSocket-Extensions"
                                                "permessage-deflate; client_max_window_bits"})
              in (.getInputStream sock)
              out (.getOutputStream sock)
              text (apply str (repeat 40 "compress me "))]
          (is (re-find #"(?i)sec-websocket-extensions: permessage-deflate\r\n" resp))
          (.write out (mask-frame 0x41 true (deflate-message (client-deflater) (utf8 text))))
          (.flush out)
          (let [f (read-frame in)]
            (is (:rsv1? f))
            (is (= text (String. (inflate-message (java.util.zip.Inflater. true) (:payload f))
                                 StandardCharsets/UTF_8))))))))
  (testing "off by default"
    (with-server echo-handler {}
      (fn [port]
        (with-open [sock (Socket. "127.0.0.1" (int port))]
          (.setSoTimeout sock 3000)
          (is (not (re-find #"(?i)sec-websocket-extensions"
                            (ws-handshake-response sock {"Sec-WebSocket-Extensions" "permessage-deflate"})))))))))

;; ---- Allocation ---------------------------------------------------------------

(deftest ws-fragmented-message-buffer-reused
  ;; A connection receiving 100 KiB messages keeps its assembly buffer
  ;; instead of regrowing it from a few KiB for every message.
  (let [n 50
        size (* 100 1024)
        half (byte-array (quot size 2))
        input (apply frames (mapcat (fn [_] [[0x2 false half] [0x0 true half]]) (range n)))
        in (ByteArrayInputStream. input)
        before (thread-allocated-bytes)
        r (run-ws in {:on-message (fn [_ _])})
        allocated (- (thread-allocated-bytes) before)]
    (is (= 1006 (second (close-event r))))
    (is (< allocated (* 1.3 n size)) (str "allocated " allocated " bytes"))))

(deftest ws-deflate-small-server-window
  ;; With server_max_window_bits=N the server must never refer back more
  ;; than 2^N bytes: messages up to 2^N are compressed on their own
  ;; (fresh window each), larger ones go uncompressed. A client inflater
  ;; limited to that window decodes every one.
  (let [small (apply str (repeat 64 "abcdefgh"))
        large (apply str (repeat 128 "abcdefgh"))
        r (run-ws-bytes (byte-array 0)
                        {:deflate (negotiated "permessage-deflate; server_max_window_bits=9")
                         :on-open (fn [^WebSocketSocket s]
                                    (.sendText s small)
                                    (.sendText s small)
                                    (.sendText s large))})
        [f1 f2 f3] (:frames r)]
    (is (= [true true false] (mapv :rsv1? [f1 f2 f3])))
    (is (= (:payload f1) (:payload f2)) "no reference to the previous message")
    (is (= small (String. (inflate-message (java.util.zip.Inflater. true) (byte-array (:payload f2)))
                          StandardCharsets/UTF_8)))
    (is (= large (String. (byte-array (:payload f3)) StandardCharsets/UTF_8)))))

;; ---- Idle connections ----------------------------------------------------------

(defn- idle-footprint
  "What a WebSocketConnection (reached through the socket its listener got)
  holds in its per-connection buffers."
  [socket]
  (let [conn (field-value socket "this$0")
        reader (field-value conn "reader")
        deflate (field-value conn "deflate")
        tls (let [s (field-value conn "socket")]
              (when (instance? com.s_exp.enso.core.TlsSocket$AdapterSocket s)
                (.tls ^com.s_exp.enso.core.TlsSocket$AdapterSocket s)))]
    {:read-buffer (alength ^bytes (field-value conn "rbuf"))
     :message-buffer (alength ^bytes (field-value reader "scratch"))
     :inflate-input (some-> ^bytes (field-value reader "inflateIn") alength)
     :gather (some-> ^bytes (field-value conn "gatherOut") alength)
     :deflate-output (alength ^bytes (field-value conn "deflateOut"))
     :deflater (some? (some-> deflate (field-value "deflater")))
     :inflater (some? (some-> deflate (field-value "inflater")))
     :tls-in (some-> tls (field-value "peerNetData") (#(.capacity ^ByteBuffer %)))
     :tls-out (some-> tls (field-value "myNetData") (#(.capacity ^ByteBuffer %)))}))

(defn- idle-release-check
  "Opens a WebSocket on a server started with `opts`, echoes a large
  message (compressed when `offer` negotiates permessage-deflate), and
  returns [footprint-after-echo footprint-after-idle echo-after-idle]."
  [opts offer]
  (let [socket-p (promise)
        handler (fn [_]
                  {:ring.websocket/listener
                   {:on-open (fn [s] (deliver socket-p s))
                    :on-message (fn [^WebSocketSocket s m]
                                  (if (string? m) (.sendText s ^String m) (.sendBinary s ^ByteBuffer m)))}})
        srv (enso/run-server handler (merge {:port 0 :idle-timeout 20000} opts))]
    (try
      (with-open [^Socket sock (if (:ssl-context opts)
                                 (let [^javax.net.ssl.SSLSocket ss
                                       (.createSocket (.getSocketFactory (support/trust-all-ssl-context))
                                                      "127.0.0.1" (int (enso/port srv)))]
                                   (.startHandshake ss)
                                   ss)
                                 (Socket. "127.0.0.1" (int (enso/port srv))))]
        (.setSoTimeout sock 5000)
        (let [[in ^java.io.OutputStream out] (ws-handshake! sock (if offer {"Sec-WebSocket-Extensions" offer} {}))
              text (apply str (repeat 10000 "0123456789"))
              d (client-deflater)
              inf (java.util.zip.Inflater. true)
              send! (fn []
                      ;; A client offering client_no_context_takeover
                      ;; compresses each message on its own.
                      (when (some-> offer (clojure.string/includes? "client_no_context_takeover"))
                        (.reset d))
                      (.write out (if offer
                                    (mask-frame 0x41 true (deflate-message d (utf8 text)))
                                    (mask-frame 0x1 true (utf8 text))))
                      (.flush out)
                      (let [f (read-frame in)]
                        (if (:rsv1? f)
                          (String. (inflate-message inf (:payload f)) StandardCharsets/UTF_8)
                          (String. ^bytes (:payload f) StandardCharsets/UTF_8))))
              socket (deref socket-p 2000 nil)]
          (is (= text (send!)))
          (let [busy (idle-footprint socket)
                idle (do (support/await-condition #(= 0 (:message-buffer (idle-footprint socket))) 5000 50)
                         (idle-footprint socket))]
            [busy idle (= text (send!))])))
      (finally (enso/stop srv)))))

(deftest ws-idle-connection-gives-back-its-buffers
  ;; After a second without frames a WebSocket keeps only small buffers:
  ;; message assembly, staging and TLS record buffers grow back when the
  ;; next message arrives.
  (testing "plain"
    (let [[busy idle echoed] (idle-release-check {} nil)]
      (is (= {:read-buffer 8192 :gather 16384} (select-keys busy [:read-buffer :gather])))
      (is (< 100000 (:message-buffer busy)))
      (is (= {:read-buffer 512 :message-buffer 0 :gather nil}
             (select-keys idle [:read-buffer :message-buffer :gather])))
      (is echoed "the next message is served")))
  (testing "TLS"
    (let [[busy idle echoed] (idle-release-check {:ssl-context (support/server-ssl-context)} nil)]
      (is (< 512 (:tls-in busy)))
      (is (= {:tls-in 512 :tls-out 512} (select-keys idle [:tls-in :tls-out])))
      (is echoed)))
  (testing "compressed, context takeover: the Deflater and Inflater keep their windows"
    (let [[busy idle echoed] (idle-release-check {:ws-compression true} "permessage-deflate")]
      (is (= {:deflater true :inflater true} (select-keys busy [:deflater :inflater])))
      (is (= {:message-buffer 0 :inflate-input nil :deflate-output 0 :deflater true :inflater true}
             (select-keys idle [:message-buffer :inflate-input :deflate-output :deflater :inflater])))
      (is echoed)))
  (testing "compressed without the server's context takeover: no Deflater between messages"
    (let [[_ idle echoed] (idle-release-check {:ws-compression true}
                                              "permessage-deflate; server_no_context_takeover")]
      (is (= {:deflater false :inflater true} (select-keys idle [:deflater :inflater])))
      (is echoed))))

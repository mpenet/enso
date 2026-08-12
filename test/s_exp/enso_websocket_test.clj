(ns s-exp.enso-websocket-test
  "Raw-socket WebSocket protocol tests. Uses low-level frame writing so
  we can inject wire-level cases the java.net.http.WebSocket client
  won't produce: control-frame interleave between fragments (#215),
  invalid UTF-8 in text frames (#216), truncated multi-byte at frame
  boundary, unmasked client frame, oversized control frame."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (com.s_exp.enso.websocket WebSocketSocket)
           (java.io ByteArrayOutputStream DataInputStream EOFException)
           (java.net Socket)
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

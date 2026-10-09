;; ABOUTME: Live-server HTTP/2 frame-level fuzzing over raw TLS: random and mutated frames, CONTINUATION
;; ABOUTME: splits and floods, rapid resets, flow-control and SETTINGS abuse, truncated frames.
(ns s-exp.enso-h2-frame-fuzz-test
  "Every trial opens a TLS connection negotiating h2, sends the preface
  and a generated sequence of frames, then a PING. While that connection
  is still open a fresh connection must get a 200 for a GET (the server
  keeps serving others). The hostile connection must then, within its
  deadline, answer the PING, send GOAWAY or close: never hang past the
  server's timeouts. Every frame the server sends must be well formed
  (lengths, stream ids, error codes), and nothing may follow a GOAWAY
  for a stream above its last-stream-id."
  (:require [clojure.test :refer [deftest is use-fixtures]]
            [clojure.walk :as walk]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [s-exp.enso :as enso]
            [s-exp.enso-property-support :as ps]
            [s-exp.enso-test-support :as support])
  (:import (com.s_exp.enso.http2 Hpack$Decoder Hpack$Encoder Hpack$HeaderField)
           (java.io ByteArrayOutputStream EOFException IOException InputStream OutputStream)
           (java.net InetSocketAddress SocketTimeoutException)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.util ArrayList List)
           (javax.net.ssl SSLContext SSLSocket)))

(set! *warn-on-reflection* true)

;; Short server timeouts so a connection left waiting for more bytes
;; resolves quickly; low abuse limits so floods trip them within a trial.
(def ^:private server-opts
  {:host "127.0.0.1"
   :port 0
   :http2 true
   :idle-timeout 1000
   :header-timeout 1000
   :read-timeout 1000
   :handshake-timeout 2000
   :http2-stream-reset-limit 20
   :http2-continuation-limit 16})

;; From the end of the trial's writes; well above every server timeout.
(def ^:private outcome-deadline-ms 6000)
(def ^:private health-deadline-ms 5000)

(def ^:dynamic ^:private *port* nil)

(def ^:private ^SSLContext client-context (support/trust-all-ssl-context))

(defn- handler [request]
  (let [n (if-let [^InputStream body (:body request)] (alength (.readAllBytes body)) 0)]
    {:status 200
     :headers {"content-type" "text/plain"}
     :body (str (:uri request) "|" n)}))

(use-fixtures :once
  (fn [f]
    (let [srv (enso/run-server handler (assoc server-opts :ssl-context (support/server-ssl-context)))]
      (try
        (binding [*port* (enso/port srv)]
          (f))
        (finally (enso/stop srv))))))

;; ---- frames -------------------------------------------------------------------

(def ^:private preface (.getBytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" StandardCharsets/ISO_8859_1))

(def ^:private DATA 0)
(def ^:private HEADERS 1)
(def ^:private PRIORITY 2)
(def ^:private RST_STREAM 3)
(def ^:private SETTINGS 4)
(def ^:private PUSH_PROMISE 5)
(def ^:private PING 6)
(def ^:private GOAWAY 7)
(def ^:private WINDOW_UPDATE 8)
(def ^:private CONTINUATION 9)

(def ^:private END_STREAM 0x1)
(def ^:private ACK 0x1)
(def ^:private END_HEADERS 0x4)
(def ^:private PADDED 0x8)
(def ^:private PRIORITY_FLAG 0x20)

(def ^:private ^"[B" ping-payload (.getBytes "enso-fz!" StandardCharsets/ISO_8859_1))

(defn- frame-bytes
  "Wire bytes of one frame; `declared` overrides the length field."
  (^bytes [type flags stream ^bytes payload]
   (frame-bytes type flags stream payload (alength payload)))
  (^bytes [type flags stream ^bytes payload declared]
   (let [n (alength payload)
         bb (ByteBuffer/allocate (+ 9 n))
         declared (long declared)]
     (.put bb (unchecked-byte (bit-shift-right declared 16)))
     (.put bb (unchecked-byte (bit-shift-right declared 8)))
     (.put bb (unchecked-byte declared))
     (.put bb (unchecked-byte type))
     (.put bb (unchecked-byte flags))
     (.putInt bb (unchecked-int stream))
     (.put bb payload)
     (.array bb))))

(defn- ints->bytes ^bytes [& ints]
  (let [bb (ByteBuffer/allocate (* 4 (count ints)))]
    (doseq [i ints] (.putInt bb (unchecked-int i)))
    (.array bb)))

(defn- settings-payload ^bytes [pairs]
  (let [bb (ByteBuffer/allocate (* 6 (count pairs)))]
    (doseq [[id v] pairs]
      (.putShort bb (unchecked-short id))
      (.putInt bb (unchecked-int v)))
    (.array bb)))

(defn- request-block
  "HPACK block for a GET/POST to `path`, from the connection's encoder."
  ^bytes [^Hpack$Encoder enc method path extra]
  (let [l (ArrayList.)]
    (doseq [[n v] (concat [[":method" method] [":scheme" "https"] [":path" path]
                           [":authority" "localhost"]]
                          extra)]
      (.add l (Hpack$HeaderField. ^String n ^String v)))
    (.encode enc l)))

(defn- split-bytes
  "`bs` cut into `n` (>= 1) nearly equal consecutive pieces."
  [^bytes bs n]
  (let [len (alength bs)
        n (max 1 (min (long n) (max 1 len)))
        step (long (Math/ceil (/ (double len) n)))]
    (if (zero? len)
      [bs]
      (for [i (range 0 len step)]
        (java.util.Arrays/copyOfRange bs (int i) (int (min len (+ i step))))))))

;; ---- operations ---------------------------------------------------------------

(def ^:private gen-stream-id
  (gen/frequency [[6 (gen/elements [1 3 5 7 9])]
                  [2 (gen/elements [0 2 4])]
                  [1 (gen/elements [0x7fffffff (unchecked-int 0x80000001) 101])]]))

(def ^:private gen-error-code (gen/frequency [[4 (gen/choose 0 13)] [1 (gen/choose 14 0xffff)]]))

(def ^:private gen-settings-pair
  (gen/tuple (gen/frequency [[5 (gen/choose 1 6)] [1 (gen/choose 7 0xffff)]])
             (gen/frequency [[3 (gen/choose 0 70000)]
                             [1 (gen/elements [0 1 2 16383 16384 16777215 16777216
                                               0x7fffffff 0x80000000 0xffffffff])]])))

(def ^:private gen-extra-headers
  (gen/vector (gen/tuple (gen/elements ["accept" "x-a" "cookie" "te" "connection" "content-length"
                                        "Upper-Case" ":fake" "user-agent"])
                         (gen/elements ["" "trailers" "1" "0" "a=b" "keep-alive" "x"
                                        (apply str (repeat 300 "v"))]))
              0 4))

(def ^:private gen-op
  (gen/frequency
   [[6 (gen/tuple (gen/return :request) (gen/one-of [(gen/return :next) gen-stream-id])
                  (gen/elements ["GET" "POST" "HEAD" "CONNECT"]) gen/boolean (gen/choose 1 4)
                  gen-extra-headers)]
    [3 (gen/tuple (gen/return :data) gen-stream-id (gen/elements [0 END_STREAM PADDED (bit-or PADDED END_STREAM)])
                  (ps/gen-bytes 300))]
    [2 (gen/tuple (gen/return :settings) (gen/vector gen-settings-pair 0 4) gen/boolean)]
    [2 (gen/tuple (gen/return :window-update) (gen/elements [0 1 3 5 9])
                  (gen/elements [0 1 65535 0x7fffffff (unchecked-int 0x80000000)]))]
    [2 (gen/tuple (gen/return :rst) gen-stream-id gen-error-code)]
    [1 (gen/tuple (gen/return :priority) gen-stream-id gen-stream-id (gen/choose 0 255))]
    [1 (gen/tuple (gen/return :ping) gen/boolean (ps/gen-bytes 10))]
    [1 (gen/tuple (gen/return :goaway) gen-stream-id gen-error-code)]
    [1 (gen/tuple (gen/return :continuation-flood) (gen/choose 4 40))]
    [1 (gen/tuple (gen/return :rapid-reset) (gen/choose 5 60))]
    [1 (gen/tuple (gen/return :orphan-continuation) gen-stream-id (ps/gen-bytes 40))]
    [2 (gen/tuple (gen/return :headers-garbage) gen-stream-id
                  (gen/elements [END_HEADERS (bit-or END_HEADERS END_STREAM) 0 (bit-or END_HEADERS PADDED)
                                 (bit-or END_HEADERS PRIORITY_FLAG)])
                  (ps/gen-bytes 60))]
    [2 (gen/tuple (gen/return :raw) (gen/frequency [[5 (gen/choose 0 9)] [1 (gen/choose 10 255)]])
                  (gen/choose 0 255) gen-stream-id (ps/gen-bytes 40))]
    [1 (gen/tuple (gen/return :bad-length) (gen/choose 0 9) gen-stream-id
                  (gen/elements [0 1 8 16384 16385 0xffffff]) (ps/gen-bytes 20))]]))

(def ^:private gen-ops (gen/vector gen-op 1 12))

(defn- materialize
  "Wire bytes for `ops`, using one HPACK encoder for the connection.
  Returns {:wire byte[] :max-frame n}: the largest frame size the server
  may use given the SETTINGS sent."
  [ops]
  (let [enc (Hpack$Encoder. 4096)
        out (ByteArrayOutputStream.)
        next-id (volatile! 1)
        max-frame (volatile! 16384)
        emit! (fn [^bytes b] (.write out b 0 (alength b)))
        fresh-id! (fn [] (let [id @next-id] (vswap! next-id + 2) id))]
    (emit! preface)
    (emit! (frame-bytes SETTINGS 0 0 (byte-array 0)))
    (doseq [[op & args] ops]
      (case op
        :request
        (let [[sid method end-stream pieces extra] args
              sid (if (= sid :next) (fresh-id!) sid)
              block (request-block enc method (str "/r" sid) extra)
              parts (vec (split-bytes block pieces))
              n (count parts)]
          (doseq [[i ^bytes part] (map-indexed vector parts)]
            (emit! (frame-bytes (if (zero? i) HEADERS CONTINUATION)
                                (bit-or (if (and (zero? i) end-stream) END_STREAM 0)
                                        (if (= i (dec n)) END_HEADERS 0))
                                sid part))))

        :data
        (let [[sid flags ^bytes payload] args
              payload (if (pos? (bit-and (long flags) PADDED))
                        (let [p (byte-array (inc (alength payload)))]
                          (aset p 0 (unchecked-byte (if (pos? (alength payload)) (aget payload 0) 0)))
                          (System/arraycopy payload 0 p 1 (alength payload))
                          p)
                        payload)]
          (emit! (frame-bytes DATA flags sid payload)))

        :settings
        (let [[pairs ack] args]
          (doseq [[id v] pairs]
            (when (and (= 5 (long id)) (<= 16384 (long v) 16777215))
              (vreset! max-frame (max (long @max-frame) (long v)))))
          (emit! (frame-bytes SETTINGS (if ack ACK 0) 0 (settings-payload pairs))))

        :window-update
        (let [[sid inc] args]
          (emit! (frame-bytes WINDOW_UPDATE 0 sid (ints->bytes inc))))

        :rst
        (let [[sid code] args]
          (emit! (frame-bytes RST_STREAM 0 sid (ints->bytes code))))

        :priority
        (let [[sid dep weight] args
              p (byte-array 5)]
          (System/arraycopy (ints->bytes dep) 0 p 0 4)
          (aset p 4 (unchecked-byte weight))
          (emit! (frame-bytes PRIORITY 0 sid p)))

        :ping
        (let [[ack ^bytes payload] args]
          (emit! (frame-bytes PING (if ack ACK 0) 0 payload)))

        :goaway
        (let [[last code] args]
          (emit! (frame-bytes GOAWAY 0 0 (ints->bytes last code))))

        :continuation-flood
        (let [[n] args
              sid (fresh-id!)
              block (request-block enc "GET" "/flood" [])]
          (emit! (frame-bytes HEADERS END_STREAM sid block))
          (dotimes [_ n]
            (emit! (frame-bytes CONTINUATION 0 sid (byte-array 0)))))

        :rapid-reset
        (let [[n] args]
          (dotimes [_ n]
            (let [sid (fresh-id!)]
              (emit! (frame-bytes HEADERS (bit-or END_HEADERS END_STREAM) sid
                                  (request-block enc "GET" "/reset" [])))
              (emit! (frame-bytes RST_STREAM 0 sid (ints->bytes 8))))))

        :orphan-continuation
        (let [[sid payload] args]
          (emit! (frame-bytes CONTINUATION END_HEADERS sid payload)))

        :headers-garbage
        (let [[sid flags payload] args]
          (emit! (frame-bytes HEADERS flags sid payload)))

        :raw
        (let [[type flags sid payload] args]
          (emit! (frame-bytes type flags sid payload)))

        :bad-length
        (let [[type sid declared payload] args]
          (emit! (frame-bytes type 0 sid payload declared)))))
    (emit! (frame-bytes PING 0 0 ping-payload))
    {:wire (.toByteArray out) :max-frame @max-frame}))

;; ---- client -------------------------------------------------------------------

(defn- connect ^SSLSocket []
  (let [^SSLSocket s (.createSocket (.getSocketFactory client-context))]
    (.connect s (InetSocketAddress. "127.0.0.1" (int *port*)) 2000)
    (let [p (.getSSLParameters s)]
      (.setApplicationProtocols p (into-array String ["h2"]))
      (.setSSLParameters s p))
    (.setSoTimeout s 2000)
    (.startHandshake s)
    (when-not (= "h2" (.getApplicationProtocol s))
      (throw (IllegalStateException. (str "ALPN negotiated " (pr-str (.getApplicationProtocol s))))))
    s))

(defn- read-fully
  "Reads exactly `n` bytes before `deadline`: byte[], :eof or :timeout."
  [^InputStream in ^long n ^long deadline]
  (let [buf (byte-array n)]
    (loop [off 0]
      (if (= off n)
        buf
        (if (> (System/currentTimeMillis) deadline)
          :timeout
          (let [r (long (try
                          (.read in buf off (- n off))
                          (catch SocketTimeoutException _ 0)
                          (catch IOException _ -1)))]
            (if (neg? r) :eof (recur (+ off r)))))))))

(defn- read-frame
  "Next frame {:type :flags :stream :payload} before `deadline`, or :eof /
  :timeout."
  [^InputStream in ^long deadline]
  (let [h (read-fully in 9 deadline)]
    (if (keyword? h)
      h
      (let [^bytes h h
            len (bit-or (bit-shift-left (bit-and (aget h 0) 0xff) 16)
                        (bit-shift-left (bit-and (aget h 1) 0xff) 8)
                        (bit-and (aget h 2) 0xff))
            p (read-fully in len deadline)]
        (if (keyword? p)
          p
          {:type (bit-and (aget h 3) 0xff)
           :flags (bit-and (aget h 4) 0xff)
           :stream (bit-and (.getInt (ByteBuffer/wrap h 5 4)) 0x7fffffff)
           :length len
           :payload p})))))

(defn- frame-violations
  "Problems with one server frame, given the trial state so far."
  [{:keys [type flags stream length ^bytes payload]} max-frame goaway-last]
  (let [type (long type) stream (long stream) length (long length) flags (long flags)]
    (cond-> []
      (> length (long max-frame)) (conj [:frame-too-large type length])
      (> type 9) (conj [:unknown-frame-type type])
      (and (#{DATA HEADERS} type) (or (zero? stream) (even? stream))) (conj [:bad-stream type stream])
      (and goaway-last (#{HEADERS PUSH_PROMISE} type) (> stream (long goaway-last)))
      (conj [:stream-after-goaway type stream goaway-last])
      (= type PUSH_PROMISE) (conj [:push-promise stream])
      (and (= type GOAWAY) (or (not (zero? stream)) (< length 8)))
      (conj [:bad-goaway stream length])
      (and (= type GOAWAY) (>= length 8) (> (Integer/toUnsignedLong (.getInt (ByteBuffer/wrap payload 4 4))) 13))
      (conj [:unknown-goaway-code (.getInt (ByteBuffer/wrap payload 4 4))])
      (and (= type RST_STREAM) (or (zero? stream) (not= length 4)))
      (conj [:bad-rst-stream stream length])
      (and (= type RST_STREAM) (= length 4) (> (Integer/toUnsignedLong (.getInt (ByteBuffer/wrap payload))) 13))
      (conj [:unknown-rst-code (.getInt (ByteBuffer/wrap payload))])
      (and (= type SETTINGS) (or (not (zero? stream))
                                 (if (pos? (bit-and flags ACK)) (pos? length) (pos? (mod length 6)))))
      (conj [:bad-settings stream length])
      (and (= type PING) (or (not (zero? stream)) (not= length 8))) (conj [:bad-ping stream length])
      (and (= type WINDOW_UPDATE)
           (or (not= length 4) (zero? (bit-and (.getInt (ByteBuffer/wrap payload)) 0x7fffffff))))
      (conj [:bad-window-update stream length]))))

(defn- outcome
  "Reads the hostile connection's frames until the PING is answered, the
  server closes, or `deadline`. {:result :alive|:goaway|:closed|:hang
  :violations [...] :frames [[type stream] ...]}."
  [^SSLSocket s max-frame ^long deadline]
  (let [in (.getInputStream s)]
    (.setSoTimeout s 200)
    (loop [violations [] frames [] goaway-last nil]
      (let [f (read-frame in deadline)]
        (cond
          (= f :eof) {:result (if goaway-last :goaway :closed) :violations violations :frames frames}
          (= f :timeout) {:result :hang :violations violations :frames frames}
          :else
          (let [{:keys [type flags stream ^bytes payload]} f
                violations (into violations (frame-violations f max-frame goaway-last))
                frames (conj frames [type stream])
                goaway-last (if (and (= GOAWAY type) (>= (alength payload) 8))
                              (bit-and (.getInt (ByteBuffer/wrap payload)) 0x7fffffff)
                              goaway-last)]
            (if (and (= PING type) (pos? (bit-and (long flags) ACK))
                     (java.util.Arrays/equals payload ping-payload) (nil? goaway-last))
              {:result :alive :violations violations :frames frames}
              (recur violations frames goaway-last))))))))

(defn- status-of
  "The :status of a response HEADERS block."
  [^Hpack$Decoder dec ^bytes block]
  (some (fn [^Hpack$HeaderField f] (when (= ":status" (.-name f)) (.-value f)))
        (.decode dec block 0 (alength block))))

(defn- healthy?
  "A fresh connection gets a 200 for a GET before the deadline."
  []
  (try
    (with-open [s (connect)]
      (let [^OutputStream out (.getOutputStream s)
            enc (Hpack$Encoder. 4096)
            dec (Hpack$Decoder. 4096)]
        (.write out ^bytes preface)
        (.write out (frame-bytes SETTINGS 0 0 (byte-array 0)))
        (.write out (frame-bytes HEADERS (bit-or END_HEADERS END_STREAM) 1
                                 (request-block enc "GET" "/health" [])))
        (.flush out)
        (.setSoTimeout s 200)
        (let [in (.getInputStream s)
              deadline (+ (System/currentTimeMillis) health-deadline-ms)]
          (loop []
            (let [f (read-frame in deadline)]
              (cond
                (keyword? f) false
                (and (= HEADERS (:type f)) (= 1 (:stream f))) (= "200" (status-of dec (:payload f)))
                :else (recur)))))))
    (catch IOException _ false)))

(defn- trial
  "Runs one generated sequence; true when every check holds, else prints
  the details and returns false."
  [ops cuts]
  (let [{:keys [^bytes wire max-frame]} (materialize ops)]
    (with-open [s (connect)]
      (let [^OutputStream out (.getOutputStream s)]
        (try
          (doseq [^bytes c (ps/split-at-points wire cuts)]
            (.write out c)
            (.flush out))
          (catch IOException _))
        (let [deadline (+ (System/currentTimeMillis) (long outcome-deadline-ms))
              others-served (healthy?)
              {:keys [result violations frames]} (outcome s max-frame deadline)
              problems (cond-> violations
                         (not others-served) (conj :other-connections-not-served)
                         (= :hang result) (conj :hang))]
          (or (empty? problems)
              (do (println "h2 frame fuzz violations:" problems "\nresult:" result
                           "\nserver frames [type stream]:" frames
                           "\nops:" (pr-str (walk/postwalk #(if (bytes? %) (vec %) %) ops)))
                  false)))))))

(deftest h2-hostile-frame-sequences-never-hang-or-break-the-server
  (ps/check!
   "HTTP/2 hostile frame sequences: PING answered, GOAWAY or close; well-formed frames; others served"
   (prop/for-all [ops gen-ops
                  cuts (gen/vector gen/nat 0 4)]
                 (trial ops cuts))
   (ps/trials 0.25)))

(deftest h2-server-survives-the-fuzzing
  ;; After the hostile run (same server, same fixture) a fresh connection
  ;; is still served.
  (is (healthy?)))

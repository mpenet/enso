;; ABOUTME: Lean HTTP/3 load generator for the perf harness: one platform thread per QUIC connection,
;; ABOUTME: batched UDP through the enso shim, a fixed number of GETs in flight per connection.
(ns s-exp.h3-load
  "Closed-loop HTTP/3 load: `connections` QUIC connections (quiche client
  through the enso JNI shim), each on its own platform thread, keeping
  `in-flight` requests open. A request is one HEADERS frame with FIN; it
  completes when the response stream's FIN arrives. Latency is measured
  per request from its send to that FIN."
  (:import (com.s_exp.enso.quiche NativeBuffer QuicheConfig QuicheConnection Quiche Records UdpSocket
                                  UdpSocket$Waker)
           (com.s_exp.enso.http3.qpack QpackFieldSection)
           (java.net InetAddress InetSocketAddress)
           (java.nio ByteBuffer)
           (java.security SecureRandom)
           (java.util.concurrent.atomic AtomicBoolean AtomicLong)
           (org.HdrHistogram Histogram)))

(set! *warn-on-reflection* true)

(def ^:private slot 2048)
(def ^:private batch 32)
(def ^:private max-payload 1350)

(defn- varint ^bytes [^long v]
  (let [b (byte-array 8)
        n (com.s_exp.enso.http3.Http3Varint/encode b 0 v)]
    (java.util.Arrays/copyOf b n)))

(defn- frame ^bytes [^long type ^bytes payload]
  (let [^bytes t (varint type) ^bytes l (varint (alength payload))
        out (byte-array (+ (alength t) (alength l) (alength payload)))]
    (System/arraycopy t 0 out 0 (alength t))
    (System/arraycopy l 0 out (alength t) (alength l))
    (System/arraycopy payload 0 out (+ (alength t) (alength l)) (alength payload))
    out))

(defn get-frame
  "HEADERS frame of a GET for `path`."
  ^bytes [^String path]
  (frame 0x01 (QpackFieldSection/encode ^Iterable (mapv #(into-array String %)
                                                        [[":method" "GET"] [":scheme" "https"]
                                                         [":authority" "localhost"] [":path" path]
                                                         ["user-agent" "enso-h3-load"]]))))

(defn- connection-loop
  "Runs one connection until `stop`; adds completions to `done` and
  latencies (ns) to `hist` (locked)."
  [port in-flight ^bytes request ^AtomicBoolean stop ^AtomicLong done ^Histogram hist]
  (let [port (long port)
        in-flight (long in-flight)
        cfg (QuicheConfig/client 30000)
        sock (UdpSocket/open (InetAddress/getByName "127.0.0.1") 0 0 (* 4 1024 1024) (* 4 1024 1024))
        waker (UdpSocket$Waker.)
        local ^InetSocketAddress (.localAddress sock)
        server (InetSocketAddress. "127.0.0.1" (int port))
        addrs (let [b (NativeBuffer/allocate (* 2 Records/ADDR_LEN))]
                (Records/putAddress (.-buffer b) 0 local)
                (Records/putAddress (.-buffer b) Records/ADDR_LEN server)
                b)
        scid (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        conn (QuicheConnection/connect cfg "localhost" scid addrs 0 Records/ADDR_LEN)
        rslab (NativeBuffer/allocate (* slot batch))
        rmeta (NativeBuffer/allocate (* Records/RECV_META_LEN (inc batch)))
        rm (.-buffer rmeta)
        sslab (NativeBuffer/allocate (* max-payload 64))
        smeta (NativeBuffer/allocate (+ Records/SEND_HEADER_LEN (* 64 Records/SEND_META_LEN)))
        sm (.-buffer smeta)
        scratch (byte-array 65536)
        started (long-array 1)
        ;; stream id -> send time; ids advance by 4
        sent-at (java.util.HashMap.)
        state (long-array 2)] ; [next-stream-id open]
    (.localAddress sock rmeta (* batch Records/RECV_META_LEN))
    (letfn [(flush! []
              (loop [count 0 off 0]
                (if (< count 64)
                  (let [rec (+ Records/SEND_HEADER_LEN (* count Records/SEND_META_LEN))
                        n (.send conn sslab off max-payload smeta rec)]
                    (if (pos? n)
                      (do (.putInt sm (int (+ rec Records/SEND_OFF)) (int off))
                          (.putInt sm (int (+ rec Records/SEND_LEN)) (int n))
                          (recur (inc count) (+ off n)))
                      (when (pos? count) (.sendBatch sock sslab smeta count 0))))
                  (do (.sendBatch sock sslab smeta count 0) (recur 0 0)))))
            (receive! []
              (loop [total 0]
                (let [n (.recvBatch sock rslab slot batch rmeta)]
                  (if (pos? n)
                    (do (dotimes [i n]
                          (let [rec (* i Records/RECV_META_LEN)]
                            (.recv conn rslab (int (* i slot)) (.getInt rm (int (+ rec Records/RECV_LEN)))
                                   rmeta (+ rec Records/RECV_PEER) (+ rec Records/RECV_LOCAL))))
                        (if (= n batch) (recur (+ total n)) (+ total n)))
                    total))))
            (open! []
              (while (< (aget state 1) in-flight)
                (let [sid (aget state 0)]
                  (.streamSend conn sid request 0 (alength request) true)
                  (.put sent-at sid (System/nanoTime))
                  (aset state 0 (+ sid 4))
                  (aset state 1 (inc (aget state 1))))))
            (read! []
              (loop []
                (let [sid (.readableNext conn)]
                  (when (>= sid 0)
                    (when (zero? (bit-and sid 3))
                      (loop []
                        (let [rc (.streamRecv conn sid scratch 0 (alength scratch))]
                          (cond
                            (and (>= rc 0) (odd? rc))
                            (let [t0 (.remove sent-at sid)]
                              (aset state 1 (dec (aget state 1)))
                              (.incrementAndGet done)
                              (when t0
                                (let [lat (- (System/nanoTime) (long t0))]
                                  (locking hist (.recordValue hist (max 1 lat))))))
                            (>= rc 0) (recur)
                            (not= rc Quiche/QUICHE_ERR_DONE)
                            (do (.remove sent-at sid) (aset state 1 (dec (aget state 1))))))))
                    (when-not (zero? (bit-and sid 3))
                      ;; server uni streams: drain
                      (loop []
                        (let [rc (.streamRecv conn sid scratch 0 (alength scratch))]
                          (when (and (>= rc 0) (even? rc) (= (bit-shift-right rc 1) (alength scratch))) (recur)))))
                    (recur)))))]
      (try
        (flush!)
        (let [deadline (+ (System/nanoTime) 5000000000)]
          (while (and (not (.isEstablished conn)) (< (System/nanoTime) deadline))
            (let [t (.timeoutNanos conn)]
              (.poll waker sock nil false (if (neg? t) 10000000 (min t 10000000))))
            (when (zero? (receive!)) (when (zero? (.timeoutNanos conn)) (.onTimeout conn)))
            (flush!)))
        (when-not (.isEstablished conn) (throw (ex-info "h3 load: handshake failed" {:port port})))
        ;; Control stream (client uni 2) with an empty SETTINGS, QPACK streams 6/10.
        (let [ctrl (byte-array [0x00 0x04 0x00])]
          (.streamSend conn 2 ctrl 0 3 false)
          (.streamSend conn 6 (byte-array [0x02]) 0 1 false)
          (.streamSend conn 10 (byte-array [0x03]) 0 1 false))
        (aset started 0 (System/nanoTime))
        (while (and (not (.get stop)) (not (.isClosed conn)))
          (open!)
          (flush!)
          (let [t (.timeoutNanos conn)]
            (when (zero? (receive!))
              (.poll waker sock nil false (if (neg? t) 10000000 (min t 10000000)))
              (when (zero? (receive!))
                (when (zero? (.timeoutNanos conn)) (.onTimeout conn)))))
          (read!))
        (finally
          (when-not (.isClosed conn)
            (.close conn true 0x100 (byte-array 0))
            (flush!))
          (.free conn)
          (.close cfg)
          (.close waker)
          (.close sock))))))

(defn run
  "Drives `port` for `ms` milliseconds; returns {:requests :rps :hist}."
  [^long port {:keys [connections in-flight ms path] :or {connections 4 in-flight 32 path "/"}}]
  (let [stop (AtomicBoolean.)
        done (AtomicLong.)
        hist (Histogram. 3600000000000 3)
        request (get-frame path)
        errors (atom [])
        threads (mapv (fn [i]
                        (doto (.unstarted (.name (Thread/ofPlatform) (str "h3-load-" i))
                                          ^Runnable (fn []
                                                      (try (connection-loop port in-flight request stop done hist)
                                                           (catch Throwable t (swap! errors conj t)))))
                          (.start)))
                      (range connections))
        t0 (System/nanoTime)]
    (Thread/sleep (long ms))
    (.set stop true)
    (doseq [^Thread t threads] (.join t 10000))
    (when-let [e (first @errors)] (throw e))
    (let [elapsed (- (System/nanoTime) t0)]
      {:requests (.get done)
       :rps (Math/round (/ (* 1e9 (.get done)) (double elapsed)))
       :hist hist})))

;; ---- many idle connections ---------------------------------------------------

(defn- dcid-key
  "The destination connection id of the datagram at slab[off, off + len) as
  a string key (client ids are 16 bytes)."
  ^String [^ByteBuffer b ^long off ^long len]
  (let [long-header (neg? (.get b (int off)))
        start (if long-header (+ off 6) (+ off 1))
        n (if long-header (bit-and (.get b (int (+ off 5))) 0xff) 16)
        bs (byte-array n)]
    (when (<= (+ start n) (+ off len))
      (.get b (int start) bs)
      (String. bs java.nio.charset.StandardCharsets/ISO_8859_1))))

(defn storm
  "Opens `n` QUIC connections to `port` from one UDP socket and one thread,
  completing each handshake (`step` at a time); returns
  {:established :close! (fn)} once done. The connections then stay idle."
  [^long port ^long n {:keys [step] :or {step 200}}]
  (let [cfg (QuicheConfig/client 0)
        sock (UdpSocket/open (InetAddress/getByName "127.0.0.1") 0 0 (* 8 1024 1024) (* 8 1024 1024))
        waker (UdpSocket$Waker.)
        local ^InetSocketAddress (.localAddress sock)
        server (InetSocketAddress. "127.0.0.1" (int port))
        addrs (let [b (NativeBuffer/allocate (* 2 Records/ADDR_LEN))]
                (Records/putAddress (.-buffer b) 0 local)
                (Records/putAddress (.-buffer b) Records/ADDR_LEN server)
                b)
        rnd (SecureRandom.)
        conns (java.util.HashMap.)
        rslab (NativeBuffer/allocate (* slot batch))
        rmeta (NativeBuffer/allocate (* Records/RECV_META_LEN (inc batch)))
        rm (.-buffer rmeta)
        sslab (NativeBuffer/allocate (* max-payload 64))
        smeta (NativeBuffer/allocate (+ Records/SEND_HEADER_LEN (* 64 Records/SEND_META_LEN)))
        sm (.-buffer smeta)]
    (.localAddress sock rmeta (* batch Records/RECV_META_LEN))
    (letfn [(flush! [^QuicheConnection conn]
              (loop [count 0 off 0]
                (let [rec (+ Records/SEND_HEADER_LEN (* count Records/SEND_META_LEN))
                      n (if (< count 64) (.send conn sslab off max-payload smeta rec) -1)]
                  (if (pos? n)
                    (do (.putInt sm (int (+ rec Records/SEND_OFF)) (int off))
                        (.putInt sm (int (+ rec Records/SEND_LEN)) (int n))
                        (recur (inc count) (+ off n)))
                    (when (pos? count) (.sendBatch sock sslab smeta count 0))))))
            (pump! [^long ms]
              (let [deadline (+ (System/currentTimeMillis) ms)]
                (loop []
                  (.poll waker sock nil false 5000000)
                  (let [touched (java.util.HashSet.)]
                    (loop []
                      (let [k (.recvBatch sock rslab slot batch rmeta)]
                        (when (pos? k)
                          (dotimes [i k]
                            (let [rec (* i Records/RECV_META_LEN)
                                  len (.getInt rm (int (+ rec Records/RECV_LEN)))
                                  key (dcid-key (.-buffer rslab) (* i slot) len)
                                  ^QuicheConnection c (when key (.get conns key))]
                              (when c
                                (.recv c rslab (int (* i slot)) len rmeta (+ rec Records/RECV_PEER) (+ rec Records/RECV_LOCAL))
                                (.add touched c))))
                          (when (= k batch) (recur)))))
                    (doseq [^QuicheConnection c touched] (flush! c)))
                  (when (< (System/currentTimeMillis) deadline) (recur)))))]
      (loop [opened 0]
        (when (< opened n)
          (let [k (min (long step) (- n opened))]
            (dotimes [_ k]
              (let [scid (let [b (byte-array 16)] (.nextBytes rnd b) b)
                    c (QuicheConnection/connect cfg "localhost" scid addrs 0 Records/ADDR_LEN)]
                (.put conns (String. scid java.nio.charset.StandardCharsets/ISO_8859_1) c)
                (flush! c)))
            (pump! 300)
            (recur (+ opened k)))))
      (pump! 1000)
      {:established (count (filter #(.isEstablished ^QuicheConnection %) (vals conns)))
       :close! (fn []
                 (doseq [^QuicheConnection c (vals conns)]
                   (when-not (.isClosed c) (.close c true 0x100 (byte-array 0)) (flush! c))
                   (.free c))
                 (.close cfg) (.close waker) (.close sock))})))

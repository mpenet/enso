;; ABOUTME: Raw HTTP/3 test client: drives a real QUIC connection (quiche via
;; ABOUTME: the enso JNI shim) against an Http3Listener with hand-built frames.
(ns s-exp.h3-client
  "End-to-end harness for the h3 server. The client speaks QUIC through
  quiche but writes HTTP/3 frames byte-for-byte, so tests can send both
  valid and deliberately malformed traffic and observe stream resets and
  connection-close error codes."
  (:import (com.s_exp.enso.api Config Config$Builder Request RingErrorHandler RingHandler)
           (com.s_exp.enso.http3 Http3FrameReader Http3FrameReader$Frame
                                 Http3FrameType Http3FrameWriter Http3Listener
                                 Http3Varint)
           (com.s_exp.enso.http3.qpack QpackFieldSection)
           (com.s_exp.enso.quiche NativeBuffer Quiche QuicheConfig QuicheConnection Records)
           (java.io ByteArrayOutputStream)
           (java.net DatagramPacket InetSocketAddress SocketTimeoutException
                     StandardProtocolFamily StandardSocketOptions)
           (java.nio ByteBuffer)
           (java.nio.channels DatagramChannel)
           (java.nio.file Files)
           (java.nio.file.attribute FileAttribute)
           (java.security SecureRandom)
           (java.util Arrays List)
           (javax.crypto Cipher Mac)
           (javax.crypto.spec GCMParameterSpec SecretKeySpec)))

(set! *warn-on-reflection* true)

;; ---- server ---------------------------------------------------------------

(def ^:private cert-pair
  (delay
    (let [dir (Files/createTempDirectory "enso-h3-e2e" (make-array FileAttribute 0))
          cert (str (.resolve dir "cert.pem"))
          key (str (.resolve dir "key.pem"))
          proc (.start (ProcessBuilder.
                        ^List (list "openssl" "req" "-x509" "-newkey" "rsa:2048"
                                    "-keyout" key "-out" cert "-sha256" "-days" "1"
                                    "-nodes" "-subj" "/CN=localhost")))]
      (.waitFor proc)
      [cert key])))

(def ^:private event-loops
  "ENSO_H3_EVENT_LOOPS runs every test listener with that many event
  loops (exercising cross-loop forwarding where sockets are shared)."
  (some-> (System/getenv "ENSO_H3_EVENT_LOOPS") parse-long))

(defn server-config
  "Config for an h3 listener on an ephemeral 127.0.0.1 UDP port (no
  Alt-Svc: nothing could advertise an ephemeral port).
  `configure` receives the Config$Builder for extra knobs."
  ^Config [configure]
  (let [[cert key] @cert-pair
        b (doto (Config/builder)
            (.host "127.0.0.1")
            (.port 0)
            (.http3 true)
            (.advertiseAltSvc false)
            (.http3CertPath cert)
            (.http3KeyPath key))]
    (when event-loops (.http3EventLoops b (int event-loops)))
    (configure b)
    (.build b)))

(defn start-server
  "Starts an Http3Listener whose handler is `handler` (Request -> Response)
  and optional `error-handler` ((Request, Throwable) -> Response).
  Returns the listener; stop with `.close`."
  (^Http3Listener [handler] (start-server handler (fn [_])))
  (^Http3Listener [handler configure] (start-server handler configure nil))
  (^Http3Listener [handler configure error-handler]
   (doto (Http3Listener. (server-config configure)
                         (reify RingHandler
                           (handle [_ req] (handler req)))
                         (when error-handler
                           (reify RingErrorHandler
                             (handle [_ req t] (error-handler req t)))))
     (.start))))

(defmacro with-server
  "Binds `sym` to a started listener for the duration of `body`."
  [[sym handler & [configure]] & body]
  `(let [~sym (start-server ~handler ~@(when configure [configure]))]
     (try ~@body (finally (.close ~sym)))))

;; ---- client ---------------------------------------------------------------

(defn- client-config
  "Client QuicheConfig; `configure` may adjust it (e.g. a small stream window)."
  ^QuicheConfig [idle-timeout-ms configure]
  (let [c (QuicheConfig/client (long idle-timeout-ms))]
    (when configure (configure c))
    c))

(defn- address-records
  "ADDR records for `local` (offset 0) and `peer` (offset Records/ADDR_LEN)."
  ^NativeBuffer [^InetSocketAddress local ^InetSocketAddress peer]
  (let [b (NativeBuffer/allocate (* 2 Records/ADDR_LEN))]
    (Records/putAddress (.-buffer b) 0 local)
    (Records/putAddress (.-buffer b) Records/ADDR_LEN peer)
    b))

(defn- now-ms ^long [] (System/currentTimeMillis))

;; The server sends multi-MiB responses as unpaced bursts on loopback;
;; with the OS default receive buffer the tail of a burst (often the lone
;; FIN packet) is dropped and only repaired by the server's PTO.
(def ^:private recv-buffer-bytes (* 8 1024 1024))

(defn- open-socket
  "Blocking UDP channel on an ephemeral 127.0.0.1 port with the largest
  receive buffer up to `recv-buffer-bytes` the OS grants (macOS refuses
  sizes above kern.ipc.maxsockbuf; Linux clamps to net.core.rmem_max)."
  ^DatagramChannel []
  (let [ch (DatagramChannel/open StandardProtocolFamily/INET)]
    (loop [size recv-buffer-bytes]
      (when (and (>= size 65536)
                 (not (try (.setOption ch StandardSocketOptions/SO_RCVBUF (Integer/valueOf (int size)))
                           true
                           (catch java.io.IOException _ false))))
        (recur (quot size 2))))
    (.bind ch (InetSocketAddress. "127.0.0.1" 0))))

(defn concat-bytes ^bytes [& arrays]
  (let [out (ByteArrayOutputStream.)]
    (doseq [^bytes a arrays] (.write out a 0 (alength a)))
    (.toByteArray out)))

;; ---- Initial packet re-padding (RFC 9001 §5) -------------------------------
;; quiche's client never sends a handshake datagram above 1200 bytes; real
;; clients do (Chrome pads its Initials to 1250+). These helpers decrypt a
;; client Initial with the Initial keys derived from its DCID, append
;; PADDING frames and re-protect it, so tests can send such datagrams.

(def ^:private initial-salt
  (byte-array (map unchecked-byte [0x38 0x76 0x2c 0xf7 0xf5 0x59 0x34 0xb3 0x4d 0x17
                                   0x9a 0xe6 0xa4 0xc8 0x0c 0xad 0xcc 0xbb 0x7f 0x0a])))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes data]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac data)))

(defn- hkdf-expand-label
  "RFC 8446 §7.1 HKDF-Expand-Label for outputs of at most 32 bytes."
  ^bytes [^bytes secret ^String label ^long len]
  (let [full (.getBytes (str "tls13 " label) "US-ASCII")
        info (byte-array (concat [0 len (alength full)] full [0 1]))]
    (Arrays/copyOf (hmac-sha256 secret info) (int len))))

(defn- read-varint
  "[value size] of the QUIC varint at `off`."
  [^bytes b ^long off]
  (let [size (bit-shift-left 1 (bit-shift-right (bit-and (aget b off) 0xff) 6))]
    [(reduce (fn [^long v ^long i] (bit-or (bit-shift-left v 8) (bit-and (aget b (+ off i)) 0xff)))
             (bit-and (aget b off) 0x3f) (range 1 size))
     size]))

(defn- aes-ecb ^bytes [^bytes k ^bytes in ^long off]
  (let [c (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init c Cipher/ENCRYPT_MODE (SecretKeySpec. k "AES"))
    (.doFinal c in (int off) 16)))

(defn- gcm ^bytes [mode ^bytes k ^bytes iv pn ^bytes aad ^bytes in off len]
  (let [pn (long pn)
        nonce (aclone iv)
        c (Cipher/getInstance "AES/GCM/NoPadding")]
    (dotimes [i 8]
      (let [j (- 11 i)]
        (aset nonce j (unchecked-byte (bit-xor (aget nonce j) (bit-shift-right pn (* 8 i)))))))
    (.init c (int mode) (SecretKeySpec. k "AES") (GCMParameterSpec. 128 nonce))
    (.updateAAD c aad)
    (.doFinal c in (int off) (int len))))

(defn- initial-dcid
  "Destination connection ID of the long-header packet `pkt`."
  ^bytes [^bytes pkt]
  (Arrays/copyOfRange pkt 6 (+ 6 (aget pkt 5))))

(defn pad-initial
  "Re-protects the client Initial packet that starts datagram `pkt` with
  PADDING appended so the datagram is `size` bytes long. Initial keys
  come from `odcid`, the DCID of the client's first Initial. With
  `new-dcid` (as long as the packet's), the packet is re-addressed to it
  and protected with its keys, as if the client had chosen it."
  (^bytes [^bytes pkt ^long size ^bytes odcid] (pad-initial pkt size odcid nil))
  (^bytes [^bytes pkt ^long size ^bytes odcid ^bytes new-dcid]
  (let [dcid-len (aget pkt 5)
        scid-off (+ 6 dcid-len)
        token-off (+ scid-off 1 (aget pkt scid-off))
        [token-len tl-size] (read-varint pkt token-off)
        len-off (+ token-off (long tl-size) (long token-len))
        [plen pl-size] (read-varint pkt len-off)
        plen (long plen)
        pn-off (+ len-off (long pl-size))
        keys (fn [^bytes id]
               (let [secret (hkdf-expand-label (hmac-sha256 initial-salt id) "client in" 32)]
                 [(hkdf-expand-label secret "quic key" 16) (hkdf-expand-label secret "quic iv" 12)
                  (hkdf-expand-label secret "quic hp" 16)]))
        [k iv hp] (keys odcid)
        [^bytes k2 ^bytes iv2 ^bytes hp2] (keys (or new-dcid odcid))
        ^bytes mask (aes-ecb hp pkt (+ pn-off 4))
        b0 (bit-xor (aget pkt 0) (bit-and (aget mask 0) 0x0f))
        pn-len (inc (bit-and b0 3))
        pn-bytes (byte-array (map-indexed (fn [i b] (bit-xor b (aget mask (inc i))))
                                          (Arrays/copyOfRange pkt (int pn-off) (int (+ pn-off pn-len)))))
        pn (reduce (fn [^long v b] (bit-or (bit-shift-left v 8) (bit-and b 0xff))) 0 pn-bytes)
        aad (concat-bytes (byte-array [b0]) (Arrays/copyOfRange pkt 1 (int pn-off)) pn-bytes)
        plain (gcm Cipher/DECRYPT_MODE k iv pn aad pkt (+ pn-off pn-len) (- plen pn-len))
        ;; Coalesced packets after this one are kept; quiche's zero fill is
        ;; replaced by PADDING frames inside the packet.
        tail (let [t (Arrays/copyOfRange pkt (int (+ pn-off plen)) (alength pkt))]
               (if (every? zero? t) (byte-array 0) t))
        ;; New Length is always a 2-byte varint; everything before it is unchanged.
        new-pn-off (+ len-off 2)
        padded (Arrays/copyOf plain (int (- size (alength tail) new-pn-off pn-len 16)))
        new-len (+ pn-len (alength padded) 16)
        head (concat-bytes (Arrays/copyOfRange pkt 0 (int len-off))
                           (byte-array [(unchecked-byte (bit-or 0x40 (bit-shift-right new-len 8)))
                                        (unchecked-byte new-len)])
                           pn-bytes)
        _ (aset head 0 (unchecked-byte b0))
        _ (when new-dcid (System/arraycopy new-dcid 0 head 6 (int dcid-len)))
        out (concat-bytes head (gcm Cipher/ENCRYPT_MODE k2 iv2 pn head padded 0 (alength padded)) tail)
        ^bytes new-mask (aes-ecb hp2 out (+ new-pn-off 4))]
    (aset out 0 (unchecked-byte (bit-xor b0 (bit-and (aget new-mask 0) 0x0f))))
    (dotimes [i pn-len]
      (let [j (+ new-pn-off i)]
        (aset out j (unchecked-byte (bit-xor (aget out j) (aget new-mask (inc i)))))))
    out)))

(defn- client-initial? [^bytes out]
  (= 0xc0 (bit-and (aget out 0) 0xf0)))

(defn- flush-out! [{:keys [^QuicheConnection conn sock ^InetSocketAddress server ^NativeBuffer send-buf
                           ^NativeBuffer send-meta initial-size odcid initial-dcid-fn]}]
  (let [out (byte-array 1350)]
    (loop []
      (let [n (.send conn send-buf 0 1350 send-meta 0)]
        (when (pos? n)
          (.get (.-buffer send-buf) 0 out 0 (int n))
          (let [pkt (Arrays/copyOf out (int n))
                ^bytes dgram (if (and initial-size (client-initial? pkt))
                               (let [first-dcid (or @odcid (reset! odcid (initial-dcid pkt)))]
                                 (pad-initial pkt initial-size first-dcid
                                              (when initial-dcid-fn (initial-dcid-fn first-dcid))))
                               pkt)]
            (.send ^DatagramChannel @sock (ByteBuffer/wrap dgram) server))
          (recur))))))

(defn- send-pending! [{:keys [^QuicheConnection conn pending]}]
  (doseq [[sid [^bytes bs off fin]] @pending]
    (let [off (long off)
          len (- (alength bs) off)
          n (.streamSend conn sid bs (int off) (int len) (boolean fin))]
      (cond
        (= n len) (swap! pending dissoc sid)
        (>= n 0) (swap! pending assoc sid [bs (+ off n) fin])
        (= n Quiche/QUICHE_ERR_DONE) nil
        :else (swap! pending dissoc sid)))))

(defn- read-stream!
  "Reads everything stream `sid` holds; unless `sid` is paused."
  [{:keys [^QuicheConnection conn streams ^bytes recv-buf paused]} sid]
  (when-not (contains? @paused sid)
    (loop []
      (let [rc (.streamRecv conn sid recv-buf 0 (alength recv-buf))]
        (cond
          (>= rc 0)
          (let [n (int (bit-shift-right rc 1))
                fin (odd? rc)]
            (swap! streams update sid
                   (fn [s]
                     (let [s (or s {:out (ByteArrayOutputStream.)})]
                       (.write ^ByteArrayOutputStream (:out s) recv-buf 0 n)
                       (cond-> s fin (assoc :fin true)))))
            (when-not fin (recur)))

          (= rc Quiche/QUICHE_ERR_DONE) nil

          :else
          (swap! streams update sid
                 (fn [s]
                   (assoc (or s {:out (ByteArrayOutputStream.)})
                          :reset (QuicheConnection/resetCode rc)))))))))

(defn- read-streams! [{:keys [^QuicheConnection conn] :as c}]
  (loop []
    (let [sid (.readableNext conn)]
      (when (>= sid 0)
        (read-stream! c sid)
        (recur)))))

(defn resume-stream!
  "Reads stream `sid` again after `pause-stream!`."
  [c sid]
  (swap! (:paused c) disj sid)
  (read-stream! c sid))

(defn pause-stream!
  "Stops reading stream `sid` (its flow-control window then fills up)."
  [c sid]
  (swap! (:paused c) conj sid))

(defn- feed-datagram! [{:keys [^QuicheConnection conn ^InetSocketAddress local ^NativeBuffer recv-direct
                               ^NativeBuffer recv-meta datagrams]}
                       ^bytes buf len ^InetSocketAddress from]
  (swap! datagrams inc)
  (.put (.-buffer recv-direct) 0 buf 0 (int len))
  (Records/putAddress (.-buffer recv-meta) 0 from)
  (Records/putAddress (.-buffer recv-meta) Records/ADDR_LEN local)
  (.recv conn recv-direct 0 (int len) recv-meta 0 Records/ADDR_LEN))

(defn- receive-all!
  "Waits up to `wait-ms` for a datagram, then feeds it and every datagram
  already queued behind it, so a burst never sits in the socket buffer
  for more than one round. Returns the number of datagrams fed."
  ^long [{:keys [sock ^bytes dgram-buf] :as c} ^long wait-ms]
  (let [^DatagramChannel ch @sock
        pkt (DatagramPacket. dgram-buf (alength dgram-buf))]
    (.setSoTimeout (.socket ch) (int (max 1 wait-ms)))
    (if-not (try (.receive (.socket ch) pkt) true (catch SocketTimeoutException _ false))
      0
      (do (feed-datagram! c dgram-buf (.getLength pkt) (.getSocketAddress pkt))
          (let [bb (ByteBuffer/wrap dgram-buf)]
            (.configureBlocking ch false)
            (try
              (loop [n 1]
                (.clear bb)
                (if-let [from (.receive ch bb)]
                  (do (feed-datagram! c dgram-buf (.position bb) from)
                      (recur (inc n)))
                  n))
              (finally (.configureBlocking ch true))))))))

(defn- service!
  "One I/O round: send pending stream bytes + datagrams, wait up to
  `wait-ms` for inbound datagrams and feed every one that arrived (or
  run timers when none did), read streams."
  [{:keys [^QuicheConnection conn] :as c} ^long wait-ms]
  (send-pending! c)
  (flush-out! c)
  (let [t (.timeoutNanos conn)
        t-ms (if (neg? t) wait-ms (max 1 (min wait-ms (quot t 1000000))))]
    (when (zero? (receive-all! c t-ms))
      (.onTimeout conn)))
  (read-streams! c)
  (send-pending! c)
  (flush-out! c))

(defn pump-until!
  "Services the connection until `(pred)` is truthy or `ms` elapse.
  Returns the final value of `(pred)`."
  [c pred ms]
  (let [deadline (+ (now-ms) (long ms))]
    (loop []
      (let [v (pred)]
        (if (or v (>= (now-ms) deadline) (.isClosed ^QuicheConnection (:conn c)))
          (or v (pred))
          (do (service! c 20)
              (recur)))))))

(defn pump!
  "Services the connection for `ms` milliseconds."
  [c ms]
  (pump-until! c (constantly false) ms))

(defn- new-client
  "Client state map around a fresh quiche connection to `port`."
  [^long port idle-timeout-ms {:keys [initial-size configure server-ip initial-dcid-fn] :or {server-ip "127.0.0.1"}}]
  (let [cfg (client-config idle-timeout-ms configure)
        sock (open-socket)
        server (InetSocketAddress. ^String server-ip (int port))
        scid (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        local ^InetSocketAddress (.getLocalAddress sock)
        conn (QuicheConnection/connect cfg "localhost" scid (address-records local server)
                                       0 Records/ADDR_LEN)]
    (when-not conn (throw (ex-info "quiche_connect failed" {})))
    {:conn conn :cfg cfg :sock (atom sock) :local local :server server
     :send-buf (NativeBuffer/allocate 1350) :send-meta (NativeBuffer/allocate Records/PKT_META_LEN)
     :recv-buf (byte-array 65536) :dgram-buf (byte-array 65536)
     :recv-direct (NativeBuffer/allocate 65536) :recv-meta (NativeBuffer/allocate (* 2 Records/ADDR_LEN))
     :pending (atom (sorted-map)) :streams (atom {}) :paused (atom #{}) :datagrams (atom 0)
     :initial-size initial-size :odcid (atom nil) :initial-dcid-fn initial-dcid-fn}))

(defn start-handshake
  "Creates a client connection to `port` and sends only its first
  Initial flight, without servicing the connection afterwards. The
  client advertises no idle timeout. `opts` as for `connect`."
  ([port] (start-handshake port {}))
  ([^long port opts]
   (let [c (new-client port 0 opts)]
     (flush-out! c)
     c)))

(defn connect
  "Opens a QUIC connection to `port` on 127.0.0.1 and completes the
  handshake. Throws when the handshake doesn't finish within 5s.
  `:initial-size` pads every client Initial datagram to that size;
  `:configure` receives the client QuicheConfig; `:idle-timeout` (ms,
  default 10000)."
  ([port] (connect port {}))
  ([^long port {:keys [idle-timeout] :or {idle-timeout 10000} :as opts}]
   (let [c (new-client port idle-timeout opts)]
     (when-not (pump-until! c #(.isEstablished ^QuicheConnection (:conn c)) 5000)
       (throw (ex-info "h3 handshake did not complete" {:port port})))
     c)))

(defn close!
  "Closes the client connection and frees native state."
  [{:keys [^QuicheConnection conn ^QuicheConfig cfg sock] :as c}]
  (when-not (.isClosed conn)
    (.close conn true 0x100 (byte-array 0))
    (flush-out! c))
  (.free conn)
  (.close cfg)
  (.close ^DatagramChannel @sock))

(defn rebind!
  "Simulates a NAT rebinding: further datagrams leave from (and are
  received on) a fresh UDP port, while quiche still believes its local
  address is the original one."
  [c]
  (let [old ^DatagramChannel @(:sock c)]
    (reset! (:sock c) (open-socket))
    (.close old)))

(defmacro with-client
  "Binds `sym` to a connected client for `body`, closing it afterwards.
  `opts` go to `connect`."
  [[sym port & [opts]] & body]
  `(let [~sym (connect ~port ~(or opts {}))]
     (try ~@body (finally (close! ~sym)))))

;; ---- frames ---------------------------------------------------------------

(defn- bb->bytes ^bytes [^ByteBuffer bb]
  (let [a (byte-array (.remaining bb))]
    (.get bb a)
    a))

(defn varint ^bytes [v]
  (let [bb (ByteBuffer/allocate 8)]
    (Http3Varint/encode bb (long v))
    (.flip bb)
    (bb->bytes bb)))

(defn frame
  "Raw HTTP/3 frame: type varint, length varint, payload."
  ^bytes [type ^bytes payload]
  (concat-bytes (varint type) (varint (alength payload)) payload))

(defn field-section
  "QPACK-encoded field section for `pairs` ([name value] vectors)."
  ^bytes [pairs]
  (QpackFieldSection/encode ^Iterable (mapv #(into-array String %) pairs)))

(defn headers-frame ^bytes [pairs]
  (frame Http3FrameType/HEADERS (field-section pairs)))

(defn data-frame ^bytes [^bytes payload]
  (frame Http3FrameType/DATA payload))

(defn request-headers
  "Pseudo-headers for a request plus any extra `[name value]` pairs."
  [method path & extra]
  (into [[":method" method] [":scheme" "https"] [":authority" "localhost"]
         [":path" path]]
        extra))

(defn settings-frame ^bytes [& id-values]
  (frame Http3FrameType/SETTINGS (apply concat-bytes (map varint id-values))))

;; ---- streams --------------------------------------------------------------

(defn send!
  "Queues `bs` on stream `sid` (with FIN when `fin`) and pushes it out."
  [c sid ^bytes bs fin]
  (swap! (:pending c) assoc sid [bs 0 fin])
  (send-pending! c)
  (flush-out! c))

(defn reset-stream!
  "Abruptly terminates the client's sending side of `sid` (RESET_STREAM)."
  [c sid code]
  (.streamShutdown ^QuicheConnection (:conn c) sid Quiche/QUICHE_SHUTDOWN_WRITE code)
  (flush-out! c))

(defn stop-sending!
  "Asks the server to stop sending on `sid` (STOP_SENDING)."
  [c sid code]
  (.streamShutdown ^QuicheConnection (:conn c) sid Quiche/QUICHE_SHUTDOWN_READ code)
  (flush-out! c))

(defn ping!
  "Sends an ack-eliciting PING (keeps the QUIC path alive)."
  [c]
  (.sendAckEliciting ^QuicheConnection (:conn c))
  (flush-out! c))

(defn open-control!
  "Opens the client control stream (id 2) carrying `first-frames`
  (default: an empty SETTINGS frame) plus QPACK encoder/decoder streams."
  ([c] (open-control! c (settings-frame)))
  ([c ^bytes first-frames]
   (send! c 2 (concat-bytes (varint 0x00) first-frames) false)
   (send! c 6 (varint 0x02) false)
   (send! c 10 (varint 0x03) false)))

(defn stream-state [c sid] (get @(:streams c) sid))

(defn stream-done?
  "True once stream `sid` saw FIN or a reset from the server."
  [c sid]
  (let [s (stream-state c sid)]
    (boolean (or (:fin s) (:reset s)))))

(defn response
  "Parses what the server sent on request stream `sid`:
  {:status :interim :headers :fields :body :fin :reset}; :interim lists the
  statuses of 1xx interim responses before the final one, :fields keeps
  every [name value] pair of the final header section in wire order."
  [c sid]
  (let [s (stream-state c sid)
        raw (if s (.toByteArray ^ByteArrayOutputStream (:out s)) (byte-array 0))
        r (Http3FrameReader. (* 1024 1024))
        body (ByteArrayOutputStream.)
        headers (atom [])]
    (doseq [off (range 0 (alength raw) 16384)]
      (.feed r raw (int off) (int (min 16384 (- (alength raw) off))))
      (loop []
        (when-let [^Http3FrameReader$Frame f (.poll r)]
          (cond
            (.isDataChunk f) (.write body ^bytes (.-dataChunk f) 0 (alength ^bytes (.-dataChunk f)))
            (= Http3FrameType/HEADERS (.-type f))
            (swap! headers conj (mapv vec (QpackFieldSection/decode ^bytes (.-payload f)))))
          (recur))))
    (let [status-of (fn [hs] (some (fn [[n v]] (when (= n ":status") (Long/parseLong v))) hs))
          ;; 1xx sections are interim responses (RFC 9114 §4.1).
          [interim final] (split-with #(when-let [st (status-of %)] (< st 200)) @headers)
          hs (first final)]
      {:status (status-of hs)
       :interim (mapv status-of interim)
       :headers (into {} (remove #(.startsWith ^String (first %) ":")) hs)
       :fields hs
       :body (.toByteArray body)
       :fin (boolean (:fin s))
       :reset (:reset s)})))

(def ^:private response-timeout-ms 5000)

;; Once response bytes stop arriving the FIN may still be missing: a lost
;; final packet is only resent after the server's PTO, which backs off.
(def ^:private fin-timeout-ms 5000)

(defn- received-bytes ^long [c sid]
  (if-let [s (stream-state c sid)] (.size ^ByteArrayOutputStream (:out s)) 0))

(defn- await-stream-done!
  "Services `c` until stream `sid` is done. Past the response deadline,
  waiting goes on while response bytes keep arriving, and the FIN gets
  `fin-timeout-ms` of its own after the last byte."
  [c sid]
  (when-not (pump-until! c #(stream-done? c sid) response-timeout-ms)
    (loop [n (received-bytes c sid)]
      (when (pos? n)
        (pump-until! c #(or (stream-done? c sid) (> (received-bytes c sid) n)) fin-timeout-ms)
        (when (and (not (stream-done? c sid)) (> (received-bytes c sid) n))
          (recur (received-bytes c sid)))))))

(defn request!
  "Sends a request on `sid` and waits for the full response."
  ([c sid pairs] (request! c sid pairs nil))
  ([c sid pairs ^bytes body]
   (send! c sid (if body
                  (concat-bytes (headers-frame pairs) (data-frame body))
                  (headers-frame pairs))
          true)
   (await-stream-done! c sid)
   (response c sid)))

(defn peer-error
  "[app? code] of the server's CONNECTION_CLOSE, or nil if it hasn't
  closed the connection."
  [c]
  (let [out (long-array 2)]
    (when (.peerError ^QuicheConnection (:conn c) out)
      [(= 1 (aget out 0)) (aget out 1)])))

(defn datagrams-received
  "Datagrams the client received from the server so far."
  ^long [c]
  @(:datagrams c))

(defn peer-certificate
  "DER bytes of the certificate the server presented, or nil."
  ^bytes [c]
  (.peerCertificate ^QuicheConnection (:conn c)))

(defn await-peer-error
  "Pumps until the server closes the connection; returns `peer-error`."
  [c ms]
  (pump-until! c #(peer-error c) ms))

(defn body-str [r] (String. ^bytes (:body r) "UTF-8"))

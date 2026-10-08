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
           (com.s_exp.enso.quiche Quiche)
           (java.io ByteArrayOutputStream)
           (java.net DatagramPacket DatagramSocket InetAddress InetSocketAddress
                     SocketTimeoutException)
           (java.nio ByteBuffer)
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

(defn server-config
  "Config for an h3 listener on an ephemeral 127.0.0.1 UDP port.
  `configure` receives the Config$Builder for extra knobs."
  ^Config [configure]
  (let [[cert key] @cert-pair
        b (doto (Config/builder)
            (.host "127.0.0.1")
            (.port 0)
            (.http3 true)
            (.http3CertPath cert)
            (.http3KeyPath key))]
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

(defn- client-config ^long [idle-timeout-ms]
  (let [c (Quiche/configNew Quiche/QUICHE_PROTOCOL_VERSION)]
    (Quiche/configSetApplicationProtos c (byte-array [2 (int \h) (int \3)]))
    (Quiche/configVerifyPeer c false)
    (Quiche/configSetMaxIdleTimeout c idle-timeout-ms)
    (Quiche/configSetMaxRecvUdpPayloadSize c 65527)
    (Quiche/configSetMaxSendUdpPayloadSize c 1350)
    (Quiche/configSetInitialMaxData c 100000000)
    (Quiche/configSetInitialMaxStreamDataBidiLocal c 10000000)
    (Quiche/configSetInitialMaxStreamDataBidiRemote c 10000000)
    (Quiche/configSetInitialMaxStreamDataUni c 10000000)
    (Quiche/configSetInitialMaxStreamsBidi c 100)
    (Quiche/configSetInitialMaxStreamsUni c 100)
    c))

(defn- now-ms ^long [] (System/currentTimeMillis))

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
  come from `odcid`, the DCID of the client's first Initial."
  ^bytes [^bytes pkt ^long size ^bytes odcid]
  (let [dcid-len (aget pkt 5)
        scid-off (+ 6 dcid-len)
        token-off (+ scid-off 1 (aget pkt scid-off))
        [token-len tl-size] (read-varint pkt token-off)
        len-off (+ token-off (long tl-size) (long token-len))
        [plen pl-size] (read-varint pkt len-off)
        plen (long plen)
        pn-off (+ len-off (long pl-size))
        secret (hkdf-expand-label (hmac-sha256 initial-salt odcid) "client in" 32)
        k (hkdf-expand-label secret "quic key" 16)
        iv (hkdf-expand-label secret "quic iv" 12)
        hp (hkdf-expand-label secret "quic hp" 16)
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
        out (concat-bytes head (gcm Cipher/ENCRYPT_MODE k iv pn head padded 0 (alength padded)) tail)
        ^bytes new-mask (aes-ecb hp out (+ new-pn-off 4))]
    (aset out 0 (unchecked-byte (bit-xor b0 (bit-and (aget new-mask 0) 0x0f))))
    (dotimes [i pn-len]
      (let [j (+ new-pn-off i)]
        (aset out j (unchecked-byte (bit-xor (aget out j) (aget new-mask (inc i)))))))
    out))

(defn- client-initial? [^bytes out]
  (= 0xc0 (bit-and (aget out 0) 0xf0)))

(defn- flush-out! [{:keys [conn sock ^InetSocketAddress server ^ByteBuffer send-buf
                           initial-size odcid]}]
  (let [out (byte-array 1350)
        to-ip (byte-array 16)
        to-meta (int-array 2)]
    (loop []
      (let [n (Quiche/connSend conn send-buf 1350 to-ip to-meta)]
        (when (pos? n)
          (.get send-buf 0 out 0 (int n))
          (let [pkt (Arrays/copyOf out (int n))
                ^bytes dgram (if (and initial-size (client-initial? pkt))
                               (pad-initial pkt initial-size
                                            (or @odcid (reset! odcid (initial-dcid pkt))))
                               pkt)]
            (.send ^DatagramSocket @sock (DatagramPacket. dgram (alength dgram) ^InetSocketAddress server)))
          (recur))))))

(defn- send-pending! [{:keys [conn pending]}]
  (doseq [[sid [^bytes bs off fin]] @pending]
    (let [off (long off)
          len (- (alength bs) off)
          n (Quiche/connStreamSend conn sid bs (int off) (int len) (boolean fin))]
      (cond
        (= n len) (swap! pending dissoc sid)
        (>= n 0) (swap! pending assoc sid [bs (+ off n) fin])
        (= n Quiche/QUICHE_ERR_DONE) nil
        :else (swap! pending dissoc sid)))))

(defn- read-streams! [{:keys [conn streams ^bytes recv-buf]}]
  (let [it (Quiche/connReadable conn)]
    (when-not (zero? it)
      (try
        (let [sid-out (long-array 1)
              fin-out (boolean-array 1)
              err-out (long-array 1)]
          (while (Quiche/streamIterNext it sid-out)
            (let [sid (aget sid-out 0)]
              (loop []
                (let [n (Quiche/connStreamRecv conn sid recv-buf (alength recv-buf)
                                               fin-out err-out)]
                  (cond
                    (>= n 0)
                    (do (swap! streams update sid
                               (fn [s]
                                 (let [s (or s {:out (ByteArrayOutputStream.)})]
                                   (.write ^ByteArrayOutputStream (:out s) recv-buf 0 (int n))
                                   (cond-> s (aget fin-out 0) (assoc :fin true)))))
                        (when-not (aget fin-out 0) (recur)))

                    (= n Quiche/QUICHE_ERR_DONE) nil

                    :else
                    (swap! streams update sid
                           (fn [s]
                             (assoc (or s {:out (ByteArrayOutputStream.)})
                                    :reset (aget err-out 0))))))))))
        (finally (Quiche/streamIterFree it))))))

(defn- service!
  "One I/O round: send pending stream bytes + datagrams, wait up to
  `wait-ms` for one inbound datagram, feed it, run timers, read streams."
  [{:keys [conn sock ^InetSocketAddress local ^bytes dgram-buf] :as c} ^long wait-ms]
  (send-pending! c)
  (flush-out! c)
  (let [t (Quiche/connTimeoutAsNanos conn)
        t-ms (if (neg? t) wait-ms (max 1 (min wait-ms (quot t 1000000))))
        pkt (DatagramPacket. dgram-buf (alength dgram-buf))]
    (.setSoTimeout ^DatagramSocket @sock (int (max 1 t-ms)))
    (try
      (.receive ^DatagramSocket @sock pkt)
      (let [from ^InetSocketAddress (.getSocketAddress pkt)]
        (Quiche/connRecv conn dgram-buf (.getLength pkt)
                         (.getAddress (.getAddress from)) (.getPort from)
                         (.getAddress (.getAddress local)) (.getPort local)))
      (catch SocketTimeoutException _
        (Quiche/connOnTimeout conn))))
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
        (if (or v (>= (now-ms) deadline) (Quiche/connIsClosed (:conn c)))
          (or v (pred))
          (do (service! c 20)
              (recur)))))))

(defn pump!
  "Services the connection for `ms` milliseconds."
  [c ms]
  (pump-until! c (constantly false) ms))

(defn start-handshake
  "Creates a client connection to `port` and sends only its first
  Initial flight, without servicing the connection afterwards. The
  client advertises no idle timeout."
  [^long port]
  (let [cfg (client-config 0)
        sock (DatagramSocket. 0 (InetAddress/getByName "127.0.0.1"))
        server (InetSocketAddress. "127.0.0.1" (int port))
        scid (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
        local ^InetSocketAddress (.getLocalSocketAddress sock)
        conn (Quiche/connect "localhost" scid
                             (.getAddress (.getAddress local)) (.getPort local)
                             (.getAddress (.getAddress server)) port cfg)
        c {:conn conn :cfg cfg :sock (atom sock) :local local :server server
           :send-buf (ByteBuffer/allocateDirect 1350) :recv-buf (byte-array 65536)
           :dgram-buf (byte-array 65536)
           :pending (atom (sorted-map)) :streams (atom {})}]
    (flush-out! c)
    c))

(defn connect
  "Opens a QUIC connection to `port` on 127.0.0.1 and completes the
  handshake. Throws when the handshake doesn't finish within 5s.
  `:initial-size` pads every client Initial datagram to that size."
  ([port] (connect port {}))
  ([^long port {:keys [initial-size]}]
   (let [cfg (client-config 10000)
         sock (doto (DatagramSocket. 0 (InetAddress/getByName "127.0.0.1")))
         server (InetSocketAddress. "127.0.0.1" (int port))
         scid (let [b (byte-array 16)] (.nextBytes (SecureRandom.) b) b)
         local ^InetSocketAddress (.getLocalSocketAddress sock)
         conn (Quiche/connect "localhost" scid
                              (.getAddress (.getAddress local)) (.getPort local)
                              (.getAddress (.getAddress server)) port cfg)
         c {:conn conn :cfg cfg :sock (atom sock) :local local :server server
            :send-buf (ByteBuffer/allocateDirect 1350) :recv-buf (byte-array 65536)
            :dgram-buf (byte-array 65536)
            :pending (atom (sorted-map)) :streams (atom {})
           :initial-size initial-size :odcid (atom nil)}]
     (when (zero? conn) (throw (ex-info "quiche_connect failed" {})))
     (when-not (pump-until! c #(Quiche/connIsEstablished conn) 5000)
       (throw (ex-info "h3 handshake did not complete" {:port port})))
     c)))

(defn close!
  "Closes the client connection and frees native state."
  [{:keys [conn cfg sock] :as c}]
  (when-not (Quiche/connIsClosed conn)
    (Quiche/connClose conn true 0x100 (byte-array 0))
    (flush-out! c))
  (Quiche/connFree conn)
  (Quiche/configFree cfg)
  (.close ^DatagramSocket @sock))

(defn rebind!
  "Simulates a NAT rebinding: further datagrams leave from (and are
  received on) a fresh UDP port, while quiche still believes its local
  address is the original one."
  [c]
  (let [old ^DatagramSocket @(:sock c)]
    (reset! (:sock c) (DatagramSocket. 0 (InetAddress/getByName "127.0.0.1")))
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
  (Quiche/connStreamShutdown (:conn c) sid Quiche/QUICHE_SHUTDOWN_WRITE code)
  (flush-out! c))

(defn stop-sending!
  "Asks the server to stop sending on `sid` (STOP_SENDING)."
  [c sid code]
  (Quiche/connStreamShutdown (:conn c) sid Quiche/QUICHE_SHUTDOWN_READ code)
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
  {:status :headers :fields :body :fin :reset}; :fields keeps every
  [name value] pair of the response header section in wire order."
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
    (let [hs (first @headers)]
      {:status (some (fn [[n v]] (when (= n ":status") (Long/parseLong v))) hs)
       :headers (into {} (remove #(.startsWith ^String (first %) ":")) hs)
       :fields hs
       :body (.toByteArray body)
       :fin (boolean (:fin s))
       :reset (:reset s)})))

(defn request!
  "Sends a request on `sid` and waits for the full response."
  ([c sid pairs] (request! c sid pairs nil))
  ([c sid pairs ^bytes body]
   (send! c sid (if body
                  (concat-bytes (headers-frame pairs) (data-frame body))
                  (headers-frame pairs))
          true)
   (pump-until! c #(stream-done? c sid) 5000)
   (response c sid)))

(defn peer-error
  "[app? code] of the server's CONNECTION_CLOSE, or nil if it hasn't
  closed the connection."
  [c]
  (let [out (long-array 2)]
    (when (Quiche/connPeerError (:conn c) out)
      [(= 1 (aget out 0)) (aget out 1)])))

(defn await-peer-error
  "Pumps until the server closes the connection; returns `peer-error`."
  [c ms]
  (pump-until! c #(peer-error c) ms))

(defn body-str [r] (String. ^bytes (:body r) "UTF-8"))

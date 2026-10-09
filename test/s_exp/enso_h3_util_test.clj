;; ABOUTME: HTTP/3 helper and JNI shim tests: body pipe, frame reader, Retry tokens, control-stream
;; ABOUTME: bookkeeping, shim loading and ABI, handles, UDP batches, stateless closes.
(ns s-exp.enso-h3-util-test
  "H3 helper class tests: Http3BodyPipe (truncation marker, read timeout),
  Http3FrameReader (mid-frame partial detection), RetryToken (issued-at
  expiry), control-stream bookkeeping and the JNI shim (handles, version
  check, UDP batches, wake-ups). No server startup required."
  (:require [clojure.test :refer [deftest testing is]])
  (:import (com.s_exp.enso.http3 Http3BodyPipe Http3FrameReader)
           (com.s_exp.enso.quiche RetryToken)
           (java.io IOException)
           (java.lang.reflect Field)
           (java.net InetSocketAddress)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)))

;; ---- Http3BodyPipe truncated marker --------------------------------------

(deftest body-pipe-truncated-throws-ioexception-on-next-read
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "abcd" StandardCharsets/UTF_8))
    (.signalTruncated pipe)
    (let [scratch (byte-array 10)
          n (.read in scratch 0 10)]
      (is (= 4 n) "queued bytes returned before poison")
      (is (thrown-with-msg? IOException #"truncated"
                            (.read in scratch 0 10))
          "next read hits truncated marker → IOException"))))

(deftest body-pipe-truncated-with-no-queued-bytes
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.signalTruncated pipe)
    (is (thrown? IOException (.read in)))))

(deftest body-pipe-signalend-still-yields-clean-eof
  ;; Sanity: signalEnd (non-truncated) must remain -1 EOF, not IOException.
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "hi" StandardCharsets/UTF_8))
    (.signalEnd pipe)
    (let [scratch (byte-array 10)]
      (is (= 2 (.read in scratch 0 10)))
      (is (= -1 (.read in scratch 0 10)) "clean EOF after signalEnd"))))

;; ---- Http3FrameReader partial detection ----------------------------------

(defn- feed-bytes! [^Http3FrameReader r ^bytes b]
  (.feed r b 0 (alength b)))

(deftest frame-reader-empty-not-partial
  (let [r (Http3FrameReader. 65536)]
    (is (not (.hasPartial r)) "fresh reader has no buffered bytes")))

(deftest frame-reader-partial-varint-detected
  ;; Feed a single byte that looks like the start of a multi-byte varint.
  ;; Http3 varint prefix 0b10xxxxxx = 2-byte, so 0x40 alone is incomplete.
  ;; Even simpler: feed 0x00 (a single-byte varint = type 0 for DATA)
  ;; without the length byte → length varint incomplete.
  (let [r (Http3FrameReader. 65536)]
    (feed-bytes! r (byte-array [(byte 0x00)]))
    (is (.hasPartial r) "type parsed but no length yet → partial")))

(deftest frame-reader-complete-frame-not-partial
  ;; DATA frame (type 0), length 3, payload "abc". Full frame → no partial.
  (let [r (Http3FrameReader. 65536)
        buf (byte-array [(byte 0x00) (byte 0x03) (byte 0x61) (byte 0x62) (byte 0x63)])]
    (feed-bytes! r buf)
    (loop []
      (when (.poll r) (recur))) ;; drain any DATA chunk emissions
    (is (not (.hasPartial r)) "fully-consumed frame leaves reader empty")))

(deftest frame-reader-mid-payload-detected
  ;; DATA type=0 length=10, only 3 payload bytes fed. Reader should
  ;; emit a partial DATA chunk (2-byte header + 3 payload) then still
  ;; report `hasPartial=true` because pendingLength > pendingConsumed.
  (let [r (Http3FrameReader. 65536)
        buf (byte-array [(byte 0x00) (byte 0x0A)
                         (byte 0x61) (byte 0x62) (byte 0x63)])]
    (feed-bytes! r buf)
    ;; drain any emitted DATA chunk
    (loop []
      (when (.poll r) (recur)))
    (is (.hasPartial r) "mid-frame payload → hasPartial")))

(deftest frame-reader-reset-clears-partial
  (let [r (Http3FrameReader. 65536)]
    (feed-bytes! r (byte-array [(byte 0x00)]))
    (is (.hasPartial r))
    (.reset r)
    (is (not (.hasPartial r)) "reset clears buffered bytes")))

(deftest frame-reader-data-chunk-larger-than-accum-cap
  ;; The accumulation cap bounds buffered frame payloads (HEADERS), not
  ;; the size of one feed: DATA bytes are streamed through.
  (let [r (Http3FrameReader. 8192)
        payload (byte-array 16384 (byte 7))
        frame (byte-array (concat [0x00 (unchecked-byte 0x80) 0x00 0x40 0x00] payload))
        total (atom 0)]
    (feed-bytes! r frame)
    (loop []
      (when-let [^com.s_exp.enso.http3.Http3FrameReader$Frame f (.poll r)]
        (swap! total + (alength ^bytes (.-dataChunk f)))
        (recur)))
    (is (= 16384 @total))
    (is (not (.hasPartial r)))))

(deftest frame-reader-headers-over-cap-still-oversized
  ;; A HEADERS frame longer than the cap is reported, never buffered.
  (let [r (Http3FrameReader. 8192)
        frame (byte-array (concat [0x01 (unchecked-byte 0x80) 0x00 0x40 0x00] (repeat 16384 0)))]
    (feed-bytes! r frame)
    (is (.-oversized ^com.s_exp.enso.http3.Http3FrameReader$Frame (.poll r)))
    (is (not (.hasPartial r)))))

;; ---- RetryToken issued-at + expiry ---------------------------------------

(deftest retry-token-issued-at-tampered-rejected
  ;; Flip a byte inside the 8-byte issued-at region: token becomes
  ;; wall-clock far past → verify rejects on age > TOKEN_MAX_AGE_SECONDS.
  (let [tok (RetryToken.)
        peer (InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array [(byte 1) (byte 2) (byte 3)])
        scid (byte-array 16 (byte 9))
        ^bytes minted (.mint tok peer odcid scid)]
    ;; Sanity: intact token verifies.
    (is (some? (.verify tok minted 0 (alength minted) peer scid 16)))
    ;; Locate issued-at start via reflection: layout is
    ;; HMAC(32) + MAGIC(4) + ISSUED_AT(8) + IP + port + odcid_len + odcid.
    ;; Flip MSB of issued-at: value jumps by 2^56 seconds → age check fails.
    (let [issued-at-off 36
          copy (aclone minted)]
      (aset copy issued-at-off
            (byte (bit-xor (aget copy issued-at-off) 0x40)))
      (is (nil? (.verify tok copy 0 (alength copy) peer scid 16))
          "tampered issued-at rejected (HMAC mismatch OR age out of window)"))))

(deftest retry-token-max-age-seconds-constant
  (let [^Field f (.getDeclaredField RetryToken "TOKEN_MAX_AGE_SECONDS")]
    (.setAccessible f true)
    (is (= 10 (.getLong f nil))
        "documented max-age is 10 seconds — bump this test if you change it")))

(deftest retry-token-issued-at-len-constant
  (let [^Field f (.getDeclaredField RetryToken "ISSUED_AT_LEN")]
    (.setAccessible f true)
    (is (= 8 (.getInt f nil))
        "issued-at is 8 bytes (big-endian seconds)")))

(deftest retry-token-min-length-accounts-for-issued-at
  ;; Length shorter than HMAC + MAGIC + ISSUED_AT + odcid_len byte is
  ;; rejected upfront without even attempting HMAC.
  (let [tok (RetryToken.)
        peer (InetSocketAddress. "127.0.0.1" 55555)
        too-short (byte-array (+ 32 4 8))]  ; missing odcid_len + odcid + peer
    (is (nil? (.verify tok too-short 0 (alength too-short) peer (byte-array 16) 16)))))

(deftest retry-token-binds-retry-source-connection-id
  ;; RFC 9000 §8.1.2/§17.2.5: the client's retried Initial must carry the
  ;; Retry packet's SCID as its DCID; a token is only valid for that CID.
  (let [tok (RetryToken.)
        peer (InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array [(byte 1) (byte 2) (byte 3)])
        scid (byte-array 16 (byte 9))
        other (byte-array 16 (byte 8))
        ^bytes minted (.mint tok peer odcid scid)
        ;; token embedded at an offset in a larger buffer (slice verify)
        buf (byte-array (+ 7 (alength minted)))]
    (System/arraycopy minted 0 buf 7 (alength minted))
    (is (= (seq odcid) (seq (.verify tok buf 7 (alength minted) peer scid 16))))
    (is (nil? (.verify tok buf 7 (alength minted) peer other 16)) "different DCID")
    (is (nil? (.verify tok buf 7 (alength minted) peer scid 15)) "different DCID length")))

(deftest retry-token-binds-the-address-family
  ;; An IPv6 token whose bytes happen to parse as an IPv4 layout (address,
  ;; port, ids) must not verify for the IPv4 peer those bytes spell.
  (let [tok (RetryToken.)
        odcid (byte-array 8 (byte 1))
        scid (byte-array 16 (byte 2))
        ;; Read as IPv4: 1.2.3.4, port 0x0506, odcid length 9 (v6 bytes
        ;; 7-15), then the scid length is the real port's high byte: 27,
        ;; exactly what follows it.
        v6 (byte-array (map unchecked-byte [1 2 3 4 5 6 9 0 0 0 0 0 0 0 0 0]))
        peer6 (InetSocketAddress. (java.net.InetAddress/getByAddress v6) (int (+ (* 27 256) 7)))
        ^bytes minted (.mint tok peer6 odcid scid)
        tail (java.util.Arrays/copyOfRange minted (- (alength minted) 27) (alength minted))
        peer4 (InetSocketAddress. (java.net.InetAddress/getByAddress (byte-array [1 2 3 4])) (int 0x0506))]
    (is (= (seq odcid) (seq (.verify tok minted 0 (alength minted) peer6 scid 16))) "valid for its own peer")
    (is (nil? (.verify tok minted 0 (alength minted) peer4 tail 27)) "never for an IPv4 reading of it")))

;; ---- Http3ControlStreams peer uni-stream bookkeeping ----------------------

(defn- control-streams
  "A package-private Http3ControlStreams with no output (grease streams
  never write)."
  []
  (let [cls (Class/forName "com.s_exp.enso.http3.Http3ControlStreams")
        out (Class/forName "com.s_exp.enso.http3.Http3ControlStreams$Output")
        ctor (doto (.getDeclaredConstructor cls (into-array Class [out Long/TYPE]))
               (.setAccessible true))]
    (.newInstance ctor (object-array [nil (long 0)]))))

(defn- invoke [obj ^String method types & args]
  (let [m (doto (.getDeclaredMethod (class obj) method (into-array Class types))
            (.setAccessible true))]
    (.invoke m obj (object-array args))))

(defn- feed-uni [cs sid ^bytes data fin]
  (invoke cs "onPeerData" [Long/TYPE (Class/forName "[B") Integer/TYPE Integer/TYPE Boolean/TYPE]
          (long sid) data (int 0) (int (alength data)) (boolean fin)))

(defn- tracked [cs] (invoke cs "trackedPeerStreams" []))

(deftest control-streams-forget-finished-grease-uni-streams
  ;; Grease / unknown peer uni streams are tracked only until they end, so
  ;; a long-lived connection's bookkeeping doesn't grow with each one.
  (let [cs (control-streams)]
    (testing "type and FIN in one chunk"
      (feed-uni cs 14 (byte-array [0x21 0x00]) true)
      (is (zero? (tracked cs))))
    (testing "FIN after the type was identified"
      (feed-uni cs 18 (byte-array [0x21]) false)
      (is (= 1 (tracked cs)))
      (feed-uni cs 18 (byte-array [0x00]) true)
      (is (zero? (tracked cs))))))

;; ---- JNI shim: handles, version, sockets ---------------------------------

(deftest quiche-natives-are-package-private
  ;; Raw pointers and descriptors stay inside com.s_exp.enso.quiche: no
  ;; native method of the shim class is public.
  (let [natives (filter #(java.lang.reflect.Modifier/isNative (.getModifiers ^java.lang.reflect.Method %))
                        (.getDeclaredMethods com.s_exp.enso.quiche.Quiche))]
    (is (seq natives))
    (is (empty? (filter #(java.lang.reflect.Modifier/isPublic (.getModifiers ^java.lang.reflect.Method %))
                        natives)))))

(deftest libquiche-version-is-checked-at-load
  (is (= com.s_exp.enso.quiche.Quiche/QUICHE_VERSION (com.s_exp.enso.quiche.Quiche/libraryVersion)))
  (let [m (doto (.getDeclaredMethod com.s_exp.enso.quiche.Quiche "requireVersion"
                                    (into-array Class [String]))
            (.setAccessible true))]
    (is (nil? (.invoke m nil (object-array [com.s_exp.enso.quiche.Quiche/QUICHE_VERSION]))))
    (is (thrown? UnsatisfiedLinkError
                 (try (.invoke m nil (object-array ["0.20.0"]))
                      (catch java.lang.reflect.InvocationTargetException e (throw (.getCause e))))))))

(defn- invoke-static
  "Calls the non-public static `method` of Quiche, unwrapping its exception."
  [method types args]
  (let [m (doto (.getDeclaredMethod com.s_exp.enso.quiche.Quiche method (into-array Class types))
            (.setAccessible true))]
    (try (.invoke m nil (object-array args))
         (catch java.lang.reflect.InvocationTargetException e (throw (.getCause e))))))

(deftest shim-abi-is-checked-at-load
  ;; The shim loaded for this run (target/native) passed the check.
  (is (pos? com.s_exp.enso.quiche.Quiche/SHIM_ABI))
  (is (nil? (invoke-static "requireShimAbi" [Integer/TYPE] [(int com.s_exp.enso.quiche.Quiche/SHIM_ABI)])))
  (is (thrown-with-msg? UnsatisfiedLinkError #"ABI 0 loaded"
                        (invoke-static "requireShimAbi" [Integer/TYPE] [(int 0)]))
      "a shim predating the check (no shimAbi entry point) reads as ABI 0"))

(deftest development-shim-is-found-next-to-the-class-directory
  ;; Never relative to the working directory: only target/native beside
  ;; the target/classes directory the shim class came from.
  (let [classes (java.nio.file.Path/of (.toURI (.getLocation (.getCodeSource (.getProtectionDomain com.s_exp.enso.quiche.Quiche)))))]
    (is (java.nio.file.Files/isDirectory classes (make-array java.nio.file.LinkOption 0)))
    (is (= (.resolve (.getParent classes) "native")
           (invoke-static "developmentDirectory" [] [])))))

(deftest shim-extraction-directory-is-configurable
  (let [dir (str (java.nio.file.Files/createTempDirectory "enso-shim-dir" (make-array java.nio.file.attribute.FileAttribute 0)))]
    (try
      (System/setProperty "enso.quiche.tmpdir" dir)
      (is (= (java.nio.file.Path/of dir (make-array String 0)) (invoke-static "extractionDirectory" [] [])))
      (finally (System/clearProperty "enso.quiche.tmpdir")))
    (is (= (java.nio.file.Path/of (System/getProperty "java.io.tmpdir") (make-array String 0))
           (invoke-static "extractionDirectory" [] []))
        "java.io.tmpdir without the property (and ENSO_QUICHE_TMPDIR unset)")))

(defn- native-buffer ^com.s_exp.enso.quiche.NativeBuffer [n]
  (com.s_exp.enso.quiche.NativeBuffer/allocate (int n)))

(defn- view ^ByteBuffer [^com.s_exp.enso.quiche.NativeBuffer b] (.-buffer b))

(defn- loopback-addr ^com.s_exp.enso.quiche.NativeBuffer [port]
  (let [b (native-buffer (* 2 com.s_exp.enso.quiche.Records/ADDR_LEN))]
    (com.s_exp.enso.quiche.Records/putAddress (view b) 0 (InetSocketAddress. "127.0.0.1" (int 40000)))
    (com.s_exp.enso.quiche.Records/putAddress (view b) com.s_exp.enso.quiche.Records/ADDR_LEN
                                              (InetSocketAddress. "127.0.0.1" (int port)))
    b))

(deftest freed-handles-refuse-use
  ;; After free/close a wrapper throws rather than hand quiche a dangling pointer.
  (let [cfg (com.s_exp.enso.quiche.QuicheConfig/client 1000)
        addrs (loopback-addr 40001)
        conn (com.s_exp.enso.quiche.QuicheConnection/connect cfg "localhost" (byte-array 16 (byte 1))
                                                             addrs 0 com.s_exp.enso.quiche.Records/ADDR_LEN)]
    (is (some? conn))
    (is (false? (.isClosed conn)))
    (.free conn)
    (.free conn)
    (is (thrown? IllegalStateException (.isClosed conn)))
    (is (thrown? IllegalStateException (.streamSend conn 0 (byte-array 1) 0 1 false)))
    (.close cfg)
    (.close cfg)
    (is (thrown? IllegalStateException (.setInitialMaxData cfg 1)))))

(deftest shim-bounds-checks-arguments
  (let [cfg (com.s_exp.enso.quiche.QuicheConfig/client 1000)
        conn (com.s_exp.enso.quiche.QuicheConnection/connect cfg "localhost" (byte-array 16 (byte 1))
                                                             (loopback-addr 40001) 0
                                                             com.s_exp.enso.quiche.Records/ADDR_LEN)]
    (try
      (is (= com.s_exp.enso.quiche.Quiche/SHIM_ERR_INVALID_ARGUMENT
             (.streamSend conn 0 (byte-array 4) 2 3 false)) "range past the array")
      (is (= com.s_exp.enso.quiche.Quiche/SHIM_ERR_INVALID_ARGUMENT
             (.streamRecv conn 0 (byte-array 4) -1 2)) "negative offset")
      (is (= com.s_exp.enso.quiche.Quiche/SHIM_ERR_INVALID_ARGUMENT
             (.recv conn (native-buffer 16) 8 9 (loopback-addr 1) 0 24)) "range past the buffer")
      (is (= com.s_exp.enso.quiche.Quiche/SHIM_ERR_INVALID_ARGUMENT
             (.recv conn (native-buffer 16) 0 8 (loopback-addr 1) 40 24)) "address record past the buffer")
      (finally (.free conn) (.close cfg)))))

;; Receives until `n` datagrams arrived on `sock` (or 2 s passed), polling
;; between batches: [{:len :first-byte :peer :local}] in arrival order.
(defn- receive-datagrams [^com.s_exp.enso.quiche.UdpSocket sock n]
  (let [slot 2048
        rslab (native-buffer (* 8 slot))
        rmeta (native-buffer (* 9 com.s_exp.enso.quiche.Records/RECV_META_LEN))
        waker (com.s_exp.enso.quiche.UdpSocket$Waker.)
        deadline (+ (System/nanoTime) 2000000000)]
    (try
      ;; the local-address template: the record after the last slot
      (.localAddress sock rmeta (* 8 com.s_exp.enso.quiche.Records/RECV_META_LEN))
      (loop [acc []]
        (let [left (- deadline (System/nanoTime))]
          (if (or (>= (count acc) n) (<= left 0))
            acc
            (do (.poll waker sock nil false left)
                (let [k (.recvBatch sock rslab slot 8 rmeta)]
                  (recur (into acc (for [i (range k)
                                         :let [rec (* i com.s_exp.enso.quiche.Records/RECV_META_LEN)]]
                                     {:len (.getInt (view rmeta) (int (+ rec com.s_exp.enso.quiche.Records/RECV_LEN)))
                                      :first-byte (.get (view rslab) (int (* i slot)))
                                      :peer (com.s_exp.enso.quiche.Records/socketAddress (view rmeta) (+ rec com.s_exp.enso.quiche.Records/RECV_PEER))
                                      :local (com.s_exp.enso.quiche.Records/socketAddress (view rmeta) (+ rec com.s_exp.enso.quiche.Records/RECV_LOCAL))}))))))))
      (finally (.close waker)))))

(deftest udp-batch-send-and-receive
  ;; A send batch reaches the peer as separate datagrams with their sizes;
  ;; the receive batch reports each one's source and the local address.
  (with-open [a (com.s_exp.enso.quiche.UdpSocket/open (java.net.InetAddress/getByName "127.0.0.1") 0 0 0 0)
              b (com.s_exp.enso.quiche.UdpSocket/open (java.net.InetAddress/getByName "127.0.0.1") 0 0 0 0)]
    (let [slab (native-buffer 4096)
          meta (native-buffer (+ com.s_exp.enso.quiche.Records/SEND_HEADER_LEN
                                 (* 3 com.s_exp.enso.quiche.Records/SEND_META_LEN)))
          ^InetSocketAddress a-addr (.localAddress a)
          ^InetSocketAddress b-addr (.localAddress b)
          sizes [100 1200 7]]
      (reduce (fn [off [i n]]
                (dotimes [k n] (.put (view slab) (int (+ off k)) (unchecked-byte (+ i k))))
                (let [rec (+ com.s_exp.enso.quiche.Records/SEND_HEADER_LEN (* i com.s_exp.enso.quiche.Records/SEND_META_LEN))]
                  (.putInt (view meta) (int (+ rec com.s_exp.enso.quiche.Records/SEND_OFF)) (int off))
                  (.putInt (view meta) (int (+ rec com.s_exp.enso.quiche.Records/SEND_LEN)) (int n))
                  (com.s_exp.enso.quiche.Records/putAddress (view meta) (+ rec com.s_exp.enso.quiche.Records/SEND_TO) b-addr))
                (+ off n))
              0 (map-indexed vector sizes))
      (is (= 3 (.sendBatch a slab meta 3 0)))
      (let [got (receive-datagrams b 3)]
        (is (= sizes (mapv :len got)))
        (is (= (map unchecked-byte (range 3)) (map :first-byte got)) "payload")
        (is (every? #(= a-addr (:peer %)) got))
        (is (every? #(= b-addr (:local %)) got)))
      (is (zero? (.recvBatch b (native-buffer 2048) 2048 1 (native-buffer (* 2 com.s_exp.enso.quiche.Records/RECV_META_LEN))))
          "nothing queued: no blocking"))))

(deftest waker-interrupts-poll
  (let [waker (com.s_exp.enso.quiche.UdpSocket$Waker.)]
    (try
      (let [t0 (System/nanoTime)]
        (is (zero? (.poll waker nil nil false 50000000)) "times out")
        (is (>= (- (System/nanoTime) t0) 40000000)))
      (let [t (Thread/startVirtualThread #(do (Thread/sleep 50) (.signal waker)))
            t0 (System/nanoTime)
            bits (.poll waker nil nil false 5000000000)]
        (.join t)
        (is (= com.s_exp.enso.quiche.UdpSocket$Waker/WAKE bits))
        (is (< (- (System/nanoTime) t0) 2000000000))
        (is (zero? (.poll waker nil nil false 0)) "drained"))
      (finally (.close waker)))
    (.signal waker)))

(deftest stateless-invalid-token-close-is-understood-by-a-client
  ;; RFC 9000 §8.1.2 / RFC 9001 §5.2: the server Initial built without
  ;; state, protected with keys from the client's destination id, closes a
  ;; real quiche client with INVALID_TOKEN (0x0b).
  (let [cfg (com.s_exp.enso.quiche.QuicheConfig/client 1000)
        scid (byte-array 16 (byte 3))
        addrs (loopback-addr 40001)
        conn (com.s_exp.enso.quiche.QuicheConnection/connect cfg "localhost" scid addrs 0
                                                             com.s_exp.enso.quiche.Records/ADDR_LEN)
        out (native-buffer 1500)
        meta (native-buffer 64)]
    (try
      (let [n (.send conn out 0 1350 meta 0)
            dcid-len (.get (view out) 5)
            dcid (byte-array dcid-len)]
        (is (pos? n))
        (.get (view out) 6 dcid)
        (let [len (com.s_exp.enso.quiche.InitialClose/invalidToken dcid scid 1 (view out) 0 1500)
              ;; from the server (record 24) to the client (record 0)
              rc (.recv conn out 0 (int len) addrs com.s_exp.enso.quiche.Records/ADDR_LEN 0)
              err (long-array 2)]
          (is (pos? len))
          (is (< len 100))
          (is (= len rc) "accepted by the client")
          (is (.peerError conn err))
          (is (= [0 0x0b] (vec err)) "transport close, INVALID_TOKEN")))
      (finally (.free conn) (.close cfg)))))

(deftest send-errors-are-packet-loss
  ;; A datagram the OS refuses (here: destination port 0, EINVAL on Linux,
  ;; EADDRNOTAVAIL on macOS, whatever the privileges; a broadcast would be
  ;; let through for root) is dropped as lost; the rest of the batch still
  ;; goes out.
  (with-open [a (com.s_exp.enso.quiche.UdpSocket/open (java.net.InetAddress/getByName "0.0.0.0") 0 0 0 0)
              b (com.s_exp.enso.quiche.UdpSocket/open (java.net.InetAddress/getByName "127.0.0.1") 0 0 0 0)]
    (let [slab (native-buffer 4096)
          meta (native-buffer (+ com.s_exp.enso.quiche.Records/SEND_HEADER_LEN
                                 (* 3 com.s_exp.enso.quiche.Records/SEND_META_LEN)))
          ^InetSocketAddress b-addr (.localAddress b)
          dests [b-addr (InetSocketAddress. "127.0.0.1" (int 0)) b-addr]]
      (doseq [[i ^InetSocketAddress to] (map-indexed vector dests)]
        (let [rec (+ com.s_exp.enso.quiche.Records/SEND_HEADER_LEN (* i com.s_exp.enso.quiche.Records/SEND_META_LEN))]
          (.putInt (view meta) (int (+ rec com.s_exp.enso.quiche.Records/SEND_OFF)) (int (* i 100)))
          (.putInt (view meta) (int (+ rec com.s_exp.enso.quiche.Records/SEND_LEN)) (int 50))
          (com.s_exp.enso.quiche.Records/putAddress (view meta) (+ rec com.s_exp.enso.quiche.Records/SEND_TO) to)))
      (is (= 3 (.sendBatch a slab meta 3 0)) "every record consumed")
      (is (= 1 (.getInt (view meta) (int com.s_exp.enso.quiche.Records/SEND_STATUS_DROPPED))) "one dropped as lost")
      (is (= 2 (count (receive-datagrams b 2))) "the others arrived"))))

(deftest quiche-config-pins-flow-control-windows
  ;; Autotuning can't grow windows past what is configured: a handler
  ;; that doesn't read bounds quiche's buffering at the configured windows.
  (let [build (fn [f] (.build (doto (com.s_exp.enso.api.Config/builder)
                                (.http3 true) (.http3CertPath "c") (.http3KeyPath "k") f)))]
    (is (= (* 4 1024 1024) (.-http3InitialMaxDataBytes ^com.s_exp.enso.api.Config (build identity)))
        "default connection window 4 MiB")
    (let [[cert key] (let [d (java.nio.file.Files/createTempDirectory "enso-h3-cfg" (make-array java.nio.file.attribute.FileAttribute 0))
                           c (str (.resolve d "c.pem")) k (str (.resolve d "k.pem"))]
                       (.waitFor (.start (ProcessBuilder. ^java.util.List
                                          (list "openssl" "req" "-x509" "-newkey" "rsa:2048"
                                                "-keyout" k "-out" c "-days" "1" "-nodes"
                                                "-subj" "/CN=localhost"))))
                       [c k])
          cfg (.build (doto (com.s_exp.enso.api.Config/builder)
                        (.http3 true) (.http3CertPath cert) (.http3KeyPath key)
                        (.http3InitialMaxDataBytes (* 8 1024 1024))))
          q (com.s_exp.enso.quiche.QuicheConfig/server cfg)]
      (try
        (is (= (* 8 1024 1024) (.connectionWindow q)))
        (is (= (* 1024 1024) (.streamWindowBidiRemote q)) "derived: max(1 MiB, data / streams)")
        (finally (.close q))))))

(deftest stateless-close-reuses-its-crypto
  ;; Forged Retry tokens each get a stateless INVALID_TOKEN close: building
  ;; one must not look up and allocate the MAC and ciphers every time.
  (let [out (ByteBuffer/allocate 1500)
        mx ^com.sun.management.ThreadMXBean (java.lang.management.ManagementFactory/getThreadMXBean)
        dcid (byte-array 16 (byte 7))
        scid (byte-array 8 (byte 3))
        close! (fn [i]
                 ;; a different id each time: new keys, as for a flood
                 (aset dcid 0 (unchecked-byte i))
                 (aset dcid 1 (unchecked-byte (bit-shift-right i 8)))
                 (com.s_exp.enso.quiche.InitialClose/invalidToken dcid scid 1 out 0 1500))]
    (dotimes [i 2000] (close! i))
    (let [before (.getCurrentThreadAllocatedBytes mx)]
      (dotimes [i 1000] (close! i))
      (let [per-call (quot (- (.getCurrentThreadAllocatedBytes mx) before) 1000)]
        (is (< per-call 4096) (str per-call " bytes per close"))))
    (testing "the same Initial answered twice gets the same packet"
      (let [n (close! 5)
            a (java.util.Arrays/copyOf (.array out) (int n))
            m (close! 5)]
        (is (pos? n))
        (is (= n m))
        (is (java.util.Arrays/equals a (java.util.Arrays/copyOf (.array out) (int m))))))))

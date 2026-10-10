;; ABOUTME: Multi-hour soak/chaos driver: runs s-exp.enso-soak-server in its own JVM, drives a throttled mix
;; ABOUTME: of every protocol plus hostile clients, samples the server's resources and writes a time series.
(ns s-exp.enso-soak
  "Run with `clojure -M:soak [OPTS-EDN]`, e.g.
  `clojure -M:soak '{:duration-m 120}'` (see doc/testing.md).

  Phases: warm-up load, a quiet period ending in the baseline sample, the
  main load for `:duration-m`, a quiet period ending in the final sample,
  then a graceful stop of the servers under load. A sample (every
  `:sample-s`) reads the server's `/__stats` after a full GC, its RSS and
  CPU (ps) and native memory (NMT), and the interval's outcome counts and
  latency per kind of client. Every client operation ends in an outcome:
  \"ok\" or a named failure; each kind lists the outcomes it expects (a
  slowloris client expects a 408), anything else is unexpected and the
  first ones of a kind trigger a thread dump of the server.

  Results go to `<:out-dir>/<timestamp>/`: timeseries.edn (one sample per
  line), timeseries.csv, summary.edn, summary.md, the server's log and GC
  log, and jcmd evidence (thread dumps, class histograms, NMT)."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [s-exp.enso-soak-server :as soak-server]
            [s-exp.enso-test-support :as support]
            [s-exp.h3-client :as h3]
            [s-exp.perf-target :as target])
  (:import (com.s_exp.enso.http2 Hpack$Decoder Hpack$Encoder Hpack$HeaderField)
           (com.sun.management OperatingSystemMXBean)
           (java.io BufferedInputStream BufferedOutputStream ByteArrayInputStream ByteArrayOutputStream
                    DataInputStream EOFException File IOException InputStream OutputStream)
           (java.lang.management ManagementFactory)
           (java.net ConnectException InetSocketAddress Socket SocketException SocketTimeoutException URI)
           (java.net.http HttpClient HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse
                          HttpResponse$BodyHandlers HttpTimeoutException)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)
           (java.nio.file CopyOption Files Paths StandardCopyOption)
           (java.security.cert CertificateFactory X509Certificate)
           (java.time Duration Instant)
           (java.util ArrayList Arrays Base64 List)
           (java.util.concurrent ConcurrentHashMap Semaphore ThreadLocalRandom TimeUnit)
           (java.util.concurrent.atomic AtomicBoolean AtomicLong LongAdder)
           (java.util.function Function)
           (java.util.zip CRC32 Deflater Inflater)
           (javax.net.ssl SSLContext SSLEngine SSLParameters SSLSocket)
           (org.HdrHistogram Histogram Recorder)))

(set! *warn-on-reflection* true)

(def ^:private defaults
  {:duration-m 120
   :warmup-m 5
   ;; Long enough for idle connections, HTTP/3 draining and the HTTP/3
   ;; driver pool's 60 s keep-alive to wind down.
   :quiet-s 150
   :sample-s 30
   ;; Multiplies every steady rate; the defaults keep one laptop usable.
   :rate-scale 1.0
   :chaos true
   :h3 true
   ;; Seconds between HTTP/3 certificate replacements.
   :cert-reload-s 300
   ;; Load kept running while the servers stop, and when the stop begins.
   :shutdown-load-s 40
   :server-jvm-opts ["-Xms512m" "-Xmx512m" "-XX:+AlwaysPreTouch" "-XX:+UseG1GC" "-XX:NativeMemoryTracking=summary"
                     "-XX:+HeapDumpOnOutOfMemoryError"]
   :server-opts {:idle-timeout 15000
                 :header-timeout 5000
                 :read-timeout 10000
                 :write-timeout 10000
                 :handshake-timeout 5000
                 :shutdown-timeout 10000
                 :max-header-bytes 16384
                 :max-request-body-bytes (* 8 1024 1024)
                 :max-buffered-bytes (* 4 1024 1024)
                 :ws-compression true
                 :http3-cert-reload-interval 5000}
   :out-dir "target/soak"})

;; ---- outcomes and latency ---------------------------------------------------------------

(def ^:private new-adder (reify Function (apply [_ _] (LongAdder.))))

(def ^:private kinds
  "kind -> {:outcomes {outcome LongAdder} :latency Recorder}"
  (ConcurrentHashMap.))

(def ^:private new-kind
  (reify Function
    (apply [_ _] {:outcomes (ConcurrentHashMap.) :latency (Recorder. 3600000000000 3)})))

(defn- kind-state [kind] (.computeIfAbsent ^ConcurrentHashMap kinds kind new-kind))

(def ^:private expected
  "Outcomes each kind expects besides \"ok\". Kinds not listed expect
  only \"ok\"."
  {"chaos-slowloris" #{"408" "closed"}
   "chaos-trickle-body" #{"408" "closed"}
   "chaos-h2-rapid-reset" #{"goaway-11"}
   "chaos-h2-malformed" #{"goaway-1" "goaway-6"}
   "chaos-malformed-h1" #{"400" "501" "505" "closed"}
   "chaos-oversized-head" #{"431"}
   "chaos-oversized-body" #{"413"}
   "chaos-oversized-chunked" #{"413" "closed"}
   "chaos-half-close" #{"closed"}
   "chaos-park-h1" #{"closed"}
   "chaos-park-h1-after-request" #{"closed"}
   "chaos-park-tls-h1" #{"closed"}
   "chaos-park-tls-h2" #{"closed"}
   "chaos-park-h2c" #{"closed"}
   "chaos-park-ws" #{"closed"}
   "chaos-tls-abandon" #{"closed"}
   "slow-reader-h1" #{"closed"}
   "slow-reader-h2c" #{"rst-stream" "goaway" "closed"}
   "h1-ignore-body" #{"ok-closed"}
   "parked-idle" #{"closed"}
   ;; Reset streams count against the concurrency limit until their
   ;; handlers return, so the request after a burst may be refused.
   "chaos-h2-rst-burst" #{"rst-stream-7"}
   "cert-reload" #{"ok-mismatched-pair-window"}})

(defn- unexpected? [kind outcome]
  (not (or (= "ok" outcome) (contains? (get expected kind #{}) outcome))))

(def ^:private incident-hook (atom nil))

(defn- record!
  "Counts `outcome` for `kind`; the latency of \"ok\" outcomes goes to its
  recorder."
  [kind outcome ^long nanos]
  (let [{:keys [^ConcurrentHashMap outcomes ^Recorder latency]} (kind-state kind)]
    (.increment ^LongAdder (.computeIfAbsent outcomes outcome new-adder))
    (when (or (= "ok" outcome) (str/starts-with? outcome "ok-"))
      (.recordValue latency (max 1 (min nanos 3599999999999))))
    (when (unexpected? kind outcome)
      (when-let [f @incident-hook] (f kind outcome)))))

(defn- outcome-counts []
  (into (sorted-map)
        (map (fn [[k {:keys [^ConcurrentHashMap outcomes]}]]
               [k (into (sorted-map) (map (fn [[o ^LongAdder n]] [o (.sum n)])) outcomes)]))
        kinds))

(defn- interval-latencies
  "Latency percentiles (ms) of the \"ok\" outcomes since the last call, per kind."
  []
  (into (sorted-map)
        (keep (fn [[k {:keys [^Recorder latency]}]]
                (let [^Histogram h (.getIntervalHistogram latency)]
                  (when (pos? (.getTotalCount h))
                    [k {:n (.getTotalCount h)
                        :p50 (/ (.getValueAtPercentile h 50.0) 1e6)
                        :p99 (/ (.getValueAtPercentile h 99.0) 1e6)
                        :max (/ (.getMaxValue h) 1e6)}]))))
        kinds))

(defn- fail!
  "Ends an operation with `outcome`."
  [outcome & [msg]]
  (throw (ex-info (or msg outcome) {:outcome outcome})))

(defn- classify
  "Outcome name of an operation that threw `t`."
  [^Throwable t]
  (let [^Throwable root (loop [^Throwable e t]
                          (if (and (.getCause e) (not (ex-data e)) (not (instance? SocketTimeoutException e)))
                            (recur (.getCause e))
                            e))
        msg (str (.getMessage root))]
    (cond
      (:outcome (ex-data t)) (:outcome (ex-data t))
      (:outcome (ex-data root)) (:outcome (ex-data root))
      (or (instance? SocketTimeoutException root) (instance? HttpTimeoutException root)
          (instance? HttpTimeoutException t)) "timeout"
      (instance? ConnectException root) "connect-refused"
      (instance? EOFException root) "eof"
      (re-find #"(?i)reset" msg) "reset"
      (re-find #"(?i)broken pipe" msg) "broken-pipe"
      (instance? SocketException root) "socket-closed"
      (instance? IOException root) (str "io " (.getSimpleName (class root)) " " (subs msg 0 (min 60 (count msg))))
      :else (str "exception " (.getName (class root)) " " (subs msg 0 (min 60 (count msg)))))))

;; ---- small helpers -------------------------------------------------------------------------

(defn- rnd ^ThreadLocalRandom [] (ThreadLocalRandom/current))

(defn- quietly [f] (try (f) (catch Throwable _ nil)))

(defn- ascii ^bytes [^String s] (.getBytes s StandardCharsets/ISO_8859_1))

(defn- millis-since ^long [^long t0] (quot (- (System/nanoTime) t0) 1000000))

(defn- sleep-unless-stopped!
  "Sleeps `ms`, waking early when `stop` is set."
  [^AtomicBoolean stop ^long ms]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (let [left (- deadline (System/currentTimeMillis))]
        (when (and (pos? left) (not (.get stop)))
          (Thread/sleep (min left 200))
          (recur))))))

(defn- pace!
  "Sleeps out the rest of `interval-ms` (jittered by up to 20%) since `t0`."
  [^AtomicBoolean stop ^long t0 ^double interval-ms]
  (let [jittered (* interval-ms (+ 0.8 (* 0.4 (.nextDouble (rnd)))))
        left (- (long jittered) (millis-since t0))]
    (when (pos? left) (sleep-unless-stopped! stop left))))

(defn- random-bytes ^bytes [n]
  (let [b (byte-array (long n))] (.nextBytes (rnd) b) b))

(defn- crc32 ^long [^bytes b]
  (let [c (CRC32.)] (.update c b) (.getValue c)))

(def ^:private upload-1m (random-bytes (* 1024 1024)))
(def ^:private upload-1m-crc (crc32 upload-1m))
(def ^:private upload-2m (random-bytes (* 2 1024 1024)))
(def ^:private upload-2m-crc (crc32 upload-2m))
(def ^:private upload-4m (random-bytes (* 4 1024 1024)))
(def ^:private upload-4m-crc (crc32 upload-4m))

(defn- pattern-sink
  "A body sink checking the server's byte pattern; returns [sink checked]
  where `(checked)` is the byte count, or throws on a mismatch."
  []
  (let [pos (long-array 1)
        bad (long-array [-1])]
    [(fn [^bytes buf ^long off ^long len]
       (let [p (aget pos 0)]
         (when (neg? (aget bad 0))
           (loop [i 0]
             (when (< i len)
               (if (= (aget buf (+ off i)) (unchecked-byte (soak-server/pattern-byte (+ p i))))
                 (recur (inc i))
                 (aset bad 0 (+ p i))))))
         (aset pos 0 (+ p len))))
     (fn []
       (when-not (neg? (aget bad 0)) (fail! "body-mismatch" (str "pattern mismatch at " (aget bad 0))))
       (aget pos 0))]))

(defn- collect-sink []
  (let [out (ByteArrayOutputStream.)]
    [(fn [^bytes buf ^long off ^long len] (.write out buf (int off) (int len)))
     (fn [] (.toByteArray out))]))

;; ---- HTTP/1.1 ---------------------------------------------------------------------------------

(defn- connect
  ^Socket [port timeout-ms]
  (doto (Socket.)
    (.setTcpNoDelay true)
    (.connect (InetSocketAddress. "127.0.0.1" (int port)) 5000)
    (.setSoTimeout (int timeout-ms))))

(defn- reset-close!
  "Closes `sock` with an RST (SO_LINGER 0)."
  [^Socket sock]
  (quietly #(.setSoLinger sock true 0))
  (quietly #(.close sock)))

(defn- read-line!
  "One CRLF-terminated line, nil at end of stream before any byte."
  ^String [^InputStream in]
  (let [sb (StringBuilder.)]
    (loop []
      (let [b (.read in)]
        (cond
          (neg? b) (if (zero? (.length sb)) nil (throw (EOFException. "end of stream in a line")))
          (= b 10) (let [n (.length sb)]
                     (when (and (pos? n) (= \return (.charAt sb (dec n)))) (.setLength sb (dec n)))
                     (str sb))
          :else (do (when (> (.length sb) 65536) (throw (IOException. "line too long")))
                    (.append sb (char b))
                    (recur)))))))

(defn- read-head!
  "Status and headers (lower-cased names) of a response; throws EOF when
  the server closed first."
  [^InputStream in]
  (let [status-line (read-line! in)]
    (when-not status-line (throw (EOFException. "server closed")))
    (let [status (Long/parseLong (second (re-find #"^HTTP/1\.[01] (\d{3})" status-line)))]
      (loop [headers {}]
        (let [line (read-line! in)]
          (cond
            (nil? line) (throw (EOFException. "end of stream in head"))
            (= "" line) {:status status :headers headers}
            :else (let [i (str/index-of line ":")]
                    (recur (assoc headers (str/lower-case (subs line 0 i)) (str/trim (subs line (inc i))))))))))))

(defn- read-n!
  "Passes the next `n` bytes of `in` to `sink`."
  [^InputStream in ^long n sink]
  (let [buf (byte-array (min n 65536))]
    (loop [left n]
      (when (pos? left)
        (let [r (.read in buf 0 (int (min left (alength buf))))]
          (when (neg? r) (throw (EOFException. "end of stream in body")))
          (sink buf 0 r)
          (recur (- left r)))))))

(defn- read-body!
  "Reads the body framed by `headers` into `sink`."
  [^InputStream in headers sink]
  (cond
    (some-> (get headers "transfer-encoding") str/lower-case (str/includes? "chunked"))
    (loop []
      (let [size-line (read-line! in)
            n (Long/parseLong (str/trim (first (str/split (str size-line) #";"))) 16)]
        (if (zero? n)
          (loop [] (when (seq (read-line! in)) (recur)))
          (do (read-n! in n sink)
              (read-line! in)
              (recur)))))
    (get headers "content-length") (read-n! in (Long/parseLong (get headers "content-length")) sink)
    :else (let [buf (byte-array 65536)]
            (loop []
              (let [r (.read in buf)]
                (when-not (neg? r) (sink buf 0 r) (recur)))))))

(defn- read-response!
  "One response: {:status :headers :body} with the body collected."
  [^InputStream in]
  (let [head (read-head! in)
        [sink result] (collect-sink)]
    (read-body! in (:headers head) sink)
    (assoc head :body (result))))

(defn- h1-open [^long port]
  (let [sock (connect port 20000)]
    {:sock sock
     :in (BufferedInputStream. (.getInputStream sock) 65536)
     :out (BufferedOutputStream. (.getOutputStream sock) 65536)}))

(defn- h1-close [{:keys [^Socket sock]}] (quietly #(.close sock)))

(defn- write! [^OutputStream out ^bytes b] (.write out b) (.flush out))

(defn- get-request ^bytes [^String path & [extra]]
  (ascii (str "GET " path " HTTP/1.1\r\nHost: localhost\r\n" extra "\r\n")))

(def ^:private hello-get (get-request "/"))

(defn- check-hello! [{:keys [status ^bytes body]}]
  (cond
    (not= 200 status) (fail! (str status))
    (not= target/hello-body (String. body StandardCharsets/ISO_8859_1)) (fail! "body-mismatch")
    :else "ok"))

(defn- h1-get-op [{:keys [in out]}]
  (write! out hello-get)
  (check-hello! (read-response! in)))

(defn- h1-pipelined-op [depth {:keys [in out]}]
  (let [batch (byte-array (* depth (alength ^bytes hello-get)))]
    (dotimes [i depth]
      (System/arraycopy hello-get 0 batch (* i (alength ^bytes hello-get)) (alength ^bytes hello-get)))
    (write! out batch)
    (dotimes [_ depth] (check-hello! (read-response! in)))
    "ok"))

(defn- h1-close-op [port]
  (let [{:keys [^Socket sock in out] :as c} (h1-open port)]
    (try
      (write! out (get-request "/" "Connection: close\r\n"))
      (check-hello! (read-response! in))
      (if (neg? (.read ^InputStream in)) "ok" (fail! "not-closed"))
      (finally (h1-close c)))))

(defn- h1-upload-op
  "POSTs `body` (Content-Length, or chunked in 16 KiB chunks) to /upload
  and checks the length and CRC the server answers."
  [port ^bytes body ^long crc chunked]
  (let [{:keys [in ^OutputStream out] :as c} (h1-open port)]
    (try
      (if chunked
        (do (.write out (ascii "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"))
            (loop [off 0]
              (when (< off (alength body))
                (let [n (min 16384 (- (alength body) off))]
                  (.write out (ascii (str (Long/toHexString n) "\r\n")))
                  (.write out body (int off) (int n))
                  (.write out (ascii "\r\n"))
                  (recur (+ off n)))))
            (write! out (ascii "0\r\n\r\n")))
        (do (.write out (ascii (str "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                                    (alength body) "\r\n\r\n")))
            (write! out body)))
      (let [expected-answer (str (alength body) " " crc)
            {:keys [status ^bytes body]} (read-response! in)
            answer (String. body StandardCharsets/ISO_8859_1)]
        (cond
          (not= 200 status) (fail! (str status))
          (not= expected-answer answer) (fail! "body-mismatch" answer)
          :else "ok"))
      (finally (h1-close c)))))

(defn- h1-ignore-body-op
  "POSTs 1 MiB to a handler that doesn't read it, then reuses the
  connection when the server kept it open."
  [port]
  (let [{:keys [in out] :as c} (h1-open port)]
    (try
      (write! out (ascii (str "POST /ignore-body HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                              (alength ^bytes upload-1m) "\r\n\r\n")))
      (write! out upload-1m)
      (let [{:keys [status headers]} (let [r (read-response! in)] r)]
        (when (not= 200 status) (fail! (str status)))
        (if (= "close" (some-> (get headers "connection") str/lower-case))
          "ok-closed"
          (do (write! out hello-get)
              (check-hello! (read-response! in)))))
      (finally (h1-close c)))))

(defn- h1-pattern-get-op
  "GETs `path` and checks the body is `n` pattern bytes (or `sse-events`
  server-sent events)."
  [port path n sse-events]
  (let [{:keys [in out] :as c} (h1-open port)]
    (try
      (write! out (get-request path))
      (let [{:keys [status headers]} (read-head! in)]
        (when (not= 200 status) (fail! (str status)))
        (if sse-events
          (let [[sink result] (collect-sink)]
            (read-body! in headers sink)
            (let [got (count (re-seq #"(?m)^data: event \d+$" (String. ^bytes (result) StandardCharsets/UTF_8)))]
              (if (= got sse-events) "ok" (fail! "body-mismatch" (str got " events")))))
          (let [[sink checked] (pattern-sink)]
            (read-body! in headers sink)
            (if (= n (checked)) "ok" (fail! "body-mismatch" (str (checked) " bytes"))))))
      (finally (h1-close c)))))

;; ---- HTTP/2 over TLS (JDK client) ------------------------------------------------------------

(defn- h2-client ^HttpClient []
  (-> (HttpClient/newBuilder)
      (.version HttpClient$Version/HTTP_2)
      (.sslContext (support/trust-all-ssl-context))
      (.connectTimeout (Duration/ofSeconds 5))
      (.build)))

(defn- h2-uri ^URI [port path] (URI. (str "https://localhost:" port path)))

(defn- h2-get-op [port ^HttpClient client]
  (let [resp (.send client (-> (HttpRequest/newBuilder (h2-uri port "/")) (.timeout (Duration/ofSeconds 20)) (.build))
                    (HttpResponse$BodyHandlers/ofByteArray))]
    (when-not (= HttpClient$Version/HTTP_2 (.version resp)) (fail! "not-h2"))
    (check-hello! {:status (.statusCode resp) :body (.body resp)})))

(defn- h2-upload-op
  "POSTs 4 MiB over HTTP/2 to `path` (/upload, /upload-slow or
  /ignore-body) and checks the answer."
  [port ^HttpClient client path]
  (let [resp (.send client (-> (HttpRequest/newBuilder (h2-uri port path))
                               (.timeout (Duration/ofSeconds 60))
                               (.POST (HttpRequest$BodyPublishers/ofByteArray upload-4m))
                               (.build))
                    (HttpResponse$BodyHandlers/ofString))
        body (str (.body resp))]
    (cond
      (not= 200 (.statusCode resp)) (fail! (str (.statusCode resp)))
      (= path "/upload") (if (= body (str (alength ^bytes upload-4m) " " upload-4m-crc)) "ok" (fail! "body-mismatch" body))
      (= path "/upload-slow") (if (= body (str (alength ^bytes upload-4m))) "ok" (fail! "body-mismatch" body))
      :else (if (= body "ignored") "ok" (fail! "body-mismatch" body)))))

(defn- h2-bytes-op [port ^HttpClient client ^long n]
  (let [resp (.send client (-> (HttpRequest/newBuilder (h2-uri port (str "/bytes?n=" n)))
                               (.timeout (Duration/ofSeconds 60)) (.build))
                    (HttpResponse$BodyHandlers/ofInputStream))
        [sink checked] (pattern-sink)]
    (with-open [^InputStream in (.body resp)]
      (when (not= 200 (.statusCode resp)) (fail! (str (.statusCode resp))))
      (let [buf (byte-array 65536)]
        (loop []
          (let [r (.read in buf)]
            (when-not (neg? r) (sink buf 0 r) (recur))))))
    (if (= n (checked)) "ok" (fail! "body-mismatch"))))

;; ---- HTTP/2 cleartext (raw frames) ----------------------------------------------------------

(def ^:private h2-preface (ascii "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

(defn- h2-frame ^bytes [type flags sid ^bytes payload]
  (let [type (long type) flags (long flags) sid (long sid)
        len (alength payload)
        b (byte-array (+ 9 len))]
    (aset b 0 (unchecked-byte (bit-shift-right len 16)))
    (aset b 1 (unchecked-byte (bit-shift-right len 8)))
    (aset b 2 (unchecked-byte len))
    (aset b 3 (unchecked-byte type))
    (aset b 4 (unchecked-byte flags))
    (aset b 5 (unchecked-byte (bit-shift-right sid 24)))
    (aset b 6 (unchecked-byte (bit-shift-right sid 16)))
    (aset b 7 (unchecked-byte (bit-shift-right sid 8)))
    (aset b 8 (unchecked-byte sid))
    (System/arraycopy payload 0 b 9 len)
    b))

(defn- u32 ^bytes [v]
  (let [v (long v)]
    (byte-array (map unchecked-byte [(bit-shift-right v 24) (bit-shift-right v 16) (bit-shift-right v 8) v]))))

(defn- h2-settings ^bytes [pairs]
  (h2-frame 4 0 0 (byte-array (mapcat (fn [[id v]] (concat [0 (unchecked-byte id)] (u32 v))) pairs))))

(defn- h2-open
  "A raw h2c connection (prior knowledge) to `port` advertising stream
  window `window`; with `auto-window` the client returns credit for every
  DATA frame it reads."
  [^long port ^long window auto-window]
  (let [sock (connect port 20000)
        c {:sock sock
           :in (DataInputStream. (BufferedInputStream. (.getInputStream sock) 65536))
           :out (BufferedOutputStream. (.getOutputStream sock) 65536)
           :enc (Hpack$Encoder. 4096)
           :decoder (Hpack$Decoder. 4096)
           :next-sid (long-array [1])
           :auto-window auto-window}
        ^OutputStream out (:out c)]
    (.write out ^bytes h2-preface)
    (.write out (h2-settings [[2 0] [4 window]]))
    (when auto-window (.write out (h2-frame 8 0 0 (u32 (* 16 1024 1024)))))
    (.flush out)
    c))

(defn- h2-headers-block ^bytes [{:keys [^Hpack$Encoder enc]} method path extra]
  (let [l (ArrayList.)]
    (doseq [[k v] (concat [[":method" method] [":scheme" "http"] [":authority" "localhost"] [":path" path]] extra)]
      (.add l (Hpack$HeaderField. k v)))
    (.encode enc l)))

(defn- h2-next-sid! ^long [{:keys [^longs next-sid]}]
  (let [sid (aget next-sid 0)] (aset next-sid 0 (+ sid 2)) sid))

(defn- h2-send-get!
  "Sends a GET for `path`; returns its stream id."
  ^long [{:keys [^OutputStream out] :as c} path]
  (let [sid (h2-next-sid! c)]
    (write! out (h2-frame 1 0x5 sid (h2-headers-block c "GET" path nil)))
    sid))

(defn- h2-read-frame [{:keys [^DataInputStream in]}]
  (let [len (bit-or (bit-shift-left (.readUnsignedByte in) 16) (bit-shift-left (.readUnsignedByte in) 8)
                    (.readUnsignedByte in))
        type (.readUnsignedByte in)
        flags (.readUnsignedByte in)
        sid (bit-and (.readInt in) 0x7fffffff)
        payload (byte-array len)]
    (.readFully in payload)
    {:type type :flags flags :sid sid :payload payload}))

(defn- frame-u32 ^long [^bytes p ^long off]
  (bit-or (bit-shift-left (bit-and (aget p off) 0xff) 24) (bit-shift-left (bit-and (aget p (+ off 1)) 0xff) 16)
          (bit-shift-left (bit-and (aget p (+ off 2)) 0xff) 8) (bit-and (aget p (+ off 3)) 0xff)))

(defn- h2-control!
  "Handles a connection-level frame (SETTINGS, PING, GOAWAY); true when it
  was one."
  [{:keys [^OutputStream out]} {:keys [type flags ^bytes payload]}]
  (case (long type)
    4 (do (when (zero? (bit-and (long flags) 1)) (write! out (h2-frame 4 1 0 (byte-array 0)))) true)
    6 (do (when (zero? (bit-and (long flags) 1)) (write! out (h2-frame 6 1 0 payload))) true)
    7 (fail! (str "goaway-" (frame-u32 payload 4)))
    8 true
    false))

(defn- h2-await-response!
  "Reads frames until stream `sid` ends; DATA goes to `sink`. Returns the
  response status."
  [{:keys [^OutputStream out ^Hpack$Decoder decoder auto-window] :as c} ^long sid sink]
  (loop [status nil]
    (let [{:keys [type flags ^bytes payload] :as f} (h2-read-frame c)
          flags (long flags)
          end (= 1 (bit-and flags 1))
          mine (= sid (:sid f))]
      (cond
        (h2-control! c f) (recur status)
        (and (= 3 type) mine) (fail! (str "rst-stream-" (frame-u32 payload 0)))
        (= 1 type) (let [pad (if (pos? (bit-and flags 0x8)) (inc (bit-and (aget payload 0) 0xff)) 0)
                         start (+ (if (pos? pad) 1 0) (if (pos? (bit-and flags 0x20)) 5 0))
                         fields (.decode decoder payload (int start) (int (- (alength payload) start (max 0 (dec pad)))))
                         st (some (fn [^Hpack$HeaderField h] (when (= ":status" (.-name h)) (Long/parseLong (.-value h))))
                                  fields)]
                     (if (and mine end) (or st status) (recur (if mine (or st status) status))))
        (= 0 type) (let [pad (if (pos? (bit-and flags 0x8)) (inc (bit-and (aget payload 0) 0xff)) 0)
                         start (if (pos? pad) 1 0)
                         n (- (alength payload) pad)]
                     (when (and auto-window (pos? (alength payload)))
                       (.write out (h2-frame 8 0 0 (u32 (alength payload))))
                       (when-not end (.write out (h2-frame 8 0 (:sid f) (u32 (alength payload)))))
                       (.flush out))
                     (when mine (sink payload start n))
                     (if (and mine end) status (recur status)))
        :else (recur status)))))

(defn- h2c-get-op [c]
  (let [sid (h2-send-get! c "/")
        [sink result] (collect-sink)
        status (h2-await-response! c sid sink)]
    (check-hello! {:status status :body (result)})))

(defn- h2c-stream-op [c]
  (let [sid (h2-send-get! c "/stream?chunks=32&size=8192&delay=2")
        [sink checked] (pattern-sink)
        status (h2-await-response! c sid sink)]
    (cond (not= 200 status) (fail! (str status))
          (not= (* 32 8192) (checked)) (fail! "body-mismatch")
          :else "ok")))

(defn- h2-close [{:keys [^Socket sock]}] (quietly #(.close sock)))

;; ---- HTTP/3 --------------------------------------------------------------------------------------

(defn- h3-open [port]
  (let [c (h3/connect port {:idle-timeout 30000})]
    (h3/open-control! c)
    (assoc c :next-sid (long-array [0]))))

(defn- h3-next-sid! ^long [{:keys [^longs next-sid]}]
  (let [sid (aget next-sid 0)] (aset next-sid 0 (+ sid 4)) sid))

(defn- h3-drop!
  "Abandons `c` without CONNECTION_CLOSE: frees its state and its socket."
  [{:keys [conn cfg sock]}]
  (quietly #(.free ^com.s_exp.enso.quiche.QuicheConnection conn))
  (quietly #(.close ^com.s_exp.enso.quiche.QuicheConfig cfg))
  (quietly #(.close ^java.nio.channels.DatagramChannel @sock)))

(defn- h3-close [c] (quietly #(h3/close! c)))

(defn- h3-request!
  "Sends a request and services the connection until its response ends
  (at most 60 s: uploads under memory pressure take a while)."
  [c method path & [^bytes body extra]]
  (let [sid (h3-next-sid! c)
        headers (h3/headers-frame (apply h3/request-headers method path extra))
        _ (h3/send! c sid (if body (h3/concat-bytes headers (h3/data-frame body)) headers) true)
        _ (h3/pump-until! c #(h3/stream-done? c sid) 60000)
        r (h3/response c sid)]
    (cond
      (:reset r) (fail! (str "h3-reset-" (:reset r)))
      (not (:fin r)) (fail! "timeout")
      :else r)))

(defn- h3-get-op [c]
  (let [r (h3-request! c "GET" "/")]
    (check-hello! {:status (:status r) :body (:body r)})))

(defn- h3-upload-op [c]
  (let [r (h3-request! c "POST" "/upload" upload-2m [["content-length" (str (alength ^bytes upload-2m))]])
        body (String. ^bytes (:body r) StandardCharsets/ISO_8859_1)]
    (cond (not= 200 (:status r)) (fail! (str (:status r)))
          (not= body (str (alength ^bytes upload-2m) " " upload-2m-crc)) (fail! "body-mismatch" body)
          :else "ok")))

(defn- h3-bytes-op [c ^long n]
  (let [r (h3-request! c "GET" (str "/bytes?n=" n))
        [sink checked] (pattern-sink)
        ^bytes body (:body r)]
    (sink body 0 (alength body))
    (cond (not= 200 (:status r)) (fail! (str (:status r)))
          (not= n (checked)) (fail! "body-mismatch")
          :else "ok")))

;; ---- WebSocket -----------------------------------------------------------------------------------

(defn- ws-open
  "An upgraded WebSocket on `port`, offering permessage-deflate when
  `deflate`."
  [^long port deflate]
  (let [{:keys [in out] :as c} (h1-open port)
        key (.encodeToString (Base64/getEncoder) (random-bytes 16))]
    (write! out (ascii (str "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            "Sec-WebSocket-Key: " key "\r\nSec-WebSocket-Version: 13\r\n"
                            (when deflate "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n")
                            "\r\n")))
    (let [{:keys [status headers]} (read-head! in)]
      (when (not= 101 status) (h1-close c) (fail! (str "ws-upgrade-" status)))
      (when (and deflate (not (some-> (get headers "sec-websocket-extensions") (str/includes? "permessage-deflate"))))
        (h1-close c)
        (fail! "ws-deflate-not-negotiated"))
      (assoc c :deflate deflate :inflater (when deflate (Inflater. true))))))

(defn- ws-frame!
  "Writes one masked frame."
  [^OutputStream out opcode fin rsv1 ^bytes payload off len]
  (let [opcode (long opcode) off (long off) len (long len)
        mask (random-bytes 4)
        hdr (ByteArrayOutputStream.)]
    (.write hdr (int (bit-or (if fin 0x80 0) (if rsv1 0x40 0) opcode)))
    (cond
      (< len 126) (.write hdr (int (bit-or 0x80 len)))
      (< len 65536) (do (.write hdr (int (bit-or 0x80 126))) (.write hdr (int (bit-shift-right len 8))) (.write hdr (int (bit-and len 0xff))))
      :else (do (.write hdr (int (bit-or 0x80 127)))
                (dotimes [i 8] (.write hdr (int (bit-and (bit-shift-right len (* 8 (- 7 i))) 0xff))))))
    (.write hdr mask)
    (let [masked (byte-array len)]
      (dotimes [i len]
        (aset masked i (unchecked-byte (bit-xor (aget payload (+ off i)) (aget mask (bit-and i 3))))))
      (.write out (.toByteArray hdr))
      (.write out masked))))

(defn- deflate-message ^bytes [^bytes payload]
  (let [d (Deflater. Deflater/DEFAULT_COMPRESSION true)
        out (ByteArrayOutputStream.)
        buf (byte-array 65536)]
    (try
      (.setInput d payload)
      (loop []
        (let [n (.deflate d buf 0 (alength buf) Deflater/SYNC_FLUSH)]
          (.write out buf 0 n)
          (when (= n (alength buf)) (recur))))
      (let [b (.toByteArray out)]
        ;; RFC 7692 §7.2.1: drop the empty block's 00 00 ff ff tail.
        (Arrays/copyOf b (- (alength b) 4)))
      (finally (.end d)))))

(defn- inflate-message ^bytes [^Inflater inf ^bytes data]
  (let [in (byte-array (+ (alength data) 4))
        out (ByteArrayOutputStream.)
        buf (byte-array 65536)]
    (System/arraycopy data 0 in 0 (alength data))
    (aset in (+ (alength data) 2) (unchecked-byte 0xff))
    (aset in (+ (alength data) 3) (unchecked-byte 0xff))
    (.setInput inf in)
    (loop []
      (let [n (.inflate inf buf)]
        (.write out buf 0 n)
        (when (or (pos? n) (not (.needsInput inf))) (when (pos? n) (recur)))))
    (.toByteArray out)))

(defn- ws-send-message!
  "Sends `payload` as one text message, in frames of `fragment` bytes."
  [{:keys [^OutputStream out deflate]} ^bytes payload ^long fragment]
  (let [^bytes data (if deflate (deflate-message payload) payload)
        n (alength data)]
    (loop [off 0 first-frame true]
      (let [len (min fragment (- n off))
            fin (>= (+ off len) n)]
        (ws-frame! out (if first-frame 1 0) fin (and deflate first-frame) data off len)
        (when-not fin (recur (+ off len) false))))
    (.flush out)))

(defn- ws-read-frame [^InputStream in]
  (let [din (DataInputStream. in)
        b0 (.readUnsignedByte din)
        b1 (.readUnsignedByte din)
        len7 (bit-and b1 0x7f)
        len (case (long len7) 126 (.readUnsignedShort din) 127 (.readLong din) len7)
        payload (byte-array len)]
    (.readFully din payload)
    {:fin (pos? (bit-and b0 0x80)) :rsv1 (pos? (bit-and b0 0x40)) :opcode (bit-and b0 0x0f) :payload payload}))

(defn- ws-read-message!
  "Reads the next data message (answering pings); throws on CLOSE."
  ^bytes [{:keys [in out inflater]}]
  (let [acc (ByteArrayOutputStream.)]
    (loop [compressed nil]
      (let [{:keys [fin rsv1 opcode ^bytes payload]} (ws-read-frame in)]
        (cond
          (= 8 opcode) (fail! (str "ws-close-" (if (>= (alength payload) 2)
                                                 (bit-or (bit-shift-left (bit-and (aget payload 0) 0xff) 8)
                                                         (bit-and (aget payload 1) 0xff))
                                                 "none")))
          (= 9 opcode) (do (ws-frame! out 10 true false payload 0 (alength payload)) (.flush ^OutputStream out)
                           (recur compressed))
          (= 10 opcode) (recur compressed)
          :else (let [compressed (if (nil? compressed) rsv1 compressed)]
                  (.write acc payload)
                  (if fin
                    (if compressed (inflate-message inflater (.toByteArray acc)) (.toByteArray acc))
                    (recur compressed))))))))

(defn- ws-close [{:keys [^Socket sock out in] :as c}]
  (quietly #(do (ws-frame! out 8 true false (byte-array [3 (unchecked-byte 0xe8)]) 0 2)
                (.flush ^OutputStream out)
                (.setSoTimeout sock 5000)
                (loop [] (let [{:keys [opcode]} (ws-read-frame in)] (when-not (= 8 opcode) (recur))))))
  (h1-close c)
  (some-> ^Inflater (:inflater c) .end))

(defn- random-text ^bytes [n]
  (let [n (long n)
        b (byte-array n)
        r (rnd)
        ;; Half the messages are repetitive (compressible), half random.
        compressible (.nextBoolean r)]
    (dotimes [i n]
      (aset b i (unchecked-byte (if compressible (+ 97 (rem (quot i 7) 26)) (+ 32 (.nextInt r 95))))))
    b))

(defn- ws-echo-op
  "Sends a message (sometimes over 64 KiB, which the memory budget
  accounts) and checks its echo."
  [c]
  (let [r (rnd)
        n (if (< (.nextInt r 100) 3) (+ 65536 (.nextInt r 200000)) (inc (.nextInt r 2000)))
        msg (random-text n)]
    (ws-send-message! c msg (if (.nextBoolean r) 16384 (max 1 n)))
    (if (Arrays/equals msg (ws-read-message! c)) "ok" (fail! "body-mismatch"))))

;; ---- TLS --------------------------------------------------------------------------------------

(def ^:private client-tls (delay (support/trust-all-ssl-context)))

(defn- tls-socket
  "A TLS socket to `port` that negotiated `alpn`."
  ^SSLSocket [port ^String alpn]
  (let [^SSLSocket s (.createSocket (.getSocketFactory ^SSLContext @client-tls) "127.0.0.1" (int port))
        params (.getSSLParameters s)]
    (.setApplicationProtocols params (into-array String [alpn]))
    (.setSSLParameters s params)
    (.setSoTimeout s 20000)
    (.startHandshake s)
    s))

(defn- client-hello
  "The first TLS flight a client sends to `port`."
  ^bytes [port]
  (let [^SSLEngine e (.createSSLEngine ^SSLContext @client-tls "localhost" (int port))
        out (ByteBuffer/allocate 65536)]
    (.setUseClientMode e true)
    (.beginHandshake e)
    (.wrap e (ByteBuffer/allocate 0) out)
    (.flip out)
    (let [b (byte-array (.remaining out))] (.get out b) b)))

;; ---- chaos ------------------------------------------------------------------------------------

(defn- await-close!
  "Reads and drops what `sock` receives until the server closes it or
  `ms` pass; returns [outcome bytes-read], outcome \"closed\" or
  \"not-closed\". The first bytes are kept for status checks."
  [^Socket sock ^long ms]
  (let [deadline (+ (System/currentTimeMillis) ms)
        in (.getInputStream sock)
        buf (byte-array 16384)
        first-bytes (ByteArrayOutputStream.)]
    (loop []
      (let [left (- deadline (System/currentTimeMillis))]
        (if (<= left 0)
          ["not-closed" (.toByteArray first-bytes)]
          (let [r (try (.setSoTimeout sock (int (max 1 (min left 1000))))
                       (.read in buf)
                       (catch SocketTimeoutException _ 0)
                       (catch IOException _ -1))]
            (if (neg? r)
              ["closed" (.toByteArray first-bytes)]
              (do (when (< (.size first-bytes) 4096) (.write first-bytes buf 0 (int r)))
                  (recur)))))))))

(defn- status-of ^String [^bytes head]
  (second (re-find #"^HTTP/1\.1 (\d{3})" (String. head StandardCharsets/ISO_8859_1))))

(defn- chaos-close-op
  "Writes `bytes`, then expects the server to answer with a status in
  `statuses` (any status when nil) or to close within `ms`. Outcome: the
  status, \"closed\" without one, or \"not-closed\"."
  [port ^bytes bytes ms]
  (let [sock (connect port 20000)]
    (try
      (when bytes (write! (.getOutputStream sock) bytes))
      (let [[outcome head] (await-close! sock ms)]
        (if (= "not-closed" outcome) outcome (or (status-of head) "closed")))
      (finally (quietly #(.close sock))))))

(def ^:private malformed-h1
  ["GARBAGE\r\n\r\n"
   "GET / HTTP/1.1\r\nHost: localhost\r\nBad Header\r\n\r\n"
   "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
   "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n"
   "GET / HTTP/9.9\r\nHost: localhost\r\n\r\n"
   "GET / HTTP/1.1\r\nHost: localhost\r\nX: a\u0000b\r\n\r\n"
   "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
   "GET /\u0001 HTTP/1.1\r\nHost: localhost\r\n\r\n"])

(defn- slowloris-op
  "Sends a request head one byte every 300 ms; expects 408 (or a close)
  shortly after :header-timeout."
  [port ^long header-timeout]
  (let [sock (connect port 20000)
        out (.getOutputStream sock)
        head (ascii "GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n")
        deadline (+ (System/currentTimeMillis) header-timeout 3000)]
    (try
      (loop [i 0]
        (let [sent (and (< i (alength head)) (< (System/currentTimeMillis) deadline)
                        (try (.write out (int (aget head i))) (.flush out) true (catch IOException _ false)))]
          (if (and sent (< (inc i) (alength head)) (zero? (.available (.getInputStream sock))))
            (do (Thread/sleep 300) (recur (inc i)))
            (let [[outcome head] (await-close! sock (max 1000 (- deadline (System/currentTimeMillis))))]
              (if (= "not-closed" outcome) outcome (or (status-of head) "closed"))))))
      (finally (quietly #(.close sock))))))

(defn- trickle-body-op
  "POSTs a 100 KB body at 20 bytes/s, under :min-data-rate-bytes; expects
  408 (or a close) after the grace period."
  [port]
  (let [sock (connect port 20000)
        out (.getOutputStream sock)
        deadline (+ (System/currentTimeMillis) 30000)]
    (try
      (write! out (ascii "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\r\n"))
      (loop []
        (let [ok (try (write! out (ascii "0123456789")) true (catch IOException _ false))]
          (if (and ok (zero? (.available (.getInputStream sock))) (< (System/currentTimeMillis) deadline))
            (do (Thread/sleep 500) (recur))
            (let [[outcome head] (await-close! sock (max 1000 (- deadline (System/currentTimeMillis))))]
              (if (= "not-closed" outcome) outcome (or (status-of head) "closed"))))))
      (finally (quietly #(.close sock))))))

(defn- half-close-op
  "Sends a full request then shuts its sending side; expects the response,
  then the server's close."
  [port]
  (let [{:keys [^Socket sock in out] :as c} (h1-open port)]
    (try
      (write! out hello-get)
      (.shutdownOutput sock)
      (let [r (try (read-response! in) (catch EOFException _ nil))]
        (cond
          (nil? r) "closed"
          (not= "ok" (check-hello! r)) (fail! "body-mismatch")
          (= "not-closed" (first (await-close! sock 20000))) "not-closed"
          :else "ok"))
      (finally (h1-close c)))))

(defn- park-op
  "Opens a connection in the state `prepare` leaves it in, then waits for
  the server to close it within `ms`."
  [^Socket sock ^long ms]
  (try
    (let [t0 (System/nanoTime)
          [outcome] (await-close! sock ms)]
      [outcome (millis-since t0)])
    (finally (quietly #(.close sock)))))

(defn- h2-burst-op
  "Opens `n` streams on a fresh h2c connection, each reset right away
  (HEADERS + RST_STREAM CANCEL), then checks a normal request still
  works. Outcome \"ok\", or the GOAWAY the server sent."
  [port ^long n]
  (let [c (h2-open port 1048576 true)
        ^OutputStream out (:out c)]
    (try
      (dotimes [_ n]
        (let [sid (h2-next-sid! c)]
          (.write out (h2-frame 1 0x5 sid (h2-headers-block c "GET" "/sleep?ms=200" nil)))
          (.write out (h2-frame 3 0 sid (u32 8)))))
      (.flush out)
      (h2c-get-op c)
      (finally (h2-close c)))))

(defn- h2-churn-op [port]
  (let [c (h2-open port 1048576 true)]
    (try
      (dotimes [_ 300] (h2c-get-op c))
      "ok"
      (finally (h2-close c)))))

(defn- h2-malformed-op
  "A protocol violation after the preface; expects GOAWAY."
  [port]
  (let [c (h2-open port 1048576 true)
        bad (if (.nextBoolean (rnd))
              (h2-frame 4 0 0 (byte-array 7))
              (h2-frame 1 0x5 2 (h2-headers-block c "GET" "/" nil)))]
    (try
      (write! (:out c) bad)
      (loop [] (h2-control! c (h2-read-frame c)) (recur))
      (catch EOFException _ "closed")
      (finally (h2-close c)))))

(defn- slow-reader-h1-op
  "Reads 1 MiB of a 64 MiB response slowly, then stops reading for longer
  than :write-timeout; expects the server to have dropped the connection."
  [port ^long write-timeout]
  (let [{:keys [^Socket sock in out] :as c} (h1-open port)
        ^InputStream in in
        buf (byte-array 65536)
        total (* 64 1024 1024)]
    (try
      (write! out (get-request (str "/bytes?n=" total "&cl=1")))
      (read-head! in)
      (loop [n 0]
        (when (< n (* 1024 1024))
          (Thread/sleep 50)
          (recur (+ n (max 0 (.read in buf))))))
      ;; The watchdog catches a stalled write within two timeouts of the
      ;; server's last write progress, and the kernel keeps taking bytes
      ;; for a few seconds after the client stops reading.
      (Thread/sleep (+ (* 2 write-timeout) 20000))
      ;; Drain what the socket buffers hold: a server that dropped the
      ;; connection ends the stream well before the body's end; one that
      ;; didn't sends the rest of the body.
      (.setSoTimeout sock 5000)
      (let [t0 (System/nanoTime)]
        (loop [n 0]
          (let [r (try (.read in buf) (catch SocketTimeoutException _ -2) (catch IOException _ -1))]
            (if (or (= r -1) (= r -2))
              (let [outcome (cond (= r -1) "closed"
                                  (> n (* 32 1024 1024)) "not-closed-body-sent"
                                  :else "not-closed-silent")]
                (when-not (= "closed" outcome)
                  (println "slow-reader-h1" outcome "drained" n "bytes in" (millis-since t0) "ms"))
                outcome)
              (recur (+ n (long r)))))))
      (finally (h1-close c)))))

(defn- slow-reader-h2c-op
  "Requests 8 MiB on an h2c connection that never returns flow-control
  credit; waits up to 40 s for the server to reset the stream, send GOAWAY
  or close."
  [port]
  (let [c (h2-open port 65535 false)]
    (try
      (h2-send-get! c "/bytes?n=8388608")
      (.setSoTimeout ^Socket (:sock c) 40000)
      (loop []
        (let [{:keys [type flags payload] :as f} (h2-read-frame c)]
          (cond
            (= 3 type) "rst-stream"
            (= 7 type) "goaway"
            (and (= 0 type) (pos? (bit-and (long flags) 1))) "completed"
            :else (do (when (#{4 6} type) (h2-control! c f)) (recur)))))
      (catch SocketTimeoutException _ "still-open")
      (catch EOFException _ "closed")
      (catch SocketException _ "closed")
      (finally (h2-close c)))))

(defn- mid-response-disconnect-op
  "Starts reading a large response, then disconnects (FIN or RST over
  HTTP/1.1, RST_STREAM over h2c then a request on the same connection,
  or an abandoned HTTP/3 connection)."
  [ports]
  (case (int (.nextInt (rnd) 3))
    0 (let [{:keys [^Socket sock in out] :as c} (h1-open (:plain ports))]
        (write! out (get-request "/bytes?n=16777216"))
        (read-head! in)
        (read-n! in 100000 (fn [_ _ _]))
        (if (.nextBoolean (rnd)) (reset-close! sock) (h1-close c))
        "ok")
    1 (let [c (h2-open (:plain ports) 1048576 true)]
        (try
          (let [sid (h2-send-get! c "/bytes?n=16777216")]
            (loop [n 0]
              (when (< n 100000)
                (let [{:keys [type ^bytes payload] :as f} (h2-read-frame c)]
                  (h2-control! c f)
                  ;; Every header block goes through the decoder, which
                  ;; keeps the dynamic table in step with the server's.
                  (when (= 1 type) (.decode ^Hpack$Decoder (:decoder c) payload 0 (alength payload)))
                  (recur (if (= 0 type) (+ n (alength ^bytes payload)) n)))))
            (write! (:out c) (h2-frame 3 0 sid (u32 8)))
            (h2c-get-op c))
          (finally (h2-close c))))
    2 (if-let [port (:h3 ports)]
        (let [c (h3-open port)]
          (h3/send! c (h3-next-sid! c) (h3/headers-frame (h3/request-headers "GET" "/bytes?n=16777216")) true)
          (h3/pump! c 100)
          (h3-drop! c)
          "ok")
        "ok")))

;; ---- certificate reload ------------------------------------------------------------------------

(defn- pem-der ^bytes [path]
  (with-open [in (io/input-stream path)]
    (.getEncoded ^X509Certificate (.generateCertificate (CertificateFactory/getInstance "X.509") in))))

(defn- replace-pem-pair!
  "Writes a fresh self-signed pair over `cert` and `key` (each by an
  atomic rename, key first); returns the new certificate's DER."
  ^bytes [cert key]
  (let [[new-cert new-key] (support/pem-cert-pair)
        opts (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING StandardCopyOption/ATOMIC_MOVE])
        stage (fn [from to]
                (let [tmp (Paths/get (str to ".tmp") (make-array String 0))]
                  (Files/copy (Paths/get from (make-array String 0)) tmp
                              ^"[Ljava.nio.file.CopyOption;" (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))
                  (Files/move tmp (Paths/get to (make-array String 0)) ^"[Ljava.nio.file.CopyOption;" opts)))]
    (stage new-key key)
    (stage new-cert cert)
    (pem-der cert)))

(defn- cert-reload-op
  "Replaces the HTTP/3 PEM pair, then checks new connections present the
  new certificate within three reload intervals."
  [port cert key ^long interval-ms]
  (let [der (replace-pem-pair! cert key)
        deadline (+ (System/currentTimeMillis) (* 3 interval-ms) 2000)]
    (loop []
      (let [seen (let [c (h3-open port)]
                   (try (h3/peer-certificate c) (finally (h3-close c))))]
        (cond
          (Arrays/equals der ^bytes seen) "ok"
          (> (System/currentTimeMillis) deadline) (fail! "stale-certificate")
          :else (do (Thread/sleep 1000) (recur)))))))

;; ---- load -------------------------------------------------------------------------------------

(defn- run-loop
  "Runs `op` on a connection from `open` every `interval-ms` until `stop`,
  recording each outcome under `kind`; the connection is replaced after a
  failure and every `recycle` operations (closed by `close`)."
  [^AtomicBoolean stop kind ^double interval-ms {:keys [open op close recycle]}]
  (let [holder (volatile! nil)
        n (long-array 1)
        drop! (fn [] (when-let [c @holder] (vreset! holder nil) (quietly #(close c))))]
    (try
      (while (not (.get stop))
        (let [t0 (System/nanoTime)]
          (try
            (when-not @holder (vreset! holder (open)))
            (record! kind (op @holder) (- (System/nanoTime) t0))
            (aset n 0 (inc (aget n 0)))
            (when (and recycle (zero? (rem (aget n 0) (long recycle)))) (drop!))
            (catch Throwable t
              (when-not (.get stop) (record! kind (classify t) (- (System/nanoTime) t0)))
              (drop!)))
          (pace! stop t0 interval-ms)))
      (finally (drop!)))))

(defn- one-shot
  "run-loop spec of an operation that opens what it needs itself."
  [op]
  {:open (constantly :none) :op (fn [_] (op)) :close (fn [_])})

(defn- interval-ms
  "Milliseconds between operations for `per-s` operations per second."
  ^double [cfg ^double per-s]
  (/ 1000.0 (* per-s (double (:rate-scale cfg)))))

(defn- workers
  "[kind interval-ms spec] of every steady worker."
  [{:keys [ports] :as cfg}]
  (let [{:keys [plain tls h3]} ports
        iv #(interval-ms cfg %)
        h3-workers
        (when h3
          (concat
           (for [i (range 2)]
             ["h3-get" (iv 20) {:open #(h3-open h3) :op h3-get-op :recycle 200
                                ;; Every fifth connection is dropped without CONNECTION_CLOSE.
                                :close #(if (zero? (.nextInt (rnd) 5)) (h3-drop! %) (h3-close %))}])
           [["h3-upload" (iv 0.2) {:open #(h3-open h3) :op h3-upload-op :close h3-close :recycle 5}]
            ["h3-bytes" (iv 0.3) {:open #(h3-open h3) :op #(h3-bytes-op % (* 1024 1024)) :close h3-close :recycle 5}]]))]
    (concat
     (for [_ (range 4)] ["h1-get" (iv 40) {:open #(h1-open plain) :op h1-get-op :close h1-close :recycle 900}])
     (for [_ (range 2)] ["h1-pipelined" (iv 10) {:open #(h1-open plain) :op #(h1-pipelined-op 8 %) :close h1-close
                                                 :recycle 100}])
     [["h1-close" (iv 20) (one-shot #(h1-close-op plain))]
      ["h1-upload-cl" (iv 0.5) (one-shot #(h1-upload-op plain upload-1m upload-1m-crc false))]
      ["h1-upload-chunked" (iv 0.5) (one-shot #(h1-upload-op plain upload-1m upload-1m-crc true))]
      ["h1-ignore-body" (iv 0.5) (one-shot #(h1-ignore-body-op plain))]
      ["h1-stream" (iv 1) (one-shot #(h1-pattern-get-op plain "/stream?chunks=64&size=8192&delay=5" (* 64 8192) nil))]
      ["h1-sse" (iv 0.5) (one-shot #(h1-pattern-get-op plain "/sse?events=50&delay=10" 0 50))]
      ["h1-bytes" (iv 0.5) (one-shot #(h1-pattern-get-op plain "/bytes?n=4194304" 4194304 nil))]
      ["h1-bytes-cl" (iv 0.5) (one-shot #(h1-pattern-get-op plain "/bytes?n=4194304&cl=1" 4194304 nil))]
      ["h1-tls" (iv 5) (one-shot #(let [s (tls-socket tls "http/1.1")
                                        in (BufferedInputStream. (.getInputStream s))]
                                    (try (write! (.getOutputStream s) (get-request "/" "Connection: close\r\n"))
                                         (check-hello! (read-response! in))
                                         (finally (quietly (fn [] (.close s)))))))]]
     (for [_ (range 2)] ["h2-get" (iv 40) {:open h2-client :op #(h2-get-op tls %) :close #(.close ^HttpClient %)
                                           :recycle 500}])
     [["h2-upload" (iv 0.3) {:open h2-client :close #(.close ^HttpClient %) :recycle 20
                             :op #(h2-upload-op tls % (rand-nth ["/upload" "/upload-slow" "/ignore-body"]))}]
      ["h2-bytes" (iv 0.2) {:open h2-client :op #(h2-bytes-op tls % (* 8 1024 1024)) :close #(.close ^HttpClient %)
                            :recycle 20}]]
     (for [_ (range 2)] ["h2c-get" (iv 40) {:open #(h2-open plain 1048576 true) :op h2c-get-op :close h2-close
                                            :recycle 1000}])
     [["h2c-stream" (iv 0.5) {:open #(h2-open plain 1048576 true) :op h2c-stream-op :close h2-close :recycle 50}]]
     (for [deflate [false false true true]]
       [(if deflate "ws-echo-deflate" "ws-echo") (iv 20) {:open #(ws-open plain deflate) :op ws-echo-op :close ws-close}
        :recycle 500])
     [["mid-response-disconnect" (iv 1) (one-shot #(mid-response-disconnect-op ports))]
      ["slow-reader-h1" (iv (/ 1.0 30)) (one-shot #(slow-reader-h1-op plain (get-in cfg [:server-opts :write-timeout])))]
      ["slow-reader-h2c" (iv (/ 1.0 60)) (one-shot #(slow-reader-h2c-op plain))]]
     h3-workers)))

(defn- chaos-actions
  "[kind f] of every chaos action; f returns an outcome."
  [{:keys [ports server-opts]}]
  (let [{:keys [plain tls h3]} ports
        {:keys [idle-timeout header-timeout handshake-timeout]} server-opts
        idle-deadline (+ idle-timeout 10000)
        park (fn [kind open ms]
               [kind #(let [[outcome elapsed] (park-op (open) ms)]
                        ;; time to close, as the latency of a "closed"
                        (if (= "closed" outcome) (fail! "closed" (str elapsed)) outcome))])]
    (concat
     [["chaos-rst-mid-request" #(let [s (connect plain 5000)]
                                  (write! (.getOutputStream s) (ascii "GET / HTTP/1.1\r\nHost: loc"))
                                  (reset-close! s) "ok")]
      ["chaos-rst-mid-body" #(let [s (connect plain 5000)]
                               (write! (.getOutputStream s) (ascii "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\r\nabc"))
                               (Thread/sleep 50)
                               (reset-close! s) "ok")]
      ["chaos-rst-mid-response" #(let [s (connect plain 5000)]
                                   (write! (.getOutputStream s) (get-request "/stream?chunks=100&size=4096&delay=10"))
                                   (Thread/sleep 100)
                                   (reset-close! s) "ok")]
      ["chaos-half-close" #(half-close-op plain)]
      ["chaos-slowloris" #(slowloris-op plain header-timeout)]
      ["chaos-trickle-body" #(trickle-body-op plain)]
      ["chaos-malformed-h1" #(chaos-close-op plain (ascii (rand-nth malformed-h1)) 10000)]
      ["chaos-oversized-head" #(chaos-close-op plain (get-request "/" (str "X-Big: " (apply str (repeat 20000 "a")) "\r\n"))
                                               10000)]
      ["chaos-oversized-body" #(chaos-close-op plain (ascii (str "POST /upload HTTP/1.1\r\nHost: localhost\r\n"
                                                                 "Content-Length: 16777216\r\n\r\n"))
                                               10000)]
      ["chaos-oversized-chunked" #(let [s (connect plain 20000)
                                        out (.getOutputStream s)
                                        chunk (byte-array 65536)]
                                    (try
                                      (write! out (ascii "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"))
                                      (try (dotimes [_ 160]
                                             (.write out (ascii "10000\r\n")) (.write out chunk) (.write out (ascii "\r\n")))
                                           (.flush out)
                                           (catch IOException _))
                                      (let [[outcome head] (await-close! s 15000)]
                                        (if (= "not-closed" outcome) outcome (or (status-of head) "closed")))
                                      (finally (quietly (fn [] (.close s))))))]
      ["chaos-h2-rst-burst" #(h2-burst-op plain 100)]
      ["chaos-h2-rapid-reset" #(h2-burst-op plain 1000)]
      ["chaos-h2-churn" #(h2-churn-op plain)]
      ["chaos-h2-malformed" #(h2-malformed-op plain)]
      ["chaos-tls-abandon" #(let [s (connect tls 20000)
                                  hello (client-hello tls)]
                              (try
                                (write! (.getOutputStream s) (if (.nextBoolean (rnd))
                                                               (Arrays/copyOf hello (quot (alength hello) 2))
                                                               hello))
                                (first (await-close! s (+ handshake-timeout 5000)))
                                (finally (quietly (fn [] (.close s))))))]
      ["chaos-ws-vanish" #(let [c (ws-open plain (.nextBoolean (rnd)))]
                            (ws-echo-op c)
                            (when (.nextBoolean (rnd))
                              ;; the first frame of a fragmented message, never finished
                              (ws-frame! (:out c) 1 false false (ascii "partial") 0 7)
                              (.flush ^OutputStream (:out c)))
                            (reset-close! (:sock c)) "ok")]
      (park "chaos-park-h1" #(connect plain 20000) idle-deadline)
      (park "chaos-park-h1-after-request" #(let [{:keys [sock in out]} (h1-open plain)]
                                             (h1-get-op {:in in :out out}) sock)
            idle-deadline)
      (park "chaos-park-tls-h1" #(tls-socket tls "http/1.1") idle-deadline)
      (park "chaos-park-tls-h2" #(tls-socket tls "h2") (+ handshake-timeout 5000))
      (park "chaos-park-h2c" #(:sock (h2-open plain 65535 true)) idle-deadline)
      (park "chaos-park-ws" #(:sock (ws-open plain false)) idle-deadline)]
     (when h3
       [["chaos-h3-drop" #(let [c (h3-open h3)]
                            (h3-get-op c)
                            (h3/send! c (h3-next-sid! c) (h3/headers-frame (h3/request-headers "GET" "/stream?chunks=50&size=4096&delay=10")) true)
                            (h3-drop! c) "ok")]
        ["chaos-h3-abandon-handshake" #(do (h3-drop! (h3/start-handshake h3)) "ok")]
        ["chaos-h3-reset-burst" #(let [c (h3-open h3)]
                                   (try
                                     (dotimes [_ 50]
                                       (let [sid (h3-next-sid! c)]
                                         (h3/send! c sid (h3/headers-frame (h3/request-headers "POST" "/upload")) false)
                                         (h3/reset-stream! c sid 0x10c)))
                                     (h3-get-op c)
                                     (finally (h3-close c))))]]))))

(defn- chaos-loop
  "Every ~`every-ms` starts a random chaos action on its own virtual
  thread (at most `max-concurrent` at once)."
  [^AtomicBoolean stop actions ^long every-ms ^long max-concurrent]
  (let [permits (Semaphore. max-concurrent)
        actions (vec actions)]
    (while (not (.get stop))
      (let [t0 (System/nanoTime)]
        (when (.tryAcquire permits)
          (let [[kind f] (rand-nth actions)]
            (Thread/startVirtualThread
             (fn []
               (let [t (System/nanoTime)]
                 (try
                   (record! kind (f) (- (System/nanoTime) t))
                   (catch Throwable e
                     (let [o (classify e)]
                       (when-not (and (.get stop) (not= o "closed"))
                         (record! kind o (if (and (= o "closed") (ex-message e) (re-matches #"\d+" (ex-message e)))
                                           (* 1000000 (Long/parseLong (ex-message e)))
                                           (- (System/nanoTime) t))))))
                   (finally (.release permits))))))))
        (pace! stop t0 every-ms)))))

(defn- budget-burst-loop
  "Every minute, uploads that outrun the handlers reading them (HTTP/2
  and HTTP/3 to /upload-slow) so the memory budget fills up and its
  backpressure paths run."
  [^AtomicBoolean stop {:keys [ports]}]
  (while (not (.get stop))
    (let [t0 (System/nanoTime)
          jobs (concat
                (for [_ (range 6)]
                  (future (let [t (System/nanoTime)]
                            (try (with-open [c (h2-client)]
                                   (record! "budget-h2-upload" (h2-upload-op (:tls ports) c "/upload-slow") (- (System/nanoTime) t)))
                                 (catch Throwable e (record! "budget-h2-upload" (classify e) 0))))))
                (when-let [p (:h3 ports)]
                  (for [_ (range 2)]
                    (future (let [t (System/nanoTime)]
                              (try (let [c (h3-open p)]
                                     (try
                                       (let [r (h3-request! c "POST" "/upload-slow" upload-2m
                                                            [["content-length" (str (alength ^bytes upload-2m))]])]
                                         (record! "budget-h3-upload"
                                                  (if (= (str (alength ^bytes upload-2m)) (String. ^bytes (:body r) StandardCharsets/ISO_8859_1))
                                                    "ok" (str (:status r)))
                                                  (- (System/nanoTime) t)))
                                       (finally (h3-close c))))
                                   (catch Throwable e (record! "budget-h3-upload" (classify e) 0)))))))
                (for [_ (range 4)]
                  (future (try (let [c (ws-open (:plain ports) false)]
                                 (try
                                   (dotimes [_ 5]
                                     (let [t (System/nanoTime)
                                           msg (random-text (+ 100000 (.nextInt (rnd) 400000)))]
                                       (ws-send-message! c msg 32768)
                                       (record! "budget-ws-large" (if (Arrays/equals msg (ws-read-message! c)) "ok" "body-mismatch")
                                                (- (System/nanoTime) t))))
                                   (finally (ws-close c))))
                               (catch Throwable e (record! "budget-ws-large" (classify e) 0))))))]
      (doseq [j jobs] (deref j 180000 nil))
      (pace! stop t0 60000.0))))

(defn- parked-pool-loop
  "Keeps `n` silent HTTP/1.1 and WebSocket connections open, each until
  the server's idle timeout closes it; records whether it did."
  [^AtomicBoolean stop {:keys [ports server-opts]} ^long n]
  (let [live (AtomicLong.)
        deadline (+ (long (:idle-timeout server-opts)) 10000)]
    (while (not (.get stop))
      (when (< (.get live) n)
        (.incrementAndGet live)
        (Thread/startVirtualThread
         (fn []
           (try
             (let [t (System/nanoTime)
                   sock (if (.nextBoolean (rnd)) (connect (:plain ports) 20000) (:sock (ws-open (:plain ports) true)))
                   [outcome] (park-op sock deadline)]
               (when-not (.get stop) (record! "parked-idle" outcome (- (System/nanoTime) t))))
             (catch Throwable e (when-not (.get stop) (record! "parked-idle" (classify e) 0)))
             (finally (.decrementAndGet live))))))
      (sleep-unless-stopped! stop 100))))

(defn- cert-reload-loop [^AtomicBoolean stop {:keys [ports cert key server-opts cert-reload-s]}]
  (sleep-unless-stopped! stop 60000)
  (while (not (.get stop))
    (let [t0 (System/nanoTime)]
      (try (record! "cert-reload" (cert-reload-op (:h3 ports) cert key (:http3-cert-reload-interval server-opts))
                    (- (System/nanoTime) t0))
           (catch Throwable e (record! "cert-reload" (classify e) 0)))
      (pace! stop t0 (* 1000.0 (long cert-reload-s))))))

(defn- start-load!
  "Starts every worker; returns {:stop :threads}."
  [cfg]
  (let [stop (AtomicBoolean.)
        start (fn [name f] (.start (.name (Thread/ofVirtual) ^String name) ^Runnable f))
        threads (doall
                 (concat
                  (for [[kind iv spec] (workers cfg)]
                    (start kind #(run-loop stop kind iv spec)))
                  (when (:chaos cfg)
                    (cond-> [(start "chaos" #(chaos-loop stop (chaos-actions cfg) 400 48))
                             (start "budget" #(budget-burst-loop stop cfg))
                             (start "parked" #(parked-pool-loop stop cfg 24))]
                      (get-in cfg [:ports :h3]) (conj (start "cert-reload" #(cert-reload-loop stop cfg)))))))]
    {:stop stop :threads threads}))

(defn- stop-load!
  "Stops the workers; returns the names of those still running after 90 s."
  [{:keys [^AtomicBoolean stop threads]}]
  (.set stop true)
  (let [deadline (+ (System/currentTimeMillis) 90000)]
    (doseq [^Thread t threads]
      (.join t (Duration/ofMillis (max 1 (- deadline (System/currentTimeMillis))))))
    (vec (for [^Thread t threads :when (.isAlive t)] (.getName t)))))

;; ---- server process ----------------------------------------------------------------------------

(defn- sh-out
  "stdout of `cmd`, or nil when it fails."
  [& cmd]
  (try
    (let [p (.start (doto (ProcessBuilder. ^List (vec cmd)) (.redirectErrorStream true)))
          out (future (slurp (.getInputStream p)))]
      (if (.waitFor p 120 TimeUnit/SECONDS)
        (when (zero? (.exitValue p)) @out)
        (do (.destroyForcibly p) nil)))
    (catch IOException _ nil)))

(defn- free-tcp-port ^long []
  (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(defn- snapshot!
  "Copies the compiled classes, native shim and Clojure sources into
  `dir`, so edits to the working tree don't reach the running server;
  returns the server's classpath."
  [^File dir]
  (let [cp (str/trim (or (sh-out "clojure" "-Spath" "-A:soak") (throw (ex-info "clojure -Spath failed" {}))))
        copies {"target/classes" "classes" "target/native" "native" "src/clj" "src-clj" "test" "test"}]
    (.mkdirs dir)
    (doseq [[from to] copies :when (.exists (io/file from))]
      (sh-out "cp" "-R" from (.getPath (io/file dir to))))
    (str/join File/pathSeparator
              (for [entry (str/split cp (re-pattern File/pathSeparator))]
                (if-let [to (get copies entry)] (.getPath (io/file dir to)) entry)))))

(defn- start-server!
  [{:keys [server-jvm-opts ports cert key server-opts h3]} ^File out ^String classpath]
  (let [java (str (System/getProperty "java.home") "/bin/java")
        log (io/file out "server.log")
        cmd (concat [java "-cp" classpath (str "-Xlog:gc*:file=" (.getPath (io/file out "gc.log")) ":time,uptime")]
                    server-jvm-opts
                    ["clojure.main" "-m" "s-exp.enso-soak-server"
                     (pr-str (cond-> {:plain (:plain ports) :tls (:tls ports) :stats (:stats ports)
                                      :server-opts server-opts}
                               h3 (assoc :h3 (:h3 ports) :cert cert :key key)))])
        proc (.start (doto (ProcessBuilder. ^List (vec cmd))
                       (.redirectErrorStream true)
                       (.redirectOutput log)))
        deadline (+ (System/currentTimeMillis) 180000)]
    (loop []
      (cond
        (and (.exists log) (str/includes? (slurp log) "READY")) {:process proc :pid (.pid proc) :log log}
        (or (not (.isAlive proc)) (> (System/currentTimeMillis) deadline))
        (throw (ex-info (str "soak server failed to start:\n" (slurp log)) {}))
        :else (do (Thread/sleep 200) (recur))))))

(defn- stats-get
  "EDN body of `path` on the stats listener."
  [ports path ^long timeout-ms]
  (let [{:keys [in out] :as c} (h1-open (:stats ports))]
    (try
      (.setSoTimeout ^Socket (:sock c) (int timeout-ms))
      (write! out (get-request path "Connection: close\r\n"))
      (let [{:keys [status ^bytes body]} (read-response! in)]
        (when (not= 200 status) (throw (ex-info (str "stats status " status) {})))
        (edn/read-string (String. body StandardCharsets/UTF_8)))
      (finally (h1-close c)))))

(defn- jcmd! [pid ^File out-file & args]
  (let [out (apply sh-out (str (System/getProperty "java.home") "/bin/jcmd") (str pid) args)]
    (when out (spit out-file out))
    out))

(defn- ps-sample
  "RSS (KiB) and CPU % of process `pid`, from ps."
  [pid]
  (when-let [out (sh-out "ps" "-o" "rss=,%cpu=" "-p" (str pid))]
    (let [[rss cpu] (str/split (str/trim out) #"\s+")]
      {:rss-kb (Long/parseLong rss) :cpu-pct (Double/parseDouble (str/replace cpu "," "."))})))

(defn- nmt-committed-kb
  "[total committed, Java heap committed] KiB from NMT."
  [pid]
  (when-let [out (sh-out (str (System/getProperty "java.home") "/bin/jcmd") (str pid) "VM.native_memory" "summary")]
    (let [kb (fn [re] (some-> (re-find re out) last Long/parseLong))]
      [(kb #"Total: reserved=\d+KB, committed=(\d+)KB") (kb #"Java Heap \(reserved=\d+KB, committed=(\d+)KB")])))

;; ---- sampling -----------------------------------------------------------------------------------

(defn- new-log-lines
  "Lines of `log` past `offset` (an atom), WARNING/SEVERE/exception ones."
  [^File log offset]
  (let [len (.length log)]
    (when (> len (long @offset))
      (with-open [raf (java.io.RandomAccessFile. log "r")]
        (.seek raf (long @offset))
        (let [b (byte-array (- len (long @offset)))]
          (.readFully raf b)
          (reset! offset len)
          (filterv #(re-find #"WARNING|SEVERE|Exception|Error" %)
                   (str/split-lines (String. b StandardCharsets/UTF_8))))))))

(defn- counts-delta [now before]
  (into (sorted-map)
        (keep (fn [[k m]]
                (let [d (into (sorted-map)
                              (keep (fn [[o n]] (let [x (- (long n) (long (get-in before [k o] 0)))] (when (pos? x) [o x]))))
                              m)]
                  (when (seq d) [k d]))))
        now))

(defn- take-sample!
  "One time-series point."
  [{:keys [ports]} {:keys [pid log]} state phase]
  (let [stats (try (stats-get ports "/__stats?gc=1" 30000) (catch Throwable e {:error (classify e)}))
        counts (outcome-counts)
        delta (counts-delta counts (:counts @state))
        lines (new-log-lines log (:log-offset @state))
        nmt (nmt-committed-kb pid)
        ^OperatingSystemMXBean os (ManagementFactory/getOperatingSystemMXBean)
        cpu-ns (.getProcessCpuTime os)
        now (System/nanoTime)
        sample (merge
                {:t-s (quot (- now (long (:t0 @state))) 1000000000)
                 :wall (str (Instant/now))
                 :phase phase
                 :server stats
                 :nmt-committed-kb (first nmt)
                 :nmt-heap-committed-kb (second nmt)
                 :ops delta
                 :unexpected (reduce + 0 (for [[k m] delta [o n] m :when (unexpected? k o)] n))
                 :latency (interval-latencies)
                 :log-warnings (count lines)
                 :log-sample (vec (take 5 (distinct lines)))
                 :driver-cpu-pct (/ (* 100.0 (- cpu-ns (long (:cpu-ns @state))))
                                    (double (max 1 (- now (long (:sampled-at @state))))))}
                (ps-sample pid))]
    (swap! state assoc :counts counts :cpu-ns cpu-ns :sampled-at now)
    sample))

;; ---- analysis ------------------------------------------------------------------------------------

(defn- metric-fns
  "Name -> value fn of a sample, for every metric with a trend verdict."
  []
  {:heap-after-gc-mb #(some-> (get-in % [:server :heap-used]) (/ 1048576.0))
   :rss-mb #(some-> (:rss-kb %) (/ 1024.0))
   :nmt-non-heap-mb #(when-let [t (:nmt-committed-kb %)] (/ (- t (or (:nmt-heap-committed-kb %) 0)) 1024.0))
   :fds #(get-in % [:server :fds])
   :threads #(get-in % [:server :threads])
   :virtual-threads #(get-in % [:server :virtual-threads :live])
   :direct-buffers-mb #(some-> (get-in % [:server :buffer-pools "direct" :used]) (/ 1048576.0))
   :connections #(some->> (get-in % [:server :servers]) vals (map :connections) (reduce +))
   :budget-used-kb #(some->> (get-in % [:server :servers]) vals (keep (comp :used :budget)) (reduce +) (* (/ 1.0 1024)))})

(defn- linear-fit
  "Least-squares slope (per hour) and r² of `points` ([t-s v])."
  [points]
  (let [n (count points)]
    (when (>= n 3)
      (let [xs (map #(/ (double (first %)) 3600.0) points)
            ys (map #(double (second %)) points)
            mx (/ (reduce + xs) n)
            my (/ (reduce + ys) n)
            sxy (reduce + (map #(* (- %1 mx) (- %2 my)) xs ys))
            sxx (reduce + (map #(let [d (- % mx)] (* d d)) xs))
            syy (reduce + (map #(let [d (- % my)] (* d d)) ys))]
        (when (pos? sxx)
          {:slope-per-h (/ sxy sxx)
           :r2 (if (pos? syy) (/ (* sxy sxy) (* sxx syy)) 0.0)
           :mean my})))))

(def ^:private leak-floor
  "Growth over the main phase below which a trend is noise, per metric."
  {:heap-after-gc-mb 16.0 :rss-mb 64.0 :nmt-non-heap-mb 32.0 :fds 32.0 :threads 8.0 :direct-buffers-mb 16.0})

(defn- trend-verdicts [samples]
  (let [main (filter #(= :main (:phase %)) samples)
        ;; The first tenth of the main phase is still warming up.
        skip (quot (count main) 10)
        main (drop skip main)
        hours (if (seq main) (/ (- (double (:t-s (last main))) (:t-s (first main))) 3600.0) 0.0)]
    (into (sorted-map)
          (keep (fn [[k f]]
                  (when-let [floor (leak-floor k)]
                    (let [pts (keep #(when-let [v (f %)] [(:t-s %) v]) main)
                          fit (linear-fit pts)]
                      (when fit
                        (let [growth (* (:slope-per-h fit) hours)
                              limit (max floor (* 0.1 (:mean fit)))]
                          [k (assoc fit
                                    :growth-over-run growth
                                    :min (reduce min (map second pts))
                                    :max (reduce max (map second pts))
                                    :verdict (if (and (> growth limit) (> (:r2 fit) 0.5)) :suspect-leak :no-leak))]))))))
          (metric-fns))))

(defn- totals-by-phase [samples]
  (reduce (fn [acc {:keys [phase ops]}]
            (reduce (fn [acc [k m]] (reduce (fn [acc [o n]] (update-in acc [phase k o] (fnil + 0) n)) acc m)) acc ops))
          (sorted-map) samples))

(defn- latency-drift
  "p99 of each steady kind over the first and last sixth of the main phase."
  [samples]
  (let [main (filterv #(= :main (:phase %)) samples)
        k (max 1 (quot (count main) 6))
        window (fn [ss kind] (let [vs (keep #(get-in % [:latency kind :p99]) ss)]
                               (when (seq vs) (nth (sort vs) (quot (count vs) 2)))))]
    (into (sorted-map)
          (for [kind ["h1-get" "h1-pipelined" "h2-get" "h2c-get" "h3-get" "ws-echo" "ws-echo-deflate"]
                :let [a (window (take k main) kind) b (window (take-last k main) kind)]
                :when (and a b)]
            [kind {:first-p99-ms a :last-p99-ms b
                   :verdict (if (and (> b (* 2 a)) (> (- b a) 5.0)) :drift :stable)}]))))

(defn- quiet-check
  "The final quiet sample against the baseline sample."
  [baseline final]
  (let [f (metric-fns)
        v (fn [s k] ((f k) s))]
    {:baseline (into {} (map (fn [k] [k (v baseline k)])) (keys f))
     :final (into {} (map (fn [k] [k (v final k)])) (keys f))
     :budget-zero (zero? (long (or (v final :budget-used-kb) -1)))
     :connections-zero (zero? (long (or (v final :connections) -1)))
     :fds-back (<= (long (v final :fds)) (+ (long (v baseline :fds)) 16))
     :threads-back (<= (long (v final :threads)) (+ (long (v baseline :threads)) 8))
     :heap-back (<= (double (v final :heap-after-gc-mb))
                    (+ (double (v baseline :heap-after-gc-mb)) (max 32.0 (* 0.5 (double (v baseline :heap-after-gc-mb))))))
     :thread-growth (into (sorted-map)
                          (keep (fn [[k n]] (let [d (- (long n) (long (get-in baseline [:server :thread-groups k] 0)))]
                                              (when-not (zero? d) [k d]))))
                          (merge (zipmap (keys (get-in baseline [:server :thread-groups])) (repeat 0))
                                 (get-in final [:server :thread-groups])))}))

(defn- fmt [x]
  (cond (float? x) (format "%.2f" (double x)) (nil? x) "" :else (str x)))

(defn- summary-md [{:keys [meta config trends quiet drift totals unexpected shutdown leftover-workers]}]
  (str "# enso soak run " (:started meta) "\n\n"
       "git " (:git meta) (when (:dirty meta) " (uncommitted changes)") ", " (:java meta) ", " (:os meta) ", "
       (:cpus meta) " CPUs, uptime at start: " (:uptime meta) "\n"
       "main phase " (:duration-m config) " min, warm-up " (:warmup-m config) " min, rate scale " (:rate-scale config)
       ", chaos " (:chaos config) ", HTTP/3 " (boolean (get-in config [:ports :h3])) "\n\n"
       "## Trends over the main phase\n\n"
       "| metric | min | max | slope/h | r² | growth over run | verdict |\n|---|---:|---:|---:|---:|---:|---|\n"
       (str/join (for [[k t] trends]
                   (str "| " (name k) " | " (fmt (:min t)) " | " (fmt (:max t)) " | " (fmt (:slope-per-h t)) " | "
                        (fmt (:r2 t)) " | " (fmt (:growth-over-run t)) " | " (name (:verdict t)) " |\n")))
       "\n## Quiet period: final against baseline\n\n"
       "| metric | baseline | final |\n|---|---:|---:|\n"
       (str/join (for [k (keys (:baseline quiet))]
                   (str "| " (name k) " | " (fmt (get-in quiet [:baseline k])) " | " (fmt (get-in quiet [:final k])) " |\n")))
       "\nbudget back to 0: " (:budget-zero quiet) ", connections 0: " (:connections-zero quiet)
       ", fds back: " (:fds-back quiet) ", threads back: " (:threads-back quiet) ", heap back: " (:heap-back quiet)
       "\nthread groups changed: " (pr-str (:thread-growth quiet)) "\n"
       "\n## Latency drift (median of interval p99s, first and last sixth of the main phase)\n\n"
       "| kind | first p99 ms | last p99 ms | verdict |\n|---|---:|---:|---|\n"
       (str/join (for [[k d] drift]
                   (str "| " k " | " (fmt (:first-p99-ms d)) " | " (fmt (:last-p99-ms d)) " | " (name (:verdict d)) " |\n")))
       "\n## Graceful stop under load\n\n" (pr-str shutdown) "\n"
       "\nworkers still running after stop: " (pr-str leftover-workers) "\n"
       "\n## Unexpected outcomes (all phases but shutdown)\n\n"
       (if (seq unexpected)
         (str "| kind | outcome | count |\n|---|---|---:|\n"
              (str/join (for [[[k o] n] unexpected] (str "| " k " | " o " | " n " |\n"))))
         "none\n")
       "\n## Outcomes per phase\n\n"
       (str/join (for [[phase m] totals]
                   (str "### " (name phase) "\n\n| kind | outcomes |\n|---|---|\n"
                        (str/join (for [[k os] m] (str "| " k " | " (str/join ", " (map (fn [[o n]] (str o " " n)) os)) " |\n")))
                        "\n")))))

(def ^:private csv-columns
  [["t_s" :t-s] ["phase" #(name (:phase %))]
   ["heap_after_gc_mb" #(some-> (get-in % [:server :heap-used]) (/ 1048576.0))]
   ["rss_mb" #(some-> (:rss-kb %) (/ 1024.0))]
   ["nmt_non_heap_mb" #(when-let [t (:nmt-committed-kb %)] (/ (- t (or (:nmt-heap-committed-kb %) 0)) 1024.0))]
   ["fds" #(get-in % [:server :fds])]
   ["threads" #(get-in % [:server :threads])]
   ["virtual_threads" #(get-in % [:server :virtual-threads :live])]
   ["direct_mb" #(some-> (get-in % [:server :buffer-pools "direct" :used]) (/ 1048576.0))]
   ["conns_plain" #(get-in % [:server :servers :plain :connections])]
   ["conns_tls" #(get-in % [:server :servers :tls :connections])]
   ["budget_plain_kb" #(some-> (get-in % [:server :servers :plain :budget :used]) (/ 1024.0))]
   ["budget_tls_kb" #(some-> (get-in % [:server :servers :tls :budget :used]) (/ 1024.0))]
   ["server_cpu_pct" :cpu-pct] ["driver_cpu_pct" :driver-cpu-pct]
   ["gc_count" #(get-in % [:server :gc-count])] ["gc_ms" #(get-in % [:server :gc-ms])]
   ["ops" #(reduce + 0 (for [[_ m] (:ops %) [_ n] m] n))]
   ["unexpected" :unexpected] ["log_warnings" :log-warnings]
   ["h1_get_p99_ms" #(get-in % [:latency "h1-get" :p99])]
   ["h2_get_p99_ms" #(get-in % [:latency "h2-get" :p99])]
   ["h2c_get_p99_ms" #(get-in % [:latency "h2c-get" :p99])]
   ["h3_get_p99_ms" #(get-in % [:latency "h3-get" :p99])]
   ["ws_echo_p99_ms" #(get-in % [:latency "ws-echo" :p99])]])

(defn- write-csv! [^File f samples]
  (spit f (str (str/join "," (map first csv-columns)) "\n"
               (str/join (for [s samples]
                           (str (str/join "," (map (fn [[_ g]] (fmt (g s))) csv-columns)) "\n"))))))

;; ---- run ---------------------------------------------------------------------------------------

(defn- incident-recorder
  "Takes a server thread dump the first times a kind has an unexpected
  outcome (at most one per kind and outcome, 30 in all)."
  [pid ^File out]
  (let [seen (ConcurrentHashMap.)
        n (AtomicLong.)]
    (fn [kind outcome]
      (when (and (nil? (.putIfAbsent seen [kind outcome] true)) (< (.incrementAndGet n) 30))
        (let [f (io/file out "incidents" (str (System/currentTimeMillis) "-" kind "-" (str/replace outcome #"[^\w-]" "_") ".txt"))]
          (.mkdirs (.getParentFile f))
          (future (jcmd! pid f "Thread.print")))))))

(defn summarize!
  "Analyses the run recorded in `out` (timeseries.edn and run.edn), writes
  timeseries.csv, summary.edn and summary.md; returns the summary."
  [out]
  (let [out (io/file out)
        all (mapv edn/read-string (str/split-lines (slurp (io/file out "timeseries.edn"))))
        {:keys [meta config shutdown leftover-workers]} (edn/read-string (slurp (io/file out "run.edn")))
        mark (fn [m] (first (filter #(= m (:mark %)) all)))
        judged (remove #(= :shutdown (:phase %)) all)
        summary {:meta meta
                 :config config
                 :trends (trend-verdicts all)
                 :quiet (quiet-check (mark :baseline) (mark :final))
                 :drift (latency-drift all)
                 :totals (totals-by-phase all)
                 :unexpected (into (sorted-map)
                                   (for [[_ m] (totals-by-phase judged) [k os] m [o n] os :when (unexpected? k o)]
                                     [[k o] n]))
                 :shutdown shutdown
                 :leftover-workers leftover-workers}]
    (write-csv! (io/file out "timeseries.csv") all)
    (spit (io/file out "summary.edn") (pr-str summary))
    (spit (io/file out "summary.md") (summary-md summary))
    (println (summary-md summary))
    (println "results in" (.getPath out))
    summary))

(defn run
  "Runs the soak with `opts` merged over the defaults; returns the summary."
  [opts]
  (let [cfg0 (merge-with (fn [a b] (if (map? a) (merge a b) b)) defaults opts)
        started (Instant/now)
        out (io/file (:out-dir cfg0) (str/replace (str started) #"[:.]" "-"))
        _ (.mkdirs out)
        h3? (and (:h3 cfg0) (support/shim-available?))
        [cert key] (when h3? (support/pem-cert-pair))
        cfg (assoc cfg0
                   :ports (cond-> {:plain (free-tcp-port) :tls (free-tcp-port) :stats (free-tcp-port)}
                            h3? (assoc :h3 (support/free-udp-port)))
                   :cert cert :key key :h3 h3?)
        classpath (snapshot! (io/file out "snapshot"))
        server (start-server! cfg out classpath)
        pid (:pid server)
        ^Process proc (:process server)
        hook (Thread. ^Runnable (fn [] (when (.isAlive proc) (.destroyForcibly proc))))
        samples (atom [])
        series (io/file out "timeseries.edn")
        state (atom {:t0 (System/nanoTime) :counts {} :log-offset (atom 0)
                     :cpu-ns (.getProcessCpuTime ^OperatingSystemMXBean (ManagementFactory/getOperatingSystemMXBean))
                     :sampled-at (System/nanoTime)})
        phase (atom :warmup)
        sample! (fn [& [mark]]
                  (let [s (cond-> (take-sample! cfg server state @phase) mark (assoc :mark mark))]
                    (swap! samples conj s)
                    (spit series (str (pr-str s) "\n") :append true)
                    (println (format "[%5ds %-8s] heap %s MB rss %s MB fds %s threads %s vthreads %s conns %s budget %s KB ops %d unexpected %d warnings %d"
                                     (:t-s s) (name (:phase s))
                                     (fmt (some-> (get-in s [:server :heap-used]) (/ 1048576.0)))
                                     (fmt (some-> (:rss-kb s) (/ 1024.0)))
                                     (get-in s [:server :fds]) (get-in s [:server :threads])
                                     (get-in s [:server :virtual-threads :live])
                                     (fmt ((:connections (metric-fns)) s)) (fmt ((:budget-used-kb (metric-fns)) s))
                                     (reduce + 0 (for [[_ m] (:ops s) [_ n] m] n)) (:unexpected s) (:log-warnings s)))
                    (when (seq (:log-sample s)) (println "  log:" (first (:log-sample s))))
                    (flush)
                    s))
        sampler-stop (AtomicBoolean.)
        sampler (Thread/startVirtualThread
                 (fn [] (while (not (.get sampler-stop))
                          (sleep-unless-stopped! sampler-stop (* 1000 (long (:sample-s cfg))))
                          (when-not (.get sampler-stop) (quietly sample!)))))
        meta {:started (str started)
              :git (some-> (sh-out "git" "rev-parse" "--short" "HEAD") str/trim)
              :dirty (boolean (seq (sh-out "git" "status" "--porcelain" "--untracked-files=no")))
              :java (System/getProperty "java.vm.version")
              :os (str (System/getProperty "os.name") " " (System/getProperty "os.arch"))
              :cpus (.availableProcessors (Runtime/getRuntime))
              :uptime (some-> (sh-out "uptime") str/trim)
              :server-pid pid}]
    (.addShutdownHook (Runtime/getRuntime) hook)
    (reset! incident-hook (incident-recorder pid out))
    (spit (io/file out "config.edn") (pr-str {:meta meta :config cfg}))
    (println "soak output in" (.getPath out) "server pid" pid "ports" (:ports cfg))
    (try
      (sample! :start)
      (let [load (start-load! cfg)]
        (Thread/sleep (long (* 60000 (double (:warmup-m cfg)))))
        (stop-load! load))
      (reset! phase :settle)
      (Thread/sleep (* 1000 (long (:quiet-s cfg))))
      (let [baseline (sample! :baseline)
            _ (jcmd! pid (io/file out "threads-baseline.txt") "Thread.print")
            _ (jcmd! pid (io/file out "histogram-baseline.txt") "GC.class_histogram")
            _ (jcmd! pid (io/file out "nmt-baseline.txt") "VM.native_memory" "summary")
            _ (jcmd! pid (io/file out "nmt-set-baseline.txt") "VM.native_memory" "baseline")
            _ (reset! phase :main)
            load (start-load! cfg)
            _ (Thread/sleep (long (* 60000 (double (:duration-m cfg)))))
            leftover (stop-load! load)
            _ (reset! phase :quiet)
            _ (Thread/sleep (* 1000 (long (:quiet-s cfg))))
            final (sample! :final)
            _ (jcmd! pid (io/file out "threads-final.txt") "Thread.print")
            _ (jcmd! pid (io/file out "histogram-final.txt") "GC.class_histogram")
            _ (jcmd! pid (io/file out "nmt-final.txt") "VM.native_memory" "summary.diff")
            _ (reset! phase :shutdown)
            load (start-load! cfg)
            _ (Thread/sleep (* 1000 (long (:shutdown-load-s cfg))))
            _ (jcmd! pid (io/file out "threads-before-stop.txt") "Thread.print")
            _ (reset! incident-hook nil)
            ;; Requests in flight when the stop begins: 3 s handlers (which
            ;; the drain lets finish) and 15 s streams (longer than
            ;; :shutdown-timeout, so cut).
            plain (get-in cfg [:ports :plain])
            in-flight (doall (for [i (range 8)]
                               (future (try (if (even? i)
                                              (let [{:keys [in out] :as c} (h1-open plain)]
                                                (try (write! out (get-request "/sleep?ms=3000"))
                                                     (str "sleep " (check-hello! (read-response! in)))
                                                     (finally (h1-close c))))
                                              (str "stream " (h1-pattern-get-op plain "/stream?chunks=300&size=1024&delay=50"
                                                                                (* 300 1024) nil)))
                                            (catch Throwable e (str (if (even? i) "sleep " "stream ") (classify e)))))))
            _ (Thread/sleep 500)
            stop-result (try (stats-get (:ports cfg) "/__stop" 120000) (catch Throwable e {:error (classify e)}))
            in-flight-results (mapv #(deref % 30000 "no result") in-flight)
            shutdown-leftover (stop-load! load)
            exit-t0 (System/nanoTime)
            _ (.destroy proc)
            exited (.waitFor proc 30 TimeUnit/SECONDS)
            shutdown {:stop (:stop stop-result)
                      :stop-total-ms (:total-ms stop-result)
                      :error (:error stop-result)
                      :after-stop {:connections (some->> (get-in stop-result [:after :servers]) vals (map :connections))
                                   :budget (some->> (get-in stop-result [:after :servers]) vals (map (comp :used :budget)))
                                   :threads (get-in stop-result [:after :thread-groups])}
                      :in-flight in-flight-results
                      :process-exited exited
                      :exit-ms (millis-since exit-t0)
                      :workers-left shutdown-leftover}
            _ (.set sampler-stop true)]
        (spit (io/file out "run.edn") (pr-str {:meta meta :config (dissoc cfg :cert :key) :shutdown shutdown
                                               :leftover-workers leftover}))
        (summarize! out))
      (finally
        (.set sampler-stop true)
        (when (.isAlive proc) (.destroyForcibly proc) (.waitFor proc 30 TimeUnit/SECONDS))
        (quietly #(.removeShutdownHook (Runtime/getRuntime) hook))))))

(defn -main
  "`OPTS-EDN` runs the soak; `{:analyze DIR}` only analyses a recorded run."
  [& args]
  (let [opts (if (seq args) (edn/read-string (first args)) {})]
    (if-let [dir (:analyze opts)] (summarize! dir) (run opts)))
  (shutdown-agents)
  (System/exit 0))

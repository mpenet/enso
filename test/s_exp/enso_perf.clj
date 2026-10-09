;; ABOUTME: Throughput / latency / allocation regression harness. Boots s-exp.enso-test-server in a
;; ABOUTME: separate JVM, drives it from this JVM (h2 via h2load) and writes EDN/JSON results + a report.
(ns s-exp.enso-perf
  "Run with `clojure -M:perf [OPTS-EDN]`, e.g.
  `clojure -M:perf '{:duration-s 10 :scenarios [:h1-get :h1-pipelined]}'`.

  Options (all optional):
  - `:scenarios` subset of [:h1-get :h1-get-rate :h1-pipelined :h2-get :h3-get :ws-echo],
    plus the upload scenarios, run only when named: :h2-upload (one
    stream) and :h2-upload-4 (four concurrent streams on one connection),
    :h3-upload and :h3-upload-4 (the same over HTTP/3)
  - `:upload-bytes` request body size for the upload scenarios (default 16 MiB)
  - `:duration-s` measured seconds per scenario (default 10)
  - `:warmup-s` unmeasured seconds before each scenario (default 5)
  - `:connections` h1 connections (default 64)
  - `:pipeline-depth` requests in flight per pipelined h1 connection (default 16)
  - `:rate` total requests/s for :h1-get-rate (default 20000)
  - `:h3-connections` / `:h3-in-flight` QUIC connections and requests in
    flight each for :h3-get (default 4 x 32)
  - `:ws-message-bytes` text message size for :ws-echo (default 128)
  - `:ws-depth` messages in flight per :ws-echo connection (default 8)
  - `:server-jvm-opts` JVM options for the server process (default [\"-Xmx1g\"])
  - `:server-opts` run-server options for the server (default unlimited
    keep-alive requests, as load generators expect, and no request body cap)
  - `:out-dir` (default \"target/perf\")

  Allocation per request is measured inside the server process: the
  difference of its total allocated bytes (all threads, carriers of
  virtual threads included) across the measured window, divided by the
  requests completed in it. Warm-up traffic is excluded. For :ws-echo a
  request is one message echoed (read, dispatched, written back)."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [s-exp.enso-test-support :as support])
  (:import (java.io File InputStream OutputStream)
           (java.net InetSocketAddress ServerSocket Socket)
           (java.nio.charset StandardCharsets)
           (java.time Instant)
           (java.util.concurrent ExecutorService Executors Future)
           (java.util.concurrent.atomic AtomicBoolean AtomicLong)
           (java.util.concurrent.locks LockSupport)
           (org.HdrHistogram Histogram)))

(set! *warn-on-reflection* true)

(def ^:private defaults
  {:scenarios [:h1-get :h1-get-rate :h1-pipelined :h2-get :h3-get :ws-echo]
   :duration-s 10
   :warmup-s 5
   :connections 64
   :pipeline-depth 16
   :rate 20000
   :h3-connections 4
   :h3-in-flight 32
   :ws-message-bytes 128
   :ws-depth 8
   :upload-bytes (* 16 1024 1024)
   :server-jvm-opts ["-Xmx1g"]
   ;; No body cap: the upload scenarios post more than the default 10 MiB.
   :server-opts {:max-keep-alive-requests 0 :max-request-body-bytes 0}
   :out-dir "target/perf"})

;; ---- process helpers ---------------------------------------------------------------

(defn- free-tcp-port ^long []
  (with-open [s (ServerSocket. 0)] (.getLocalPort s)))

(defn- sh-out
  "stdout of `cmd`, or nil when it can't run."
  [& cmd]
  (try
    (let [p (.start (doto (ProcessBuilder. ^java.util.List (vec cmd)) (.redirectErrorStream true)))
          out (slurp (.getInputStream p))]
      (when (zero? (.waitFor p)) out))
    (catch java.io.IOException _ nil)))

(defn- start-server!
  "Starts the test server JVM; returns {:process :log :ports}."
  [{:keys [server-jvm-opts server-opts out-dir]} h3?]
  (let [ports (cond-> {:h1 (free-tcp-port) :h2 (free-tcp-port)}
                h3? (assoc :h3 (support/free-udp-port)))
        log (io/file out-dir "server.log")
        cmd (concat ["clojure"] (map #(str "-J" %) server-jvm-opts) ["-M:test-server"]
                    (mapcat (fn [[k v]] [(name k) (str v)]) ports)
                    ["opts" (pr-str server-opts)])
        proc (.start (doto (ProcessBuilder. ^java.util.List (vec cmd))
                       (.redirectErrorStream true)
                       (.redirectOutput log)))
        deadline (+ (System/currentTimeMillis) 180000)]
    (loop []
      (cond
        (and (.exists log) (str/includes? (slurp log) "READY")) {:process proc :log log :ports ports}
        (or (not (.isAlive proc)) (> (System/currentTimeMillis) deadline))
        (throw (ex-info (str "test server failed to start:\n" (slurp log)) {}))
        :else (do (Thread/sleep 200) (recur))))))

(defn- stop-server! [{:keys [^Process process]}]
  (.destroy process)
  (.waitFor process))

;; ---- HTTP/1.1 client ------------------------------------------------------------------

(def ^:private crlfcrlf (.getBytes "\r\n\r\n" StandardCharsets/ISO_8859_1))
(def ^:private cl-marker (.getBytes "Content-Length: " StandardCharsets/ISO_8859_1))

(defn- index-of ^long [^bytes hay ^long from ^long to ^bytes needle]
  (let [m (alength needle)]
    (loop [i from]
      (cond
        (> (+ i m) to) -1
        (loop [j 0]
          (cond (= j m) true
                (= (aget hay (+ i j)) (aget needle j)) (recur (inc j))
                :else false)) i
        :else (recur (inc i))))))

(defn- response-reader
  "Returns a fn reading one complete HTTP/1.1 response from `in`
  (Content-Length framed), using a reused buffer."
  [^InputStream in]
  (let [buf (byte-array 65536)
        state (long-array 2)] ; [pos limit]
    (letfn [(fill! []
              (let [pos (aget state 0) lim (aget state 1)]
                (when (pos? pos)
                  (System/arraycopy buf pos buf 0 (- lim pos))
                  (aset state 1 (- lim pos))
                  (aset state 0 0)))
              (let [lim (aget state 1)
                    n (.read in buf (int lim) (int (- (alength buf) lim)))]
                (when (neg? n) (throw (java.io.EOFException. "server closed")))
                (aset state 1 (+ lim n))))]
      (fn []
        (loop []
          (let [pos (aget state 0) lim (aget state 1)
                head-end (index-of buf pos lim crlfcrlf)]
            (if (neg? head-end)
              (do (fill!) (recur))
              (let [cl-at (index-of buf pos head-end cl-marker)
                    cl (if (neg? cl-at)
                         0
                         (loop [i (+ cl-at (alength ^bytes cl-marker)) v 0]
                           (let [b (aget buf i)]
                             (if (<= 48 b 57) (recur (inc i) (+ (* v 10) (- b 48))) v))))
                    end (+ head-end 4 (long cl))]
                (if (> end (aget state 1))
                  (do (fill!) (recur))
                  (aset state 0 end))))))))))

(def ^:private get-request (.getBytes "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" StandardCharsets/ISO_8859_1))

(defn- connect ^Socket [port]
  (doto (Socket.)
    (.setTcpNoDelay true)
    (.connect (InetSocketAddress. "127.0.0.1" (int port)) 5000)))

(defn- run-workers!
  "Runs `(worker i stop)` on `n` virtual threads until `duration-ms`
  elapse; returns elapsed nanoseconds."
  ^long [^long n ^long duration-ms worker]
  (let [stop (AtomicBoolean.)
        ^ExecutorService pool (Executors/newVirtualThreadPerTaskExecutor)
        start (System/nanoTime)
        futs (mapv (fn [i] (.submit pool ^Callable (fn [] (worker i stop)))) (range n))]
    (Thread/sleep duration-ms)
    (.set stop true)
    (doseq [^Future f futs] (.get f))
    (.close pool)
    (- (System/nanoTime) start)))

(defn- h1-closed-loop-worker
  "Keeps `depth` requests in flight on one connection; records the
  latency of each batch's requests (closed loop: not corrected for
  coordinated omission)."
  [^long port ^long depth ^Histogram hist ^AtomicLong done]
  (fn [_ ^AtomicBoolean stop]
    (with-open [sock (connect port)]
      (let [^OutputStream out (.getOutputStream sock)
            read! (response-reader (.getInputStream sock))
            batch (byte-array (* depth (alength ^bytes get-request)))]
        (dotimes [i depth]
          (System/arraycopy get-request 0 batch (* i (alength ^bytes get-request)) (alength ^bytes get-request)))
        (while (not (.get stop))
          (let [t0 (System/nanoTime)]
            (.write out batch)
            (.flush out)
            (dotimes [_ depth] (read!))
            (let [lat (- (System/nanoTime) t0)]
              (locking hist (.recordValue hist (max 1 lat))))
            (.addAndGet done depth)))))))

(defn- h1-rate-worker
  "Open-model worker: sends at `interval-ns` intended start times and
  measures latency from the intended start, so server stalls show up
  in the percentiles (coordinated-omission corrected, as wrk2 does)."
  [^long port ^long interval-ns ^Histogram hist ^AtomicLong done]
  (fn [i ^AtomicBoolean stop]
    (with-open [sock (connect port)]
      (let [^OutputStream out (.getOutputStream sock)
            read! (response-reader (.getInputStream sock))
            ;; Stagger connections across one interval.
            start (+ (System/nanoTime) (rem (* (long i) 7919) interval-ns))]
        (loop [k 0]
          (when-not (.get stop)
            (let [intended (+ start (* k interval-ns))
                  wait (- intended (System/nanoTime))]
              (when (pos? wait) (LockSupport/parkNanos wait))
              (.write out ^bytes get-request)
              (.flush out)
              (read!)
              (let [lat (- (System/nanoTime) intended)]
                (locking hist (.recordValue hist (max 1 lat))))
              (.incrementAndGet done)
              (recur (inc k)))))))))

;; ---- WebSocket client ------------------------------------------------------------------------

(def ^:private ws-upgrade
  (.getBytes (str "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
             StandardCharsets/ISO_8859_1))

(defn- ws-connect
  "A socket upgraded to WebSocket on the test server's echo endpoint."
  ^Socket [port]
  (let [sock (connect port)
        in (.getInputStream sock)]
    (.write (.getOutputStream sock) ^bytes ws-upgrade)
    (.flush (.getOutputStream sock))
    ;; Skip the 101 head: read up to CRLF CRLF.
    (loop [matched 0]
      (let [b (.read in)]
        (when (neg? b) (throw (java.io.EOFException. "upgrade refused")))
        (let [matched (long (cond (= b (aget ^bytes crlfcrlf matched)) (inc matched)
                                  (= b 13) 1
                                  :else 0))]
          (when (< matched 4) (recur matched)))))
    sock))

(defn- ws-text-frame
  "A masked client text frame of `n` ASCII bytes. The mask key is zero, so
  the payload goes out as is."
  ^bytes [^long n]
  (let [header (if (< n 126)
                 [0x81 (bit-or 0x80 n) 0 0 0 0]
                 [0x81 (bit-or 0x80 126) (bit-shift-right n 8) (bit-and n 0xFF) 0 0 0 0])]
    (byte-array (concat (map unchecked-byte header) (repeat n (byte \x))))))

(defn- ws-frame-reader
  "Returns a fn reading (and dropping) one server frame from `in`."
  [^InputStream in]
  (let [buf (byte-array 65536)
        state (long-array 2)] ; [pos limit]
    (letfn [(ensure! [^long n]
              (when (< (- (aget state 1) (aget state 0)) n)
                (let [pos (aget state 0) lim (aget state 1)]
                  (System/arraycopy buf pos buf 0 (- lim pos))
                  (aset state 0 0)
                  (aset state 1 (- lim pos)))
                (while (< (aget state 1) n)
                  (let [lim (aget state 1)
                        r (.read in buf (int lim) (int (- (alength buf) lim)))]
                    (when (neg? r) (throw (java.io.EOFException. "server closed")))
                    (aset state 1 (+ lim r))))))]
      (fn []
        (ensure! 2)
        (let [pos (aget state 0)
              len7 (bit-and (aget buf (inc pos)) 0x7F)
              [hdr len] (case (long len7)
                          126 (do (ensure! 4)
                                  [4 (bit-or (bit-shift-left (bit-and (aget buf (+ pos 2)) 0xFF) 8)
                                             (bit-and (aget buf (+ pos 3)) 0xFF))])
                          127 (throw (IllegalStateException. "frame too large for the harness"))
                          [2 len7])
              total (+ (long hdr) (long len))]
          (ensure! total)
          (aset state 0 (+ (aget state 0) total)))))))

(defn- ws-echo-worker
  "Keeps `depth` text messages in flight on one WebSocket and waits for
  their echoes; records each batch's latency (closed loop)."
  [port depth ^bytes frame ^Histogram hist ^AtomicLong done]
  (fn [_ ^AtomicBoolean stop]
    (with-open [sock (ws-connect port)]
      (let [^OutputStream out (.getOutputStream sock)
            read! (ws-frame-reader (.getInputStream sock))
            depth (long depth)
            batch (byte-array (* depth (alength frame)))]
        (dotimes [i depth]
          (System/arraycopy frame 0 batch (* i (alength frame)) (alength frame)))
        (while (not (.get stop))
          (let [t0 (System/nanoTime)]
            (.write out batch)
            (.flush out)
            (dotimes [_ depth] (read!))
            (let [lat (- (System/nanoTime) t0)]
              (locking hist (.recordValue hist (max 1 lat))))
            (.addAndGet done depth)))))))

;; ---- server stats -------------------------------------------------------------------------

(defn- server-stats [^long h1-port]
  (with-open [sock (connect h1-port)]
    (let [^OutputStream out (.getOutputStream sock)]
      (.write out (.getBytes "GET /__stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                             StandardCharsets/ISO_8859_1))
      (.flush out)
      (let [resp (slurp (.getInputStream sock))]
        (edn/read-string (subs resp (+ 4 (str/index-of resp "\r\n\r\n"))))))))

(defn- measured
  "Runs `(warmup)` then `(run)` (returning {:requests n ...}), reading
  server counters around the measured part only."
  [h1-port warmup run]
  (warmup)
  (let [before (server-stats h1-port)
        result (run)
        after (server-stats h1-port)
        n (long (:requests result))]
    (merge result
           {:alloc-bytes-per-request (when (pos? n)
                                       (Math/round (/ (double (- (:allocated-bytes after) (:allocated-bytes before))) n)))
            :gc-count (- (:gc-count after) (:gc-count before))
            :gc-ms (- (:gc-ms after) (:gc-ms before))})))

(defn- percentiles-ms [^Histogram h]
  (into {}
        (map (fn [[k p]] [k (/ (.getValueAtPercentile h (double p)) 1e6)]))
        {:p50 50.0 :p90 90.0 :p99 99.0 :p999 99.9 :max 100.0}))

(defn- h1-scenario [{:keys [ports duration-s warmup-s connections]} worker-fn latency-model]
  (let [port (:h1 ports)
        go (fn [secs]
             (let [hist (Histogram. 3600000000000 3)
                   done (AtomicLong.)
                   ns (run-workers! connections (* 1000 (long secs)) (worker-fn port hist done))]
               {:requests (.get done)
                :rps (Math/round (/ (* 1e9 (.get done)) (double ns)))
                :latency-ms (percentiles-ms hist)
                :latency-model latency-model}))]
    (measured port #(go warmup-s) #(go duration-s))))

;; ---- HTTP/2 via h2load -----------------------------------------------------------------------

(defn- duration-ms
  "h2load duration (\"1.23ms\", \"850us\", \"1.5s\") in milliseconds."
  [^String s]
  (let [[_ n unit] (re-matches #"([0-9.]+)(us|ms|s)" s)
        v (Double/parseDouble n)]
    (case unit "us" (/ v 1000.0) "ms" v "s" (* v 1000.0))))

(defn- h2load-latency
  "Request latency from h2load output. nghttp2 >= 1.62 prints
  min/max/median/p95/p99/mean; older versions min/max/mean only."
  [^String out]
  (if-let [[_ & cols] (re-find #"(?m)^request\s+:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)" out)]
    (let [[_ mx median _ p99 mean] (map duration-ms cols)]
      [{:p50 median :p99 p99 :max mx :mean mean} "median/p99"])
    (let [[_ _ mx mean] (re-find #"time for request:\s+(\S+)\s+(\S+)\s+(\S+)" out)]
      [{:max (some-> mx duration-ms) :mean (some-> mean duration-ms)} "min/max/mean only"])))

(defn- h2load [port secs]
  (if-let [out (sh-out "h2load" "-D" (str secs) "-c" "8" "-m" "32" "-t" "2"
                       (str "https://127.0.0.1:" port "/"))]
    (let [[_ rps] (re-find #"finished in [0-9.]+s, ([0-9.]+) req/s" out)
          [_ done] (re-find #"requests: \d+ total, \d+ started, (\d+) done" out)
          [latency reported] (h2load-latency out)]
      {:requests (Long/parseLong done)
       :rps (Math/round (Double/parseDouble rps))
       :latency-ms latency
       :latency-model (str "h2load -c 8 -m 32 closed loop (not CO-corrected); h2load reports " reported)})
    (throw (ex-info "h2load failed" {:port port}))))

(defn- h2-scenario [{:keys [ports duration-s warmup-s]}]
  (if-not (sh-out "h2load" "--version")
    {:skipped "h2load not found on PATH"}
    (measured (:h1 ports) #(h2load (:h2 ports) warmup-s) #(h2load (:h2 ports) duration-s))))

;; ---- HTTP/2 uploads via h2load -----------------------------------------------------------------

(defn- upload-file
  "A file of `n` zero bytes under `out-dir`, the body every upload posts."
  ^File [out-dir n]
  (let [f (io/file out-dir (str "upload-" n ".bin"))]
    (when-not (= n (.length f))
      (with-open [out (io/output-stream f)]
        (let [chunk (byte-array (* 64 1024))]
          (loop [left (long n)]
            (when (pos? left)
              (.write out chunk 0 (int (min left (alength chunk))))
              (recur (- left (alength chunk))))))))
    f))

(defn- h2load-upload
  "POSTs `file` to /upload for `secs` over one TLS h2 connection with
  `streams` requests in flight."
  [port secs streams ^File file]
  (if-let [out (sh-out "h2load" "-D" (str secs) "-c" "1" "-m" (str streams) "-t" "1"
                       "-d" (.getPath file) (str "https://127.0.0.1:" port "/upload"))]
    (let [[_ done ok] (re-find #"requests: \d+ total, \d+ started, (\d+) done, (\d+) succeeded" out)
          _ (when (not= done ok) (throw (ex-info (str "uploads failed: " ok " of " done " succeeded") {})))
          [_ rps] (re-find #"finished in [0-9.]+s, ([0-9.]+) req/s" out)
          [latency reported] (h2load-latency out)
          mib (/ (.length file) 1048576.0)]
      {:requests (Long/parseLong done)
       :rps (Math/round (Double/parseDouble rps))
       :mib-per-s (* mib (Double/parseDouble rps))
       :latency-ms latency
       :latency-model (str "h2load -c 1 -m " streams " POST of " (Math/round mib) " MiB, closed loop; "
                           "h2load reports " reported)})
    (throw (ex-info "h2load failed" {:port port}))))

(defn- h2-upload-scenario [{:keys [ports duration-s warmup-s out-dir upload-bytes]} streams]
  (if-not (sh-out "h2load" "--version")
    {:skipped "h2load not found on PATH"}
    (let [file (upload-file out-dir upload-bytes)
          r (measured (:h1 ports)
                      #(h2load-upload (:h2 ports) warmup-s streams file)
                      #(h2load-upload (:h2 ports) duration-s streams file))]
      (assoc r :alloc-bytes-per-mib (when-let [per-request (:alloc-bytes-per-request r)]
                                      (Math/round (/ (* 1048576.0 (long per-request)) (long upload-bytes))))))))

;; ---- HTTP/3 via the batched quiche load client ----------------------------------------

(defn- h3-run [{:keys [h3-connections h3-in-flight]} port secs]
  (let [run! (requiring-resolve 's-exp.h3-load/run)
        {:keys [requests rps hist]} (run! port {:connections h3-connections
                                                :in-flight h3-in-flight
                                                :ms (* 1000 (long secs))})]
    {:requests requests
     :rps rps
     :latency-ms (percentiles-ms hist)
     :latency-model (str h3-connections " QUIC connections x " h3-in-flight
                         " requests in flight, closed loop (not CO-corrected)")}))

(defn- h3-scenario [{:keys [ports duration-s warmup-s] :as cfg}]
  (cond
    (not (:h3 ports)) {:skipped "enso_quiche shim not available"}
    :else (measured (:h1 ports) #(h3-run cfg (:h3 ports) warmup-s) #(h3-run cfg (:h3 ports) duration-s))))

;; ---- HTTP/3 uploads via the quiche load client ------------------------------------------------

(defn- h3-upload-run [port secs streams upload-bytes]
  (let [upload (requiring-resolve 's-exp.h3-load/upload)
        {:keys [requests rps hist]} (upload port {:streams streams :body-bytes upload-bytes
                                                  :ms (* 1000 (long secs))})
        mib (/ (long upload-bytes) 1048576.0)]
    {:requests requests
     :rps (Math/round (double rps))
     :mib-per-s (* mib (double rps))
     :latency-ms (percentiles-ms hist)
     :latency-model (str "1 QUIC connection x " streams " POST of " (Math/round mib) " MiB in flight, closed loop")}))

(defn- h3-upload-scenario [{:keys [ports duration-s warmup-s upload-bytes]} streams]
  (if-not (:h3 ports)
    {:skipped "enso_quiche shim not available"}
    (let [r (measured (:h1 ports)
                      #(h3-upload-run (:h3 ports) warmup-s streams upload-bytes)
                      #(h3-upload-run (:h3 ports) duration-s streams upload-bytes))]
      (assoc r :alloc-bytes-per-mib (when-let [per-request (:alloc-bytes-per-request r)]
                                      (Math/round (/ (* 1048576.0 (long per-request)) (long upload-bytes))))))))

;; ---- output -----------------------------------------------------------------------------------

(defn- json [x]
  (cond
    (map? x) (str "{" (str/join "," (map (fn [[k v]] (str (json (if (keyword? k) (name k) (str k))) ":" (json v))) x)) "}")
    (sequential? x) (str "[" (str/join "," (map json x)) "]")
    (keyword? x) (json (name x))
    (string? x) (str "\"" (str/escape x {\" "\\\"" \\ "\\\\" \newline "\\n" \return "\\r" \tab "\\t"}) "\"")
    (nil? x) "null"
    (ratio? x) (str (double x))
    :else (str x)))

(defn- upload-report-md
  "Throughput table of the upload scenarios in `scenarios`, empty without any."
  [scenarios]
  (let [uploads (filter (fn [[_ r]] (:mib-per-s r)) scenarios)]
    (if (empty? uploads)
      ""
      (str "\n| upload | MiB/s | alloc B/MiB |\n|---|---:|---:|\n"
           (str/join (for [[k r] uploads]
                       (format "| %s | %.1f | %s |\n" (name k) (double (:mib-per-s r))
                               (:alloc-bytes-per-mib r))))))))

(defn- report-md [{:keys [meta config scenarios]}]
  (str "# enso perf run " (:timestamp meta) "\n\n"
       "git " (:git meta) ", " (:java meta) ", " (:os meta) ", " (:cpus meta) " CPUs\n"
       "duration " (:duration-s config) "s (warm-up " (:warmup-s config) "s), server JVM opts "
       (pr-str (:server-jvm-opts config)) "\n\n"
       "| scenario | req/s | alloc B/req | p50 ms | p99 ms | p99.9 ms | max ms | GCs | latency model |\n"
       "|---|---:|---:|---:|---:|---:|---:|---:|---|\n"
       (str/join
        (for [[k r] scenarios]
          (if (:skipped r)
            (str "| " (name k) " | skipped: " (:skipped r) " ||||||||\n")
            (let [l (:latency-ms r)
                  fmt #(if (number? %) (format "%.2f" (double %)) "")]
              (str "| " (name k) " | " (:rps r) " | " (:alloc-bytes-per-request r)
                   " | " (fmt (:p50 l)) " | " (fmt (:p99 l)) " | " (fmt (:p999 l)) " | "
                   (fmt (:max l))
                   " | " (:gc-count r) " | " (:latency-model r) " |\n")))))
       (upload-report-md scenarios)))

(defn- write-results! [{:keys [out-dir]} result]
  (let [stamp (str/replace (str (:timestamp (:meta result))) #"[:.]" "-")
        dir (io/file out-dir)]
    (.mkdirs dir)
    (doseq [base [stamp "latest"]]
      (spit (io/file dir (str base ".edn")) (pr-str result))
      (spit (io/file dir (str base ".json")) (json result))
      (spit (io/file dir (str base ".md")) (report-md result)))
    (println (report-md result))
    (println "results written to" (.getPath (io/file dir "latest.edn")))))

(defn run
  "Runs the harness with `opts` merged over the defaults; returns the
  result map (also written to :out-dir)."
  [opts]
  (let [cfg (merge defaults opts)
        _ (.mkdirs (io/file (:out-dir cfg)))
        h3? (and (some #{:h3-get :h3-upload :h3-upload-4} (:scenarios cfg)) (support/shim-available?))
        server (start-server! cfg h3?)
        cfg (assoc cfg :ports (:ports server))
        n-conn (long (:connections cfg))]
    (try
      (let [scenarios
            (into (array-map)
                  (for [s (:scenarios cfg)]
                    (do (println "running" s)
                        [s (try
                             (case s
                               :h1-get (h1-scenario cfg #(h1-closed-loop-worker %1 1 %2 %3)
                                                    (str n-conn " connections, closed loop (not CO-corrected)"))
                               :h1-get-rate (let [interval (long (/ (* 1e9 n-conn) (double (:rate cfg))))]
                                              (h1-scenario cfg #(h1-rate-worker %1 interval %2 %3)
                                                           (str "open model at " (:rate cfg) " req/s over "
                                                                n-conn " connections, CO-corrected")))
                               :h1-pipelined (h1-scenario (update cfg :connections #(min 16 (long %)))
                                                          #(h1-closed-loop-worker %1 (:pipeline-depth cfg) %2 %3)
                                                          (str "pipelined depth " (:pipeline-depth cfg)
                                                               ", latency per batch"))
                               :h2-get (h2-scenario cfg)
                               :h3-get (h3-scenario cfg)
                               :h2-upload (h2-upload-scenario cfg 1)
                               :h2-upload-4 (h2-upload-scenario cfg 4)
                               :h3-upload (h3-upload-scenario cfg 1)
                               :h3-upload-4 (h3-upload-scenario cfg 4)
                               :ws-echo (let [frame (ws-text-frame (:ws-message-bytes cfg))
                                              depth (long (:ws-depth cfg))]
                                          (h1-scenario cfg #(ws-echo-worker %1 depth frame %2 %3)
                                                       (str n-conn " WebSocket connections × " depth " "
                                                            (:ws-message-bytes cfg) "-byte text messages, "
                                                            "per batch (req = message)"))))
                             (catch Exception e
                               {:skipped (str "failed: " (.getMessage e))}))])))]
        (let [result {:meta {:timestamp (str (Instant/now))
                             :git (some-> (sh-out "git" "rev-parse" "--short" "HEAD") str/trim)
                             :java (System/getProperty "java.vm.version")
                             :os (str (System/getProperty "os.name") " " (System/getProperty "os.arch"))
                             :cpus (.availableProcessors (Runtime/getRuntime))}
                      :config (dissoc cfg :ports)
                      :scenarios scenarios}]
          (write-results! cfg result)
          result))
      (finally (stop-server! server)))))

(defn -main [& args]
  (run (if (seq args) (edn/read-string (first args)) {}))
  (shutdown-agents)
  (System/exit 0))

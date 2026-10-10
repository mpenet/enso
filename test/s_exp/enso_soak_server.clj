;; ABOUTME: Server process of the soak/chaos run: enso on every protocol with soak routes (uploads, streams,
;; ABOUTME: SSE, WebSocket echo) plus a separate stats listener reporting heap, fds, threads, budget and events.
(ns s-exp.enso-soak-server
  "Started by `s-exp.enso-soak` in its own JVM:
  `java -cp ... clojure.main -m s-exp.enso-soak-server OPTS-EDN`, OPTS a
  map of `:plain` (HTTP/1.1, WebSocket and h2c prior knowledge), `:tls`
  (HTTP/2 + HTTP/1.1 over TLS), `:h3` (UDP), `:stats` ports, `:cert` and
  `:key` PEM paths for HTTP/3 and `:server-opts` merged into the run-server
  options of the plain and TLS servers.

  Routes on the plain and TLS servers:
  - `/` the hello response
  - `/upload` reads the body, answers `<length> <crc32>`
  - `/upload-slow` reads the body 16 KiB at a time with a pause between
    reads, answers its length (keeps bodies buffered: memory budget)
  - `/ignore-body` answers without reading the body
  - `/stream?chunks=N&size=S&delay=MS` a (fn [ChunkedWriter]) body
  - `/sse?events=N&delay=MS` server-sent events
  - `/bytes?n=N[&cl=1]` an InputStream body of N pattern bytes (with a
    Content-Length when cl=1)
  - `/sleep?ms=N` answers the hello body after N ms
  - any WebSocket upgrade: echo

  The stats listener (default options, never under chaos) answers
  `/__stats[?gc=1]` with an EDN map of process and server counters and
  `/__stop` by stopping the plain and TLS servers concurrently and
  reporting how long that took and what was left running. Prints
  `READY` once every listener is bound."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [s-exp.enso :as enso]
            [s-exp.enso-test-support :as support]
            [s-exp.perf-target :as target])
  (:import (com.s_exp.enso EnsoServer)
           (com.s_exp.enso.api ChunkedWriter WebSocketSocket)
           (com.s_exp.enso.core MemoryBudget)
           (com.sun.management OperatingSystemMXBean UnixOperatingSystemMXBean)
           (java.io InputStream)
           (java.lang.management BufferPoolMXBean GarbageCollectorMXBean ManagementFactory MemoryPoolMXBean
                                 MemoryType)
           (java.nio ByteBuffer)
           (java.time Duration)
           (java.util.concurrent ConcurrentHashMap)
           (java.util.concurrent.atomic LongAdder)
           (java.util.function Consumer Function)
           (java.util.zip CRC32)
           (jdk.jfr.consumer RecordingStream)))

(set! *warn-on-reflection* true)

;; ---- counters ----------------------------------------------------------------------

(defn- counter-map ^ConcurrentHashMap [] (ConcurrentHashMap.))

(def ^:private new-adder
  (reify Function (apply [_ _] (LongAdder.))))

(defn- bump! [^ConcurrentHashMap m k]
  (.increment ^LongAdder (.computeIfAbsent m k new-adder)))

(defn- snapshot-counts [^ConcurrentHashMap m]
  (into (sorted-map) (map (fn [[k ^LongAdder v]] [k (.sum v)])) m))

(def ^:private events
  {:opened (counter-map) :closed (counter-map) :requests (counter-map) :protocol-errors (counter-map)})

(def ^:private server-events
  {:connection-opened (fn [protocol _] (bump! (:opened events) protocol))
   :connection-closed (fn [protocol _ _] (bump! (:closed events) protocol))
   :request-completed (fn [protocol _ status _ _ _] (bump! (:requests events) (str protocol " " status)))
   :protocol-error (fn [protocol kind] (bump! (:protocol-errors events) (str protocol " " kind)))})

;; Virtual thread starts and ends, and pinning, counted from JFR.
(def ^:private jfr-counts (counter-map))

(defn- start-jfr! ^RecordingStream []
  (let [rs (RecordingStream.)]
    (doseq [e ["jdk.VirtualThreadStart" "jdk.VirtualThreadEnd" "jdk.VirtualThreadPinned"
               "jdk.VirtualThreadSubmitFailed"]]
      (.enable rs ^String e)
      (.onEvent rs ^String e (reify Consumer (accept [_ _] (bump! jfr-counts e)))))
    ;; Only pinning longer than this is an event.
    (.withThreshold (.enable rs "jdk.VirtualThreadPinned") (Duration/ofMillis 20))
    (.setMaxAge rs (Duration/ofSeconds 30))
    (.startAsync rs)
    rs))

;; ---- handler -----------------------------------------------------------------------

(defn- query-long
  "Long value of query parameter `k` of `request`, or `default`."
  ^long [request ^String k ^long default]
  (if-let [[_ v] (some->> (:query-string request) (re-find (re-pattern (str "(?:^|&)" k "=(\\d+)"))))]
    (Long/parseLong v)
    default))

(defn pattern-byte
  "Byte at offset `i` of every generated body."
  ^long [^long i]
  (bit-and (+ 32 (rem i 91)) 0xFF))

(defn- pattern-bytes ^bytes [^long n]
  (let [b (byte-array n)]
    (dotimes [i n] (aset b i (unchecked-byte (pattern-byte i))))
    b))

(def ^:private pattern-block (pattern-bytes (* 91 720)))

(defn- pattern-stream
  "InputStream of `n` pattern bytes."
  ^InputStream [^long n]
  (let [pos (long-array 1)]
    (proxy [InputStream] []
      (read
        ([] (let [p (aget pos 0)]
              (if (>= p n) -1 (do (aset pos 0 (inc p)) (pattern-byte p)))))
        ([^bytes b off len]
         (let [p (aget pos 0)
               k (min (long len) (- n p))]
           (if (<= k 0)
             -1
             (do (dotimes [i k] (aset b (+ (long off) i) (unchecked-byte (pattern-byte (+ p i)))))
                 (aset pos 0 (+ p k))
                 k))))))))

(defn- read-body
  "Reads `body` to its end; [length crc32]. `pause-ms` between 16 KiB reads."
  [body ^long pause-ms]
  (if-not (instance? InputStream body)
    [0 0]
    (let [^InputStream in body
          buf (byte-array 16384)
          crc (CRC32.)]
      (loop [n 0]
        (let [r (.read in buf)]
          (if (neg? r)
            [n (.getValue crc)]
            (do (.update crc buf 0 r)
                (when (pos? pause-ms) (Thread/sleep pause-ms))
                (recur (+ n r)))))))))

(defn- text [s] {:status 200 :headers {"content-type" "text/plain"} :body s})

(def ^:private echo-listener
  {:on-message (fn [^WebSocketSocket socket message]
                 (if (instance? CharSequence message)
                   (.sendText socket ^CharSequence message)
                   (.sendBinary socket ^ByteBuffer message)))})

(defn- stream-body [^long chunks ^long size ^long delay]
  (fn [^ChunkedWriter w]
    (dotimes [i chunks]
      ;; Each chunk continues the pattern where the previous one ended.
      (.write w pattern-block (int (rem (* i size) 91)) (int size))
      (.flush w)
      (when (pos? delay) (Thread/sleep delay)))))

(defn- sse-body [^long n ^long delay]
  (fn [^ChunkedWriter w]
    (dotimes [i n]
      (enso/write! w (str "id: " i "\ndata: event " i "\n\n"))
      (.flush w)
      (when (pos? delay) (Thread/sleep delay)))))

(defn handler [request]
  (if (target/websocket-upgrade? request)
    {:ring.websocket/listener echo-listener}
    (case (:uri request)
      "/" (do (target/drain! (:body request)) target/hello-response)
      "/upload" (let [[n crc] (read-body (:body request) 0)] (text (str n " " crc)))
      "/upload-slow" (let [[n] (read-body (:body request) 20)] (text (str n)))
      "/ignore-body" (text "ignored")
      "/stream" {:status 200
                 :headers {"content-type" "application/octet-stream"}
                 :body (stream-body (query-long request "chunks" 16)
                                    (min (- (alength ^bytes pattern-block) 91) (query-long request "size" 4096))
                                    (query-long request "delay" 0))}
      "/sse" {:status 200
              :headers {"content-type" "text/event-stream" "cache-control" "no-cache"}
              :body (sse-body (query-long request "events" 10) (query-long request "delay" 10))}
      "/bytes" (let [n (query-long request "n" 1024)]
                 {:status 200
                  :headers (cond-> {"content-type" "application/octet-stream"}
                             (= 1 (query-long request "cl" 0)) (assoc "content-length" (str n)))
                  :body (pattern-stream n)})
      "/sleep" (do (Thread/sleep (query-long request "ms" 100)) target/hello-response)
      {:status 404 :headers {"content-type" "text/plain"} :body "not found"})))

;; ---- stats -------------------------------------------------------------------------

(defn- thread-groups
  "Live platform threads counted by name, digits collapsed."
  []
  (into (sorted-map)
        (frequencies (map #(str/replace (.getName ^Thread %) #"\d+" "N") (keys (Thread/getAllStackTraces))))))

(defn- budget-stats [^EnsoServer s]
  (when-let [svc (.service s)]
    (let [^MemoryBudget b (.-budget svc)]
      {:used (.used b) :limit (.limit b) :accounts (.activeAccounts b) :exhausted (.exhausted b)})))

(defn- collection-usage
  "Heap pools' usage after their last collection, summed."
  ^long []
  (reduce + 0 (keep (fn [^MemoryPoolMXBean p]
                      (when (= MemoryType/HEAP (.getType p))
                        (some-> (.getCollectionUsage p) .getUsed)))
                    (ManagementFactory/getMemoryPoolMXBeans))))

(defn stats
  "Process and server counters; a full GC first when `gc`."
  [servers gc]
  (when gc
    (System/gc)
    (Thread/sleep 50))
  (let [mem (ManagementFactory/getMemoryMXBean)
        ^OperatingSystemMXBean os (ManagementFactory/getOperatingSystemMXBean)
        heap (.getHeapMemoryUsage mem)
        jfr (snapshot-counts jfr-counts)
        vstart (get jfr "jdk.VirtualThreadStart" 0)
        vend (get jfr "jdk.VirtualThreadEnd" 0)]
    (merge
     (target/stats)
     {:time-ms (System/currentTimeMillis)
      :uptime-ms (.getUptime (ManagementFactory/getRuntimeMXBean))
      :heap-used (.getUsed heap)
      :heap-committed (.getCommitted heap)
      :heap-after-gc (collection-usage)
      :non-heap-used (.getUsed (.getNonHeapMemoryUsage mem))
      :buffer-pools (into {} (map (fn [^BufferPoolMXBean p]
                                    [(.getName p) {:count (.getCount p) :used (.getMemoryUsed p)}]))
                          (ManagementFactory/getPlatformMXBeans BufferPoolMXBean))
      :fds (.getOpenFileDescriptorCount ^UnixOperatingSystemMXBean os)
      :process-cpu-ns (.getProcessCpuTime os)
      :threads (.getThreadCount (ManagementFactory/getThreadMXBean))
      :thread-groups (thread-groups)
      :virtual-threads {:started vstart :ended vend :live (- (long vstart) (long vend))
                        :pinned (get jfr "jdk.VirtualThreadPinned" 0)
                        :submit-failed (get jfr "jdk.VirtualThreadSubmitFailed" 0)}
      :gcs (into {} (map (fn [^GarbageCollectorMXBean g]
                           [(.getName g) {:count (.getCollectionCount g) :ms (.getCollectionTime g)}]))
                 (ManagementFactory/getGarbageCollectorMXBeans))
      :servers (into {} (map (fn [[k ^EnsoServer s]]
                               [k {:connections (.connectionCount s)
                                   :running (.isRunning s)
                                   :healthy (.isHealthy s)
                                   :dropped-events (.droppedEvents s)
                                   :budget (budget-stats s)}]))
                     servers)
      :events (into {} (map (fn [[k m]] [k (snapshot-counts m)])) events)})))

(defn- edn-response [x]
  {:status 200 :headers {"content-type" "application/edn"} :body (pr-str x)})

(defn- stop-all!
  "Stops `servers` concurrently; how long each took and what was left."
  [servers]
  (let [t0 (System/nanoTime)
        stops (into {} (map (fn [[k s]]
                              [k (future (let [t (System/nanoTime)]
                                           (try (enso/stop s) {:ms (quot (- (System/nanoTime) t) 1000000)}
                                                (catch Throwable e {:error (str e)}))))]))
                    servers)
        results (into {} (map (fn [[k f]] [k (deref f 60000 {:error "stop did not return in 60 s"})])) stops)]
    ;; Threads a stopped server leaves behind end shortly after close
    ;; returns (writer lingering, pools winding down).
    (Thread/sleep 2000)
    {:stop results
     :total-ms (quot (- (System/nanoTime) t0) 1000000)
     :after (stats servers true)}))

(defn stats-handler [servers]
  (fn [request]
    (case (:uri request)
      "/__stats" (edn-response (stats servers (= "gc=1" (:query-string request))))
      "/__stop" (edn-response (stop-all! servers))
      {:status 404 :body "not found"})))

;; ---- main ------------------------------------------------------------------------------

(defn -main [opts-edn]
  (let [{:keys [plain tls h3 stats cert key server-opts]} (edn/read-string opts-edn)
        opts (merge {:host "127.0.0.1" :server-events server-events} server-opts)
        jfr (start-jfr!)
        plain-server (enso/run-server handler (assoc opts :port plain :http2c true))
        tls-server (enso/run-server handler (cond-> (assoc opts :port tls :http2 true
                                                           :ssl-context (support/server-ssl-context))
                                              h3 (assoc :http3 true :http3-port h3
                                                        :http3-cert-path cert :http3-key-path key)))
        servers {:plain plain-server :tls tls-server}
        stats-server (enso/run-server (stats-handler servers) {:host "127.0.0.1" :port stats})]
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. ^Runnable (fn []
                                           (run! #(try (enso/stop %) (catch Throwable _))
                                                 [plain-server tls-server stats-server])
                                           (.close jfr))))
    (println "READY" (pr-str {:pid (.pid (java.lang.ProcessHandle/current))}))
    (flush)
    @(promise)))

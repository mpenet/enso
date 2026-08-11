(ns enso.bench
  "Side-by-side bench harness for Enso, http-kit, Jetty (ring-jetty-adapter).
  Boots all servers in one JVM, drives wrk against each, aggregates throughput
  + latency percentiles, and profiles allocation via clj-async-profiler.

  Aleph/netty are excluded from the bench alias because they were of limited
  additional value versus the Jetty comparison and inflated the classpath."
  (:require [clj-async-profiler.core :as prof]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [org.httpkit.server :as httpkit]
            [ring.adapter.jetty :as jetty]
            [s-exp.enso :as enso]))

;; --- Handlers ---------------------------------------------------------------

(defn plaintext-handler
  "TechEmpower-style plaintext: fixed 404 body 'nf'. Same shape as our previous
  wrk baseline. Keeps the response tight so we're measuring adapter overhead
  rather than user code."
  [_]
  {:status 404
   :headers {"content-type" "text/plain"}
   :body "nf"})

;; --- Server lifecycle -------------------------------------------------------

(defonce ^:private state (atom {}))

(defn stop! []
  (let [{:keys [enso-srv hk-stop jetty-srv]} @state]
    (when enso-srv (enso/stop enso-srv))
    (when hk-stop (hk-stop))
    (when jetty-srv (.stop jetty-srv)))
  (reset! state {})
  :stopped)

(defn start!
  "Starts all servers on the given ports. Idempotent - existing instances are
  stopped first."
  ([]
   (start! {:enso 8080 :httpkit 8081 :jetty 8082}))
  ([ports]
   (stop!)
   (let [enso-srv (enso/run-server plaintext-handler {:port (:enso ports)})
         hk-stop (httpkit/run-server plaintext-handler
                                     {:port (:httpkit ports)
                                      :thread 8
                                      :worker-name-prefix "hk-"})
         jetty-srv (jetty/run-jetty plaintext-handler
                                    {:port (:jetty ports)
                                     :join? false})]
     (reset! state {:enso-srv enso-srv
                    :hk-stop hk-stop
                    :jetty-srv jetty-srv
                    :ports ports})
     (into {} (for [[k p] ports]
                [k (str "http://127.0.0.1:" p "/nope")])))))

;; --- wrk driver -------------------------------------------------------------

(def ^:private pipeline-lua
  (fn [depth path]
    (str "init = function(args)\n"
         "  local r = {}\n"
         "  for i = 1, " depth " do\n"
         "    r[i] = wrk.format(\"GET\", \"" path "\")\n"
         "  end\n"
         "  req = table.concat(r)\n"
         "end\n"
         "request = function() return req end\n")))

(defn- write-lua! [depth path]
  (let [f (java.io.File/createTempFile "enso-bench-" ".lua")]
    (spit f (pipeline-lua depth path))
    (.getPath f)))

(defn- parse-wrk [^String out]
  {:raw out
   :rps (when-let [m (re-find #"Requests/sec:\s+([0-9.]+)" out)]
          (Double/parseDouble (nth m 1)))
   :xfer (when-let [m (re-find #"Transfer/sec:\s+([0-9.]+)([A-Z]+)" out)]
           (str (nth m 1) (nth m 2)))
   :latency-avg (when-let [m (re-find #"Latency\s+([0-9.]+)(us|ms|s)" out)]
                  (str (nth m 1) (nth m 2)))
   :latency-max (when-let [m (re-find #"Latency\s+[0-9.]+[a-z]+\s+[0-9.]+[a-z]+\s+([0-9.]+)(us|ms|s)" out)]
                  (str (nth m 1) (nth m 2)))
   :non-2xx (when-let [m (re-find #"Non-2xx or 3xx responses:\s+(\d+)" out)]
              (Long/parseLong (nth m 1)))})

(defn wrk!
  "Runs `wrk` against `url` and returns a parsed summary map. `depth` = pipeline
  depth (1 for non-pipelined). Runs *two* warmup passes before the bench so the
  JIT has time to compile + inline the hot path — a single 5s warmup on cold
  code leaves most methods still in interpreter tier."
  ([url] (wrk! url {}))
  ([url {:keys [duration threads connections depth latency? warmup warmup-passes]
         :or {duration "8s" threads 4 connections 64 depth 1
              latency? true warmup "10s" warmup-passes 2}}]
   (let [base (if (> depth 1)
                (let [f (write-lua! depth "/nope")]
                  [(str "-t" threads) (str "-c" connections) "-s" f])
                [(str "-t" threads) (str "-c" connections)])
         with-dur (fn [d]
                    (concat base (when latency? ["--latency"])
                            [(str "-d" d) url]))]
     ;; JIT warmup: two consecutive passes with the real bench workload
     ;; shape (connections/depth match) so tier-1 → tier-4 promotion
     ;; happens on the same call sites we measure.
     (dotimes [_ warmup-passes]
       (apply sh/sh "wrk" (with-dur warmup)))
     (let [{:keys [out]} (apply sh/sh "wrk" (with-dur duration))]
       (let [base (parse-wrk out)
             pct (into {}
                       (for [p ["50%" "75%" "90%" "99%" "99.9%" "99.99%"]]
                         (when-let [m (re-find
                                       (re-pattern (str "(?m)^\\s+" p "\\s+([0-9.]+)(us|ms|s)"))
                                       out)]
                           [p (str (nth m 1) (nth m 2))])))]
         (assoc base :percentiles pct))))))

;; --- Comparison ------------------------------------------------------------

(defn compare!
  "Runs the same wrk workload against every started server and returns a map
  keyed by server name. Requires start! to have been called."
  [{:keys [duration depth connections targets]
    :or {duration "8s" depth 1 connections 64
         targets [:enso :httpkit :jetty]}}]
  (let [{:keys [ports]} @state
        opts {:duration duration :depth depth :connections connections}
        results (into {}
                      (for [t targets
                            :let [p (get ports t)]
                            :when p]
                        (let [url (str "http://127.0.0.1:" p "/nope")
                              r (wrk! url opts)]
                          [t {:rps (:rps r)
                              :latency-avg (:latency-avg r)
                              :latency-max (:latency-max r)
                              :xfer (:xfer r)
                              :percentiles (:percentiles r)}])))]
    {:workload (str "wrk -t4 -c" connections " -d" duration
                    (when (> depth 1) (str " (pipelined d=" depth ")")))
     :results results
     :rps-ranking (->> results
                       (map (fn [[k v]] [k (:rps v)]))
                       (sort-by second >)
                       (into []))}))

;; --- HTTP/3 harness --------------------------------------------------------

(defn- gen-cert-key!
  "Shells out to openssl to write cert.pem + key.pem into a tempdir. Returns
  [cert-path key-path]. Quiche loads PEM directly, no keystore round-trip."
  []
  (let [dir (java.nio.file.Files/createTempDirectory
             "enso-h3-bench" (into-array java.nio.file.attribute.FileAttribute []))
        cert (str (.resolve dir "cert.pem"))
        key (str (.resolve dir "key.pem"))
        cmd ["openssl" "req" "-x509" "-newkey" "rsa:2048"
             "-keyout" key "-out" cert
             "-sha256" "-days" "1" "-nodes"
             "-subj" "/CN=localhost"
             "-addext" "subjectAltName=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true)
                 (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info (str "openssl failed: " (slurp (.getInputStream proc))) {})))
    [cert key]))

(defonce ^:private h3-state (atom {}))

(defn h3-stop! []
  (when-let [srv (:srv @h3-state)]
    (enso/stop srv))
  (reset! h3-state {})
  :stopped)

(defn h3-start!
  "Boots a single-server enso with h3 enabled. TCP port 0 (unused), UDP port
  fixed so h2load can target it. Handler is same plaintext shape as the h1
  bench for apples-to-apples.

  Knobs match Netty/Jetty defaults for fair comparison: no stateless retry
  (Netty h3 example server doesn't enforce), 30s idle timeout, 100 max
  concurrent streams — same as their defaults."
  ([] (h3-start! {:h3-port 18443}))
  ([{:keys [h3-port]}]
   (h3-stop!)
   (let [[cert key] (gen-cert-key!)
         srv (enso/run-server
              plaintext-handler
              {:port 0
               :http3 true
               :http3-port h3-port
               :http3-cert-path cert
               :http3-key-path key
               ;; Match Netty h3 example defaults so cross-server bench
               ;; isn't biased by config drift.
               :http3-stateless-retry false
               :http3-max-idle-timeout 30000
               :http3-initial-max-streams-bidi 100})]
     (reset! h3-state {:srv srv :h3-port h3-port :cert cert :key key})
     {:h3-url (str "https://127.0.0.1:" h3-port "/nope")})))

(defn- run-quiche-client
  "One quiche-client process, `requests` GETs on a single QUIC connection.
  Returns exit code + captured stderr tail. stdout is /dev/null since we
  don't need response bodies."
  [url requests]
  (let [cmd ["quiche-client" "--no-verify" "-n" (str requests) url]
        pb (-> (ProcessBuilder. ^java.util.List cmd)
               (.redirectOutput java.lang.ProcessBuilder$Redirect/DISCARD)
               (.redirectErrorStream true))
        proc (.start pb)]
    ;; quiche-client is chatty on stderr — read to /dev/null so pipe fills
    ;; don't stall the child.
    (future (with-open [is (.getInputStream proc)]
              (let [buf (byte-array 4096)]
                (while (not= -1 (.read is buf 0 4096))))))
    (.waitFor proc)
    {:exit (.exitValue proc)}))

(defn drive-h3!
  "Fans `clients` concurrent quiche-client processes, each issuing `per-client`
  requests on one QUIC connection. Returns total requests + wall-clock ms.
  quiche-client with `-n N` reuses one connection, so per-client bumps stream
  volume without paying handshake cost each time."
  [url {:keys [clients per-client]
        :or {clients 8 per-client 500}}]
  (let [t0 (System/nanoTime)
        futs (doall (for [_ (range clients)]
                      (future (run-quiche-client url per-client))))
        results (mapv deref futs)
        wall-ms (/ (- (System/nanoTime) t0) 1e6)
        ok (count (filter #(zero? (:exit %)) results))]
    {:clients clients
     :per-client per-client
     :total-req (* clients per-client)
     :ok-clients ok
     :fail-clients (- clients ok)
     :wall-ms wall-ms
     :rps-est (double (/ (* clients per-client) (/ wall-ms 1000.0)))}))

;; --- Cross-server h3 bench (task #95) --------------------------------------

(defn- gen-p12!
  "Wraps a PEM cert + key into a PKCS12 keystore for Jetty. Returns
  [keystore-path password]."
  [cert-pem key-pem]
  (let [dir (-> cert-pem java.io.File. .getParentFile .toPath)
        p12 (str (.resolve dir "keystore.p12"))
        pass "bench"
        cmd ["openssl" "pkcs12" "-export"
             "-in" cert-pem "-inkey" key-pem
             "-out" p12 "-name" "bench"
             "-passout" (str "pass:" pass)]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true) (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info (str "openssl pkcs12 failed: "
                           (slurp (.getInputStream proc))) {})))
    [p12 pass]))

(defonce ^:private netty-h3-state (atom nil))
(defonce ^:private jetty-h3-state (atom nil))

(defn netty-h3-stop! []
  (when-let [h @netty-h3-state]
    (enso.bench.NettyH3BenchServer/stop h)
    (reset! netty-h3-state nil))
  :stopped)

(defn netty-h3-start!
  ([] (netty-h3-start! {:port 18444}))
  ([{:keys [port]}]
   (netty-h3-stop!)
   (let [[cert key] (gen-cert-key!)
         h (enso.bench.NettyH3BenchServer/start port cert key)]
     (reset! netty-h3-state h)
     {:h3-url (str "https://127.0.0.1:" port "/nope")})))

(defn jetty-h3-stop! []
  (when-let [h @jetty-h3-state]
    (enso.bench.JettyH3BenchServer/stop h)
    (reset! jetty-h3-state nil))
  :stopped)

(defn jetty-h3-start!
  ([] (jetty-h3-start! {:port 18445}))
  ([{:keys [port]}]
   (jetty-h3-stop!)
   (let [[cert key] (gen-cert-key!)
         [p12 pass] (gen-p12! cert key)
         h (enso.bench.JettyH3BenchServer/start port cert key p12 pass)]
     (reset! jetty-h3-state h)
     {:h3-url (str "https://127.0.0.1:" port "/nope")})))

(defn compare-h3!
  "Boot enso, Netty, Jetty h3 servers on distinct UDP ports, drive
  identical `clients × per-client` quiche-client load against each,
  return the wall-time / rps results side by side. Warms up each server
  first to amortise JIT + TLS handshake."
  ([] (compare-h3! {:clients 32 :per-client 1000}))
  ([opts]
   (let [enso-url (:h3-url (h3-start! {:h3-port 18443}))
         netty-url (:h3-url (netty-h3-start!))
         jetty-url (:h3-url (jetty-h3-start!))
         ;; JIT + TLS-cache warmup. Three passes with the real workload
         ;; shape so tier-1 → tier-4 promotion + session cache warm-up
         ;; happen on the same call sites we then measure. Two passes
         ;; are usually enough for HotSpot; the third is cheap insurance.
         warmup {:clients 4 :per-client 100}
         run (fn [label url]
               (drive-h3! url warmup)
               (drive-h3! url warmup)
               (drive-h3! url warmup)
               (let [r (drive-h3! url opts)]
                 [label (select-keys r [:total-req :wall-ms :rps-est
                                        :ok-clients :fail-clients])]))
         results (into {} [(run :enso enso-url)
                           (run :netty netty-url)
                           (run :jetty jetty-url)])]
     (h3-stop!)
     (netty-h3-stop!)
     (jetty-h3-stop!)
     {:opts opts
      :results results
      :rps-ranking (->> results
                        (map (fn [[k v]] [k (:rps-est v)]))
                        (sort-by second >)
                        (into []))})))

;; --- Allocation profiling --------------------------------------------------

(defn profile-alloc-h3!
  "Attaches async-profiler in alloc mode, drives h3 load via quiche-client fanout,
  dumps flamegraph. h3-start! must be live."
  [{:keys [clients per-client interval]
    :or {clients 8 per-client 500 interval 1048576}}]
  (let [{:keys [h3-port]} @h3-state
        _ (when-not h3-port (throw (ex-info "h3-start! first" {})))
        url (str "https://127.0.0.1:" h3-port "/nope")]
    ;; Warmup — fill JIT + zero-alloc paths.
    (drive-h3! url {:clients 2 :per-client 50})
    (prof/start {:event :alloc :interval interval})
    (let [result (drive-h3! url {:clients clients :per-client per-client})
          f (prof/stop {:generate-flamegraph? true})
          collapsed (str/replace (.getPath f) #"-flamegraph\.html$" "-collapsed.txt")
          total (when (.exists (io/file collapsed))
                  (with-open [r (io/reader collapsed)]
                    (reduce (fn [acc line]
                              (let [space (str/last-index-of line " ")]
                                (+ acc (Long/parseLong (subs line (inc space))))))
                            0
                            (line-seq r))))]
      {:flamegraph (.getPath f)
       :collapsed collapsed
       :load result
       :alloc-total-samples total
       :samples-per-req (when (and total (:total-req result) (pos? (:total-req result)))
                          (double (/ total (:total-req result))))})))

(defn profile-alloc-h3-jfr!
  "JFR-based allocation profiler for h3. Uses the JVM's built-in
  jdk.ObjectAllocationSample event stream (JEP 331, always enabled at low
  overhead on JDK 16+). Sidesteps async-profiler's SIGABRT-in-GC-thread
  crashes we hit at task #76 on JDK 25 + FFM.

  Returns {jfr-path, top-classes, load} — a small aggregated report over
  the recording plus the raw .jfr for deeper drill-down via `jfr print`."
  [{:keys [clients per-client]
    :or {clients 4 per-client 200}}]
  (let [{:keys [h3-port]} @h3-state
        _ (when-not h3-port (throw (ex-info "h3-start! first" {})))
        url (str "https://127.0.0.1:" h3-port "/nope")
        jfr-path (java.nio.file.Paths/get
                  "/tmp/enso-h3-alloc.jfr" (make-array String 0))
        recording (jdk.jfr.Recording.)]
    ;; Warmup.
    (drive-h3! url {:clients 2 :per-client 50})
    ;; Enable the two allocation events. jdk.ObjectAllocationSample is
    ;; the low-overhead sampling event (default rate ≈ 100 Hz per class);
    ;; jdk.ObjectAllocationInNewTLAB fires on every TLAB refill and gives
    ;; higher-resolution data at higher cost.
    (doto recording
      (.enable "jdk.ObjectAllocationSample")
      (.enable "jdk.ObjectAllocationInNewTLAB")
      (.setToDisk true)
      (.setDestination jfr-path)
      (.start))
    (let [result (drive-h3! url {:clients clients :per-client per-client})]
      (.stop recording)
      (.close recording)
      (let [top (with-open [it (jdk.jfr.consumer.RecordingFile. jfr-path)]
                  (loop [counts (transient {})]
                    (if (.hasMoreEvents it)
                      (let [ev (.readEvent it)
                            klass-field (.getValue ev "objectClass")
                            klass-name (some-> klass-field .getName)]
                        (recur (if klass-name
                                 (assoc! counts klass-name
                                         (inc (or (get counts klass-name) 0)))
                                 counts)))
                      (persistent! counts))))
            ranked (->> top
                        (sort-by (comp - val))
                        (take 15))]
        {:jfr (.toString jfr-path)
         :load result
         :top-classes ranked
         :total-events (reduce + (vals top))}))))

(defn profile-cpu-h3!
  [{:keys [clients per-client]
    :or {clients 8 per-client 500}}]
  (let [{:keys [h3-port]} @h3-state
        _ (when-not h3-port (throw (ex-info "h3-start! first" {})))
        url (str "https://127.0.0.1:" h3-port "/nope")]
    (drive-h3! url {:clients 2 :per-client 50})
    (prof/start {:event :cpu})
    (let [result (drive-h3! url {:clients clients :per-client per-client})
          f (prof/stop {:generate-flamegraph? true})]
      {:flamegraph (.getPath f)
       :load result})))

;; --- Allocation profiling (h1) ---------------------------------------------

(defn profile-alloc!
  [url {:keys [duration depth interval connections]
        :or {duration "10s" depth 1 interval 1048576 connections 64}}]
  (prof/start {:event :alloc :interval interval})
  (let [result (wrk! url {:duration duration :depth depth :connections connections})
        f (prof/stop {:generate-flamegraph? true})
        collapsed (str/replace (.getPath f) #"-flamegraph\.html$" "-collapsed.txt")
        total (when (.exists (io/file collapsed))
                (with-open [r (io/reader collapsed)]
                  (reduce (fn [acc line]
                            (let [space (str/last-index-of line " ")]
                              (+ acc (Long/parseLong (subs line (inc space))))))
                          0
                          (line-seq r))))
        n-req (some-> (:rps result) (* (Double/parseDouble
                                        (str/replace duration #"[a-z]" ""))))]
    {:flamegraph (.getPath f)
     :collapsed collapsed
     :rps (:rps result)
     :alloc-total-samples total
     :samples-per-req (when (and total n-req (pos? n-req))
                        (double (/ total n-req)))}))

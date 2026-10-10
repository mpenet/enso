;; ABOUTME: Cross-server comparison driver: runs s-exp.enso-perf against enso and peer servers (each in
;; ABOUTME: its own JVM) in interleaved rounds, then writes medians, ranges and machine load per run.
(ns enso.compare
  "Run with `clojure -M:bench/compare [OPTS-EDN]`, e.g.
  `clojure -M:bench/compare '{:rounds 5 :servers [:enso :jetty]}'`.

  Every round starts each server in a fresh JVM (`:server-jvm-opts`, the
  same for all) and runs the scenarios it supports through
  `s-exp.enso-perf`, which checks a response before measuring and
  measures allocation inside the server JVM. The server order rotates
  from round to round. Before each server run the driver waits up to
  `:load-wait-s` for the 1-minute load average to fall under `:max-load`
  and records it.

  Options (all optional):
  - `:servers` subset of the keys of `servers` (default all)
  - `:scenarios` subset of :h1-wrk :h1-wrk-pipelined :h2-get :h3-get :ws-echo
  - `:rounds` (default 3)
  - `:duration-s` / `:warmup-s` per scenario (default 10 / 10)
  - `:max-load` / `:load-wait-s` (default 4.0 / 180)
  - `:server-jvm-opts` (default [\"-Xmx1g\"])
  - `:out-dir` (default \"target/compare\")

  Results: `<out-dir>/summary.{edn,md}`, and every run's own perf
  results under `<out-dir>/round-N/<server>/`."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [s-exp.enso-perf :as perf])
  (:import (java.lang.management ManagementFactory)
           (java.time Instant)))

(set! *warn-on-reflection* true)

(def servers
  "Server id -> deps alias starting it, the scenarios it serves and the
  options its process gets (enso: the perf harness defaults, unlimited
  keep-alive requests and no body cap)."
  {:enso {:alias "test-server" :scenarios [:h1-wrk :h1-wrk-pipelined :h2-get :h3-get :ws-echo]}
   :http-kit {:alias "bench/http-kit" :server-opts {} :scenarios [:h1-wrk :h1-wrk-pipelined :ws-echo]}
   :jetty {:alias "bench/jetty" :server-opts {} :scenarios [:h1-wrk :h1-wrk-pipelined :h2-get :h3-get :ws-echo]}
   :jetty-virtual {:alias "bench/jetty" :server-opts {:virtual-threads? true}
                   :scenarios [:h1-wrk :h1-wrk-pipelined :h2-get :h3-get :ws-echo]}
   :aleph {:alias "bench/aleph" :server-opts {} :scenarios [:h1-wrk :h1-wrk-pipelined :h2-get :ws-echo]}
   :netty {:alias "bench/netty" :server-opts {} :scenarios [:h3-get]}})

(def ^:private defaults
  {:servers [:enso :http-kit :jetty :jetty-virtual :aleph :netty]
   :scenarios [:h1-wrk :h1-wrk-pipelined :h2-get :h3-get :ws-echo]
   :rounds 3
   :duration-s 10
   :warmup-s 10
   :max-load 4.0
   :load-wait-s 180
   :server-jvm-opts ["-Xmx1g"]
   :out-dir "target/compare"})

(defn- load-1m ^double []
  (.getSystemLoadAverage (ManagementFactory/getOperatingSystemMXBean)))

(defn- await-quiet!
  "Waits up to `wait-s` for the 1-minute load average to drop under
  `max-load`; returns the load average when it stops waiting."
  [max-load wait-s]
  (let [deadline (+ (System/currentTimeMillis) (* 1000 (long wait-s)))]
    (loop []
      (let [l (load-1m)]
        (if (or (< l (double max-load)) (> (System/currentTimeMillis) deadline))
          l
          (do (Thread/sleep 5000) (recur)))))))

(defn- rotate [xs n]
  (let [n (mod n (count xs))]
    (concat (drop n xs) (take n xs))))

(defn- run-server!
  "One perf run of `server` over the scenarios both it and `cfg` select."
  [{:keys [scenarios duration-s warmup-s server-jvm-opts out-dir max-load load-wait-s]} round server]
  (let [{:keys [alias server-opts] :as spec} (servers server)
        selected (filterv (set (:scenarios spec)) scenarios)
        load-before (await-quiet! max-load load-wait-s)
        uptime (str/trim (:out (sh/sh "uptime")))
        _ (println (str "round " round " " (name server) " " selected " load " load-before))
        result (try
                 (perf/run (cond-> {:server-alias alias
                                    :scenarios selected
                                    :duration-s duration-s
                                    :warmup-s warmup-s
                                    :server-jvm-opts server-jvm-opts
                                    :out-dir (str (io/file out-dir (str "round-" round) (name server)))}
                             server-opts (assoc :server-opts server-opts)))
                 (catch Exception e
                   {:failed (.getMessage e)}))]
    {:round round
     :server server
     :load-before load-before
     :load-after (load-1m)
     :uptime uptime
     :scenarios (:scenarios result)
     :failed (:failed result)}))

(defn- median [xs]
  (let [v (vec (sort xs))
        n (count v)]
    (when (pos? n)
      (if (odd? n)
        (v (quot n 2))
        (/ (+ (v (dec (quot n 2))) (v (quot n 2))) 2.0)))))

(defn- summarize
  "Per scenario and server: median, min and max req/s, median allocation
  and latency, summed errors over the measured runs."
  [runs]
  (let [cells (for [{:keys [server scenarios]} runs
                    [scenario r] scenarios
                    :when (not (:skipped r))]
                [[scenario server] r])
        skipped (for [{:keys [server scenarios]} runs
                      [scenario r] scenarios
                      :when (:skipped r)]
                  [scenario server (:skipped r)])]
    {:cells (into (sorted-map)
                  (for [[k rs] (group-by first cells)
                        :let [rs (map second rs)
                              rps (map :rps rs)
                              allocs (keep :alloc-bytes-per-request rs)]]
                    [k {:runs (count rs)
                        :rps (median rps)
                        :rps-min (apply min rps)
                        :rps-max (apply max rps)
                        :alloc (median allocs)
                        :alloc-min (when (seq allocs) (apply min allocs))
                        :alloc-max (when (seq allocs) (apply max allocs))
                        :p50 (median (keep (comp :p50 :latency-ms) rs))
                        :p99 (median (keep (comp :p99 :latency-ms) rs))
                        :errors (reduce + 0 (keep :errors rs))
                        :non-2xx (reduce + 0 (keep :non-2xx rs))
                        :verified (:verified (first rs))}]))
     :skipped (vec (distinct skipped))}))

(defn- fmt-num [x]
  (cond
    (nil? x) "–"
    (and (number? x) (< (double x) 100)) (format "%.2f" (double x))
    :else (format "%,d" (Math/round (double x)))))

(defn- summary-md [{:keys [meta config summary runs]}]
  (str "# Cross-server comparison " (:timestamp meta) "\n\n"
       "git " (:git meta) ", " (:java meta) ", " (:os meta) ", " (:cpus meta) " CPUs, "
       (:rounds config) " rounds, " (:duration-s config) " s measured after " (:warmup-s config)
       " s warm-up, server JVM " (pr-str (:server-jvm-opts config)) "\n\n"
       (str/join
        (for [[scenario cells] (group-by (comp first key) (:cells summary))]
          (str "## " (name scenario) "\n\n"
               "| server | req/s | min | max | alloc B/req | alloc range | p50 ms | p99 ms | errors | non-2xx |\n"
               "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
               (str/join
                (for [[[_ server] c] (sort-by (comp - :rps val) cells)]
                  (str "| " (name server) " | " (fmt-num (:rps c)) " | " (fmt-num (:rps-min c)) " | "
                       (fmt-num (:rps-max c)) " | " (fmt-num (:alloc c)) " | "
                       (fmt-num (:alloc-min c)) "–" (fmt-num (:alloc-max c)) " | "
                       (fmt-num (:p50 c)) " | " (fmt-num (:p99 c)) " | " (:errors c) " | " (:non-2xx c) " |\n")))
               "\n")))
       (when (seq (:skipped summary))
         (str "## Skipped\n\n"
              (str/join (for [[scenario server why] (:skipped summary)]
                          (str "- " (name server) " " (name scenario) ": " why "\n")))
              "\n"))
       "## Load per run\n\n| round | server | 1-min load before | after | uptime |\n|---:|---|---:|---:|---|\n"
       (str/join (for [{:keys [round server load-before load-after uptime failed]} runs]
                   (format "| %d | %s | %.2f | %.2f | %s%s |\n" round (name server) load-before load-after uptime
                           (if failed (str " (failed: " failed ")") ""))))))

(defn run
  "Runs the comparison with `opts` over the defaults; returns the result
  (also written to :out-dir)."
  [opts]
  (let [cfg (merge defaults opts)
        runs (vec (for [round (range 1 (inc (long (:rounds cfg))))
                        server (rotate (:servers cfg) (dec round))]
                    (run-server! cfg round server)))
        result {:meta {:timestamp (str (Instant/now))
                       :git (str/trim (:out (sh/sh "git" "rev-parse" "--short" "HEAD")))
                       :java (System/getProperty "java.vm.version")
                       :os (str (System/getProperty "os.name") " " (System/getProperty "os.arch"))
                       :cpus (.availableProcessors (Runtime/getRuntime))}
                :config cfg
                :summary (summarize runs)
                :runs runs}
        dir (io/file (:out-dir cfg))]
    (.mkdirs dir)
    (spit (io/file dir "summary.edn") (pr-str result))
    (spit (io/file dir "summary.md") (summary-md result))
    (println (summary-md result))
    result))

(defn -main [& args]
  (run (if (seq args) (edn/read-string (first args)) {}))
  (shutdown-agents)
  (System/exit 0))

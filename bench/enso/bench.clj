(ns enso.bench
  "Side-by-side bench harness for Enso, http-kit, Jetty (ring-jetty-adapter),
  and Aleph. Boots all servers in one JVM, drives wrk against each, aggregates
  throughput + latency percentiles, and profiles allocation via
  clj-async-profiler."
  (:require [aleph.http :as aleph]
            [clj-async-profiler.core :as prof]
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
  (let [{:keys [enso-srv hk-stop jetty-srv aleph-srv]} @state]
    (when enso-srv (enso/stop enso-srv))
    (when hk-stop (hk-stop))
    (when jetty-srv (.stop jetty-srv))
    (when aleph-srv (.close aleph-srv)))
  (reset! state {})
  :stopped)

(defn start!
  "Starts all servers on the given ports. Idempotent - existing instances are
  stopped first."
  ([]
   (start! {:enso 8080 :httpkit 8081 :jetty 8082 :aleph 8083}))
  ([ports]
   (stop!)
   (let [enso-srv (enso/run-server plaintext-handler {:port (:enso ports)})
         hk-stop (httpkit/run-server plaintext-handler
                                     {:port (:httpkit ports)
                                      :thread 8
                                      :worker-name-prefix "hk-"})
         jetty-srv (jetty/run-jetty plaintext-handler
                                    {:port (:jetty ports)
                                     :join? false})
         aleph-srv (aleph/start-server plaintext-handler
                                       {:port (:aleph ports)})]
     (reset! state {:enso-srv enso-srv
                    :hk-stop hk-stop
                    :jetty-srv jetty-srv
                    :aleph-srv aleph-srv
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
  depth (1 for non-pipelined). Warms up first, then benches for `duration`."
  ([url] (wrk! url {}))
  ([url {:keys [duration threads connections depth latency? warmup]
         :or {duration "8s" threads 4 connections 64 depth 1
              latency? true warmup "5s"}}]
   (let [base (if (> depth 1)
                (let [f (write-lua! depth "/nope")]
                  [(str "-t" threads) (str "-c" connections) "-s" f])
                [(str "-t" threads) (str "-c" connections)])
         with-dur (fn [d]
                    (concat base (when latency? ["--latency"])
                            [(str "-d" d) url]))]
     (apply sh/sh "wrk" (with-dur warmup))
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
         targets [:enso :httpkit :jetty :aleph]}}]
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

;; --- Allocation profiling --------------------------------------------------

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

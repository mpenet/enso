;; ABOUTME: What every server process driven by the perf harness shares: the hello response, the
;; ABOUTME: /__stats allocation and GC counters, argument parsing and the READY handshake.
(ns s-exp.perf-target
  "Server processes started by `s-exp.enso-perf` (enso's test server and
  the peer servers under bench/enso/peer) take `[h1 PORT] [h2 PORT]
  [h3 PORT] ...` arguments, answer `GET /__stats` on the h1 port with
  `stats` as EDN and print `READY ...` once listening."
  (:require [clojure.edn :as edn])
  (:import (java.lang.management GarbageCollectorMXBean ManagementFactory)
           (java.io InputStream IOException OutputStream)))

(set! *warn-on-reflection* true)

(def hello-body "Hello, World!")

(def hello-response
  {:status 200
   :headers {"content-type" "text/plain"}
   :body hello-body})

(defn stats
  "Process counters: total bytes allocated by all threads (carriers of
  virtual threads included), GC count and time."
  []
  (let [gcs (ManagementFactory/getGarbageCollectorMXBeans)]
    {:allocated-bytes (.getTotalThreadAllocatedBytes
                       ^com.sun.management.ThreadMXBean (ManagementFactory/getThreadMXBean))
     :gc-count (reduce + 0 (map #(.getCollectionCount ^GarbageCollectorMXBean %) gcs))
     :gc-ms (reduce + 0 (map #(.getCollectionTime ^GarbageCollectorMXBean %) gcs))}))

(defn stats-response []
  {:status 200
   :headers {"content-type" "application/edn"}
   :body (pr-str (stats))})

(defn websocket-upgrade? [request]
  (some-> ^String (get-in request [:headers "upgrade"]) .toLowerCase (= "websocket")))

(defn drain!
  "Reads a request body to its end, if there is one. The first byte is
  read on its own so that an empty body (some servers pass an empty
  stream for a GET) doesn't pay for the buffer `transferTo` allocates."
  [body]
  (when (instance? InputStream body)
    (try
      (let [^InputStream in body]
        (when-not (neg? (.read in))
          (.transferTo in (OutputStream/nullOutputStream))))
      (catch IOException _))))

(defn ring-handler
  "The Ring handler peer servers run: WebSocket upgrades go to `upgrade`,
  `/__stats` answers `stats`, anything else drains the body and answers
  `hello-response`."
  [upgrade]
  (fn [request]
    (cond
      (websocket-upgrade? request) (upgrade request)
      (= "/__stats" (:uri request)) (stats-response)
      :else (do (drain! (:body request)) hello-response))))

(defn parse-args
  "`[\"h1\" \"8080\" \"opts\" \"{...}\"]` -> {:h1 8080 :opts {...}}."
  [args]
  (into {}
        (map (fn [[k v]]
               (let [k (keyword k)]
                 [k (if (= :opts k) (edn/read-string v) (Integer/parseInt v))])))
        (partition 2 args)))

(defn serve!
  "Announces READY for `ports`, runs `stop` on JVM shutdown and blocks."
  [ports stop]
  (.addShutdownHook (Runtime/getRuntime) (Thread. ^Runnable stop))
  (println "READY" (pr-str ports))
  (flush)
  @(promise))

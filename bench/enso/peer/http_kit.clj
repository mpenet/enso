;; ABOUTME: http-kit target process for the cross-server comparison: plain HTTP/1.1 and a
;; ABOUTME: WebSocket echo on the h1 port, default worker pool, driven by s-exp.enso-perf.
(ns enso.peer.http-kit
  "Run with `clojure -M:bench/http-kit h1 PORT`. http-kit has no HTTP/2 or
  HTTP/3 server. Workers: http-kit's default pool (`:thread 4`)."
  (:require [org.httpkit.server :as http-kit]
            [s-exp.perf-target :as target]))

(set! *warn-on-reflection* true)

(defn- echo [request]
  (http-kit/as-channel request {:on-receive (fn [ch message] (http-kit/send! ch message))}))

(defn -main [& args]
  (let [{:keys [h1] :as ports} (target/parse-args args)
        server (http-kit/run-server (target/ring-handler echo)
                                    {:ip "127.0.0.1" :port h1 :legacy-return-value? false})]
    (target/serve! ports (fn [] @(http-kit/server-stop! server)))))

;; ABOUTME: Standalone enso server process used as the target of conformance suites
;; ABOUTME: (h2spec, Autobahn, h3spec) and of the out-of-process load/allocation harness.
(ns s-exp.enso-test-server
  "Run with `clojure -M:test-server [h1 PORT] [h2c PORT] [h2 PORT] [h3 PORT] [opts EDN]`.

  - h1: plain HTTP/1.1 + WebSocket echo (any request carrying
    `Upgrade: websocket` is echoed back message by message)
  - h2c: plain listener serving HTTP/1.1 and cleartext HTTP/2 with prior
    knowledge (`:http2c`)
  - h2: TLS listener advertising h2 + http/1.1 (self-signed cert)
  - h3: QUIC/HTTP/3 listener on that UDP port (needs the JNI shim)

  `opts` is an EDN map merged into every `run-server` option map.

  `GET /__stats` answers an EDN map of process counters (total bytes
  allocated by all threads, GC count and time) for the load harness.
  `/upload` reads the request body to its end and answers its length.
  Every other request is answered `200 text/plain \"Hello, World!\"`.
  Prints `READY ...` on stdout once every listener is bound."
  (:require [clojure.edn :as edn]
            [s-exp.enso :as enso]
            [s-exp.enso-test-support :as support])
  (:import (com.s_exp.enso.api WebSocketSocket)
           (java.lang.management GarbageCollectorMXBean ManagementFactory)
           (java.nio ByteBuffer)))

(set! *warn-on-reflection* true)

(def ^:private hello-response
  {:status 200
   :headers {"content-type" "text/plain"}
   :body "Hello, World!"})

(def ^:private echo-listener
  {:on-message (fn [^WebSocketSocket socket message]
                 (if (instance? CharSequence message)
                   (.sendText socket ^CharSequence message)
                   (.sendBinary socket ^ByteBuffer message)))})

(defn- websocket-upgrade? [request]
  (some-> ^String (get-in request [:headers "upgrade"]) .toLowerCase (= "websocket")))

(defn- stats []
  (let [gcs (ManagementFactory/getGarbageCollectorMXBeans)]
    {:allocated-bytes (.getTotalThreadAllocatedBytes
                       ^com.sun.management.ThreadMXBean (ManagementFactory/getThreadMXBean))
     :gc-count (reduce + 0 (map #(.getCollectionCount ^GarbageCollectorMXBean %) gcs))
     :gc-ms (reduce + 0 (map #(.getCollectionTime ^GarbageCollectorMXBean %) gcs))}))

(defn handler [request]
  (cond
    (websocket-upgrade? request) {:ring.websocket/listener echo-listener}
    (= "/__stats" (:uri request)) {:status 200
                                   :headers {"content-type" "application/edn"}
                                   :body (pr-str (stats))}
    (= "/upload" (:uri request)) {:status 200
                                  :headers {"content-type" "text/plain"}
                                  :body (str (if-let [^java.io.InputStream body (:body request)]
                                               (.transferTo body (java.io.OutputStream/nullOutputStream))
                                               0))}
    ;; The body is read to its end first: h2spec's body-validation cases
    ;; need the server still reading the stream when the bad frames arrive
    ;; (an answer before them resets the stream, and later frames on it are
    ;; ignored, RFC 9113 §5.1).
    :else (do (when-let [^java.io.InputStream body (:body request)]
                (try
                  (.transferTo body (java.io.OutputStream/nullOutputStream))
                  (catch java.io.IOException _)))
              hello-response)))

(defn- parse-args [args]
  (into {}
        (map (fn [[k v]]
               (let [k (keyword k)]
                 [k (if (= :opts k) (edn/read-string v) (Integer/parseInt v))])))
        (partition 2 args)))

(defn start!
  "Starts the listeners named in `ports` ({:h1 n :h2c n :h2 n :h3 n :opts m});
  returns the started servers."
  [{:keys [h1 h2c h2 h3 opts]}]
  (let [[cert key] (when h3 (support/pem-cert-pair))
        plain (when h1
                (enso/run-server handler (merge {:host "127.0.0.1" :port h1} opts)))
        cleartext-h2 (when h2c
                       (enso/run-server handler (merge {:host "127.0.0.1" :port h2c :http2c true} opts)))
        tls (when (or h2 h3)
              (enso/run-server handler
                               (cond-> {:host "127.0.0.1"
                                        :port (or h2 0)
                                        :http2 true
                                        :ssl-context (support/server-ssl-context)}
                                 h3 (assoc :http3 true
                                           :http3-port h3
                                           :http3-cert-path cert
                                           :http3-key-path key)
                                 true (merge opts))))]
    (remove nil? [plain cleartext-h2 tls])))

(defn -main [& args]
  (let [ports (parse-args args)
        servers (start! ports)]
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. ^Runnable (fn [] (run! enso/stop servers))))
    (println "READY" (pr-str ports))
    (flush)
    @(promise)))

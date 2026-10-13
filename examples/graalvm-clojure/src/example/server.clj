;; ABOUTME: GraalVM native-image example using the Clojure run-server API. Plaintext HTTP/1.1 +
;; ABOUTME: HTTP/2 with HTTP/3 off; serves TLS when ENSO_TLS_CERT and ENSO_TLS_KEY are set.
(ns example.server
  (:require [s-exp.enso :as enso])
  (:gen-class))

(defn handler [_request]
  {:status 200
   :headers {"content-type" "text/plain"}
   :body "hello from native clojure enso\n"})

(defn -main [& args]
  (let [cert (System/getenv "ENSO_TLS_CERT")
        key (System/getenv "ENSO_TLS_KEY")
        tls (and cert key)
        port (if (seq args)
               (Integer/parseInt (first args))
               (if tls 8443 8080))
        opts (cond-> {:host "127.0.0.1" :port port}
               tls (assoc :ssl-cert-path cert :ssl-key-path key))]
    (enso/run-server handler opts)
    (println "enso listening on" port (if tls "(tls)" ""))
    @(promise)))

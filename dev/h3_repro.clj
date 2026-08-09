(ns h3-repro
  (:require [s-exp.enso :as enso])
  (:import (java.nio.file Files)
           (java.nio.file.attribute FileAttribute)))

(defn- gen-cert []
  (let [dir (Files/createTempDirectory "enso-h3" (into-array FileAttribute []))
        cert (str (.resolve dir "cert.pem"))
        key (str (.resolve dir "key.pem"))
        p (-> (ProcessBuilder. ^java.util.List
               ["openssl" "req" "-x509" "-newkey" "rsa:2048"
                "-keyout" key "-out" cert "-sha256" "-days" "1" "-nodes"
                "-subj" "/CN=localhost"
                "-addext" "subjectAltName=DNS:localhost,IP:127.0.0.1"])
              (.redirectErrorStream true)
              (.start))]
    (.waitFor p)
    [cert key]))

(defn -main [& _]
  (let [[c k] (gen-cert)]
    (enso/run-server
     (fn [_] {:status 200 :headers {"content-type" "text/plain"} :body "nf"})
     {:port 0
      :http3 true
      :http3-port 18443
      :http3-cert-path c
      :http3-key-path k}))
  (println "READY: h3 on 18443")
  (flush)
  @(promise))

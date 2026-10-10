;; ABOUTME: Aleph target process for the cross-server comparison: HTTP/1.1 and WebSocket echo on
;; ABOUTME: the h1 port, HTTP/2 + HTTP/1.1 over TLS on the h2 port, driven by s-exp.enso-perf.
(ns enso.peer.aleph
  "Run with `clojure -M:bench/aleph h1 PORT h2 PORT [opts EDN]`. Aleph's
  defaults: handlers run on its utilization executor (up to 512 threads),
  NIO transport. `opts` is merged into the start-server options. TLS uses
  the JDK provider and the same keytool certificate as enso's test server.
  Aleph has no HTTP/3 server."
  (:require [aleph.http :as http]
            [aleph.netty :as netty]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [s-exp.enso-test-support :as support]
            [s-exp.perf-target :as target])
  (:import (java.io Closeable FileInputStream)
           (java.net InetSocketAddress)
           (java.security KeyStore PrivateKey)
           (java.security.cert X509Certificate)))

(set! *warn-on-reflection* true)

(defn- echo [request]
  (d/let-flow [conn (http/websocket-connection request)]
              (s/connect conn conn)
              nil))

(defn- ssl-context []
  (let [file (support/self-signed-keystore)
        pass (.toCharArray ^String support/keystore-password)
        ks (KeyStore/getInstance "PKCS12")]
    (with-open [in (FileInputStream. file)]
      (.load ks in pass))
    (.delete file)
    (netty/ssl-server-context
     {:private-key ^PrivateKey (.getKey ks "enso" pass)
      :certificate-chain (into-array X509Certificate (.getCertificateChain ks "enso"))
      :ssl-provider :jdk
      :application-protocol-config (netty/application-protocol-config [:http2 :http1])})))

(defn -main [& args]
  (let [{:keys [h1 h2 opts] :as ports} (target/parse-args args)
        handler (target/ring-handler echo)
        servers (cond-> [(http/start-server handler (merge {:socket-address (InetSocketAddress. "127.0.0.1" (int h1))}
                                                           opts))]
                  h2 (conj (http/start-server handler (merge {:socket-address (InetSocketAddress. "127.0.0.1" (int h2))
                                                              :ssl-context (ssl-context)
                                                              :http-versions [:http2 :http1]}
                                                             opts))))]
    (target/serve! ports (fn [] (run! #(.close ^Closeable %) servers)))))

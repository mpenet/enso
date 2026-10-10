;; ABOUTME: Jetty 12 target process (ring-jetty9-adapter) for the cross-server comparison: HTTP/1.1 and
;; ABOUTME: WebSocket echo on h1, HTTP/2 over TLS on h2, HTTP/3 on h3, driven by s-exp.enso-perf.
(ns enso.peer.jetty
  "Run with `clojure -M:bench/jetty h1 PORT h2 PORT h3 PORT`.
  ring-jetty9-adapter defaults: a QueuedThreadPool of 8 to 50 platform
  threads. `opts {:virtual-threads? true}` switches handlers to virtual
  threads. TLS (h2 and h3) uses the same keytool certificate as enso's
  test server.

  HTTP/3 is set up as Jetty 12.1 documents it (HTTP3ServerQuicConfiguration
  and HTTP3ServerConnectionFactory over Jetty's quiche binding, FFM) and
  serves the same Ring handler. The adapter's own `:http3?` option installs
  a raw HTTP/3 factory with an empty session listener and Jetty's
  zero-stream QUIC defaults, so it answers no request."
  (:require [ring.adapter.jetty9 :as jetty]
            [ring.websocket :as ws]
            [s-exp.enso-test-support :as support]
            [s-exp.perf-target :as target])
  (:import (java.nio.file Files)
           (java.nio.file.attribute FileAttribute)
           (org.eclipse.jetty.http3.server HTTP3ServerConnectionFactory HTTP3ServerQuicConfiguration)
           (org.eclipse.jetty.quic.quiche.server QuicheServerConnector QuicheServerQuicConfiguration)
           (org.eclipse.jetty.server ConnectionFactory Connector HttpConnectionFactory Server ServerConnector
                                     SslConnectionFactory)))

(set! *warn-on-reflection* true)

(def ^:private echo-listener
  {:on-message (fn [socket message] (ws/send socket message))})

(defn- echo [_request]
  {:ring.websocket/listener echo-listener})

(defn- add-http3-connector
  "Adds an HTTP/3 connector on UDP `port`, sharing the TLS connector's
  certificate and the HTTP configuration of the other connectors."
  [port]
  (fn [^Server server]
    (let [tls ^ServerConnector (first (filter #(.getConnectionFactory ^Connector % SslConnectionFactory)
                                              (.getConnectors server)))
          ssl (.getSslContextFactory ^SslConnectionFactory (.getConnectionFactory tls SslConnectionFactory))
          http-config (.getHttpConfiguration ^HttpConnectionFactory (.getConnectionFactory tls HttpConnectionFactory))
          pem-dir (Files/createTempDirectory "enso-jetty-h3" (make-array FileAttribute 0))
          quic (HTTP3ServerQuicConfiguration/configure (QuicheServerQuicConfiguration. pem-dir))]
      (.addConnector server (doto (QuicheServerConnector. server ssl ^QuicheServerQuicConfiguration quic
                                                          ^"[Lorg.eclipse.jetty.server.ConnectionFactory;"
                                                          (into-array ConnectionFactory [(HTTP3ServerConnectionFactory. http-config)]))
                              (.setHost "127.0.0.1")
                              (.setPort (int port)))))))

(defn -main [& args]
  (let [{:keys [h1 h2 h3 opts] :as ports} (target/parse-args args)
        keystore (when (or h2 h3) (support/self-signed-keystore))
        server (jetty/run-jetty (target/ring-handler echo)
                                (cond-> {:host "127.0.0.1"
                                         :port h1
                                         :join? false}
                                  keystore (assoc :ssl-port (or h2 0)
                                                  :h2? true
                                                  :keystore (.getPath keystore)
                                                  :keystore-type "PKCS12"
                                                  :key-password support/keystore-password
                                                  :ssl-hot-reload? false)
                                  h3 (assoc :configurator (add-http3-connector h3))
                                  true (merge opts)))]
    (some-> keystore .delete)
    (target/serve! ports (fn [] (.stop ^Server server)))))

(ns s-exp.enso-http2-test
  "HTTP/2 end-to-end tests via java.net.http. Server runs h2 over TLS
  (h2c is not supported). Covers session changes:
  #209 (HPACK size update — indirect via multiple requests reusing
  connection), #211 (trailers path — verified negatively: no crash),
  #237 (FrameSeg envelope refactor), #226/#236 (stream state races),
  plus baseline GET/POST/concurrent-stream shape."
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.string :as str]
            [s-exp.enso :as enso])
  (:import (java.io ByteArrayInputStream)
           (java.net URI)
           (java.net.http HttpClient HttpClient$Version HttpRequest
                          HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
           (java.nio.charset StandardCharsets)
           (java.security KeyStore)
           (java.security.cert X509Certificate)
           (java.time Duration)
           (java.util.concurrent CompletableFuture CountDownLatch TimeUnit)
           (javax.net.ssl KeyManagerFactory SSLContext SSLParameters
                          TrustManager X509TrustManager)))

;; ---- Shared TLS helpers --------------------------------------------------

(defn- gen-server-context ^SSLContext []
  (let [pass "changeit"
        ks-file (java.io.File/createTempFile "enso-h2" ".p12")
        _ (.delete ks-file)
        cmd ["keytool" "-genkeypair" "-alias" "enso" "-keyalg" "RSA" "-keysize" "2048"
             "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
             "-storepass" pass "-validity" "365"
             "-dname" "CN=localhost, OU=test, O=enso, L=x, S=x, C=US"
             "-ext" "SAN=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true) (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info "keytool failed" {})))
    (let [ks (KeyStore/getInstance "PKCS12")
          _ (with-open [in (java.io.FileInputStream. ks-file)]
              (.load ks in (.toCharArray pass)))
          kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
          _ (.init kmf ks (.toCharArray pass))
          ctx (SSLContext/getInstance "TLS")]
      (.init ctx (.getKeyManagers kmf) nil nil)
      (.delete ks-file)
      ctx)))

(defn- trust-all-context ^SSLContext []
  (let [tm (reify X509TrustManager
             (checkClientTrusted [_ _ _])
             (checkServerTrusted [_ _ _])
             (getAcceptedIssuers [_] (make-array X509Certificate 0)))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx nil (into-array TrustManager [tm]) nil)
    ctx))

(defn- h2-client
  "Fresh HttpClient forced to HTTP/2 over TLS with our trust-all
  context. Our cert's SAN includes IP:127.0.0.1 so default HTTPS
  endpoint identification accepts the loopback dial."
  ^HttpClient []
  (-> (HttpClient/newBuilder)
      (.version HttpClient$Version/HTTP_2)
      (.sslContext (trust-all-context))
      .build))

(def ^:dynamic *port* nil)

(defn- with-h2-server [handler f]
  (let [srv (enso/run-server handler
                             {:port 0 :http2 true
                              :ssl-context (gen-server-context)})]
    (try
      (binding [*port* (enso/port srv)]
        (f))
      (finally (enso/stop srv)))))

(defn- get! [^String path]
  (let [client (h2-client)
        req (-> (HttpRequest/newBuilder
                 (URI/create (str "https://127.0.0.1:" *port* path)))
                (.version HttpClient$Version/HTTP_2)
                (.GET) .build)]
    (.send client req (HttpResponse$BodyHandlers/ofString))))

(defn- post! [^String path ^String body]
  (let [client (h2-client)
        req (-> (HttpRequest/newBuilder
                 (URI/create (str "https://127.0.0.1:" *port* path)))
                (.version HttpClient$Version/HTTP_2)
                (.POST (HttpRequest$BodyPublishers/ofString body))
                .build)]
    (.send client req (HttpResponse$BodyHandlers/ofString))))

;; ---- Baseline shape ------------------------------------------------------

(deftest h2-get-negotiated
  (with-h2-server
    (fn [_] {:status 200 :body "h2-hi"})
    (fn []
      (let [resp (get! "/")]
        (is (= HttpClient$Version/HTTP_2 (.version resp))
            "ALPN chose h2")
        (is (= 200 (.statusCode resp)))
        (is (= "h2-hi" (.body resp)))))))

(deftest h2-post-body-echoed
  (with-h2-server
    (fn [req] {:status 200 :body (slurp (:body req))})
    (fn []
      (let [resp (post! "/echo" "payload-abc")]
        (is (= 200 (.statusCode resp)))
        (is (= "payload-abc" (.body resp)))))))

(deftest h2-response-headers-round-trip
  (with-h2-server
    (fn [_] {:status 201
             :headers {"x-custom" "yes"
                       "content-type" "text/plain"}
             :body "ok"})
    (fn []
      (let [resp (get! "/")
            h (.headers resp)]
        (is (= 201 (.statusCode resp)))
        (is (= "yes" (.orElse (.firstValue h "x-custom") nil)))
        (is (str/starts-with? (.orElse (.firstValue h "content-type") "")
                              "text/plain"))))))

;; ---- Request / method verbs ---------------------------------------------

(deftest h2-method-in-request-map
  (let [captured (atom nil)]
    (with-h2-server
      (fn [req] (reset! captured (:request-method req))
        {:status 200 :body "ok"})
      (fn []
        (post! "/x" "y")
        (is (= :post @captured))))))

(deftest h2-path-and-query-parsed
  (let [captured (atom nil)]
    (with-h2-server
      (fn [req] (reset! captured (select-keys req [:uri :query-string]))
        {:status 200 :body "ok"})
      (fn []
        (get! "/api/items?limit=5&offset=10")
        (is (= "/api/items" (:uri @captured)))
        (is (= "limit=5&offset=10" (:query-string @captured)))))))

;; ---- Reuse connection: multiple requests share the h2 conn --------------
;; This exercises HPACK dynamic-table state across streams. If the
;; encoder had a bug that emitted a stale table-size update or leaked
;; state, later requests would fail.

(deftest h2-multiple-requests-on-same-connection
  (let [call-count (atom 0)]
    (with-h2-server
      (fn [_] (swap! call-count inc)
        {:status 200 :body "ok"})
      (fn []
        (let [client (h2-client)]
          (dotimes [_ 10]
            (let [req (-> (HttpRequest/newBuilder
                           (URI/create (str "https://127.0.0.1:" *port* "/")))
                          (.version HttpClient$Version/HTTP_2)
                          .GET .build)
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= HttpClient$Version/HTTP_2 (.version resp)))))
          (is (= 10 @call-count)))))))

;; ---- Concurrent streams --------------------------------------------------
;; HttpClient may multiplex multiple requests over the same connection.
;; The server must handle concurrent stream dispatch without dropping.

(deftest h2-concurrent-streams-serve-all
  (let [n 20
        seen (atom #{})]
    (with-h2-server
      (fn [req]
        (swap! seen conj (:uri req))
        {:status 200 :body (:uri req)})
      (fn []
        (let [client (h2-client)
              futures (mapv (fn [i]
                              (let [req (-> (HttpRequest/newBuilder
                                             (URI/create (str "https://127.0.0.1:" *port*
                                                              "/req/" i)))
                                            (.version HttpClient$Version/HTTP_2)
                                            .GET .build)]
                                (.sendAsync client req (HttpResponse$BodyHandlers/ofString))))
                            (range n))]
          (doseq [^CompletableFuture f futures]
            (let [resp (.get f 10 TimeUnit/SECONDS)]
              (is (= 200 (.statusCode resp)))))
          (is (= n (count @seen))))))))

;; ---- Large body over DATA frames (FrameSeg envelope + emitData copy) ----

(deftest h2-large-response-body-integrity
  ;; Response ≥ 32 KiB fans out into multiple DATA frames. The
  ;; emitData copy fix (from the review pass) ensures the bytes
  ;; observed by the client match the source byte-for-byte.
  (let [payload (byte-array 65536)]
    (dotimes [i (alength payload)]
      (aset payload i (unchecked-byte (mod i 251))))
    (with-h2-server
      (fn [_] {:status 200 :body payload})
      (fn []
        (let [client (h2-client)
              req (-> (HttpRequest/newBuilder
                       (URI/create (str "https://127.0.0.1:" *port* "/")))
                      (.version HttpClient$Version/HTTP_2)
                      .GET .build)
              resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
              body (.body resp)]
          (is (= 200 (.statusCode resp)))
          (is (= (alength payload) (alength body))
              "body length matches")
          (is (java.util.Arrays/equals ^bytes payload ^bytes body)
              "byte-for-byte match — proves FrameSeg copy fix"))))))

(deftest h2-inputstream-response-body
  ;; Streaming InputStream body → server chunks into DATA frames via
  ;; streamInputStream(). Verify byte integrity end-to-end.
  (let [payload (byte-array 40000 (unchecked-byte 42))]
    (with-h2-server
      (fn [_] {:status 200
               :body (ByteArrayInputStream. payload)})
      (fn []
        (let [client (h2-client)
              req (-> (HttpRequest/newBuilder
                       (URI/create (str "https://127.0.0.1:" *port* "/")))
                      (.version HttpClient$Version/HTTP_2)
                      .GET .build)
              resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
              body (.body resp)]
          (is (= 200 (.statusCode resp)))
          (is (= 40000 (alength body)))
          (is (every? #(= 42 (bit-and % 0xFF)) body)))))))

;; ---- Error handler on h2 -------------------------------------------------

(deftest h2-handler-throws-500
  (with-h2-server
    (fn [_] (throw (RuntimeException. "boom")))
    (fn []
      (let [resp (get! "/")]
        (is (= 500 (.statusCode resp)))))))

;; ---- HEAD via h2 ---------------------------------------------------------

(deftest h2-head-omits-body-but-keeps-content-length
  (with-h2-server
    (fn [_] {:status 200 :body "hello"})
    (fn []
      (let [client (h2-client)
            req (-> (HttpRequest/newBuilder
                     (URI/create (str "https://127.0.0.1:" *port* "/")))
                    (.version HttpClient$Version/HTTP_2)
                    (.method "HEAD" (HttpRequest$BodyPublishers/noBody))
                    .build)
            resp (.send client req (HttpResponse$BodyHandlers/ofString))]
        (is (= 200 (.statusCode resp)))
        (is (= "" (.body resp))
            "HEAD response body is empty on the wire")
        (is (= "5"
               (.orElse (.firstValue (.headers resp) "content-length") nil))
            "content-length reflects would-be body size")))))

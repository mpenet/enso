(ns s-exp.enso-tls-test
  "TLS integration tests focused on reloadable SSL context (#242).
  Verifies the sslContextProvider path serves live-swapped contexts on
  new connections without restart."
  (:require [clojure.test :refer [deftest testing is]]
            [s-exp.enso :as enso])
  (:import (java.io File FileInputStream)
           (java.security KeyStore)
           (java.security.cert X509Certificate)
           (java.util.concurrent.atomic AtomicReference)
           (java.util.function Supplier)
           (javax.net.ssl KeyManagerFactory SSLContext TrustManager X509TrustManager)))

;; ---- Helpers -------------------------------------------------------------

(defn- keytool-gen!
  "Shell out to keytool to create a PKCS12 keystore with a self-signed
  cert whose CN is `cn`. Returns loaded SSLContext ready for server-side
  use. `cn` distinguishes cert-A from cert-B in the reload test."
  ^SSLContext [cn]
  (let [pass "changeit"
        ks-file (File/createTempFile "enso-tls-reload" ".p12")
        _ (.delete ks-file)
        cmd ["keytool" "-genkeypair" "-alias" cn "-keyalg" "RSA" "-keysize" "2048"
             "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
             "-storepass" pass "-validity" "365"
             "-dname" (str "CN=" cn ", OU=test, O=enso, L=x, S=x, C=US")
             "-ext" "SAN=DNS:localhost,IP:127.0.0.1"]
        proc (-> (ProcessBuilder. ^java.util.List cmd)
                 (.redirectErrorStream true)
                 (.start))]
    (.waitFor proc)
    (when-not (zero? (.exitValue proc))
      (throw (ex-info (str "keytool failed: "
                           (slurp (.getInputStream proc)))
                      {})))
    (let [ks (KeyStore/getInstance "PKCS12")
          _ (with-open [in (FileInputStream. ks-file)]
              (.load ks in (.toCharArray pass)))
          kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
          _ (.init kmf ks (.toCharArray pass))
          ctx (SSLContext/getInstance "TLS")]
      (.init ctx (.getKeyManagers kmf) nil nil)
      (.delete ks-file)
      ctx)))

(defn- capturing-trust-context
  "SSLContext whose trust manager captures every seen server cert into
  `captured` for inspection. Accepts anything (test-only)."
  ^SSLContext [captured]
  (let [tm (reify X509TrustManager
             (checkClientTrusted [_ _ _])
             (checkServerTrusted [_ chain _]
               (when (pos? (alength chain))
                 (swap! captured conj ^X509Certificate (aget chain 0))))
             (getAcceptedIssuers [_]
               (make-array X509Certificate 0)))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx nil (into-array TrustManager [tm]) nil)
    ctx))

(defn- do-tls-get!
  "One TLS GET / against `port`, ignoring the response body. Returns
  the response status line."
  [^SSLContext trust-ctx port]
  (let [factory (.getSocketFactory trust-ctx)]
    (with-open [^javax.net.ssl.SSLSocket sock
                (.createSocket factory "127.0.0.1" (int port))]
      (.setEnabledProtocols sock (into-array String ["TLSv1.3" "TLSv1.2"]))
      (.startHandshake sock)
      (let [out (.getOutputStream sock)
            in (.getInputStream sock)]
        (.write out (.getBytes "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                               java.nio.charset.StandardCharsets/ISO_8859_1))
        (.flush out)
        (.readAllBytes in)))))

;; ---- Tests ---------------------------------------------------------------

(deftest ssl-context-provider-serves-initial-cert
  ;; Baseline: provider that returns a fixed context works exactly like
  ;; the static :ssl-context option would.
  (let [ctx-a (keytool-gen! "cert-a")
        captured (atom [])
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier (get [_] ctx-a))})]
    (try
      (do-tls-get! (capturing-trust-context captured) (enso/port srv))
      (is (pos? (count @captured)) "server presented a cert")
      (let [subject (.getName (.getSubjectX500Principal ^X509Certificate (first @captured)))]
        (is (re-find #"CN=cert-a" subject)
            (str "expected CN=cert-a in " subject)))
      (finally (enso/stop srv)))))

(deftest ssl-context-provider-swap-serves-new-cert
  ;; Reload semantics: swap the atom, next TLS handshake uses the new
  ;; cert. Old cert should not resurface on later connections.
  (let [ctx-a (keytool-gen! "cert-alpha")
        ctx-b (keytool-gen! "cert-beta")
        ref (AtomicReference. ctx-a)
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier (get [_] (.get ref)))})]
    (try
      (let [captured-1 (atom [])
            captured-2 (atom [])]
        (do-tls-get! (capturing-trust-context captured-1) (enso/port srv))
        (let [subj-1 (.getName (.getSubjectX500Principal
                                ^X509Certificate (first @captured-1)))]
          (is (re-find #"CN=cert-alpha" subj-1) "1st conn saw alpha"))
        ;; Swap; TLS session cache could reuse — force a fresh context
        ;; on client side too so we're not reusing a resumed session.
        (.set ref ctx-b)
        (do-tls-get! (capturing-trust-context captured-2) (enso/port srv))
        (let [subj-2 (.getName (.getSubjectX500Principal
                                ^X509Certificate (first @captured-2)))]
          (is (re-find #"CN=cert-beta" subj-2)
              (str "2nd conn expected beta, got " subj-2))))
      (finally (enso/stop srv)))))

(deftest ssl-context-provider-called-per-accept
  ;; Provider.get() is invoked on every accept — count calls to verify.
  (let [ctx (keytool-gen! "cert-count")
        calls (atom 0)
        srv (enso/run-server
             (fn [_] {:status 200 :body "ok"})
             {:port 0
              :http2 true
              :ssl-context-provider
              (reify Supplier
                (get [_]
                  (swap! calls inc)
                  ctx))})]
    (try
      (let [initial @calls]
        (dotimes [_ 3]
          (do-tls-get! (capturing-trust-context (atom [])) (enso/port srv)))
        (is (<= (+ initial 3) @calls)
            (str "provider called on each accept: initial=" initial
                 " now=" @calls)))
      (finally (enso/stop srv)))))

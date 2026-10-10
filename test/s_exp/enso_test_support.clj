;; ABOUTME: Shared helpers for the property, fuzz, soak and conformance namespaces:
;; ABOUTME: self-signed certificates, trust-all TLS clients, shim detection, bounded waits.
(ns s-exp.enso-test-support
  (:import (java.io File FileInputStream)
           (java.net DatagramSocket InetAddress)
           (java.nio.file Files)
           (java.nio.file.attribute FileAttribute)
           (java.security KeyStore)
           (java.security.cert X509Certificate)
           (java.util List)
           (javax.net.ssl KeyManagerFactory SSLContext TrustManager X509TrustManager)))

(set! *warn-on-reflection* true)

(defn- sh! [cmd]
  (let [proc (-> (ProcessBuilder. ^List cmd)
                 (.redirectErrorStream true)
                 (.start))
        out (slurp (.getInputStream proc))]
    (when-not (zero? (.waitFor proc))
      (throw (ex-info (str "command failed: " (first cmd) "\n" out) {:cmd cmd})))
    out))

(def keystore-password "changeit")

(defn self-signed-keystore
  "A fresh PKCS12 keystore file holding a self-signed RSA certificate for
  localhost / 127.0.0.1, generated with keytool, password
  `keystore-password`. The caller deletes it."
  ^File []
  (let [ks-file (File/createTempFile "enso-support" ".p12")]
    (.delete ks-file)
    (sh! ["keytool" "-genkeypair" "-alias" "enso" "-keyalg" "RSA" "-keysize" "2048"
          "-storetype" "PKCS12" "-keystore" (.getPath ks-file)
          "-storepass" keystore-password "-validity" "365"
          "-dname" "CN=localhost, OU=test, O=enso, L=x, S=x, C=US"
          "-ext" "SAN=DNS:localhost,IP:127.0.0.1"])
    ks-file))

(defn server-ssl-context
  "SSLContext holding a fresh self-signed RSA certificate for localhost /
  127.0.0.1 (see `self-signed-keystore`)."
  ^SSLContext []
  (let [pass (.toCharArray ^String keystore-password)
        ks-file (self-signed-keystore)
        ks (KeyStore/getInstance "PKCS12")
        _ (with-open [in (FileInputStream. ks-file)]
            (.load ks in pass))
        kmf (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
              (.init ks pass))
        ctx (SSLContext/getInstance "TLS")]
    (.init ctx (.getKeyManagers kmf) nil nil)
    (.delete ks-file)
    ctx))

(defn pem-cert-pair
  "[cert-path key-path] of a fresh self-signed PEM pair (openssl), as
  needed by the HTTP/3 listener."
  []
  (let [dir (Files/createTempDirectory "enso-support" (make-array FileAttribute 0))
        cert (str (.resolve dir "cert.pem"))
        key (str (.resolve dir "key.pem"))]
    (sh! ["openssl" "req" "-x509" "-newkey" "rsa:2048" "-keyout" key "-out" cert
          "-sha256" "-days" "1" "-nodes" "-subj" "/CN=localhost"])
    [cert key]))

(defn trust-all-ssl-context
  "Client SSLContext accepting any server certificate (test-only)."
  ^SSLContext []
  (let [tm (reify X509TrustManager
             (checkClientTrusted [_ _ _])
             (checkServerTrusted [_ _ _])
             (getAcceptedIssuers [_] (make-array X509Certificate 0)))]
    (doto (SSLContext/getInstance "TLS")
      (.init nil (into-array TrustManager [tm]) nil))))

(defn shim-available?
  "True when the enso_quiche JNI shim loads in this JVM."
  []
  (try
    (Class/forName "com.s_exp.enso.quiche.Quiche")
    true
    (catch Throwable _ false)))

(defn free-udp-port
  "A UDP port on 127.0.0.1 that was free a moment ago (for listeners
  whose bound port isn't observable through the public API)."
  ^long []
  (with-open [s (DatagramSocket. 0 (InetAddress/getByName "127.0.0.1"))]
    (.getLocalPort s)))

(defn env-long
  "Long value of environment variable `k`, or `default`."
  ^long [^String k ^long default]
  (if-let [v (System/getenv k)]
    (Long/parseLong v)
    default))

(defn await-condition
  "Polls `pred` every `poll-ms` until truthy or `timeout-ms` elapse.
  Returns the last value of `(pred)`. For conditions with no event to
  wait on (OS-level resource counts)."
  [pred ^long timeout-ms ^long poll-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (let [v (pred)]
        (if (or v (>= (System/currentTimeMillis) deadline))
          v
          (do (Thread/sleep poll-ms) (recur)))))))

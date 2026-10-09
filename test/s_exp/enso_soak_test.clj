;; ABOUTME: Soak/leak test: churns thousands of HTTP/1.1, HTTP/2 and HTTP/3 connections (graceful,
;; ABOUTME: aborted, idle-timed-out) and asserts fds, threads and post-GC heap return to baseline.
(ns s-exp.enso-soak-test
  "Excluded from the default run (script/test.sh skips this namespace;
  the deftests carry ^:soak for test-runner :excludes). Run with
  `script/test.sh s-exp.enso-soak-test`. ENSO_SOAK_CONNECTIONS sets the
  total connection count (default 10000), split across protocols."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [s-exp.enso :as enso]
            [s-exp.enso-test-support :as support]
            [s-exp.h3-client :as h3])
  (:import (com.sun.management UnixOperatingSystemMXBean)
           (java.io InputStream OutputStream)
           (java.lang.management ManagementFactory)
           (java.net InetSocketAddress Socket URI)
           (java.net.http HttpClient HttpClient$Version HttpRequest HttpResponse$BodyHandlers)
           (java.nio.charset StandardCharsets)
           (java.time Duration)
           (java.util.concurrent ExecutorService Executors Future)))

(set! *warn-on-reflection* true)

(def ^:private idle-timeout-ms 2000)

(defn- open-fds ^long []
  (.getOpenFileDescriptorCount ^UnixOperatingSystemMXBean (ManagementFactory/getOperatingSystemMXBean)))

(defn- live-threads ^long []
  (.getThreadCount (ManagementFactory/getThreadMXBean)))

(defn- heap-after-gc ^long []
  (dotimes [_ 3]
    (System/gc)
    (Thread/sleep 100))
  (.getUsed (.getHeapMemoryUsage (ManagementFactory/getMemoryMXBean))))

(defn- thread-names
  "Live platform thread names with digits collapsed, counted per pattern."
  []
  (frequencies (map #(str/replace (.getName ^Thread %) #"\d+" "N") (keys (Thread/getAllStackTraces)))))

(defn- snapshot []
  {:fds (open-fds) :threads (live-threads) :heap (heap-after-gc)})

(defn- thread-growth [before after]
  (into {} (keep (fn [[k n]] (let [d (- (long n) (long (get before k 0)))] (when (pos? d) [k d])))) after))

(defn- in-parallel!
  "Runs `(f i)` for i in [0, n) on `concurrency` virtual threads; rethrows
  the first failure."
  [^long n ^long concurrency f]
  (let [^ExecutorService pool (Executors/newVirtualThreadPerTaskExecutor)]
    (try
      (let [per (long (Math/ceil (/ n (double concurrency))))
            futs (mapv (fn [w]
                         (.submit pool ^Callable
                                  (fn []
                                    (doseq [i (range (* w per) (min n (* (inc w) per)))]
                                      (f i)))))
                       (range concurrency))]
        (doseq [^Future fut futs] (.get fut)))
      (finally (.close pool)))))

;; ---- HTTP/1.1 ---------------------------------------------------------------------

(defn- read-response-head!
  "Reads until the end of a response head; true when one arrived."
  [^InputStream in]
  (loop [state 0]
    (let [b (.read in)]
      (cond
        (neg? b) false
        (= state 3) (if (= b 10) true (recur 0))
        (and (= b 13) (even? state)) (recur (inc state))
        (and (= b 10) (odd? state)) (recur (inc state))
        :else (recur 0)))))

(defn- h1-connection!
  "One HTTP/1.1 connection in one of several shapes, chosen by `i`."
  [^long port ^long i]
  (with-open [sock (Socket.)]
    (.connect sock (InetSocketAddress. "127.0.0.1" (int port)) 5000)
    (.setSoTimeout sock 10000)
    (let [^OutputStream out (.getOutputStream sock)
          in (.getInputStream sock)
          req (fn [extra] (.getBytes (str "GET /soak HTTP/1.1\r\nHost: localhost\r\n" extra "\r\n")
                                     StandardCharsets/ISO_8859_1))]
      (case (int (mod i 4))
        ;; graceful: server closes after the response
        0 (do (.write out ^bytes (req "Connection: close\r\n"))
              (.flush out)
              (assert (read-response-head! in)))
        ;; keep-alive, two requests, client closes
        1 (do (.write out ^bytes (req ""))
              (.write out ^bytes (req ""))
              (.flush out)
              (assert (read-response-head! in)))
        ;; aborted mid-request head
        2 (do (.write out (.getBytes "GET /soak HTTP/1.1\r\nHost: loc" StandardCharsets/ISO_8859_1))
              (.flush out))
        ;; aborted mid-body
        3 (do (.write out (.getBytes "POST /soak HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nabc"
                                     StandardCharsets/ISO_8859_1))
              (.flush out))))))

(defn- h1-idle-connections!
  "Opens `n` connections that never send a byte and leaves them for the
  server's idle timeout to reclaim; closes the client side afterwards."
  [^long port ^long n]
  (let [socks (doall (for [_ (range n)]
                       (doto (Socket.) (.connect (InetSocketAddress. "127.0.0.1" (int port)) 5000))))]
    (Thread/sleep (long (+ idle-timeout-ms 1000)))
    (doseq [^Socket s socks] (.close s))))

;; ---- HTTP/2 ------------------------------------------------------------------------

(defn- h2-connection!
  "One HTTP/2 connection: a fresh client (so a fresh TLS + h2 session),
  two requests, then the client is closed."
  [^long port _]
  (with-open [client (-> (HttpClient/newBuilder)
                         (.version HttpClient$Version/HTTP_2)
                         (.sslContext (support/trust-all-ssl-context))
                         (.connectTimeout (Duration/ofSeconds 5))
                         (.build))]
    (dotimes [_ 2]
      (let [resp (.send client (-> (HttpRequest/newBuilder (URI. (str "https://localhost:" port "/soak")))
                                   (.timeout (Duration/ofSeconds 10))
                                   (.build))
                        (HttpResponse$BodyHandlers/discarding))]
        (assert (= 200 (.statusCode resp)))
        (assert (= HttpClient$Version/HTTP_2 (.version resp)))))))

;; ---- HTTP/3 ------------------------------------------------------------------------

(defn- h3-connection! [^long port ^long i]
  (h3/with-client [c port]
    (h3/open-control! c)
    (let [r (h3/request! c 0 (h3/request-headers "GET" "/soak"))]
      (assert (= 200 (:status r)) (pr-str (dissoc r :body))))
    ;; Every other connection is abandoned without CONNECTION_CLOSE being
    ;; flushed in order (closed right after a second request is queued).
    (when (odd? i)
      (h3/send! c 4 (h3/headers-frame (h3/request-headers "GET" "/soak")) true))))

;; ---- the test --------------------------------------------------------------------------

(defn- within-baseline? [base now]
  (and (<= (:fds now) (+ (:fds base) 16))
       (<= (:threads now) (+ (:threads base) 8))))

(deftest ^:soak connection-churn-returns-to-baseline
  (let [total (support/env-long "ENSO_SOAK_CONNECTIONS" 10000)
        h3? (support/shim-available?)
        per (quot total (if h3? 3 2))
        [cert key] (when h3? (support/pem-cert-pair))
        h3-port (when h3? (support/free-udp-port))
        handler (fn [_] {:status 200 :headers {"content-type" "text/plain"} :body "ok"})
        plain (enso/run-server handler {:host "127.0.0.1" :port 0 :idle-timeout idle-timeout-ms})
        tls (enso/run-server handler (cond-> {:host "127.0.0.1" :port 0 :idle-timeout idle-timeout-ms
                                              :http2 true :ssl-context (support/server-ssl-context)}
                                       h3? (assoc :http3 true :http3-port h3-port
                                                  :http3-cert-path cert :http3-key-path key)))]
    (try
      ;; Warm-up so lazily created pools, JIT and TLS caches are part of
      ;; the baseline.
      (in-parallel! 200 16 #(h1-connection! (enso/port plain) %))
      (in-parallel! 20 4 #(h2-connection! (enso/port tls) %))
      (when h3? (in-parallel! 20 4 #(h3-connection! h3-port %)))
      (let [base (snapshot)
            base-threads (thread-names)
            started (System/nanoTime)]
        (println "soak baseline" base "connections per protocol" per "h3" h3?)
        (testing "HTTP/1.1 churn"
          (in-parallel! per 32 #(h1-connection! (enso/port plain) %))
          (h1-idle-connections! (enso/port plain) 200))
        (testing "HTTP/2 churn"
          (in-parallel! per 16 #(h2-connection! (enso/port tls) %)))
        (when h3?
          (testing "HTTP/3 churn"
            (in-parallel! per 8 #(h3-connection! h3-port %))))
        (println "soak churn took" (quot (- (System/nanoTime) started) 1000000) "ms")
        ;; Server-side closes (idle timeout, QUIC draining) are
        ;; asynchronous: poll the OS-level counters until they settle.
        ;; The HTTP/3 listener's connection drivers run on a cached pool
        ;; whose idle threads exit after 60 s, so the window covers that;
        ;; a driver stuck on a dead connection would never exit.
        (support/await-condition #(within-baseline? base {:fds (open-fds) :threads (live-threads)})
                                 75000 250)
        (let [now (snapshot)]
          (println "soak after" now)
          (is (<= (:fds now) (+ (:fds base) 16)) (str "file descriptors leaked: " base " -> " now))
          (is (<= (:threads now) (+ (:threads base) 8)) (str "threads leaked: " base " -> " now
                                                             ", new threads: " (thread-growth base-threads (thread-names))))
          (is (<= (:heap now) (+ (:heap base) (max (* 32 1024 1024) (quot (:heap base) 2))))
              (str "heap after GC grew: " base " -> " now))))
      (finally
        (enso/stop plain)
        (enso/stop tls)))))

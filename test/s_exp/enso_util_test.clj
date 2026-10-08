(ns s-exp.enso-util-test
  "Direct tests against `com.s_exp.enso.util` helpers that don't need a
  running server. Covers header merge semantics + primitive-key map
  edge cases exercised by h2/h3 request dispatch + h3 stream tracking,
  and the Ring map contract of `com.s_exp.enso.api.Request`."
  (:require [clojure.test :refer [deftest testing is]])
  (:import (com.s_exp.enso.api Request)
           (com.s_exp.enso.core HttpFields)
           (com.s_exp.enso.util Long2ObjectHashMap RingHeaders)
           (java.nio.charset StandardCharsets)
           (java.net InetAddress)))

(deftest merge-duplicates-no-dup-returns-fit-array
  (let [in (object-array ["a" "1" "b" "2"])
        out (RingHeaders/mergeDuplicates in 4)]
    (is (= 4 (alength out)))
    (is (= "a" (aget out 0)))
    (is (= "1" (aget out 1)))
    (is (= "b" (aget out 2)))
    (is (= "2" (aget out 3)))))

(deftest merge-duplicates-trims-oversized-input
  (let [in (object-array 10)]
    (aset in 0 "a") (aset in 1 "1")
    (aset in 2 "b") (aset in 3 "2")
    (let [out (RingHeaders/mergeDuplicates in 4)]
      (is (= 4 (alength out)) "trimmed to exact len when no dups"))))

(deftest merge-duplicates-cookie-uses-semicolon
  (let [in (object-array ["cookie" "a=1" "cookie" "b=2" "cookie" "c=3"])
        out (RingHeaders/mergeDuplicates in 6)]
    (is (= 2 (alength out)))
    (is (= "cookie" (aget out 0)))
    (is (= "a=1; b=2; c=3" (aget out 1))
        "cookie duplicates join with '; ' per RFC 9113 §8.2.3")))

(deftest merge-duplicates-non-cookie-uses-comma
  (let [in (object-array ["accept" "text/html" "accept" "application/json"])
        out (RingHeaders/mergeDuplicates in 4)]
    (is (= 2 (alength out)))
    (is (= "text/html, application/json" (aget out 1))
        "non-cookie duplicates join with ', ' per RFC 9110 §5.3")))

(deftest merge-duplicates-mixed-dups-and-uniques
  (let [in (object-array ["host" "example.com"
                          "cookie" "a=1"
                          "cookie" "b=2"
                          "accept" "*/*"])
        out (RingHeaders/mergeDuplicates in 8)]
    (is (= 6 (alength out)))
    (is (= "host" (aget out 0)))
    (is (= "example.com" (aget out 1)))
    (is (= "cookie" (aget out 2)))
    (is (= "a=1; b=2" (aget out 3)))
    (is (= "accept" (aget out 4)))
    (is (= "*/*" (aget out 5)))))

(deftest merge-duplicates-many-fields-linear
  ;; One HTTP/3 HEADERS block can decode to ~65K fields. Both many
  ;; duplicates of one name and many distinct names must merge in
  ;; linear time.
  (let [n 65536
        timed (fn [^objects in]
                (let [t0 (System/nanoTime)
                      out (RingHeaders/mergeDuplicates in (alength in))]
                  [out (/ (- (System/nanoTime) t0) 1e6)]))]
    (testing "duplicates of one name"
      (let [in (object-array (mapcat (fn [i] ["x-a" (str i)]) (range n)))
            [^objects out ms] (timed in)]
        (is (= 2 (alength out)))
        (is (= (apply str (interpose ", " (range n))) (aget out 1)))
        (is (< ms 1000) (str ms " ms"))))
    (testing "cookie duplicates"
      (let [in (object-array (mapcat (fn [i] ["cookie" (str "c" i "=1")]) (range n)))
            [^objects out ms] (timed in)]
        (is (= (apply str (interpose "; " (map #(str "c" % "=1") (range n)))) (aget out 1)))
        (is (< ms 1000) (str ms " ms"))))
    (testing "distinct names"
      (let [in (object-array (mapcat (fn [i] [(str "x-" i) "v"]) (range n)))
            [^objects out ms] (timed in)]
        (is (identical? in out) "no duplicates returns the exact-fit input")
        (is (< ms 1000) (str ms " ms"))))
    (testing "mixed, order of first occurrence kept"
      (let [in (object-array (concat (mapcat (fn [i] [(str "x-" i) "v"]) (range 40))
                                     ["x-3" "w" "x-0" "w"]))
            ^objects out (RingHeaders/mergeDuplicates in (alength in))]
        (is (= 80 (alength out)))
        (is (= ["x-0" "v, w" "x-1" "v" "x-2" "v" "x-3" "v, w"] (take 8 out)))))))

(deftest long2obj-contains-key-hit-and-miss
  (let [m (Long2ObjectHashMap.)]
    (is (not (.containsKey m 42)) "empty map returns false")
    (.put m 42 "v")
    (is (.containsKey m 42))
    (is (not (.containsKey m 99)))
    (.remove m 42)
    (is (not (.containsKey m 42)))))

(deftest long2obj-contains-key-zero-key
  (let [m (Long2ObjectHashMap.)]
    (is (not (.containsKey m 0)))
    (.put m 0 "zero")
    (is (.containsKey m 0) "zero key uses special hasZeroKey slot")
    (.remove m 0)
    (is (not (.containsKey m 0)))))

(deftest long2obj-contains-key-null-value-not-mistaken-for-absent
  ;; Regression for #233: earlier containsKey delegated to `get() != null`
  ;; and reported false when the value was a legit null. Now a direct probe.
  (let [m (Long2ObjectHashMap.)]
    (.put m 5 nil)
    (is (.containsKey m 5) "key present with null value")
    (is (nil? (.get m 5)))))

(deftest long2obj-contains-key-null-value-zero-key
  (let [m (Long2ObjectHashMap.)]
    (.put m 0 nil)
    (is (.containsKey m 0) "zero key with null value")))

(deftest long2obj-collision-linear-probe-terminates
  ;; Force a chain by inserting keys that collide under the mixer for
  ;; small capacity, then verify containsKey walks the probe chain.
  (let [m (Long2ObjectHashMap. 4)]
    (dotimes [i 20] (.put m i (str i)))
    (dotimes [i 20]
      (is (.containsKey m i) (str "key " i " present after fills")))
    (is (not (.containsKey m 999)))))

;; ---- Request as a Ring map -----------------------------------------------

(defn- request
  (^Request [] (request Request/K_HTTP))
  (^Request [scheme]
   (Request. "GET" "/p" "a=1" "HTTP/1.1" {"host" "example.com:80"} nil
             (InetAddress/getLoopbackAddress) (int 8080) scheme)))

(def ^:private expected-request
  {:server-port 8080 :server-name "example.com" :remote-addr "127.0.0.1"
   :uri "/p" :query-string "a=1" :scheme :http :request-method :get
   :protocol "HTTP/1.1" :headers {"host" "example.com:80"} :body nil})

(deftest request-scheme
  (is (= :http (:scheme (request Request/K_HTTP))))
  (is (= :https (:scheme (request Request/K_HTTPS)))))

(deftest request-map-equality-and-hash
  (let [req (request)]
    (is (= expected-request req))
    (is (= req expected-request))
    (is (= (hash expected-request) (hash req)))
    (is (.equals req expected-request))
    (is (= (.hashCode ^Object expected-request) (.hashCode req)))
    (is (contains? #{expected-request} req))
    (is (not= (assoc expected-request :uri "/q") req))
    (is (not= (dissoc expected-request :body) req))
    (is (not= (assoc expected-request :extra 1) req))))

(deftest request-invokable-as-fn
  (let [req (request)]
    (is (= "/p" (req :uri)))
    (is (nil? (req :missing)))
    (is (= ::nf (req :missing ::nf)))
    (is (= ["/p" :get] (mapv req [:uri :request-method])))))

(deftest request-metadata
  (let [req (with-meta (request) {:a 1})]
    (is (= {:a 1} (meta req)))
    (is (nil? (meta (request))))
    (is (= expected-request req))
    (is (= {:b 2} (meta (vary-meta req (constantly {:b 2})))))))

(deftest request-kv-reduce
  (let [req (request)]
    (is (= expected-request (reduce-kv assoc {} req)))
    (is (= 1 (reduce-kv (fn [n _ _] (if (= n 1) (reduced n) (inc n))) 0 req)))
    (is (= expected-request (into {} req)))))

(deftest response-charset-from-content-type
  ;; Same reading of Content-Type as ring.core.protocols: the charset
  ;; parameter (token or quoted, any case) or UTF-8 when absent.
  (is (= StandardCharsets/UTF_8 (HttpFields/responseCharset nil)))
  (is (= StandardCharsets/UTF_8 (HttpFields/responseCharset {"content-type" "text/plain"})))
  (is (= StandardCharsets/UTF_8 (HttpFields/responseCharset {"Content-Type" "text/html; charset=utf-8"})))
  (is (= StandardCharsets/ISO_8859_1 (HttpFields/responseCharset {"Content-Type" "text/plain;charset=ISO-8859-1"})))
  (is (= StandardCharsets/ISO_8859_1 (HttpFields/responseCharset {"content-type" "text/plain; foo=bar; CHARSET=\"latin1\""})))
  (is (= StandardCharsets/UTF_8 (HttpFields/responseCharset {"x-charset" "text/plain; charset=latin1"})))
  (is (thrown? IllegalArgumentException
               (HttpFields/responseCharset {"content-type" "text/plain; charset=no-such-charset"}))))

(deftest response-charset-does-not-allocate
  ;; Called for every String response: a lookup of a conventionally
  ;; spelled Content-Type must not allocate (no map entry iteration),
  ;; even before the JIT gets a chance to scalar-replace anything.
  (let [mx ^com.sun.management.ThreadMXBean (java.lang.management.ManagementFactory/getThreadMXBean)
        headers {"server" "x" "cache-control" "no-cache" "Content-Type" "text/html; charset=utf-8"}
        lower {"server" "x" "content-type" "text/plain"}
        before (.getCurrentThreadAllocatedBytes mx)]
    (dotimes [_ 10000]
      (HttpFields/responseCharset headers)
      (HttpFields/responseCharset lower))
    (let [allocated (- (.getCurrentThreadAllocatedBytes mx) before)]
      (is (< allocated (* 64 1024)) (str "allocated " allocated " bytes")))))

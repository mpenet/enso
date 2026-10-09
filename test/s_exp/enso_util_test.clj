;; ABOUTME: Unit tests for helpers that need no running server: header merging, Long2ObjectHashMap edge
;; ABOUTME: cases, and the Ring map contract of com.s_exp.enso.api.Request.
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
           (java.net Inet6Address InetAddress InetSocketAddress ServerSocket Socket)))

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
  ;; containsKey probes for the key itself: a key mapped to null is
  ;; present, which `get() != null` would report as absent.
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
   :protocol "HTTP/1.1" :headers {"host" "example.com:80"} :body nil
   :ssl-client-cert nil})

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

;; ---- Request: assoc / dissoc keep the request lazy ------------------------

(deftest request-assoc-adds-keys-without-materializing
  ;; Middleware assoc'ing keys gets a Request back (the lazy fields are not
  ;; computed into a plain map), and it behaves as the equivalent map.
  (let [req (request)
        r2 (assoc req :params {:a 1})
        expected (assoc expected-request :params {:a 1})]
    (is (instance? Request r2))
    (is (= expected r2))
    (is (= r2 expected))
    (is (= (hash expected) (hash r2)))
    (is (= {:a 1} (:params r2)))
    (is (= "/p" (:uri r2)))
    (is (= (count expected) (count r2)))
    (is (contains? r2 :params))
    (is (= expected (reduce-kv assoc {} r2)))
    (is (= (set (keys expected)) (set (keys r2))))
    (is (= expected (into {} r2)))))

(deftest request-assoc-overrides-and-dissoc
  (let [req (request)
        over (assoc req :uri "/q")
        gone (dissoc req :body)
        back (assoc gone :body "b")]
    (is (instance? Request over))
    (is (= "/q" (:uri over)))
    (is (= "/q" (over :uri)))
    (is (= (assoc expected-request :uri "/q") over))
    (is (= (count expected-request) (count over)))
    (is (instance? Request gone))
    (is (not (contains? gone :body)))
    (is (= ::nf (get gone :body ::nf)))
    (is (= (dissoc expected-request :body) gone))
    (is (= (dec (count expected-request)) (count gone)))
    (is (= (assoc expected-request :body "b") back))
    (is (identical? req (dissoc req :absent)) "dissoc of an absent key returns the request itself")
    (is (= expected-request (dissoc (assoc req :x 1) :x)))
    (is (= {:m 1} (meta (assoc (with-meta req {:m 1}) :x 1))))
    (is (= {:m 1} (meta (dissoc (with-meta req {:m 1}) :uri))))
    (is (= (merge expected-request {:a 1 :b 2}) (conj req [:a 1] {:b 2})))
    (is (= (assoc expected-request :a 1) (into req {:a 1})))
    (is (thrown? RuntimeException (.assocEx req :uri "/x")))
    (is (= (assoc expected-request :y 2) (.assocEx req :y 2)))))

(deftest request-java-map-views-are-read-only
  (let [req (assoc (request) :x 1)]
    (is (= (set (keys (assoc expected-request :x 1))) (set (.keySet req))))
    (is (thrown? UnsupportedOperationException (.add (.keySet req) :y)))
    (is (thrown? UnsupportedOperationException (.clear (.values req))))
    (is (thrown? UnsupportedOperationException (.clear (.entrySet req))))
    (is (.containsValue req "/p"))
    (is (.containsValue req 1))))

(deftest request-extension-methods
  (doseq [[m kw] [["PROPFIND" :propfind] ["MKCOL" :mkcol] ["GET" :get] ["QUERY" :query]]]
    (is (= kw (:request-method (Request. m "/" nil "HTTP/1.1" {} nil
                                         (InetAddress/getLoopbackAddress) (int 80) Request/K_HTTP))))))

(defn- remote-addr-of [^InetAddress addr]
  (:remote-addr (Request. "GET" "/" nil "HTTP/1.1" {"host" "h"} nil addr (int 80) Request/K_HTTP)))

(deftest request-remote-addr-ipv6-is-rfc-5952
  ;; Shortest form: lowercase, longest run of zero groups as "::"
  ;; (leftmost on a tie, never a single group), no zone index.
  (doseq [[in expected] [["::1" "::1"]
                         ["0:0:0:0:0:0:0:0" "::"]
                         ["2001:db8:0:0:1:0:0:1" "2001:db8::1:0:0:1"]
                         ["2001:0:0:1:0:0:0:1" "2001:0:0:1::1"]
                         ["2001:db8:0:1:1:1:1:1" "2001:db8:0:1:1:1:1:1"]
                         ["2001:DB8:0:0:0:0:0:ABCD" "2001:db8::abcd"]
                         ["1:0:0:0:2:0:0:0" "1::2:0:0:0"]
                         ["0:0:1:0:0:0:0:0" "0:0:1::"]]]
    (is (= expected (remote-addr-of (InetAddress/getByName in))) in))
  (let [scoped (Inet6Address/getByAddress nil (.getAddress (InetAddress/getByName "fe80::1")) (int 3))]
    (is (= "fe80::1" (remote-addr-of scoped)) "zone index dropped"))
  (is (= "10.1.2.3" (remote-addr-of (InetAddress/getByName "10.1.2.3")))))

(deftest request-server-name-without-host-is-the-local-address
  (with-open [ss (ServerSocket. 0 1 (InetAddress/getLoopbackAddress))
              client (Socket. (InetAddress/getLoopbackAddress) (.getLocalPort ss))
              accepted (.accept ss)]
    (let [req (Request. "GET" "/" nil "HTTP/1.0" {} nil (.getInetAddress accepted)
                        (int (.getLocalPort accepted)) Request/K_HTTP accepted)]
      (is (= "127.0.0.1" (:server-name req))))))

(deftest request-ssl-client-cert-is-nil-without-tls
  (is (contains? (request) :ssl-client-cert))
  (is (nil? (:ssl-client-cert (request)))))

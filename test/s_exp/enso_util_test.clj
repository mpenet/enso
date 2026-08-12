(ns s-exp.enso-util-test
  "Direct tests against `com.s_exp.enso.util` helpers that don't need a
  running server. Covers header merge semantics + primitive-key map
  edge cases exercised by h2/h3 request dispatch + h3 stream tracking."
  (:require [clojure.test :refer [deftest testing is]])
  (:import (com.s_exp.enso.util Long2ObjectHashMap RingHeaders)))

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

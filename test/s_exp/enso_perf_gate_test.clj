;; ABOUTME: Verdicts of the allocation regression gate (s-exp.enso-perf-gate) on synthetic runs:
;; ABOUTME: within tolerance, regression, skipped scenario, and a platform without a baseline.
(ns s-exp.enso-perf-gate-test
  (:require [clojure.test :refer [deftest is]]
            [s-exp.enso-perf-gate :as gate]))

(def ^:private baseline
  {:tolerance {:ratio 1.2 :slack-bytes 48}
   :platforms {"Linux amd64" {:java "25" :alloc-bytes-per-request {:h1-get 400 :h2-get 1100}}}})

(defn- run [platform allocs]
  {:meta {:os platform :java "25"}
   :scenarios (into {} (map (fn [[k v]] [k (if (map? v) v {:alloc-bytes-per-request v})])) allocs)})

(defn- check
  "The gate's verdict on `results`, its report discarded."
  [results]
  (let [verdict (volatile! nil)]
    (with-out-str (vreset! verdict (gate/check baseline results)))
    @verdict))

(deftest within-tolerance-passes
  ;; 400 * 1.2 + 48 = 528
  (is (true? (check (run "Linux amd64" {:h1-get 528 :h2-get 1100})))))

(deftest regression-fails
  (is (false? (check (run "Linux amd64" {:h1-get 529 :h2-get 1100})))))

(deftest skipped-scenario-fails
  (is (false? (check (run "Linux amd64" {:h1-get 400 :h2-get {:skipped "h2load not found"}})))))

(deftest unbaselined-scenario-is-not-gated
  (is (true? (check (run "Linux amd64" {:h1-get 400 :h2-get 1100 :ws-echo 99999})))))

(deftest platform-without-baseline-passes
  (is (true? (check (run "Mac OS X aarch64" {:h1-get 99999})))))

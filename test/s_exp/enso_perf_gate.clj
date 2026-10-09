;; ABOUTME: Allocation regression gate over a perf harness run: compares bytes allocated per request
;; ABOUTME: per scenario with the per-platform baseline in bench/perf/baseline.edn, or refreshes it.
(ns s-exp.enso-perf-gate
  "Run with `clojure -M:perf-gate [check|update] [RESULTS-EDN]` after
  `clojure -M:perf` (RESULTS-EDN defaults to target/perf/latest.edn).

  Only allocation per request is gated: it is a property of the code
  path (bytes allocated by the server divided by requests served), stable
  to a few percent across runs and machines, while req/s and latency
  depend on the runner. A scenario fails when its allocation exceeds
  `baseline * ratio + slack-bytes` (`:tolerance` in the baseline file),
  or when a scenario with a baseline was skipped. Baselines are kept per
  platform (`os.name os.arch` as recorded in the run); a platform without
  one fails, printing the entry to add: a gate with nothing to compare
  against gates nothing.

  `update` replaces the current platform's entry with the run's numbers."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]))

(set! *warn-on-reflection* true)

(def ^:private baseline-file "bench/perf/baseline.edn")
(def ^:private default-results "target/perf/latest.edn")
(def ^:private default-tolerance {:ratio 1.2 :slack-bytes 48})

(defn- read-edn [path]
  (with-open [r (java.io.PushbackReader. (io/reader path))]
    (edn/read r)))

(defn- run-allocations
  "{scenario alloc-bytes-per-request} of the scenarios a run measured."
  [results]
  (into (sorted-map)
        (keep (fn [[k r]]
                (when-let [a (:alloc-bytes-per-request r)]
                  [k (long a)])))
        (:scenarios results)))

(defn- verdicts
  "One map per baselined scenario: {:scenario :baseline :actual :limit :status}."
  [baseline-allocs allocs {:keys [ratio slack-bytes]}]
  (for [[k base] (sort-by key baseline-allocs)
        :let [base (long base)
              actual (get allocs k)
              limit (long (+ (* base (double ratio)) (long slack-bytes)))
              floor (long (- (/ base (double ratio)) (long slack-bytes)))]]
    {:scenario k
     :baseline base
     :actual actual
     :limit limit
     :status (cond
               (nil? actual) :missing
               (> (long actual) limit) :regression
               (< (long actual) floor) :improved
               :else :ok)}))

(defn- summary! [^String text]
  (println text)
  (when-let [f (System/getenv "GITHUB_STEP_SUMMARY")]
    (spit f (str text "\n") :append true)))

(defn- table [vs]
  (str "| scenario | baseline B/req | actual B/req | limit | status |\n"
       "|---|---:|---:|---:|---|\n"
       (str/join (for [{:keys [scenario baseline actual limit status]} vs]
                   (str "| " (name scenario) " | " baseline " | " (or actual "-") " | " limit " | "
                        (case status
                          :ok "ok"
                          :improved "improved: lower the baseline (`clojure -M:perf-gate update`)"
                          :missing "**missing (skipped or failed)**"
                          :regression "**regression**")
                        " |\n")))))

(defn- platform-entry [results]
  {:java (get-in results [:meta :java])
   :git (get-in results [:meta :git])
   :alloc-bytes-per-request (run-allocations results)})

(defn- write-baseline! [baseline]
  (io/make-parents baseline-file)
  (spit baseline-file
        (str ";; ABOUTME: Per-platform allocation-per-request baselines for the perf gate (s-exp.enso-perf-gate).\n"
             ";; ABOUTME: Written by `clojure -M:perf-gate update`; see doc/testing.md before raising a number.\n"
             (with-out-str (pprint/pprint baseline)))))

(defn check
  "Gates `results` against `baseline`. Returns true when nothing regressed."
  [baseline results]
  (let [platform (get-in results [:meta :os])
        tolerance (merge default-tolerance (:tolerance baseline))
        entry (get-in baseline [:platforms platform])
        allocs (run-allocations results)]
    (summary! (str "### Allocation gate (" platform ", java " (get-in results [:meta :java]) ")\n"))
    (if-not entry
      (do (summary! (str "**No baseline for platform `" platform "`: failing.** Record one under `:platforms` in `"
                         baseline-file "` (or run `clojure -M:perf-gate update` on that platform):\n\n```\n"
                         (pr-str {platform (platform-entry results)}) "\n```\n"))
          false)
      (let [vs (verdicts (:alloc-bytes-per-request entry) allocs tolerance)
            failed (filter #(#{:missing :regression} (:status %)) vs)]
        (when (not= (:java entry) (get-in results [:meta :java]))
          (summary! (str "Note: baseline recorded on java " (:java entry) ".\n")))
        (summary! (table vs))
        (summary! (if (seq failed)
                    (str "**" (count failed) " scenario(s) over the allocation limit or missing.**")
                    "Allocation within limits."))
        (empty? failed)))))

(defn update-baseline!
  "Replaces the current platform's baseline entry with `results`."
  [results]
  (let [baseline (if (.exists (io/file baseline-file))
                   (read-edn baseline-file)
                   {:tolerance default-tolerance :platforms {}})
        platform (get-in results [:meta :os])]
    (write-baseline! (assoc-in baseline [:platforms platform] (platform-entry results)))
    (println "baseline for" platform "written to" baseline-file)))

(defn -main [& [mode results-path]]
  (let [results (read-edn (or results-path default-results))
        ok (case (or mode "check")
             "check" (check (read-edn baseline-file) results)
             "update" (do (update-baseline! results) true))]
    (shutdown-agents)
    (System/exit (if ok 0 1))))

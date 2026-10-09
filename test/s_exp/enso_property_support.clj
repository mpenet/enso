;; ABOUTME: test.check plumbing shared by the property and fuzz namespaces: trial counts and
;; ABOUTME: seeds from the environment, failure reports with seed + shrunk input, time-boxed calls.
(ns s-exp.enso-property-support
  (:require [clojure.test :refer [is]]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen])
  (:import (java.util.concurrent ExecutionException ExecutorService Executors Future
                                 ThreadFactory TimeUnit TimeoutException)))

(set! *warn-on-reflection* true)

(defn trials
  "Number of trials per property: ENSO_PROPERTY_TRIALS (default 200),
  scaled by `factor` for expensive properties (at least 1)."
  (^long [] (trials 1.0))
  (^long [factor]
   (let [n (or (some-> (System/getenv "ENSO_PROPERTY_TRIALS") Long/parseLong) 200)]
     (max 1 (long (* (double factor) n))))))

(defn- seed []
  (or (some-> (System/getenv "ENSO_PROPERTY_SEED") Long/parseLong)
      (System/currentTimeMillis)))

(defn check!
  "Runs `prop` for `n` trials and asserts it held. The seed is printed
  up front (rerun with ENSO_PROPERTY_SEED=<seed>); on failure the report
  repeats it with the shrunk counterexample."
  ([prop-name prop] (check! prop-name prop (trials)))
  ([prop-name prop n]
   (let [s (seed)
         _ (println (str prop-name ": " n " trials, ENSO_PROPERTY_SEED=" s))
         r (tc/quick-check n prop :seed s :max-size 200)]
     (is (:pass? r)
         (str prop-name " failed; rerun with ENSO_PROPERTY_SEED=" (:seed r)
              "\nshrunk: " (pr-str (get-in r [:shrunk :smallest]))
              "\nresult: " (pr-str (get-in r [:shrunk :result-data] (:result-data r)))
              (when-let [t (:result r)]
                (when (instance? Throwable t) (str "\nthrown: " t)))))
     r)))

(def ^:private ^ExecutorService bounded-executor
  (Executors/newCachedThreadPool
   (reify ThreadFactory
     (newThread [_ r]
       (doto (Thread. r "enso-property-bounded")
         (.setDaemon true))))))

(defn bounded
  "Calls `f` on a helper thread, waiting at most `ms`. Returns
  {:value v}, {:thrown t} or {:timeout true}."
  [^long ms f]
  (let [^Future fut (.submit bounded-executor ^Callable (fn [] (f)))]
    (try
      {:value (.get fut ms TimeUnit/MILLISECONDS)}
      (catch ExecutionException e {:thrown (.getCause e)})
      (catch TimeoutException _
        (.cancel fut true)
        {:timeout true}))))

;; ---- generators -------------------------------------------------------------

(def gen-octet (gen/choose 0 255))

(defn gen-bytes
  "byte[] of 0..max-len random octets."
  [max-len]
  (gen/fmap #(byte-array (map unchecked-byte %)) (gen/vector gen-octet 0 max-len)))

(def gen-mutation
  "One byte-level mutation: [kind position-seed length-seed octet]."
  (gen/tuple (gen/elements [:flip :set :insert :delete :truncate :duplicate])
             gen/nat gen/nat gen-octet))

(defn mutate
  "Applies `mutations` (from gen-mutation) to `bs`, returning a new byte[]."
  ^bytes [^bytes bs mutations]
  (reduce
   (fn [^bytes b [kind pos-seed len-seed octet]]
     (let [n (alength b)
           pos (if (pos? n) (mod (long pos-seed) n) 0)
           len (inc (mod (long len-seed) 8))
           v (vec b)]
       (byte-array
        (map unchecked-byte
             (case kind
               :flip (if (pos? n) (update v pos #(bit-xor (long %) (bit-shift-left 1 (mod (long octet) 8)))) v)
               :set (if (pos? n) (assoc v pos octet) v)
               :insert (concat (subvec v 0 pos) (repeat len octet) (subvec v pos))
               :delete (concat (subvec v 0 pos) (subvec v (min n (+ pos len))))
               :truncate (subvec v 0 pos)
               :duplicate (let [end (min n (+ pos len))]
                            (concat (subvec v 0 end) (subvec v pos end) (subvec v end))))))))
   bs
   mutations))

(defn gen-mutated
  "Generator of byte[] obtained by applying 1..4 mutations to a value of
  `gen-valid` (a byte[] generator)."
  [gen-valid]
  (gen/fmap (fn [[bs ms]] (mutate bs ms))
            (gen/tuple gen-valid (gen/vector gen-mutation 1 4))))

(defn split-at-points
  "Splits `bs` into consecutive chunks at the (unsorted) cut `points`."
  [^bytes bs points]
  (let [n (alength bs)
        cuts (distinct (sort (concat [0] (map #(mod (long %) (inc n)) points) [n])))]
    (map (fn [[a b]] (java.util.Arrays/copyOfRange bs (int a) (int b)))
         (partition 2 1 cuts))))

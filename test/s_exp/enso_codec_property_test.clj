;; ABOUTME: Property-based tests (test.check) for the wire codecs: HPACK, Huffman, QPACK field sections
;; ABOUTME: (both decoders), QUIC varints and the HTTP/3 frame reader: round-trips, robustness on hostile bytes.
(ns s-exp.enso-codec-property-test
  (:require [clojure.test :refer [deftest]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [s-exp.enso-property-support :as ps])
  (:import (com.s_exp.enso.http2 Hpack$Decoder Hpack$Encoder Hpack$HeaderField HpackHuffman)
           (com.s_exp.enso.http3 Http3FrameReader Http3FrameReader$Frame Http3FrameType Http3Varint)
           (com.s_exp.enso.http3.qpack QpackDecoder QpackDecoder$FieldSink QpackException QpackFieldSection)
           (java.io ByteArrayOutputStream IOException)
           (java.nio BufferUnderflowException ByteBuffer)
           (java.util ArrayList List Locale)))

(set! *warn-on-reflection* true)

;; Per-input time box for decoders fed hostile bytes: anything slower is a
;; hang for our purposes.
(def ^:private decode-budget-ms 2000)

;; ---- generators ---------------------------------------------------------------

(def ^:private gen-latin1-char (gen/fmap char (gen/choose 0 255)))

(def ^:private gen-token-char
  (gen/elements (seq "abcdefghijklmnopqrstuvwxyz0123456789-_.~!#$%&'*+^`|")))

(defn- gen-string [gen-char max-len]
  (gen/fmap #(apply str %) (gen/vector gen-char 0 max-len)))

(def ^:private common-names
  [":method" ":path" ":scheme" ":status" ":authority" "content-type" "content-length"
   "cookie" "set-cookie" "authorization" "accept-encoding" "user-agent" "etag" "x-custom"])

(def ^:private common-values
  ["" "GET" "POST" "/" "/index.html" "http" "https" "200" "204" "404" "500"
   "gzip, deflate" "text/plain" "Hello, World!"])

(def ^:private gen-field-name
  (gen/frequency [[3 (gen/elements common-names)]
                  [3 (gen-string gen-token-char 20)]
                  [2 (gen-string gen-latin1-char 20)]]))

(def ^:private gen-field-value
  (gen/frequency [[3 (gen/elements common-values)]
                  [4 (gen-string gen-latin1-char 40)]
                  ;; Large enough to overflow small dynamic tables.
                  [1 (gen-string gen-latin1-char 600)]]))

(def ^:private gen-fields
  (gen/vector (gen/tuple gen-field-name gen-field-value gen/boolean) 0 20))

;; ---- HPACK --------------------------------------------------------------------

(defn- header-fields ^List [fields]
  (let [l (ArrayList.)]
    (doseq [[n v sensitive] fields]
      (.add l (Hpack$HeaderField. ^String n ^String v (boolean sensitive))))
    l))

(defn- decoded-pairs [^List decoded]
  (mapv (fn [^Hpack$HeaderField f] [(.-name f) (.-value f)]) decoded))

(def ^:private gen-hpack-ops
  ;; A connection's worth of header blocks, interleaved with peer
  ;; SETTINGS_HEADER_TABLE_SIZE changes (never above the decoder's 4096).
  (gen/vector (gen/frequency [[4 (gen/tuple (gen/return :block) gen-fields)]
                              [1 (gen/tuple (gen/return :resize) (gen/choose 0 4096))]])
              1 12))

(deftest hpack-round-trip
  (ps/check!
   "HPACK encode/decode round-trip over a connection's blocks"
   (prop/for-all [ops gen-hpack-ops]
                 (let [enc (Hpack$Encoder. 4096)
                       dec (Hpack$Decoder. 4096)]
                   (every? (fn [[op x]]
                             (if (= op :resize)
                               (do (.setMaxTableSize enc (int x)) true)
                               (let [^bytes block (.encode enc (header-fields x))
                                     decoded (.decode dec block 0 (alength block))]
                                 (and (= (mapv (fn [[n v]] [n v]) x) (decoded-pairs decoded))
                          ;; Never-indexed stays never-indexed across hops (§6.2.3).
                                      (every? true? (map (fn [[_ _ sensitive] ^Hpack$HeaderField f]
                                                           (or (not sensitive) (.-sensitive f)))
                                                         x decoded))))))
                           ops)))))

(deftest hpack-huffman-round-trip
  (ps/check!
   "HPACK Huffman encode/decode round-trip"
   (prop/for-all [^bytes plain (ps/gen-bytes 300)]
                 (let [n (alength plain)
                       out (byte-array (HpackHuffman/encodedLength plain 0 n))
                       written (HpackHuffman/encode plain 0 n out 0)]
                   (and (= written (alength out))
                        (java.util.Arrays/equals plain (HpackHuffman/decode out 0 written)))))))

(defn- protocol-error-or-value?
  "True when `outcome` (from ps/bounded) is a value or a throwable of
  `allowed` class: never a timeout or any other exception/error."
  [outcome ^Class allowed]
  (or (contains? outcome :value)
      (instance? allowed (:thrown outcome))))

(def ^:private gen-valid-hpack-block
  (gen/fmap (fn [fields] (.encode (Hpack$Encoder. 4096) (header-fields fields))) gen-fields))

(def ^:private gen-hostile-hpack-block
  (gen/one-of [(ps/gen-bytes 300) (ps/gen-mutated gen-valid-hpack-block)]))

(deftest hpack-decoder-rejects-hostile-input-with-compression-error
  ;; A connection's decoder first sees a valid block (populating its
  ;; dynamic table), then a hostile one. Only IOException (mapped to
  ;; COMPRESSION_ERROR by the connection) may escape, within the budget.
  (ps/check!
   "HPACK decoder: hostile blocks yield a value or IOException"
   (prop/for-all [^bytes warmup gen-valid-hpack-block
                  ^bytes hostile gen-hostile-hpack-block]
                 (let [dec (Hpack$Decoder. 4096)]
                   (.decode dec warmup 0 (alength warmup))
                   (protocol-error-or-value?
                    (ps/bounded decode-budget-ms #(.decode dec hostile 0 (alength hostile)))
                    IOException)))))

(deftest hpack-huffman-decoder-rejects-hostile-input
  (ps/check!
   "HPACK Huffman decoder: random bytes yield a value or IOException"
   (prop/for-all [^bytes bs (ps/gen-bytes 200)]
                 (protocol-error-or-value?
                  (ps/bounded decode-budget-ms #(HpackHuffman/decode bs 0 (alength bs)))
                  IOException))))

;; ---- QPACK --------------------------------------------------------------------

(defn- qpack-headers ^List [fields]
  (ArrayList. ^java.util.Collection (mapv (fn [[n v]] (into-array String [n v])) fields)))

(defn- qpack-pairs [^List decoded]
  (mapv (fn [^"[Ljava.lang.String;" a] [(aget a 0) (aget a 1)]) decoded))

(defn- field-section-size
  "RFC 9114 §4.2.2 size: name + value + 32 per field."
  ^long [fields]
  (reduce + 0 (map (fn [[^String n ^String v]] (+ 32 (count n) (count v))) fields)))

(deftest qpack-round-trip
  (ps/check!
   "QPACK field section encode/decode round-trip (names lowercased by the encoder)"
   (prop/for-all [fields gen-fields]
                 (let [decoded (QpackFieldSection/decode (QpackFieldSection/encode (qpack-headers fields)))]
                   (= (mapv (fn [[^String n v]] [(.toLowerCase n Locale/ROOT) v]) fields)
                      (qpack-pairs decoded))))))

(deftest qpack-scratch-encoder-matches-one-shot-encoder
  (ps/check!
   "QPACK encode with a small reused scratch buffer equals encodeInto output"
   (prop/for-all [fields gen-fields]
                 (let [scratch (ByteBuffer/allocate 16)
                       ^bytes a (QpackFieldSection/encode ^Iterable (qpack-headers fields) scratch)
                       out (ByteBuffer/allocate (+ 2 (reduce + 0 (map (fn [[n v]] (QpackFieldSection/maxEncodedLength n v))
                                                                      fields))))
                       written (QpackFieldSection/encodeInto out (qpack-headers fields))]
                   (java.util.Arrays/equals a (java.util.Arrays/copyOf (.array out) written))))))

(deftest qpack-decoded-size-cap
  (ps/check!
   "QPACK decode with a size cap fails with stream-level H3_EXCESSIVE_LOAD exactly when the section exceeds it"
   (prop/for-all [fields gen-fields
                  cap (gen/choose 1 4000)]
                 (let [lowered (mapv (fn [[^String n v]] [(.toLowerCase n Locale/ROOT) v]) fields)
                       payload (QpackFieldSection/encode (qpack-headers fields))
                       over? (> (field-section-size lowered) (long cap))]
                   (try
                     (QpackFieldSection/decode payload (long cap))
                     (not over?)
                     (catch QpackException e
                       (and over?
                            (= QpackException/H3_EXCESSIVE_LOAD (.errorCode e))
                            (.isStreamLevel e))))))))

(def ^:private gen-hostile-qpack
  (gen/one-of [(ps/gen-bytes 300)
               (ps/gen-mutated (gen/fmap #(QpackFieldSection/encode (qpack-headers %)) gen-fields))]))

(deftest qpack-decoder-rejects-hostile-input-with-qpack-error
  (ps/check!
   "QPACK decoder: hostile field sections yield a value or QpackException"
   (prop/for-all [^bytes bs gen-hostile-qpack]
                 (protocol-error-or-value?
                  (ps/bounded decode-budget-ms #(QpackFieldSection/decode bs 65536))
                  QpackException))))

;; ---- QPACK production decoder (QpackDecoder, used by Http3Loop) -----------------

(defn- production-decode
  "Fields [name value] decoded by `dec` from `bs` embedded at `off` in a
  larger buffer of junk, so the decoder must honour its off/len bounds."
  [^QpackDecoder dec ^bytes bs ^long off ^long cap]
  (let [buf (byte-array (+ off (alength bs) 7) (unchecked-byte 0x80))
        out (ArrayList.)]
    (System/arraycopy bs 0 buf off (alength bs))
    (.decode dec buf (int off) (alength bs) cap
             (reify QpackDecoder$FieldSink
               (field [_ n v] (.add out [n v]))))
    (vec out)))

(defn- decode-outcome
  "{:fields [...]} or {:error [code stream-level?]} of `f`; any other
  exception propagates."
  [f]
  (try
    {:fields (f)}
    (catch QpackException e
      {:error [(.errorCode e) (.isStreamLevel e)]})))

(deftest qpack-production-decoder-round-trip
  ;; One decoder across all trials, as one event loop's is across
  ;; requests: its string cache must never leak a previous value.
  (let [dec (QpackDecoder.)]
    (ps/check!
     "QpackDecoder decodes encoder output (names lowercased), at any offset, with a warm cache"
     (prop/for-all [fields gen-fields
                    off (gen/choose 0 9)]
                   (= (mapv (fn [[^String n v]] [(.toLowerCase n Locale/ROOT) v]) fields)
                      (production-decode dec (QpackFieldSection/encode (qpack-headers fields)) off 0))))))

(deftest qpack-production-decoder-size-cap
  (ps/check!
   "QpackDecoder with a size cap fails with stream-level H3_EXCESSIVE_LOAD exactly when the section exceeds it"
   (prop/for-all [fields gen-fields
                  cap (gen/choose 1 4000)]
                 (let [lowered (mapv (fn [[^String n v]] [(.toLowerCase n Locale/ROOT) v]) fields)
                       payload (QpackFieldSection/encode (qpack-headers fields))
                       over? (> (field-section-size lowered) (long cap))
                       outcome (decode-outcome #(production-decode (QpackDecoder.) payload 0 cap))]
                   (if over?
                     (= [QpackException/H3_EXCESSIVE_LOAD true] (:error outcome))
                     (= lowered (:fields outcome)))))))

(deftest qpack-production-decoder-agrees-with-reference-on-hostile-input
  ;; QpackDecoder documents the same results, error codes and levels as
  ;; QpackFieldSection.decode; only QpackException may escape, within the
  ;; time budget, and a warm cache must not change the answer.
  (let [dec (QpackDecoder.)]
    (ps/check!
     "QpackDecoder vs QpackFieldSection.decode on random and mutated field sections"
     (prop/for-all [^bytes bs gen-hostile-qpack
                    cap (gen/elements [0 64 512 65536])]
                   (let [r (ps/bounded decode-budget-ms
                                       (fn []
                                         (let [expected (decode-outcome
                                                         #(qpack-pairs (QpackFieldSection/decode bs (long cap))))
                                               fresh (decode-outcome #(production-decode (QpackDecoder.) bs 3 cap))
                                               warm (decode-outcome #(production-decode dec bs 0 cap))]
                                           (and (= expected fresh) (= fresh warm)))))]
                     (true? (:value r)))))))

;; ---- QUIC varint ---------------------------------------------------------------

(def ^:private gen-varint-value
  (gen/one-of [(gen/choose 0 63)
               (gen/choose 64 16383)
               (gen/choose 16384 1073741823)
               (gen/fmap (fn [^long x] (bit-and x Http3Varint/MAX_VALUE)) gen/large-integer)
               (gen/elements [0 63 64 16383 16384 1073741823 1073741824 Http3Varint/MAX_VALUE])]))

(deftest varint-round-trip
  (ps/check!
   "QUIC varint encode/decode round-trip with minimal length"
   (prop/for-all [v gen-varint-value]
                 (let [v (long v)
                       bb (ByteBuffer/allocate 8)]
                   (Http3Varint/encode bb v)
                   (let [written (.position bb)]
                     (.flip bb)
                     (and (= written (Http3Varint/size v))
                          (= written (Http3Varint/peekLength bb))
                          (= v (Http3Varint/decode bb))
                          (not (.hasRemaining bb))))))))

(deftest varint-fixed8-decodes-to-same-value
  (ps/check!
   "QUIC varint 8-byte form decodes to the same value"
   (prop/for-all [v gen-varint-value]
                 (let [bb (ByteBuffer/allocate 8)]
                   (Http3Varint/encodeFixed8 bb 0 (long v))
                   (= (long v) (Http3Varint/decode bb))))))

(deftest varint-decode-on-arbitrary-bytes
  ;; Any byte sequence either decodes to an in-range value consuming
  ;; exactly peekLength bytes, or underflows when that many aren't there.
  (ps/check!
   "QUIC varint decode on arbitrary bytes"
   (prop/for-all [^bytes bs (ps/gen-bytes 10)]
                 (let [bb (ByteBuffer/wrap bs)
                       expected-len (Http3Varint/peekLength bb)]
                   (try
                     (let [v (Http3Varint/decode bb)]
                       (and (<= 0 v Http3Varint/MAX_VALUE)
                            (= expected-len (.position bb))))
                     (catch BufferUnderflowException _
                       (< (alength bs) (max 1 expected-len))))))))

(deftest varint-rejects-out-of-range-values
  (ps/check!
   "QUIC varint encode rejects negative and > 2^62-1 values"
   (prop/for-all [v (gen/one-of [(gen/fmap #(bit-or (long %) Long/MIN_VALUE) gen/large-integer)
                                 (gen/fmap #(bit-or (long %) (bit-shift-left 1 62)) gen/large-integer)])]
                 (try
                   (Http3Varint/encode (ByteBuffer/allocate 8) (long v))
                   false
                   (catch IllegalArgumentException _ true)))))

;; ---- HTTP/3 frame reader --------------------------------------------------------

(def ^:private accumulated-types
  #{Http3FrameType/HEADERS Http3FrameType/SETTINGS Http3FrameType/GOAWAY
    Http3FrameType/MAX_PUSH_ID Http3FrameType/CANCEL_PUSH Http3FrameType/PUSH_PROMISE})

(def ^:private gen-frame-type
  (gen/frequency [[6 (gen/elements [Http3FrameType/DATA Http3FrameType/HEADERS Http3FrameType/SETTINGS
                                    Http3FrameType/GOAWAY Http3FrameType/MAX_PUSH_ID
                                    Http3FrameType/CANCEL_PUSH Http3FrameType/PUSH_PROMISE])]
                  [1 (gen/elements [0x02 0x06 0x08 0x09])]
                  ;; RFC 9114 §7.2.8 reserved (grease) types.
                  [1 (gen/fmap #(+ 0x21 (* 0x1f (long %))) (gen/choose 0 1000))]
                  [1 (gen/fmap (fn [^long x] (bit-and x Http3Varint/MAX_VALUE)) gen/large-integer)]]))

(def ^:private gen-frames
  (gen/vector (gen/tuple gen-frame-type (ps/gen-bytes 300) gen/boolean) 0 8))

(defn- encode-frames
  "Wire bytes for [type payload fixed8-length?] frames."
  ^bytes [frames]
  (let [out (ByteArrayOutputStream.)]
    (doseq [[t ^bytes p fixed8] frames]
      (let [bb (ByteBuffer/allocate 16)]
        (Http3Varint/encode bb (long t))
        (if fixed8
          (do (Http3Varint/encodeFixed8 bb (.position bb) (alength p))
              (.position bb (+ 8 (.position bb))))
          (Http3Varint/encode bb (alength p)))
        (.write out (.array bb) 0 (.position bb))
        (.write out p 0 (alength p))))
    (.toByteArray out)))

(defn- expected-events
  "What the reader must report for complete `frames` with `max-accum`."
  [frames ^long max-accum]
  (loop [fs frames
         out []]
    (if-let [[t ^bytes p] (first fs)]
      (let [t (long t)]
        (cond
          (= t Http3FrameType/DATA) (recur (rest fs) (conj out [:data (vec p)]))
          (Http3FrameType/isReservedHttp2 t) (recur (rest fs) (conj out [:frame t []]))
          (not (accumulated-types t)) (recur (rest fs) out)
          (and (= t Http3FrameType/HEADERS) (> (alength p) max-accum)) (recur (rest fs) (conj out [:oversized]))
          (> (alength p) max-accum) {:events out :error true}
          :else (recur (rest fs) (conj out [:frame t (vec p)]))))
      {:events out :error false})))

(defn- drain-events
  "Polls every ready frame from `r`, merging DATA chunks of one frame."
  [^Http3FrameReader r state]
  (loop [{:keys [events data] :as st} state]
    (if-let [^Http3FrameReader$Frame f (.poll r)]
      (cond
        (.isDataChunk f)
        (let [data (into (or data []) (.-dataChunk f))]
          (if (.-dataFinalChunk f)
            (recur {:events (conj events [:data data]) :data nil})
            (recur {:events events :data data})))

        (.-oversized f) (recur (update st :events conj [:oversized]))
        :else (recur (update st :events conj [:frame (.-type f) (vec (.-payload f))])))
      st)))

(defn- read-chunks
  "Feeds `chunks` to a fresh reader; {:events [...] :error bool :partial bool}."
  [chunks max-accum]
  (let [r (Http3FrameReader. (int max-accum))]
    (loop [cs chunks
           st {:events [] :data nil}]
      (if-let [^bytes c (first cs)]
        (let [st' (try
                    (.feed r c 0 (alength c))
                    (drain-events r st)
                    (catch IllegalStateException _
                      (assoc (drain-events r st) :error true)))]
          (if (:error st')
            {:events (:events st') :error true}
            (recur (rest cs) st')))
        {:events (:events st) :error false :partial (.hasPartial r)}))))

(deftest h3-frame-reader-matches-model-under-any-chunking
  (ps/check!
   "Http3FrameReader: frames split at arbitrary points parse as the model says"
   (prop/for-all [frames gen-frames
                  cuts (gen/vector gen/nat 0 12)
                  max-accum (gen/elements [16 128 1024 65536])]
                 (let [wire (encode-frames frames)
                       expected (expected-events frames max-accum)
                       actual (read-chunks (ps/split-at-points wire cuts) max-accum)]
                   (and (= (:events expected) (:events actual))
                        (= (:error expected) (:error actual))
                        (or (:error actual) (false? (:partial actual))))))))

(deftest h3-frame-reader-reports-truncation-as-partial
  (ps/check!
   "Http3FrameReader: input cut inside a frame leaves the reader partial"
   (prop/for-all [frames (gen/not-empty gen-frames)
                  cut-seed gen/nat]
                 (let [wire (encode-frames frames)
                       cut (mod (long cut-seed) (alength wire))
                       r (Http3FrameReader. 65536)]
       ;; Every frame has at least a 2-byte header, so a cut strictly
       ;; inside the stream ends mid-frame unless it lands on a boundary.
                   (let [boundaries (set (reductions + 0 (map (fn [f] (alength (encode-frames [f]))) frames)))]
                     (try
                       (.feed r wire 0 (int cut))
                       (= (.hasPartial r) (not (contains? boundaries cut)))
                       (catch IllegalStateException _ true)))))))

(deftest h3-frame-reader-survives-hostile-input
  ;; Only IllegalStateException (oversized non-HEADERS frame), mapped to
  ;; H3_FRAME_ERROR / EXCESSIVE_LOAD by the session, may escape.
  (ps/check!
   "Http3FrameReader: random or mutated chunked input yields frames or IllegalStateException"
   (prop/for-all [^bytes wire (gen/one-of [(ps/gen-bytes 400)
                                           (ps/gen-mutated (gen/fmap encode-frames gen-frames))])
                  cuts (gen/vector gen/nat 0 12)]
                 (protocol-error-or-value?
                  (ps/bounded decode-budget-ms #(read-chunks (ps/split-at-points wire cuts) 4096))
                  IllegalStateException))))

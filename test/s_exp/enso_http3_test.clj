(ns s-exp.enso-http3-test
  "HTTP/3 protocol-level unit tests: QPACK codec round-trip, H3 frame
  writer/reader interop, varint boundaries. Java-only — no live UDP
  server needed. End-to-end h3 smoke via live quiche-client lives in
  the main enso_test.clj with :h3-integration opt-in."
  (:require [clojure.test :refer [deftest testing is]])
  (:import (com.s_exp.enso.http3 Http3FrameReader Http3FrameType
                                 Http3FrameWriter Http3StreamType Http3Varint)
           (com.s_exp.enso.http3.qpack QpackException QpackFieldSection QpackHuffman)
           (java.nio ByteBuffer)
           (java.util ArrayList List)))

;; ---- Varint round-trip ---------------------------------------------------

(defn- roundtrip-varint [v]
  (let [buf (ByteBuffer/allocate 8)]
    (Http3Varint/encode buf v)
    (.flip buf)
    (Http3Varint/decode buf)))

(deftest varint-boundaries
  (testing "1-byte range [0, 63]"
    (is (= 0 (roundtrip-varint 0)))
    (is (= 63 (roundtrip-varint 63))))
  (testing "2-byte range [64, 16383]"
    (is (= 64 (roundtrip-varint 64)))
    (is (= 16383 (roundtrip-varint 16383))))
  (testing "4-byte range [16384, 1073741823]"
    (is (= 16384 (roundtrip-varint 16384)))
    (is (= 1073741823 (roundtrip-varint 1073741823))))
  (testing "8-byte range up to 2^62 - 1"
    (is (= 1073741824 (roundtrip-varint 1073741824)))
    (is (= Http3Varint/MAX_VALUE (roundtrip-varint Http3Varint/MAX_VALUE)))))

(deftest varint-size-matches-encoding
  (is (= 1 (Http3Varint/size 63)))
  (is (= 2 (Http3Varint/size 64)))
  (is (= 2 (Http3Varint/size 16383)))
  (is (= 4 (Http3Varint/size 16384)))
  (is (= 4 (Http3Varint/size 1073741823)))
  (is (= 8 (Http3Varint/size 1073741824))))

(deftest varint-peek-length-matches-actual
  ;; peekLength must not advance the buffer position.
  (doseq [v [0 63 64 16383 16384 1073741823 (Long/parseLong "12345678901")]]
    (let [buf (ByteBuffer/allocate 8)]
      (Http3Varint/encode buf v)
      (.flip buf)
      (let [pos-before (.position buf)
            peeked (Http3Varint/peekLength buf)]
        (is (= (.position buf) pos-before) "peekLength doesn't move position")
        (is (= (Http3Varint/size v) peeked)
            (str "peek matches size for v=" v))))))

;; ---- QPACK static-table round-trip ---------------------------------------

(defn- pair-list [pairs]
  (let [l (ArrayList.)]
    (doseq [[k v] pairs]
      (.add l (into-array String [k v])))
    l))

(defn- pairs [^List decoded]
  (mapv (fn [^"[Ljava.lang.String;" a] [(aget a 0) (aget a 1)]) decoded))

(deftest qpack-encode-decode-static-table-hits
  ;; :status 200, :method GET, :path / are all in QPACK static table.
  (let [in (pair-list [[":status" "200"] [":method" "GET"] [":path" "/"]])
        encoded (QpackFieldSection/encode in)
        decoded (QpackFieldSection/decode encoded)]
    (is (= [[":status" "200"] [":method" "GET"] [":path" "/"]] (pairs decoded)))))

(deftest qpack-encode-decode-literal-headers
  (let [in (pair-list [[":status" "418"]
                       ["content-type" "application/x-tea"]
                       ["x-custom-header" "some literal value"]])
        encoded (QpackFieldSection/encode in)
        decoded (QpackFieldSection/decode encoded)]
    (is (= [[":status" "418"]
            ["content-type" "application/x-tea"]
            ["x-custom-header" "some literal value"]]
           (pairs decoded)))))

(deftest qpack-encodeinto-and-decode-large-value
  (let [big-value (apply str (repeat 4096 "x"))
        in (pair-list [[":status" "200"]
                       ["x-large" big-value]])
        scratch (ByteBuffer/allocate 8192)
        n (QpackFieldSection/encodeInto scratch in)]
    (.flip scratch)
    (let [encoded (byte-array n)]
      (.get scratch encoded)
      (let [decoded (QpackFieldSection/decode encoded)
            back (pairs decoded)]
        (is (= 2 (count back)))
        (is (= [":status" "200"] (first back)))
        (is (= "x-large" (first (second back))))
        (is (= 4096 (count (second (second back)))))))))

(deftest qpack-decode-empty-payload-yields-empty
  (let [decoded (QpackFieldSection/decode (byte-array [(byte 0) (byte 0)]))]
    (is (zero? (.size decoded)) "prefix 0,0 = zero-length header block")))

(deftest qpack-decode-truncated-throws
  ;; Payload advertises a value but ends short of it.
  (is (thrown? QpackException
               (QpackFieldSection/decode (byte-array [(byte 0) (byte 0) (unchecked-byte 0x80)])))))

;; ---- QPACK Huffman round-trip fuzz ---------------------------------------

(deftest qpack-huffman-roundtrip-ascii
  ;; Encode + decode a range of ASCII strings via QpackHuffman.
  (doseq [s ["hello" "content-type" "application/json"
             "GET" "/api/v1/users?limit=10"
             "" "x"]]
    (let [bytes (.getBytes s "UTF-8")
          n (alength bytes)
          enc-len (QpackHuffman/encodedLength bytes 0 n)
          enc (byte-array enc-len)
          _ (QpackHuffman/encode bytes 0 n enc 0)
          dec (QpackHuffman/decode enc 0 enc-len)]
      (is (= (seq bytes) (seq dec))
          (str "roundtrip failed for '" s "'")))))

;; ---- H3 frame writer + reader interop ------------------------------------

(defn- feed-and-drain
  "Feed `bytes` into a fresh reader, drain all frames, return the list."
  [^bytes bytes]
  (let [r (Http3FrameReader. 65536)
        acc (java.util.ArrayList.)]
    (.feed r bytes 0 (alength bytes))
    (loop []
      (let [f (.poll r)]
        (when f
          (.add acc f)
          (recur))))
    acc))

(deftest frame-writer-data-round-trip
  (let [payload (.getBytes "hello, h3" "UTF-8")
        bb (Http3FrameWriter/data payload)
        raw (byte-array (.remaining bb))
        _ (.get bb raw)
        frames (feed-and-drain raw)]
    (is (= 1 (.size frames)))
    (let [f (.get frames 0)]
      (is (= Http3FrameType/DATA (.type f)))
      ;; DATA frames are emitted as chunks with dataChunk set.
      (is (= (seq payload) (seq (.dataChunk f)))))))

(deftest frame-writer-headers-round-trip
  (let [encoded (byte-array [(byte 0) (byte 0) (unchecked-byte 0xC0)]) ;; QPACK :authority static idx
        bb (Http3FrameWriter/headers encoded)
        raw (byte-array (.remaining bb))
        _ (.get bb raw)
        frames (feed-and-drain raw)]
    (is (= 1 (.size frames)))
    (is (= Http3FrameType/HEADERS (.type (.get frames 0))))))

(deftest frame-writer-goaway-round-trip
  (let [bb (Http3FrameWriter/goaway 42)
        raw (byte-array (.remaining bb))
        _ (.get bb raw)
        frames (feed-and-drain raw)]
    (is (= 1 (.size frames)))
    (let [f (.get frames 0)]
      (is (= Http3FrameType/GOAWAY (.type f))))))

(deftest frame-writer-settings-round-trip
  (let [pairs (long-array [Http3StreamType/CONTROL 4096  ;; SETTINGS_MAX_FIELD_SECTION_SIZE-ish
                           7 100])
        bb (Http3FrameWriter/settings pairs)
        raw (byte-array (.remaining bb))
        _ (.get bb raw)
        frames (feed-and-drain raw)]
    (is (= 1 (.size frames)))
    (is (= Http3FrameType/SETTINGS (.type (.get frames 0))))))

(deftest frame-reader-multi-frame-in-one-feed
  ;; Concat HEADERS + DATA in a single feed — reader should emit both.
  (let [hb (Http3FrameWriter/headers (byte-array [(byte 0) (byte 0)]))
        db (Http3FrameWriter/data (.getBytes "abc" "UTF-8"))
        joined (byte-array (+ (.remaining hb) (.remaining db)))
        _ (.get hb joined 0 (.remaining hb))
        h-off (- (alength joined) (.remaining db))
        _ (.get db joined h-off (.remaining db))
        frames (feed-and-drain joined)]
    (is (<= 2 (.size frames)) "at least HEADERS + DATA emitted")
    (is (some #(= Http3FrameType/HEADERS (.type %)) frames))
    (is (some #(= Http3FrameType/DATA (.type %)) frames))))

(deftest frame-reader-drip-fed-bytes-still-parses
  ;; Feed a HEADERS frame one byte at a time. Reader must accumulate
  ;; without losing data.
  (let [bb (Http3FrameWriter/headers (byte-array [(byte 0) (byte 0)]))
        raw (byte-array (.remaining bb))
        _ (.get bb raw)
        r (Http3FrameReader. 65536)]
    (dotimes [i (alength raw)]
      (.feed r raw i 1))
    (let [f (.poll r)]
      (is (some? f) "frame assembled from drip feed")
      (is (= Http3FrameType/HEADERS (.type f))))))

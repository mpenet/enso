(ns s-exp.quiche-h3-foundation-test
  "Unit tests for the low-level H3 + QPACK primitives: varint, N-bit
  integer/string codecs, static table lookups. These have no dependency on
  a live QUIC connection and are purely CPU-driven."
  (:require [clojure.test :refer [deftest is testing]])
  (:import (com.s_exp.enso.http3 Http3FrameType Http3FrameReader Http3FrameWriter Http3Varint)
           (com.s_exp.enso.http3.qpack NBitInteger NBitString QpackFieldSection
                                       QpackHuffman QpackStaticTable)
           (java.nio ByteBuffer)))

(set! *warn-on-reflection* true)

(defn- to-bytes [^ByteBuffer bb]
  (let [dup (.duplicate bb)
        arr (byte-array (.remaining dup))]
    (.get dup arr)
    arr))

(deftest varint-roundtrip
  (doseq [v [0 1 63          ; 1-byte boundary
             64 16383        ; 2-byte
             16384 1073741823 ; 4-byte
             1073741824 (dec (bit-shift-left 1 62))]] ; 8-byte
    (let [bb (ByteBuffer/allocate 8)]
      (Http3Varint/encode bb v)
      (.flip bb)
      (is (= v (Http3Varint/decode bb)) (str "varint roundtrip " v))
      (is (not (.hasRemaining bb)) (str "varint " v " consumed all bytes")))))

(deftest varint-size-boundary
  (is (= 1 (Http3Varint/size 0)))
  (is (= 1 (Http3Varint/size 63)))
  (is (= 2 (Http3Varint/size 64)))
  (is (= 2 (Http3Varint/size 16383)))
  (is (= 4 (Http3Varint/size 16384)))
  (is (= 4 (Http3Varint/size 1073741823)))
  (is (= 8 (Http3Varint/size 1073741824))))

(deftest varint-peek-length
  (let [bb (ByteBuffer/allocate 8)]
    (Http3Varint/encode bb 1000)
    (.flip bb)
    (is (= 2 (Http3Varint/peekLength bb)))
    ;; Peek does not advance.
    (is (= 0 (.position bb)))))

(deftest nbit-integer-single-byte
  (let [bb (ByteBuffer/allocate 4)]
    ;; n=7, value=42, prefixBits=0x80 → single byte 0xAA
    (NBitInteger/encode bb 7 0x80 42)
    (.flip bb)
    (is (= 1 (.remaining bb)))
    (let [first (bit-and (.get bb) 0xFF)]
      ;; strip prefix: low 7 bits = 42
      (is (= 42 (NBitInteger/decode bb 7 (bit-and first 0x7F)))))))

(deftest nbit-integer-multi-byte
  ;; n=5, value=1337 → RFC 7541 §5.1 example.
  (let [bb (ByteBuffer/allocate 4)]
    (NBitInteger/encode bb 5 0 1337)
    (.flip bb)
    (let [b0 (bit-and (.get bb) 0xFF)]
      ;; low 5 bits = 31 (2^5 - 1)
      (is (= 31 (bit-and b0 0x1F)))
      (is (= 1337 (NBitInteger/decode bb 5 b0))))))

(deftest nbit-string-huffman-roundtrip
  (let [bb (ByteBuffer/allocate 128)]
    (NBitString/encode bb 3 0 "www.example.com" true)
    (.flip bb)
    (let [b0 (bit-and (.get bb) 0xFF)]
      (is (= "www.example.com"
             (NBitString/decode bb 3 (bit-and b0 0x0F)))))))

(deftest nbit-string-literal-roundtrip
  (let [bb (ByteBuffer/allocate 128)]
    (NBitString/encode bb 3 0 "hello world" false)
    (.flip bb)
    (let [b0 (bit-and (.get bb) 0xFF)]
      (is (= "hello world"
             (NBitString/decode bb 3 (bit-and b0 0x0F)))))))

(deftest huffman-lorem-roundtrip
  (let [text "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
        src (.getBytes text java.nio.charset.StandardCharsets/UTF_8)
        enc-len (QpackHuffman/encodedLength src 0 (alength src))
        enc (byte-array enc-len)]
    (is (< enc-len (alength src)) "Huffman shrinks the text")
    (QpackHuffman/encode src 0 (alength src) enc 0)
    (is (= text (String. (QpackHuffman/decode enc 0 enc-len)
                         java.nio.charset.StandardCharsets/UTF_8)))))

(deftest qpack-static-table-known-entries
  ;; Spot-check RFC 9204 Appendix A entries.
  (is (= [":authority" ""] (into [] (QpackStaticTable/get 0))))
  (is (= [":path" "/"] (into [] (QpackStaticTable/get 1))))
  (is (= [":method" "GET"] (into [] (QpackStaticTable/get 17))))
  (is (= [":status" "200"] (into [] (QpackStaticTable/get 25))))
  (is (= 99 (QpackStaticTable/size))))

(deftest qpack-static-table-lookups
  (is (= 17 (QpackStaticTable/findExact ":method" "GET")))
  (is (= 25 (QpackStaticTable/findExact ":status" "200")))
  ;; findName returns the LOWEST index for that name (so encoders emit
  ;; the shortest indexed-name reference).
  (is (= 15 (QpackStaticTable/findName ":method")))
  (is (= 24 (QpackStaticTable/findName ":status")))
  (is (= -1 (QpackStaticTable/findExact ":method" "TRACE")))
  (is (= -1 (QpackStaticTable/findName "x-custom"))))

(deftest h3-frame-writer-basic
  ;; SETTINGS frame with one id/value pair.
  (let [bb (Http3FrameWriter/settings (long-array [0x06 4096]))
        bytes (to-bytes bb)]
    ;; type=0x04, len=varint payload len, payload=id+value varints
    (is (= 0x04 (bit-and (aget bytes 0) 0xFF))
        "first byte is SETTINGS frame type")))

(deftest h3-frame-reader-single-headers
  (let [payload (byte-array [0x01 0x02 0x03])
        wire (to-bytes (Http3FrameWriter/headers payload))
        reader (Http3FrameReader.)]
    (.feed reader (ByteBuffer/wrap wire))
    (let [f (.poll reader)]
      (is (some? f))
      (is (= Http3FrameType/HEADERS (.-type f)))
      (is (= (seq payload) (seq (.-payload f)))))))

(deftest h3-frame-reader-fragmented-headers
  ;; Feed the frame in one-byte chunks — parser must survive partial
  ;; input for both header AND payload.
  (let [payload (byte-array [10 20 30 40 50])
        wire (to-bytes (Http3FrameWriter/headers payload))
        reader (Http3FrameReader.)]
    (doseq [b wire]
      (.feed reader (ByteBuffer/wrap (byte-array [b]))))
    (let [f (.poll reader)]
      (is (some? f) "reader emits frame after full assembly")
      (is (= (seq payload) (seq (.-payload f)))))))

(deftest h3-frame-reader-streams-data-chunks
  ;; Large DATA frame arriving in three chunks. Reader must stream them
  ;; without buffering the full payload.
  (let [body (byte-array (repeat 1500 42))
        wire (to-bytes (Http3FrameWriter/data body))
        reader (Http3FrameReader.)
        halves [(java.util.Arrays/copyOfRange wire 0 700)
                (java.util.Arrays/copyOfRange wire 700 (alength wire))]]
    (doseq [chunk halves]
      (.feed reader (ByteBuffer/wrap chunk)))
    (let [chunks (loop [acc []]
                   (let [f (.poll reader)]
                     (if (nil? f) acc (recur (conj acc f)))))]
      (is (every? #(.isDataChunk %) chunks))
      (is (= (alength body)
             (reduce + (map #(alength (.-dataChunk %)) chunks))))
      (is (.-dataFinalChunk (last chunks))))))

(defn- roundtrip-headers [pairs]
  (let [encoded (QpackFieldSection/encode
                 ^Iterable (mapv #(into-array String %) pairs))
        decoded (QpackFieldSection/decode encoded)]
    (mapv vec decoded)))

(deftest qpack-field-section-indexed-static
  ;; :method GET is index 17 in static table — should encode as single
  ;; Indexed byte (0xC0 | 17 = 0xD1) after the two-byte prefix.
  (let [encoded (QpackFieldSection/encode
                 ^Iterable [(into-array String [":method" "GET"])])]
    (is (= 3 (alength encoded)) "prefix (2) + one Indexed byte")
    (is (= 0x00 (bit-and (aget encoded 0) 0xFF)))
    (is (= 0x00 (bit-and (aget encoded 1) 0xFF)))
    (is (= 0xD1 (bit-and (aget encoded 2) 0xFF)))))

(deftest qpack-field-section-roundtrip-static-only
  (let [pairs [[":method" "GET"]
               [":scheme" "https"]
               [":path" "/"]
               [":status" "200"]]]
    (is (= pairs (roundtrip-headers pairs)))))

(deftest qpack-field-section-roundtrip-literal-name-ref
  ;; :authority has index 0 (empty value), so "example.com" should encode
  ;; as literal-with-name-ref (static).
  (let [pairs [[":method" "GET"]
               [":authority" "example.com"]
               [":path" "/api"]]]
    (is (= pairs (roundtrip-headers pairs)))))

(deftest qpack-field-section-roundtrip-literal-literal
  ;; Custom header not in static table — must encode as Literal Literal.
  (let [pairs [[":method" "POST"]
               ["x-custom-header" "some value"]
               ["another-header" "!@#$% weird chars"]]]
    (is (= pairs (roundtrip-headers pairs)))))

(deftest qpack-field-section-lowercases-literal-names
  ;; QPACK requires lowercase header names on the wire; our encoder
  ;; normalises. Decoder must return lowercase.
  (let [encoded (QpackFieldSection/encode
                 ^Iterable [(into-array String ["X-Weird-CASE" "v"])])
        decoded (QpackFieldSection/decode encoded)]
    (is (= "x-weird-case" (aget ^"[Ljava.lang.String;" (first decoded) 0)))))

(deftest qpack-field-section-large-value-huffman
  (let [big-val (apply str (repeat 200 "abcdef"))
        pairs [[":method" "GET"]
               ["etag" big-val]]
        roundtripped (roundtrip-headers pairs)]
    (is (= pairs roundtripped))))

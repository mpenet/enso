(ns s-exp.quiche-h3-foundation-test
  "Unit tests for the low-level H3 + QPACK primitives: varint, N-bit
  integer/string codecs, static table lookups. These have no dependency on
  a live QUIC connection and are purely CPU-driven."
  (:require [clojure.test :refer [deftest is testing]])
  (:import (com.s_exp.enso.http3 Http3FrameType Http3FrameReader Http3FrameReader$Frame Http3FrameWriter Http3Varint)
           (com.s_exp.enso.http3.qpack NBitInteger NBitString QpackFieldSection
                                       QpackHuffman QpackStaticTable)
           (java.nio ByteBuffer)))

(set! *warn-on-reflection* true)

(defn- to-bytes ^bytes [^ByteBuffer bb]
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
        halves [(java.util.Arrays/copyOfRange wire (int 0) (int 700))
                (java.util.Arrays/copyOfRange wire (int 700) (alength wire))]]
    (doseq [chunk halves]
      (.feed reader (ByteBuffer/wrap chunk)))
    (let [chunks (loop [acc []]
                   (let [f (.poll reader)]
                     (if (nil? f) acc (recur (conj acc f)))))]
      (is (every? #(.isDataChunk ^Http3FrameReader$Frame %) chunks))
      (is (= (alength body)
             (reduce + (map #(alength ^bytes (.-dataChunk ^Http3FrameReader$Frame %)) chunks))))
      (is (.-dataFinalChunk ^Http3FrameReader$Frame (last chunks))))))

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

(defn- thread-allocated-bytes ^long []
  (.getCurrentThreadAllocatedBytes
   ^com.sun.management.ThreadMXBean (java.lang.management.ManagementFactory/getThreadMXBean)))

(defn- decode-error-code [^bytes field-section]
  (try (QpackFieldSection/decode field-section)
       :no-error
       (catch com.s_exp.enso.http3.qpack.QpackException e (.errorCode e))
       (catch Throwable t (class t))))

(deftest qpack-huffman-literal-length-checked-before-allocating
  ;; Literal-with-literal-name, H=1, 3-bit length prefix saturated, then
  ;; continuation bytes claiming ~1 GiB in a 9-byte field section.
  (let [fs (byte-array (map unchecked-byte [0x00 0x00 0x2F 0xFF 0xFF 0xFF 0xFF 0x03]))
        before (thread-allocated-bytes)
        code (decode-error-code fs)
        allocated (- (thread-allocated-bytes) before)]
    (is (= 0x200 code) "QPACK_DECOMPRESSION_FAILED")
    (is (< allocated (* 1024 1024)) (str "allocated " allocated " bytes"))))

(deftest qpack-huffman-literal-length-over-1gib-is-decompression-failure
  ;; Claimed length 2^30 + 1: scratch sizing used to overflow to a
  ;; negative array size (NegativeArraySizeException escaped).
  (let [n (inc (bit-shift-left 1 30))
        bb (ByteBuffer/allocate 16)]
    (.put bb (byte 0x00))
    (.put bb (byte 0x00))
    (NBitInteger/encode bb 3 0x28 n)
    (.flip bb)
    (is (= 0x200 (decode-error-code (to-bytes bb))))))

(deftest qpack-plain-literal-truncated-is-decompression-failure
  ;; Name ref :authority (static 0), plain value claiming 10 bytes, 2 present.
  (let [fs (byte-array (map unchecked-byte [0x00 0x00 0x50 0x0A 0x61 0x62]))]
    (is (= 0x200 (decode-error-code fs)))))

(deftest qpack-decoded-field-section-size-capped
  ;; 2000 × indexed static 62 (x-xss-protection: 1; mode=block) = 2 KB
  ;; on the wire but ~122 KB decoded (name + value + 32 per field).
  (let [fs (byte-array (concat [0 0] (repeat 2000 (unchecked-byte 0xFE))))]
    (is (= 2000 (.size (QpackFieldSection/decode fs))) "uncapped decode")
    (let [^com.s_exp.enso.http3.qpack.QpackException e (try (QpackFieldSection/decode fs 4096) nil
                                                            (catch com.s_exp.enso.http3.qpack.QpackException e e))]
      (is (some? e) "cap exceeded")
      (when e
        (is (= 0x107 (.errorCode e)) "H3_EXCESSIVE_LOAD")
        (is (.isStreamLevel e) "stream error, not connection error")))))

(deftest nbit-string-huffman-only-when-shorter
  ;; 'ü' is octet 0xFC, whose Huffman code is longer than 8 bits: raw must win.
  (let [s (apply str (repeat 50 "ü"))
        bb (ByteBuffer/allocate 256)]
    (NBitString/encode bb 7 0 s true)
    (.flip bb)
    (let [b0 (bit-and (.get bb) 0xFF)]
      (is (zero? (bit-and b0 0x80)) "H bit clear")
      (is (= s (NBitString/decode bb 7 b0)))))
  (let [s "www.example.com/some/path"
        bb (ByteBuffer/allocate 256)]
    (NBitString/encode bb 7 0 s true)
    (is (< (.position bb) (inc (count s))) "ASCII text still Huffman-compressed")))

(deftest qpack-encoded-size-within-max-encoded-length
  (doseq [[n v] [["x-u" (apply str (repeat 300 "ü"))]
                 ["x-emoji" (apply str (repeat 100 "😀"))]
                 ["x-bin" (apply str (map char (range 1 128)))]
                 ["content-type" "text/html; charset=utf-8"]
                 ["x-long" (apply str (repeat 5000 "z"))]]]
    (let [bb (ByteBuffer/allocate 65536)
          written (- (QpackFieldSection/encodeInto bb [(into-array String [n v])]) 2)]
      (is (<= written (QpackFieldSection/maxEncodedLength n v)) n))))

(deftest nbit-string-field-bytes-are-latin1-octets
  ;; Field values are octets (RFC 9110 §5.5), carried as ISO-8859-1 like
  ;; h1 and h2: every byte round-trips and chars above U+00FF become '?'.
  (let [bb (ByteBuffer/allocate 16)]
    (NBitString/encode bb 7 0 "ü" false)
    (.flip bb)
    (is (= [1 0xFC] (mapv #(bit-and % 0xFF) (take (.limit bb) (.array bb)))))
    (let [b0 (bit-and (.get bb) 0xFF)]
      (is (= "ü" (NBitString/decode bb 7 b0)))))
  (let [bb (ByteBuffer/wrap (byte-array [1 (unchecked-byte 0xFF)]))
        b0 (bit-and (.get bb) 0xFF)]
    (is (= "ÿ" (NBitString/decode bb 7 b0))))
  (let [bb (ByteBuffer/allocate 16)]
    (NBitString/encode bb 7 0 "€\n" false)
    (is (= [2 (int \?) 10] (mapv #(bit-and % 0xFF) (take (.position bb) (.array bb)))))))

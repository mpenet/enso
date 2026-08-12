(ns s-exp.enso-h3-util-test
  "H3 helper class tests: Http3BodyPipe (truncation marker per #212),
  Http3FrameReader (mid-frame partial detection per #219), and
  RetryToken (issued-at expiry per #235). Tests target the Java
  classes directly, no server startup required."
  (:require [clojure.test :refer [deftest testing is]])
  (:import (com.s_exp.enso.http3 Http3BodyPipe Http3FrameReader)
           (com.s_exp.enso.quiche RetryToken)
           (java.io IOException)
           (java.lang.reflect Field)
           (java.net InetSocketAddress)
           (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets)))

;; ---- Http3BodyPipe truncated marker --------------------------------------

(deftest body-pipe-truncated-throws-ioexception-on-next-read
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "abcd" StandardCharsets/UTF_8))
    (.signalTruncated pipe)
    (let [scratch (byte-array 10)
          n (.read in scratch 0 10)]
      (is (= 4 n) "queued bytes returned before poison")
      (is (thrown-with-msg? IOException #"exceeded size cap"
                            (.read in scratch 0 10))
          "next read hits truncated marker → IOException"))))

(deftest body-pipe-truncated-with-no-queued-bytes
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.signalTruncated pipe)
    (is (thrown? IOException (.read in)))))

(deftest body-pipe-signalend-still-yields-clean-eof
  ;; Sanity: signalEnd (non-truncated) must remain -1 EOF, not IOException.
  (let [pipe (Http3BodyPipe.)
        in (.inputStream pipe)]
    (.enqueue pipe (.getBytes "hi" StandardCharsets/UTF_8))
    (.signalEnd pipe)
    (let [scratch (byte-array 10)]
      (is (= 2 (.read in scratch 0 10)))
      (is (= -1 (.read in scratch 0 10)) "clean EOF after signalEnd"))))

;; ---- Http3FrameReader partial detection ----------------------------------

(defn- feed-bytes! [^Http3FrameReader r ^bytes b]
  (.feed r b 0 (alength b)))

(deftest frame-reader-empty-not-partial
  (let [r (Http3FrameReader. 65536)]
    (is (not (.hasPartial r)) "fresh reader has no buffered bytes")))

(deftest frame-reader-partial-varint-detected
  ;; Feed a single byte that looks like the start of a multi-byte varint.
  ;; Http3 varint prefix 0b10xxxxxx = 2-byte, so 0x40 alone is incomplete.
  ;; Even simpler: feed 0x00 (a single-byte varint = type 0 for DATA)
  ;; without the length byte → length varint incomplete.
  (let [r (Http3FrameReader. 65536)]
    (feed-bytes! r (byte-array [(byte 0x00)]))
    (is (.hasPartial r) "type parsed but no length yet → partial")))

(deftest frame-reader-complete-frame-not-partial
  ;; DATA frame (type 0), length 3, payload "abc". Full frame → no partial.
  (let [r (Http3FrameReader. 65536)
        buf (byte-array [(byte 0x00) (byte 0x03) (byte 0x61) (byte 0x62) (byte 0x63)])]
    (feed-bytes! r buf)
    (loop []
      (when (.poll r) (recur))) ;; drain any DATA chunk emissions
    (is (not (.hasPartial r)) "fully-consumed frame leaves reader empty")))

(deftest frame-reader-mid-payload-detected
  ;; DATA type=0 length=10, only 3 payload bytes fed. Reader should
  ;; emit a partial DATA chunk (2-byte header + 3 payload) then still
  ;; report `hasPartial=true` because pendingLength > pendingConsumed.
  (let [r (Http3FrameReader. 65536)
        buf (byte-array [(byte 0x00) (byte 0x0A)
                         (byte 0x61) (byte 0x62) (byte 0x63)])]
    (feed-bytes! r buf)
    ;; drain any emitted DATA chunk
    (loop []
      (when (.poll r) (recur)))
    (is (.hasPartial r) "mid-frame payload → hasPartial")))

(deftest frame-reader-reset-clears-partial
  (let [r (Http3FrameReader. 65536)]
    (feed-bytes! r (byte-array [(byte 0x00)]))
    (is (.hasPartial r))
    (.reset r)
    (is (not (.hasPartial r)) "reset clears buffered bytes")))

;; ---- RetryToken issued-at + expiry ---------------------------------------

(deftest retry-token-issued-at-tampered-rejected
  ;; Flip a byte inside the 8-byte issued-at region: token becomes
  ;; wall-clock far past → verify rejects on age > TOKEN_MAX_AGE_SECONDS.
  (let [tok (RetryToken.)
        peer (InetSocketAddress. "127.0.0.1" 55555)
        odcid (byte-array [(byte 1) (byte 2) (byte 3)])
        ^bytes minted (.mint tok peer odcid)]
    ;; Sanity: intact token verifies.
    (is (some? (.verify tok minted peer)))
    ;; Locate issued-at start via reflection: layout is
    ;; HMAC(32) + MAGIC(4) + ISSUED_AT(8) + IP + port + odcid_len + odcid.
    ;; Flip MSB of issued-at: value jumps by 2^56 seconds → age check fails.
    (let [issued-at-off 36
          copy (aclone minted)]
      (aset copy issued-at-off
            (byte (bit-xor (aget copy issued-at-off) 0x40)))
      (is (nil? (.verify tok copy peer))
          "tampered issued-at rejected (HMAC mismatch OR age out of window)"))))

(deftest retry-token-max-age-seconds-constant
  (let [^Field f (.getDeclaredField RetryToken "TOKEN_MAX_AGE_SECONDS")]
    (.setAccessible f true)
    (is (= 10 (.getLong f nil))
        "documented max-age is 10 seconds — bump this test if you change it")))

(deftest retry-token-issued-at-len-constant
  (let [^Field f (.getDeclaredField RetryToken "ISSUED_AT_LEN")]
    (.setAccessible f true)
    (is (= 8 (.getInt f nil))
        "issued-at is 8 bytes (big-endian seconds)")))

(deftest retry-token-min-length-accounts-for-issued-at
  ;; Length shorter than HMAC + MAGIC + ISSUED_AT + odcid_len byte is
  ;; rejected upfront without even attempting HMAC.
  (let [tok (RetryToken.)
        peer (InetSocketAddress. "127.0.0.1" 55555)
        too-short (byte-array (+ 32 4 8))]  ; missing odcid_len + odcid + peer
    (is (nil? (.verify tok too-short peer)))))

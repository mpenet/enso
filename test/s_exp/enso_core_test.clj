;; ABOUTME: Unit tests for the protocol-neutral core shared by every driver: timer, write
;; ABOUTME: watchdog, response head, request-head validation, limiter, events; incl. allocation bounds.
(ns s-exp.enso-core-test
  (:require [clojure.test :refer [are deftest testing is]])
  (:import (com.s_exp.enso.api Response RingErrorHandler StreamingBody)
           (com.s_exp.enso.core ConnectionLimiter ConnectionRegistry Drainable Jfr MemoryBudget
                                MemoryBudget$Waiter RequestHead ResponseHead Timer Timer$Task
                                WatchedOutputStream WriteWatchdog)
           (java.net InetAddress)
           (jdk.jfr Recording)
           (com.s_exp.enso.api WebSocketListener)
           (java.io ByteArrayInputStream File OutputStream)
           (java.lang.management ManagementFactory)
           (java.util.concurrent CountDownLatch TimeUnit)
           (java.util.concurrent.atomic AtomicInteger)))

(set! *warn-on-reflection* true)

(def ^:private ^com.sun.management.ThreadMXBean thread-mx
  (ManagementFactory/getThreadMXBean))

(defn- bytes-per-op
  "Bytes the current thread allocates per run of `f`, over `n` runs after
  the same number of warm-up runs. Any real per-run allocation is at least
  16 bytes (one object header), so a result below 1 means none: what is
  left is one-off JIT / safepoint noise spread over the runs."
  ^double [n f]
  (dotimes [_ n] (f))
  (let [before (.getCurrentThreadAllocatedBytes thread-mx)]
    (dotimes [_ n] (f))
    (/ (double (- (.getCurrentThreadAllocatedBytes thread-mx) before)) n)))

;; ---- Timer -----------------------------------------------------------------

(defn- counting-task ^Timer$Task [^AtomicInteger fired ^CountDownLatch latch]
  (proxy [Timer$Task] []
    (onTimeout []
      (.incrementAndGet fired)
      (.countDown latch))))

(deftest timer-fires-no-earlier-than-the-delay
  (with-open [timer (Timer.)]
    (let [fired (AtomicInteger.)
          latch (CountDownLatch. 1)
          task (counting-task fired latch)
          t0 (System/nanoTime)]
      (.schedule timer task 50)
      (is (.await latch 2 TimeUnit/SECONDS))
      (is (>= (/ (- (System/nanoTime) t0) 1e6) 50.0))
      (is (= 1 (.get fired))))))

(deftest timer-cancel-before-expiry-wins
  (with-open [timer (Timer.)]
    (let [fired (AtomicInteger.)
          task (counting-task fired (CountDownLatch. 1))]
      (.schedule timer task 50)
      (is (true? (.cancel timer task)))
      (is (false? (.cancel timer task)) "second cancel finds nothing armed")
      (Thread/sleep 150)
      (is (zero? (.get fired))))))

(deftest timer-cancel-after-expiry-reports-fired
  (with-open [timer (Timer.)]
    (let [fired (AtomicInteger.)
          latch (CountDownLatch. 1)
          task (counting-task fired latch)]
      (.schedule timer task 10)
      (is (.await latch 2 TimeUnit/SECONDS))
      (is (false? (.cancel timer task))))))

(deftest timer-rearm-extends-and-shortens
  (with-open [timer (Timer.)]
    (testing "re-arming later postpones expiry"
      (let [fired (AtomicInteger.)
            latch (CountDownLatch. 1)
            task (counting-task fired latch)
            t0 (System/nanoTime)]
        (.schedule timer task 30)
        (.schedule timer task 200)
        (is (.await latch 2 TimeUnit/SECONDS))
        (is (>= (/ (- (System/nanoTime) t0) 1e6) 200.0))
        (is (= 1 (.get fired)))))
    (testing "re-arming sooner advances expiry"
      (let [fired (AtomicInteger.)
            latch (CountDownLatch. 1)
            task (counting-task fired latch)
            t0 (System/nanoTime)]
        (.schedule timer task 60000)
        (.schedule timer task 20)
        (is (.await latch 2 TimeUnit/SECONDS))
        (is (< (/ (- (System/nanoTime) t0) 1e6) 1000.0))))
    (testing "a task can be re-armed after it fired"
      (let [fired (AtomicInteger.)
            latch (CountDownLatch. 2)
            task (counting-task fired latch)]
        (.schedule timer task 10)
        (Thread/sleep 100)
        (.schedule timer task 10)
        (is (.await latch 2 TimeUnit/SECONDS))
        (is (= 2 (.get fired)))))))

(deftest timer-delays-beyond-one-wheel-rotation
  (with-open [timer (Timer. "enso-test-timer" 1 8)]
    (let [fired (AtomicInteger.)
          latch (CountDownLatch. 1)
          task (counting-task fired latch)
          t0 (System/nanoTime)]
      (.schedule timer task 40)
      (is (.await latch 2 TimeUnit/SECONDS))
      (is (>= (/ (- (System/nanoTime) t0) 1e6) 40.0)))))

(deftest timer-many-tasks-each-fire-once
  (with-open [timer (Timer.)]
    (let [n 5000
          fired (AtomicInteger.)
          latch (CountDownLatch. n)
          tasks (vec (repeatedly n #(counting-task fired latch)))]
      (doseq [[i ^Timer$Task t] (map-indexed vector tasks)]
        (.schedule timer t (+ 1 (mod i 50))))
      (is (.await latch 5 TimeUnit/SECONDS))
      (Thread/sleep 50)
      (is (= n (.get fired))))))

(deftest timer-callback-failure-does-not-stop-the-timer
  (with-open [timer (Timer.)]
    (let [latch (CountDownLatch. 1)
          bad (proxy [Timer$Task] [] (onTimeout [] (throw (RuntimeException. "boom"))))
          good (counting-task (AtomicInteger.) latch)]
      (.schedule timer bad 5)
      (.schedule timer good 30)
      (is (.await latch 2 TimeUnit/SECONDS)))))

(defn- collected? [^java.lang.ref.WeakReference ref ms]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (System/gc)
      (cond
        (nil? (.get ref)) true
        (> (System/currentTimeMillis) deadline) false
        :else (do (Thread/sleep 20) (recur))))))

(deftest timer-retire-lets-go-of-one-shot-tasks-promptly
  ;; A cancelled task is unlinked lazily, when the wheel reaches its slot
  ;; (up to one rotation). A retired one is unlinked on the next tick, so
  ;; per-request objects don't outlive their request in the wheel.
  (with-open [timer (Timer. "enso-test-timer" 10 4096)]
    (let [ref (java.lang.ref.WeakReference.
               (let [task (counting-task (AtomicInteger.) (CountDownLatch. 1))]
                 (.schedule timer task 30000)
                 (Thread/sleep 50)
                 (is (true? (.retire timer task)))
                 task))]
      (is (collected? ref 3000) "retired task no longer referenced by the wheel")))
  (testing "retiring a task that was cancelled earlier (still linked) lets go of it too"
    (with-open [timer (Timer. "enso-test-timer" 10 4096)]
      (let [ref (java.lang.ref.WeakReference.
                 (let [task (counting-task (AtomicInteger.) (CountDownLatch. 1))]
                   (.schedule timer task 30000)
                   (Thread/sleep 50)
                   (is (true? (.cancel timer task)))
                   (is (false? (.retire timer task)) "it was no longer armed")
                   task))]
        (is (collected? ref 3000))))))

(deftest timer-arm-and-cancel-allocate-nothing
  (with-open [timer (Timer.)]
    (let [task (counting-task (AtomicInteger.) (CountDownLatch. 1))]
      (is (> 1.0 (bytes-per-op 100000 (fn [] (.schedule timer task 10000) (.cancel timer task)))))
      (testing "re-arming an armed task"
        (is (> 1.0 (bytes-per-op 100000 (fn [] (.schedule timer task 10000)))))))))

;; ---- Write watchdog --------------------------------------------------------

(defn- watchdog ^WriteWatchdog [^Timer timer timeout-ms stalled]
  (proxy [WriteWatchdog] [timer (long timeout-ms)]
    (onStall [] (deliver stalled (System/nanoTime)))))

(defn- sink
  "OutputStream whose writes each take `write-ms` and block for good once
  `blocked` is realized."
  ^OutputStream [write-ms blocked]
  (proxy [OutputStream] []
    (write
      ([_])
      ([_ _ _]
       (when (realized? blocked) @(promise))
       (when (pos? write-ms) (Thread/sleep (long write-ms)))))))

(deftest watchdog-fires-on-a-write-without-progress
  (with-open [timer (Timer.)]
    (let [stalled (promise)
          blocked (doto (promise) (deliver true))
          out (WatchedOutputStream. (sink 0 blocked) (watchdog timer 100 stalled))
          t0 (System/nanoTime)]
      (future (.write out (byte-array 10) 0 10))
      (let [at (deref stalled 2000 nil)]
        (is (some? at) "stall detected")
        (when at
          (is (<= 100 (/ (- at t0) 1e6) 1000)))))))

(deftest watchdog-tolerates-slow-but-progressing-writes
  (with-open [timer (Timer.)]
    (let [stalled (promise)
          ;; Each 256 KiB slice takes 60ms: slower than nothing, but every
          ;; slice completes well inside the 150ms timeout.
          out (WatchedOutputStream. (sink 60 (promise)) (watchdog timer 150 stalled))]
      (.write out (byte-array (* 8 256 1024)) 0 (* 8 256 1024))
      (is (not (realized? stalled))))))

(deftest watchdog-ignores-idle-connections
  (with-open [timer (Timer.)]
    (let [stalled (promise)
          out (WatchedOutputStream. (sink 0 (promise)) (watchdog timer 30 stalled))]
      (.write out (byte-array 10) 0 10)
      (Thread/sleep 200)
      (is (not (realized? stalled))))))

(deftest watched-writes-allocate-nothing
  (with-open [timer (Timer.)]
    (let [out (WatchedOutputStream. (OutputStream/nullOutputStream) (watchdog timer 60000 (promise)))
          buf (byte-array 512)]
      (is (> 1.0 (bytes-per-op 100000 (fn [] (.write out buf 0 512) (.flush out))))))))

;; ---- Response head ---------------------------------------------------------

(defn- head-of
  (^ResponseHead [status headers body] (head-of status headers body false ResponseHead/HTTP1))
  (^ResponseHead [status headers body head? mode]
   (doto (ResponseHead.) (.prepare (Response. (int status) headers body) (boolean head?) (int mode)))))

(defn- fields [^ResponseHead h]
  (vec (for [i (range (.fieldCount h))] [(.name h i) (.value h i)])))

(def ^:private ws-listener
  (reify WebSocketListener
    (onOpen [_ _]) (onMessage [_ _ _]) (onPing [_ _ _]) (onPong [_ _ _])
    (onError [_ _ _]) (onClose [_ _ _ _])))

(deftest response-head-simple-get
  (let [h (head-of 200 {"content-type" "text/plain"} "hello")]
    (is (= 200 (.status h)))
    (is (= [["content-type" "text/plain"]] (fields h)))
    (is (= ResponseHead/BODY_ASCII (.bodyKind h)))
    (is (= "hello" (.text h)))
    (is (= 5 (.contentLength h)))
    (is (.bodyAllowed h))
    (is (not (.hasDate h)))
    (is (not (.hasServer h)))
    (is (not (.hasAltSvc h)))))

(deftest response-head-status-validation
  (doseq [status [0 99 100 103 101 199 600 1000 -1]]
    (is (thrown? IllegalArgumentException (head-of status nil nil)) (str status)))
  (doseq [status [200 204 299 304 404 418 599]]
    (is (= status (.status (head-of status nil nil)))))
  (testing "101 only with a WebSocket listener"
    (let [h (ResponseHead.)]
      (.prepare h (Response. 101 nil nil ws-listener nil) false ResponseHead/HTTP1)
      (is (= 101 (.status h)))
      (is (= -1 (.contentLength h))))))

(deftest response-head-field-policy
  (testing "names must be tokens, values RFC 9110 field values"
    (doseq [headers [{"bad name" "v"} {"" "v"} {"x\u010d" "v"} {"x" "a\rb"} {"x" "a\nb"}
                     {"x" "a\u0000b"} {"x" "\u0100"} {"x" ["ok" "a\rb"]}]]
      (is (thrown? IllegalArgumentException (head-of 200 headers nil)) (pr-str headers))))
  (testing "nil values are skipped, seqs expand to one field per element"
    (is (= [["set-cookie" "a=1"] ["set-cookie" "b=2"]]
           (fields (head-of 200 {"x-nil" nil "set-cookie" ["a=1" nil "b=2"]} nil))))
    (is (= [["x" "1"] ["x" "2"]] (fields (head-of 200 {"x" (list "1" "2")} nil)))))
  (testing "numbers are kept as numbers"
    (is (= [["x-n" 42]] (fields (head-of 200 {"x-n" 42} nil)))))
  (testing "framing belongs to the server"
    (let [h (head-of 200 {"Transfer-Encoding" "chunked" "Content-Length" "99"} "abc")]
      (is (= [] (fields h)))
      (is (= 3 (.contentLength h)))))
  (testing "invalid handler Content-Length is a handler error"
    (doseq [cl ["-1" "1.0" "+5" "5, 5" "" "x"]]
      (is (thrown? IllegalArgumentException
                   (head-of 200 {"content-length" cl} (ByteArrayInputStream. (byte-array 0))))
          cl)))
  (testing "Date, Server and Alt-Svc are noticed"
    (let [h (head-of 200 {"Date" "x" "SERVER" "y" "alt-svc" "z"} nil)]
      (is (.hasDate h))
      (is (.hasServer h))
      (is (.hasAltSvc h)))))

(deftest response-head-connection-specific-fields
  (let [headers {"Connection" "close" "Keep-Alive" "timeout=5" "Upgrade" "h2c"
                 "Proxy-Connection" "x" "X-Ok" "1"}]
    (testing "HTTP/1.1 keeps them and notices close"
      (let [h (head-of 200 headers nil)]
        (is (.closeRequested h))
        (is (= 5 (.fieldCount h)))))
    (testing "multiplexed protocols drop them and get lowercase names"
      (let [h (head-of 200 headers nil false ResponseHead/MULTIPLEXED)]
        (is (= [["x-ok" "1"]] (fields h)))))))

(deftest response-head-body-kinds
  (is (= [ResponseHead/BODY_NONE 0] ((juxt #(.bodyKind ^ResponseHead %) #(.contentLength ^ResponseHead %))
                                     (head-of 200 nil nil))))
  (let [h (head-of 200 nil (byte-array 7))]
    (is (= ResponseHead/BODY_BYTES (.bodyKind h)))
    (is (= 7 (.contentLength h))))
  (testing "non-ASCII text is encoded with the Content-Type charset"
    (let [h (head-of 200 nil "\u00e9t\u00e9")]
      (is (= ResponseHead/BODY_BYTES (.bodyKind h)))
      (is (= 5 (.contentLength h))))
    (let [h (head-of 200 {"Content-Type" "text/plain; charset=ISO-8859-1"} "\u00e9t\u00e9")]
      (is (= 3 (.contentLength h))))
    (is (thrown? IllegalArgumentException
                 (head-of 200 {"content-type" "text/plain; charset=nope"} "x"))))
  (let [f (doto (File/createTempFile "enso-head" ".txt") (.deleteOnExit))]
    (spit f "0123456789")
    (let [h (head-of 200 nil f)]
      (is (= ResponseHead/BODY_FILE (.bodyKind h)))
      (is (= 10 (.contentLength h)))
      (is (some? (.fileChannel h)))
      (.release h)))
  (let [h (head-of 200 nil (ByteArrayInputStream. (byte-array 3)))]
    (is (= ResponseHead/BODY_STREAM (.bodyKind h)))
    (is (= -1 (.contentLength h))))
  (let [h (head-of 200 {"content-length" "3"} (ByteArrayInputStream. (byte-array 3)))]
    (is (= 3 (.contentLength h)))
    (is (= 3 (.declaredLength h))))
  (let [h (head-of 200 nil (reify StreamingBody (write [_ _])))]
    (is (= ResponseHead/BODY_STREAMING (.bodyKind h))))
  (is (thrown? IllegalArgumentException (head-of 200 nil 42))))

(deftest response-head-bodiless-responses
  (testing "HEAD: no body, length as GET would have it, handler length wins"
    (let [h (head-of 200 nil "hello" true ResponseHead/HTTP1)]
      (is (not (.bodyAllowed h)))
      (is (= 5 (.contentLength h))))
    (is (= 99 (.contentLength (head-of 200 {"content-length" "99"} "hello" true ResponseHead/HTTP1)))))
  (testing "1xx and 204 never carry Content-Length"
    (is (= -1 (.contentLength (head-of 204 {"content-length" "5"} nil))))
    (is (not (.bodyAllowed (head-of 204 nil "x")))))
  (testing "304 keeps a handler length, never computes one"
    (is (= 5 (.contentLength (head-of 304 {"content-length" "5"} nil))))
    (is (= -1 (.contentLength (head-of 304 nil "abc"))))
    (is (not (.bodyAllowed (head-of 304 nil nil))))))

(deftest response-head-release-closes-unsent-bodies
  (let [closed (atom false)
        in (proxy [ByteArrayInputStream] [(byte-array 1)] (close [] (reset! closed true)))
        h (head-of 204 nil in)]
    (.release h)
    (is @closed)
    (is (nil? (.stream h)))))

(deftest response-head-allocates-nothing-per-response
  (let [h (ResponseHead.)
        small (Response. 200 {"content-type" "text/plain" "x-request-id" "abc"} "hello")
        big (Response. 404 (into {} (for [i (range 20)] [(str "x-h" i) (str "v" i)])) (byte-array 10))]
    (is (> 1.0 (bytes-per-op 100000 (fn [] (.prepare h small false ResponseHead/HTTP1) (.release h)))))
    (is (> 1.0 (bytes-per-op 100000 (fn [] (.prepare h big false ResponseHead/HTTP1) (.release h)))))
    (is (> 1.0 (bytes-per-op 100000 (fn [] (.prepare h small false ResponseHead/MULTIPLEXED) (.release h)))))))

;; ---- Request head ----------------------------------------------------------

(def ^:private good-request
  [[":method" "GET"] [":scheme" "https"] [":authority" "example.com:8443"] [":path" "/a?b=1"]
   ["accept" "*/*"] ["cookie" "a=1"] ["te" "trailers"] ["content-length" "0"]])

(defn- verdict
  "Feeds `fields` to a fresh RequestHead; :ok, :connect or the failing field index / :finish."
  [fields]
  (let [h (RequestHead.)]
    (or (first (keep-indexed (fn [i [n v]]
                               (when (= RequestHead/MALFORMED (.add h n v)) i))
                             fields))
        (condp = (.finish h)
          RequestHead/OK :ok
          RequestHead/NOT_IMPLEMENTED :connect
          :finish))))

(deftest request-head-accepts-a-valid-request
  (let [h (RequestHead.)
        kinds (mapv (fn [[n v]] (.add h n v)) good-request)]
    (is (= [RequestHead/PSEUDO RequestHead/PSEUDO RequestHead/PSEUDO RequestHead/PSEUDO
            RequestHead/FIELD RequestHead/FIELD RequestHead/FIELD RequestHead/FIELD]
           kinds))
    (is (= RequestHead/OK (.finish h)))
    (is (= "GET" (.method h)))
    (is (= "https" (.scheme h)))
    (is (= "/a?b=1" (.path h)))
    (is (= "example.com:8443" (.authority h)))
    (is (= 0 (.contentLength h)))
    (testing "reset makes the instance reusable"
      (.reset h)
      (is (= RequestHead/PSEUDO (.add h ":method" "POST")))
      (is (nil? (.path h)))
      (is (= -1 (.contentLength h))))))

(defmacro ^:private are-verdicts [& pairs]
  `(do ~@(for [[fields expected] (partition 2 pairs)]
           `(is (= ~expected (verdict ~fields)) (pr-str ~fields)))))

(deftest request-head-pseudo-header-rules
  (are-verdicts
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] ["host" "x"]] :ok
   [[":method" "GET"] [":scheme" "https"] [":path" "/"]] :finish
   [[":scheme" "https"] [":path" "/"] [":authority" "x"]] :finish
   [[":method" "GET"] [":path" "/"] [":authority" "x"]] :finish
   [[":method" "GET"] [":scheme" "https"] [":authority" "x"]] :finish
   [[":method" "GET"] [":method" "GET"]] 1
   [[":method" "GET"] ["x" "1"] [":path" "/"]] 2
   [[":method" "GET"] [":protocol" "websocket"]] 1
   [[":status" "200"]] 0
   [[":method" "G T"]] 0
   [[":method" "GET"] [":scheme" "ftp"] [":path" "/"] [":authority" "x"]] :finish
   [[":method" "GET"] [":scheme" "https"] [":path" "a"] [":authority" "x"]] :finish
   [[":method" "GET"] [":scheme" "https"] [":path" ""] [":authority" "x"]] :finish
   [[":method" "GET"] [":scheme" "https"] [":path" "/a b"] [":authority" "x"]] :finish
   [[":method" "GET"] [":scheme" "https"] [":path" "*"] [":authority" "x"]] :finish
   [[":method" "OPTIONS"] [":scheme" "https"] [":path" "*"] [":authority" "x"]] :ok))

(deftest request-head-connect-is-not-implemented
  (are-verdicts
   [[":method" "CONNECT"] [":authority" "example.com:443"]] :connect
   [[":method" "CONNECT"] [":authority" "example.com:443"] [":path" "/"]] :finish
   [[":method" "CONNECT"] [":authority" "example.com:443"] [":scheme" "https"]] :finish
   [[":method" "CONNECT"]] :finish))

(deftest request-head-authority-and-host
  (are-verdicts
   (conj (pop good-request) ["host" "EXAMPLE.com:8443"]) :ok
   (conj (pop good-request) ["host" "other.com"]) :finish
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "user@x"]] 3
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" ""]] 3
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "[::1]:443"]] :ok
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "[::1"]] 3
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "a b"]] 3
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "x:12345678"]] 3
   [[":method" "GET"] [":scheme" "https"] [":path" "/"] ["host" "x"] ["host" "x"]] 4))

(deftest request-head-field-rules
  (let [base [[":method" "GET"] [":scheme" "https"] [":path" "/"] [":authority" "x"]]]
    (doseq [[field expected] [[["Accept" "x"] 4]
                              [["acc ept" "x"] 4]
                              [["" "x"] 4]
                              [["connection" "close"] 4]
                              [["keep-alive" "1"] 4]
                              [["proxy-connection" "x"] 4]
                              [["transfer-encoding" "chunked"] 4]
                              [["upgrade" "h2c"] 4]
                              [["te" "gzip"] 4]
                              [["te" "Trailers"] :ok]
                              [["x" "a\u0000b"] 4]
                              [["x" "a\rb"] 4]
                              [["x" "a\nb"] 4]
                              [["x" "a\u0001b"] 4]
                              [["x" "a\u007fb"] 4]
                              [["x" "a\tb"] :ok]
                              [["x" " a"] 4]
                              [["x" "a\t"] 4]
                              [["x" ""] :ok]
                              [["content-length" "+1"] 4]
                              [["content-length" "1,1"] 4]]]
      (is (= expected (verdict (conj base field))) (pr-str field))))
  (testing "a repeated content-length is malformed, agreeing or not (as on HTTP/1.1)"
    (is (= 5 (verdict [[":method" "POST"] [":scheme" "https"] [":path" "/"] [":authority" "x"]
                       ["content-length" "5"] ["content-length" "5"]])))
    (is (= 5 (verdict [[":method" "POST"] [":scheme" "https"] [":path" "/"] [":authority" "x"]
                       ["content-length" "5"] ["content-length" "6"]])))))

(deftest request-head-splits-the-target
  (let [split (fn [path]
                (let [h (RequestHead.)]
                  (doseq [[n v] [[":method" "GET"] [":scheme" "https"] [":authority" "x"] [":path" path]]]
                    (.add h n v))
                  (.finish h)
                  [(.uri h) (.query h)]))]
    (is (= ["/a" nil] (split "/a")))
    (is (= ["/a" "b=1&c"] (split "/a?b=1&c")))
    (is (= ["/a" ""] (split "/a?")))
    (is (= ["*" nil] (let [h (RequestHead.)]
                       (doseq [[n v] [[":method" "OPTIONS"] [":scheme" "https"] [":authority" "x"] [":path" "*"]]]
                         (.add h n v))
                       (.finish h)
                       [(.uri h) (.query h)])))))

(deftest request-head-host-grammar
  (doseq [ok ["example.com" "example.com:80" "127.0.0.1" "127.0.0.1:8080" "[::1]" "[::1]:80"
              "[v1.fe80::a+en1]" "xn--bcher-kva.example" "a-b_c~d!$&'()*+,;=" "x:" "%41"]]
    (is (RequestHead/isValidAuthority ok) ok))
  (doseq [bad ["" "user@example.com" "a b" "a/b" "a?b" "a#b" "[::1" "::1" "[::1]x" "[]" "%4" "%zz"
               "x:1a" "x:123456" "[g::1]"]]
    (is (not (RequestHead/isValidAuthority bad)) bad)))

(deftest request-head-absolute-form-target
  (are [target authority path query] (= [authority path query]
                                        (some-> (RequestHead/parseAbsoluteForm target)
                                                ((juxt #(.authority ^com.s_exp.enso.core.RequestHead$AbsoluteForm %)
                                                       #(.path ^com.s_exp.enso.core.RequestHead$AbsoluteForm %)
                                                       #(.query ^com.s_exp.enso.core.RequestHead$AbsoluteForm %)))))
    "http://example.com/a/b?c=d" "example.com" "/a/b" "c=d"
    "HTTPS://example.com:8443" "example.com:8443" "/" nil
    "http://example.com?x" "example.com" "/" "x"
    "http://[::1]:80/p" "[::1]:80" "/p" nil)
  (doseq [bad ["ftp://x/" "http:/x" "http://" "http:///p" "http://u@x/" "http://a b/" "example.com/x"]]
    (is (nil? (RequestHead/parseAbsoluteForm bad)) bad)))

(deftest request-head-validation-allocates-nothing
  (let [h (RequestHead.)
        ^"[Ljava.lang.String;" fields (into-array String (mapcat identity good-request))
        n (alength fields)]
    (is (> 1.0 (bytes-per-op 100000
                             (fn []
                               (.reset h)
                               (loop [i 0]
                                 (when (< i n)
                                   (.add h (aget fields i) (aget fields (inc i)))
                                   (recur (+ i 2))))
                               (.finish h)))))))

;; ---- Connection limiter ----------------------------------------------------

(def ^:private ip-a (InetAddress/getByName "10.0.0.1"))
(def ^:private ip-b (InetAddress/getByName "10.0.0.2"))

(deftest limiter-caps-total-connections
  (let [l (ConnectionLimiter. 2 0)]
    (is (.tryAcquire l ip-a))
    (is (.tryAcquire l ip-b))
    (is (not (.tryAcquire l ip-a)))
    (is (= 2 (.active l)))
    (.release l ip-a)
    (is (.tryAcquire l ip-b))))

(deftest limiter-caps-connections-per-address
  (let [l (ConnectionLimiter. 0 2)]
    (is (.tryAcquire l ip-a))
    (is (.tryAcquire l ip-a))
    (is (not (.tryAcquire l ip-a)) "third from the same address")
    (is (.tryAcquire l ip-b) "other addresses unaffected")
    (.release l ip-a)
    (is (.tryAcquire l ip-a))
    (testing "a refused per-address attempt doesn't hold a global slot"
      (let [l (ConnectionLimiter. 2 1)]
        (is (.tryAcquire l ip-a))
        (is (not (.tryAcquire l ip-a)))
        (is (.tryAcquire l ip-b))))))

(deftest limiter-unlimited-and-allocation-free
  (let [l (ConnectionLimiter. 0 0)]
    (dotimes [_ 1000] (is (.tryAcquire l ip-a)))
    (is (= 1000 (.active l))))
  (let [l (ConnectionLimiter. 10 0)]
    (is (> 1.0 (bytes-per-op 100000 (fn [] (.tryAcquire l ip-a) (.release l ip-a)))))))

;; ---- Connection registry ---------------------------------------------------

(defn- drainable [log id]
  (reify Drainable
    (beginDrain [_] (swap! log conj [:drain id]))
    (forceClose [_] (swap! log conj [:force id]))))

(deftest registry-drains-then-forces-stragglers
  (let [log (atom [])
        r (ConnectionRegistry.)
        a (drainable log :a)
        b (drainable log :b)]
    (.register r a)
    (.register r b)
    (is (= 2 (.size r)))
    (.beginDrainAll r)
    (is (= #{[:drain :a] [:drain :b]} (set @log)))
    (future (Thread/sleep 50) (.unregister r a))
    (let [t0 (System/nanoTime)
          drained (.awaitEmpty r (+ t0 (* 300 1000000)))]
      (is (not drained) "b never leaves")
      (is (>= (/ (- (System/nanoTime) t0) 1e6) 290.0)))
    (.forceCloseAll r)
    (is (some #{[:force :b]} @log))
    (is (not (some #{[:force :a]} @log)))
    (.unregister r b)
    (is (.awaitEmpty r (System/nanoTime)))))

(deftest registry-keeps-going-past-a-failing-connection
  ;; One connection throwing from beginDrain / forceClose must not keep
  ;; the others from draining or closing.
  (let [log (atom [])
        r (ConnectionRegistry.)
        bad (reify Drainable
              (beginDrain [_] (throw (IllegalStateException. "drain")))
              (forceClose [_] (throw (IllegalStateException. "force"))))]
    (.register r bad)
    (.register r (drainable log :a))
    (.register r (drainable log :b))
    (.beginDrainAll r)
    (is (= #{[:drain :a] [:drain :b]} (set @log)))
    (.forceCloseAll r)
    (is (= #{[:drain :a] [:drain :b] [:force :a] [:force :b]} (set @log)))))

;; ---- JFR -------------------------------------------------------------------

(deftest jfr-flags-follow-recordings
  (is (not (or (Jfr/connections) (Jfr/requests) (Jfr/protocolErrors))) "off without a recording")
  (with-open [rec (Recording.)]
    (.start rec)
    (is (Jfr/connections))
    (is (Jfr/protocolErrors))
    (is (not (Jfr/requests)) "request events are opt-in")
    (.stop rec))
  (with-open [rec (Recording.)]
    (.enable rec "com.s_exp.enso.Request")
    (.start rec)
    (is (Jfr/requests))
    (.stop rec))
  (is (not (or (Jfr/connections) (Jfr/requests) (Jfr/protocolErrors)))))

;; ---- Error handler policy --------------------------------------------------

(deftest error-policy-terminates-on-cause-cycles
  ;; A handler can throw an exception whose causes form a cycle; deciding
  ;; how to log it must still terminate.
  (let [a (RuntimeException. "a")
        b (IllegalStateException. "b")]
    (.initCause a b)
    (.initCause b a)
    (let [f (future (RingErrorHandler/respond nil nil a))]
      (is (nil? (deref f 2000 ::hung)) "no error handler: nil, promptly"))))

;; ---- Memory budget ---------------------------------------------------------

(defn- counting-waiter ^MemoryBudget$Waiter [^AtomicInteger woken]
  (proxy [MemoryBudget$Waiter] []
    (budgetAvailable [] (.incrementAndGet woken))))

(deftest memory-budget-reserves-charges-and-wakes-waiters
  (let [b (MemoryBudget. 100)
        woken (AtomicInteger.)
        w (counting-waiter woken)]
    (is (.tryReserve b 60))
    (is (not (.tryReserve b 50)) "refused past the limit")
    (.charge b 50)
    (is (= 110 (.used b)) "a charge may go over")
    (is (.exhausted b))
    (.await b w)
    (is (zero? (.get woken)) "waits while exhausted")
    (.await b w)
    (.release b 5)
    (is (zero? (.get woken)) "still over the limit")
    (.release b 50)
    (is (= 1 (.get woken)) "woken once, when room came back")
    (.release b 55)
    (is (zero? (.used b)))
    (is (= 1 (.get woken)) "a woken waiter is no longer registered")
    (.await b w)
    (is (= 2 (.get woken)) "registering with room wakes at once (no lost wake-up)")))

(deftest memory-budget-allocates-nothing
  (let [b (MemoryBudget. Long/MAX_VALUE)]
    (is (> 1.0 (bytes-per-op 100000 (fn [] (.tryReserve b 100) (.charge b 10) (.release b 110)))))))

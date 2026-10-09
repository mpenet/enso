# Testing

Everything below runs from the repository root after building the Java
sources (and, for HTTP/3, the JNI shim):

```
clojure -T:build javac
clojure -T:build shim     # needs libquiche (brew install cloudflare-quiche)
```

## Unit and integration tests

Each namespace runs in its own JVM, so state (ports, threads, the native
library, static caches) never leaks between namespaces:

```
script/test.sh                              # every *_test namespace except the soak test
script/test.sh s-exp.enso-http2-test        # selected namespaces
clojure -X:test :nses '[s-exp.enso-hpack-test]'   # same thing, by hand
```

`script/test.sh` prints a PASS/FAIL line per namespace, keeps each
namespace's output under `target/test-logs/` (`ENSO_TEST_LOG_DIR` moves
it), and exits non-zero if any namespace failed. `ENSO_TEST_EXCLUDE`
overrides the namespaces skipped by default (the soak test). Do not run
the whole suite in a single JVM.

## Property-based and fuzz tests

| Namespace | What it checks |
|---|---|
| `s-exp.enso-codec-property-test` | HPACK round-trip across a connection's blocks with table-size updates and Latin-1 octets; Huffman round-trip; QPACK round-trip, scratch-buffer encoder and `SETTINGS_MAX_FIELD_SECTION_SIZE` cap; the production QPACK decoder (`QpackDecoder`, used by the HTTP/3 event loop): round-trip at arbitrary buffer offsets with one warm instance (its string cache must never leak a previous value), size cap, and on random/mutated sections the same fields or the same error code and level as `QpackFieldSection.decode`; QUIC varint round-trip/range/underflow; `Http3FrameReader` against a model under arbitrary chunking, truncation detection. Decoders fed random and mutated bytes may only return a value or throw their protocol error (`IOException` for HPACK, `QpackException`, `IllegalStateException` for the frame reader), each input time-boxed to 2 s. |
| `s-exp.enso-h2-frame-fuzz-test` | Live HTTP/2 server over raw TLS (ALPN h2). Each trial sends the preface and a generated frame sequence (valid requests split over CONTINUATION, random and mutated frames, unknown types and flags, bad stream ids, truncated and over-declared lengths, SETTINGS / WINDOW_UPDATE / flow-control abuse, CONTINUATION floods, rapid resets), then a PING. While that connection is open a fresh one must get a 200; the hostile one must answer the PING, send GOAWAY or close before its deadline (never hang past the server's timeouts), and every frame the server sends must be well formed (lengths, stream ids, GOAWAY / RST_STREAM codes, nothing after GOAWAY above its last-stream-id). A last test checks the server still serves after the whole run. |
| `s-exp.enso-wire-fuzz-test` | Live server over raw sockets. HTTP/1.1: valid pipelines (Content-Length, chunked with extensions/trailers) answered in order; smuggling-shaped framing (CL+TE, conflicting/invalid Content-Length, non-final chunked, whitespace before colon, broken chunk sizes) answered at most once and then closed so a smuggled follow-up is never served; random/mutated requests (bare CR/LF, obs-fold, NUL, injected headers) never hang, never produce malformed responses, never desync the pipelined sentinel request. WebSocket: random fragmentation, masks and interleaved pings are echoed exactly and ponged; protocol violations close with the mandated code (1002/1007) after echoing only prior messages; garbage after the handshake never hangs. |

Knobs (environment variables):

- `ENSO_PROPERTY_TRIALS` — trials per property (default 200; CI uses 200,
  the nightly job 2000). Live-server properties run fewer: the wire fuzz
  tests half, the HTTP/2 frame fuzz a quarter.
- `ENSO_PROPERTY_SEED` — replay a failure. Every property prints its
  seed and trial count when it starts, and a failure report repeats the
  seed with the shrunk counterexample; the wire fuzz tests also print the
  exact bytes sent and received, the HTTP/2 frame fuzz test the frame
  operations sent and the frames received.

## Coverage-guided fuzzing (Jazzer)

Four [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) targets
live in `fuzz/java/com/s_exp/enso/fuzz/`, instrumenting `com.s_exp.enso.**`:

| Target | What it drives | Fails on |
|---|---|---|
| `HpackDecoderFuzz` | `Hpack.Decoder` as HTTP/2 connections use it (sink API, header-list limits, dynamic table across up to 4 blocks) | any exception but `IOException`; an accepted block that changes when re-encoded and decoded |
| `QpackDecoderFuzz` | the production `QpackDecoder` (one warm instance), against `QpackFieldSection.decode` | any exception but `QpackException`; the two decoders disagreeing on fields or error code/level; a warm-cache decode differing from the first |
| `Http1RequestFuzz` | `HttpConnection.run()` in-process over an in-memory socket (pipelined requests, bodies, chunked framing, WebSocket upgrades); the handler drains bodies and never fails | an exception out of `run()`; output not starting with an HTTP/1.1 status line; any `500` (the server failing on client input); a hang (Jazzer's 10 s per-input timeout) |
| `WebSocketFrameFuzz` | `WebSocketConnection.run()` in-process over an in-memory socket, with and without permessage-deflate, echoing messages | an exception out of `run()`; `onClose` not called exactly once; the socket left open; server output that is not a sequence of valid unmasked frames |

```
clojure -T:build javac
script/fuzz.sh Http1RequestFuzz 300            # fuzz for 300 s
script/fuzz.sh QpackDecoderFuzz 0 target/fuzz/findings/QpackDecoderFuzz/crash-<sha>   # replay one input
```

New coverage-reaching inputs accumulate in `target/fuzz/corpus/<target>/`
and are reused by the next run; seed inputs are checked in under
`fuzz/corpus/<target>/` and the HTTP/1.1 target has a dictionary in
`fuzz/dict/`. A finding writes the crashing input and a standalone Java
reproducer to `target/fuzz/findings/<target>/`; extra arguments after the
duration go to Jazzer / libFuzzer (e.g. `--keep_going=20`). The connection
targets borrow the config and timer of a started server (on an ephemeral
loopback port); the fuzzed connections are driven directly, never
accepted.

## Sanitizer run

The HTTP/3 namespaces can run against an AddressSanitizer +
UndefinedBehaviorSanitizer build of the JNI shim (every UB report aborts):

```
native/enso_quiche/build-libquiche.sh /tmp/quiche
make -C native/enso_quiche QUICHE_STATIC=1 SANITIZE=1 \
  QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
script/sanitizer-test.sh                      # the four HTTP/3 namespaces
```

The JVM is not instrumented, so `script/sanitizer-test.sh` hands the
Clojure CLI a java wrapper (`JAVA_CMD`) that preloads the sanitizer runtime
(`LD_PRELOAD` of gcc's `libasan.so` on Linux, `DYLD_INSERT_LIBRARIES` of
clang's `libclang_rt.asan_osx_dynamic.dylib` on macOS) into the JVMs only.
`ASAN_OPTIONS` leaves SIGSEGV / SIGBUS to the JVM (implicit null checks,
safepoint polls) and turns leak detection off. On macOS the wrapper must
start the JDK's own `bin/java`: `/usr/bin/java` is SIP-protected and
drops `DYLD_*` variables. The script refuses a shim without an ASan
dependency, and fails on a test failure or any report written to
`target/sanitizer/`. Rebuild the normal shim afterwards.

## Soak / leak test

`s-exp.enso-soak-test` churns `ENSO_SOAK_CONNECTIONS` (default 10000)
connections split across HTTP/1.1 (graceful, keep-alive, aborted mid-head,
aborted mid-body, idle until the server's timeout), HTTP/2 (fresh TLS
session per connection) and HTTP/3 (when the shim loads, half of them
abandoned with a request in flight). After a warm-up baseline it asserts
open file descriptors (`UnixOperatingSystemMXBean`), live threads and
post-GC heap return near the baseline.

It is excluded from the default run (and its tests carry `^:soak` for
test-runner `:excludes`):

```
script/test.sh s-exp.enso-soak-test
```

On macOS raise the fd limit first (`ulimit -n 10240`).

## Conformance suites

Each runner boots `s-exp.enso-test-server` (`clojure -M:test-server`) in
its own JVM, runs a pinned version of the suite, and checks its results
against a checked-in expectations file listing the cases allowed to fail
and the suite size (`total-cases: N`). A run fails with exit 1 when the
tool crashed (non-zero exit without a recorded failure, or killed), the
report is missing, or the number of cases run differs from `total-cases`
(a truncated run, or a suite change to confirm by hand); with exit 2 when
a case outside the file fails or a listed case did not fail (remove its
line). Filtered runs (`--match` for h3spec, `AUTOBAHN_CASES`) skip the
count check; a listed case only counts as stale when it ran and passed.
`bench/conformance-lib-test.sh` checks these verdicts on synthetic
results. Reports land under `target/conformance/<suite>/`.

| Suite | Runner | Expectations | Needs |
|---|---|---|---|
| h2spec 2.6.0 (HTTP/2 over TLS) | `bench/h2spec/run.sh` | `bench/h2spec/expected-failures.txt` | Linux x86-64 / Intel mac: downloaded + checksum-verified; Apple Silicon: `brew install h2spec`; elsewhere set `H2SPEC_BIN` |
| h2spec 2.6.0 (cleartext HTTP/2, prior knowledge) | `bench/h2spec/run.sh h2c` | `bench/h2spec/expected-failures-h2c.txt` | as above |
| Autobahn TestSuite 25.10.1 (WebSocket, fuzzingclient) | `bench/autobahn/run.sh` | `bench/autobahn/expected-failures.txt` | Docker (image pinned by digest) |
| h3spec 0.1.13 (QUIC + HTTP/3) | `bench/h3spec/run.sh` | `bench/h3spec/expected-failures.txt` | the JNI shim; binary downloaded + checksum-verified (linux-x86_64, mac-arm64; on Linux it needs `libgmp10` and `zlib1g`) |

Pinned tool binaries are cached in `target/tools/`. `ENSO_SERVER_OPTS`
(an EDN map) passes extra `run-server` options to the test server, e.g.
`ENSO_SERVER_OPTS='{:max-header-bytes 131072}' bench/h2spec/run.sh`.
Autobahn runs every case; its echo server defaults to
`{:ws-compression true :ws-max-message-bytes 16777216}` (permessage-deflate
for 12.* / 13.*, and room for the suite's 16 MiB messages), replaced by
`ENSO_SERVER_OPTS` when set. The client runs emulated on Apple Silicon
(x86 image), so 12.* / 13.* take a while there: the largest 12.5 cases
run 30-45 s each with the server mostly idle (about 0.2 CPU-seconds per
second), and under other CPU load the emulated client can hit its own
connection timeout ("User timeout caused connection failure"), which the
runner reports as an incomplete run. Rerun the affected groups alone
(`AUTOBAHN_CASES='["12.5.*"]'`); CI runs the client natively.

Current results (default server options):

- h2spec over TLS: 146 cases, no expected failures.
- h2spec cleartext (`h2c`): 146 cases, 1 expected failure, 3.5/2 (invalid
  connection preface). By design: an `:http2c` port also serves HTTP/1.1,
  so bytes that aren't the HTTP/2 preface are an HTTP/1.1 request,
  answered 400 and closed, where h2spec expects a GOAWAY.
- Autobahn: 517 cases, no expected failures.
- h3spec: 49 cases, 2 expected failures (reserved header bits, checked
  only inside libquiche; see `doc/h3-conformance.md`).

## Performance and allocation harness

See [performance.md](performance.md#methodology). In short:

```
clojure -M:perf                                         # all scenarios, 10 s each
clojure -M:perf '{:duration-s 5 :scenarios [:h1-get]}'  # quick run
```

Results go to `target/perf/latest.{edn,json,md}` (plus a timestamped copy).

### Allocation gate

Throughput and latency on shared runners are a trend line, but bytes
allocated per request are a property of the code path, stable to a few
percent run to run. `s-exp.enso-perf-gate` compares a run with
`bench/perf/baseline.edn`:

```
clojure -M:perf-gate                    # check target/perf/latest.edn
clojure -M:perf-gate update             # record this run as the platform's baseline
```

A scenario fails above `baseline * ratio + slack-bytes` (`:tolerance`,
1.2 and 48 bytes) or when it was skipped; a result far below the baseline
is reported as an improvement to record. Baselines are per platform
(`os.name os.arch` of the run); a platform without one passes and prints
the entry to add. Only "Mac OS X aarch64" is recorded, so the nightly
gate on Linux only prints its entry until one is added. Raise a baseline only for an allocation that is
intended, in the same change that introduces it.

## CI

- `.github/workflows/test.yml` (push to main, pull requests, and called by
  `release.yml` so nothing is published unless it passes): builds the
  static shim once (libquiche cached per pinned inputs) and checks
  THIRD-PARTY-NOTICES against the lockfile; runs every test namespace in
  its own JVM with HTTP/3 enabled on JDK 21 and on JDK 25; runs the
  HTTP/3 namespaces against an ASan/UBSan shim (built in that job); runs
  the conformance suites as separate jobs with their reports uploaded
  (h2spec over TLS and h2c, preceded by the verdict-logic self-test
  `bench/conformance-lib-test.sh`; Autobahn; h3spec).
- `.github/workflows/release.yml`: builds the five shims (Linux ones in
  AlmaLinux 8 / Alpine containers), each checked and load-tested in a JVM
  where it was built (`native/enso_quiche/check-shim.sh`, see
  [build.md](build.md#http3-shim)), runs the HTTP/3 end-to-end namespaces
  on macOS against the darwin shim being shipped, then packages and
  publishes.
- `.github/workflows/nightly.yml` (scheduled + manual, non-gating): soak
  test; deep property/fuzz run (2000 trials, HTTP/2 frame fuzzing
  included); each Jazzer target for 15 minutes with its corpus carried
  over between runs and findings uploaded; perf harness with the report
  in the run summary and the allocation gate.

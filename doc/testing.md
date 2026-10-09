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

### Flaky-test quarantine

A test with evidence of intermittent failure (a CI run where it failed
and then passed on the same commit, or on one matrix leg only) can be
quarantined while the cause is investigated, by tagging it `^:flaky`:

```clojure
(deftest ^:flaky h2-something-timing-dependent ...)
```

`script/test.sh` then runs that namespace's other tests as usual and the
quarantined ones in a second JVM (`:includes [:flaky]`). A quarantined
test that fails is rerun once. Passing on the rerun prints `FLAKY` (a
`::warning` annotation and a "Flaky" section in the job summary, with the
first run's log kept as `target/test-logs/<ns>.flaky.log`): the run
passes but the flake is visible. Failing twice fails the run like any
other test. Quarantine is a stopgap, not a fix: open an issue for every
tagged test, and remove the tag in the change that fixes the cause.
Nothing is quarantined unless CI history shows the flake.

## Coverage

```
clojure -T:build javac
script/coverage.sh                          # the default namespaces, with coverage
script/coverage.sh s-exp.enso-http2-test    # selected namespaces
```

`script/coverage.sh` runs the same namespaces as `script/test.sh` (or the
ones given as arguments) with the JaCoCo agent attached to every test JVM
through `JDK_JAVA_OPTIONS`, so enso itself stays dependency-free and the
agent is only resolved through the `:coverage` alias. All JVMs append to
`target/coverage/jacoco.exec` (`ENSO_COVERAGE_APPEND=1` keeps adding to a
previous run), then the script writes HTML
(`target/coverage/html/index.html`), XML and CSV reports for the Java
core compiled from `src/java` (fuzz harnesses excluded), and a
per-package line and branch table, printed and, on GitHub Actions, added
to the job summary. The exit status is the test run's; the report is
written even when tests fail. Only Java is measured, not the Clojure
namespaces in `src/clj`. Agent overhead is within run-to-run noise (the
suite is bound by timeouts, not CPU). The `coverage` job in `test.yml`
runs it on every push and pull request without gating.

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

Six [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) targets
live in `fuzz/java/com/s_exp/enso/fuzz/`, instrumenting `com.s_exp.enso.**`:

| Target | What it drives | Fails on |
|---|---|---|
| `HpackDecoderFuzz` | `Hpack.Decoder` as HTTP/2 connections use it (sink API, header-list limits, dynamic table across up to 4 blocks) | any exception but `IOException`; an accepted block that changes when re-encoded and decoded |
| `QpackDecoderFuzz` | the production `QpackDecoder` (one warm instance), against `QpackFieldSection.decode` | any exception but `QpackException`; the two decoders disagreeing on fields or error code/level; a warm-cache decode differing from the first |
| `Http1RequestFuzz` | `HttpConnection.run()` in-process over an in-memory socket (pipelined requests, bodies, chunked framing, WebSocket upgrades); the handler drains bodies and never fails | an exception out of `run()`; output not starting with an HTTP/1.1 status line; any `500` (the server failing on client input); a hang (Jazzer's 10 s per-input timeout) |
| `WebSocketFrameFuzz` | `WebSocketConnection.run()` in-process over an in-memory socket, with and without permessage-deflate, echoing messages | an exception out of `run()`; `onClose` not called exactly once; the socket left open; server output that is not a sequence of valid unmasked frames |
| `Http2ConnectionFuzz` | `Http2Connection.run()` (cleartext, prior knowledge) in-process over an in-memory socket, from structured client frame sequences (input decoded as operations, see the class doc): requests with HPACK / CONTINUATION / padding / priority, DATA, SETTINGS, WINDOW_UPDATE, RST_STREAM bursts, PING, GOAWAY, PUSH_PROMISE, unknown and mis-sized frames, raw bytes; low limits so edge cases are reachable; the handler drains bodies and answers 200 (text, bytes, streamed, InputStream) or 204 | an exception out of `run()`; any WARNING log or uncaught exception; the socket left open; writer or handler threads still running after `run()`; output that isn't whole, well-formed frames (SETTINGS first, valid ids, lengths, error codes, PING / SETTINGS ACKs answering the client's); header blocks interleaved or not decoding to one `:status`; any `500`; DATA before the head, after END_STREAM, after our RST_STREAM, past Content-Length or past the client's flow-control windows; HEADERS / DATA above a GOAWAY last-stream-id or a rising last-stream-id; a hang |
| `Http3StreamFuzz` | client HTTP/3 stream bytes, delivered both in fuzz-chosen chunks and whole: peer unidirectional streams (types, SETTINGS / GOAWAY / MAX_PUSH_ID / CANCEL_PUSH / reserved frames, QPACK instructions, resets) into `Http3ControlStreams`; request streams into `Http3FrameReader`, their HEADERS into `QpackDecoder` and DATA into `Http3BodyPipe` | control streams raising anything but `Http3ConnectionException` with an RFC 9114 / 9204 code; frame readers raising anything but `IllegalStateException`; QPACK raising anything but `QpackException`; the two deliveries disagreeing on whether and where a stream fails, on control-stream state or on the frames read; the body pipe losing, reordering or inventing bytes, ending wrongly or leaving memory budget charged |

```
clojure -T:build javac
script/fuzz.sh Http1RequestFuzz 300            # fuzz for 300 s
script/fuzz.sh QpackDecoderFuzz 0 target/fuzz/findings/QpackDecoderFuzz/crash-<sha>   # replay one input
```

New coverage-reaching inputs accumulate in `target/fuzz/corpus/<target>/`
and are reused by the next run; seed inputs are checked in under
`fuzz/corpus/<target>/`, dictionaries in `fuzz/dict/<target>.dict`. A finding writes the crashing input and a standalone Java
reproducer to `target/fuzz/findings/<target>/`; extra arguments after the
duration go to Jazzer / libFuzzer (e.g. `--keep_going=20`). The connection
targets borrow the config and timer of a started server (on an ephemeral
loopback port); the fuzzed connections are driven directly, never
accepted.

`Http3RequestReader` (the production request-stream reader) is not
fuzzed at this level: it reads through `QuicheConnection.streamRecv` and
dispatches through an `Http3Connection`, which only a live quiche
connection (JNI shim) can create. `Http3StreamFuzz` drives the same
building blocks (frame reader, QPACK decoder, body pipe) with its own
model of a request stream; the real reader's own checks (DATA before
HEADERS, a stream ending mid-frame) are covered by the h3spec suite and
`s-exp.enso-h3-e2e-test`.

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
| h3spec 0.1.14 (QUIC + HTTP/3) | `bench/h3spec/run.sh` | `bench/h3spec/expected-failures.txt` | the JNI shim; binary downloaded + checksum-verified (linux-x86_64, mac-arm64; on Linux it needs `libgmp10` and `zlib1g`) |

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
- h3spec: 77 cases, 2 expected failures (reserved header bits, checked
  only inside libquiche; see `doc/h3-conformance.md`).

### QUIC interop (quic-interop-runner)

`bench/quic-interop-runner/run.sh [CLIENTS]` builds the enso endpoint
image (`bench/quic-interop-runner/Dockerfile`: static shim from the
pinned native inputs, as released), fetches the official
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
at a pinned commit, registers enso as a server-only implementation and
runs it against the given clients (default
`quiche,ngtcp2,quic-go,neqo,quinn`) through the network simulator. The
results are checked against `bench/quic-interop-runner/expected-results.txt`
(`check_results.py`: exit 1 when nothing ran, 2 on any difference,
including a listed failure that now passes). Logs, pcaps and
`results.json` land in `target/conformance/quic-interop/`. The nightly
`interop` job runs it on `ubuntu-24.04`.

Only the `http3` test case applies to enso as a server. The runner's
other cases (handshake, transfer, retry, multiconnect, chacha20,
resumption, zerortt, keyupdate, ...) are run by every client over the
`hq-interop` ALPN (HTTP/0.9 over QUIC), which enso does not speak: its
endpoint answers them with exit 127 ("unsupported"). Serving
`hq-interop` from the test endpoint would open those cases.

Needs Docker with Compose, Python >= 3.10 and tshark >= 4.5; on Linux
also `sudo modprobe ip6table_filter`. On macOS the runner can't run
natively (Docker Desktop does not share `/tmp`, where it creates the
directories it mounts into the simulator, and the system `openssl` is
LibreSSL), so run it from a Linux container talking to the host daemon:

```
docker build -t enso-qir-host -f bench/quic-interop-runner/runner.Dockerfile bench/quic-interop-runner
docker build -t enso-interop:latest -f bench/quic-interop-runner/Dockerfile .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp \
  -v "$PWD:$PWD" -w "$PWD" -e INTEROP_IMAGE=enso-interop:latest \
  enso-qir-host bench/quic-interop-runner/run.sh quic-go,ngtcp2
```

(`-v /tmp:/tmp` mounts the Docker VM's `/tmp`, which is what the
simulator containers see.) Apple Silicon runs arm64 images natively;
quiche's client image is amd64-only and runs emulated.

Current result: quic-go, ngtcp2, neqo and quinn pass `http3` (run as
above, arm64 images on Apple Silicon). The simulator starts once the
server answers its readiness probe (an unknown-version long header,
1207 bytes, zero-length DCID) with Version Negotiation, which the server
sends for any unsupported version whatever its connection id lengths
(0 to 255 bytes, RFC 8999). quiche's client image is amd64-only: emulated
on Apple Silicon, its `ethtool -K eth0 tx off` fails ("Function not
implemented"), its datagrams keep partial (offloaded) UDP checksums and
the server's kernel drops them, so that pair fails there before enso sees
a packet; the expectations file records the result expected on a native
x86-64 host (the nightly job). On Apple Silicon run the other four:
`... run.sh quic-go,ngtcp2,neqo,quinn`.

The endpoint turns off checksum offload on its interface
(`ethtool -K eth0 tx off` in `run_endpoint.sh`, as the runner's standard
endpoint images do): without it the server's packets cross the
simulator but never reach the client's socket (ngtcp2 counts zero
received packets), with it the transfers above pass.

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
(`os.name os.arch` of the run); a platform without one fails the gate
and prints the entry to add. "Mac OS X aarch64" (development machines)
and "Linux amd64" (the nightly job) are recorded. Raise a baseline only
for an allocation that is intended, in the same change that introduces
it.

Allocation per request depends on the code path, but also on how much
work each wake-up batches, so on the platform and the number of CPUs:
HTTP/2 allocates about 40% more per request on a 2-CPU JVM than on an
8-CPU one (1150 vs 1640 B/req on the same Mac with
`-XX:ActiveProcessorCount=2`), and Linux and macOS differ by a few
percent elsewhere. Record a baseline on hardware shaped like where the
gate runs. The Linux entry comes from a container run:

```
bench/perf/linux-baseline.sh                  # linux/amd64 (emulated on Apple Silicon), Ubuntu 24.04 + Temurin 25 + h2load
clojure -M:perf-gate update target/perf-linux-amd64/latest.edn
```

Emulated with 2 CPUs it can only be an upper bound for the 4-vCPU
`ubuntu-24.04` runner, so the nightly gate may first report
"improved": then record the nightly run's own numbers instead (download
the `perf-results` artifact and run
`clojure -M:perf-gate update perf-results/latest.edn`).

## CI

- `.github/workflows/test.yml` (push to main, pull requests, and called by
  `release.yml` so nothing is published unless it passes): builds the
  static shim natively on x86-64 and on arm64 (libquiche cached per
  pinned inputs and architecture) and checks THIRD-PARTY-NOTICES against
  the lockfile; runs every test namespace in its own JVM with HTTP/3
  enabled on JDK 21 and JDK 25 (x86-64) and on JDK 25 (arm64,
  `ubuntu-24.04-arm`, against the arm64 shim); runs the same namespaces
  with JaCoCo for the coverage report (`coverage`, informational, never
  fails the workflow); runs the HTTP/3 namespaces against an ASan/UBSan
  shim (built in that job); runs the conformance suites as separate jobs
  with their reports uploaded (h2spec over TLS and h2c, preceded by the
  verdict-logic self-test `bench/conformance-lib-test.sh`; Autobahn;
  h3spec). The conformance suites run on x86-64 only: neither h2spec
  2.6.0 nor h3spec ships a Linux arm64 binary, and what they check is
  protocol logic in Java, the same on every architecture (the arm64
  native path is exercised by the HTTP/3 namespaces).
- `.github/workflows/release.yml`: builds the five shims (Linux ones in
  AlmaLinux 8 / Alpine containers), each checked and load-tested in a JVM
  where it was built (`native/enso_quiche/check-shim.sh`, see
  [build.md](build.md#http3-shim)), runs the HTTP/3 end-to-end namespaces
  on macOS against the darwin shim being shipped, then packages and
  publishes.
- `.github/workflows/nightly.yml` (03:17 UTC daily and manual
  `workflow_dispatch` with knobs; non-gating): soak test, then the deep
  property/fuzz run (2000 trials, HTTP/2 frame fuzzing included) even if
  the soak failed; each Jazzer target for 15 minutes with its corpus
  carried over between runs (saved even when the run found something)
  and findings uploaded; the perf harness with the report in the run
  summary and the allocation gate (a missing "Linux amd64" baseline
  fails); the QUIC interop run (below); `cargo audit` of the quiche
  lockfile. Every job fails on a regression and uploads its logs or
  reports; when a scheduled run fails, a last job opens (or comments on)
  a "Nightly workflow failing" issue so the failure does not go unseen.
- `.github/dependabot.yml`: weekly grouped updates of the SHA-pinned
  Actions (workflows and composite actions). Dependabot has no ecosystem
  for `deps.edn` or for a bare `Cargo.lock`: Clojure/Maven test
  dependencies are bumped by hand, and the shim's crates are covered by
  the nightly `cargo audit` (see `SECURITY.md`).

## Recommended GitHub settings

Branch protection and repository security settings can only be applied
by a repository admin (Settings → Branches / Rules, Settings → Code
security). Recommended for `main`:

- Require a pull request before merging (direct pushes off; admins
  included, so release tags always point at reviewed, tested commits).
  One approval when there is more than one maintainer.
- Require status checks to pass, and branches to be up to date before
  merging. Required checks (job names of `test.yml`):
  - `shim (amd64)`, `shim (arm64)`
  - `test (JDK 21)`, `test (JDK 25)`, `test (JDK 25, arm64)`
  - `sanitizer`
  - `h2spec`, `autobahn`, `h3spec`

  Not required: `coverage` (informational) and everything in
  `nightly.yml` (scheduled, it reports through a "Nightly workflow
  failing" issue instead).
- Require linear history; block force pushes and branch deletion.
- Tag protection (a ruleset on `v*`): only admins may create or delete
  release tags, since a `v*` tag publishes to Clojars.
- Environments: put the Clojars credentials in a `release` environment
  restricted to `v*` tags instead of repository-wide secrets (the
  `package` job in `release.yml` would then declare
  `environment: release`).
- Code security: enable private vulnerability reporting (referenced by
  `SECURITY.md`), Dependabot alerts and Dependabot security updates
  (`.github/dependabot.yml` covers version updates of the Actions).
- Actions: "Allow actions and reusable workflows" limited to the ones
  pinned in the workflows (GitHub-owned, `DeLaGuardo/setup-clojure`,
  `dtolnay/rust-toolchain`, `docker/setup-docker-action`), and default
  `GITHUB_TOKEN` permissions set to read-only (the workflows request
  more per job where needed).

When a job is renamed or a matrix leg added, update the required-checks
list in the same change, or pull requests wait forever for a check that
no longer exists.

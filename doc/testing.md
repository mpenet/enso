# Testing

Build the Java sources first, and the JNI shim for the HTTP/3 tests:

```
clojure -T:build javac
clojure -T:build shim     # needs libquiche: brew install cloudflare-quiche
```

The development shim links a stock libquiche, so the tests that need
receive-window control are skipped. Build the shim the release way to run
them (see [build.md](build.md#http3-shim)).

## Unit and integration tests

```
script/test.sh                                    # every *_test namespace except the soak test
script/test.sh s-exp.enso-http2-test              # selected namespaces
clojure -X:test :nses '[s-exp.enso-hpack-test]'   # one namespace, by hand
```

Each namespace runs in its own JVM, so ports, threads, the native library
and static caches never leak between namespaces. Don't run the whole
suite in one JVM.

`script/test.sh` prints a PASS or FAIL line per namespace, keeps each
namespace's output under `target/test-logs/` (`ENSO_TEST_LOG_DIR` moves
it), and exits non-zero if any namespace failed. `ENSO_TEST_EXCLUDE`
overrides the namespaces skipped by default (the soak test).

### Flaky tests

A test with evidence of intermittent failure in CI (it failed and then
passed on the same commit, or failed on one matrix leg only) can be
quarantined while the cause is investigated, by tagging it `^:flaky`:

```clojure
(deftest ^:flaky h2-something-timing-dependent ...)
```

`script/test.sh` then runs the namespace's other tests as usual, and the
quarantined ones in a second JVM (`:includes [:flaky]`). A quarantined
test that fails is rerun once. If the rerun passes, the run passes and
prints `FLAKY`, with a `::warning` annotation, a "Flaky" section in the
job summary, and the first run's log kept as
`target/test-logs/<ns>.flaky.log`. If it fails twice, the run fails.

Quarantine is a stopgap. Open an issue for every tagged test and remove
the tag in the change that fixes the cause. Nothing is quarantined without
CI history showing the flake.

## Coverage

```
clojure -T:build javac
script/coverage.sh                          # the default namespaces
script/coverage.sh s-exp.enso-http2-test    # selected namespaces
```

`script/coverage.sh` runs the same namespaces as `script/test.sh` with the
JaCoCo agent attached to every test JVM through `JDK_JAVA_OPTIONS`. The
agent comes from the `:coverage` alias, so enso itself stays
dependency-free. All JVMs append to `target/coverage/jacoco.exec`
(`ENSO_COVERAGE_APPEND=1` adds to a previous run).

The script then writes HTML (`target/coverage/html/index.html`), XML and
CSV reports for the Java core in `src/java` (fuzz harnesses excluded),
and prints a per-package line and branch table, which also goes to the
job summary on GitHub Actions. Only Java is measured, not the Clojure
namespaces. The exit status is the test run's, and the report is written
even when tests fail. The agent's overhead is within run-to-run noise,
since the suite is bound by timeouts rather than CPU.

## Property and fuzz tests

Three namespaces use test.check:

- `s-exp.enso-codec-property-test`: HPACK, Huffman, QPACK and QUIC varint round-trips; the production `QpackDecoder` agreeing with `QpackFieldSection.decode` on random and mutated input (same fields, or same error code and level) and never leaking a cached value across decodes; `Http3FrameReader` against a model under arbitrary chunking. Decoders fed garbage may only return a value or throw their protocol error, within 2 s per input.
- `s-exp.enso-h2-frame-fuzz-test`: a live HTTP/2 server over TLS receives generated frame sequences (valid requests over CONTINUATION, mutated and unknown frames, bad ids and lengths, flow-control abuse, CONTINUATION floods, rapid resets) followed by a PING. A fresh connection must still get a 200 meanwhile. The hostile one must answer the PING, send GOAWAY or close in time, and every frame the server sends must be well formed.
- `s-exp.enso-wire-fuzz-test`: a live server over raw sockets. HTTP/1.1 pipelines are answered in order; smuggling-shaped framing is answered at most once and the connection closed; mutated requests never hang, never get a malformed response and never desync the pipeline. WebSocket fragmentation, masking and interleaved pings are echoed exactly; protocol violations close with 1002 or 1007; garbage never hangs.

`ENSO_PROPERTY_TRIALS` sets the trials per property: 200 by default and
in CI, 2000 in the nightly job. The live-server tests run a half (wire)
or a quarter (HTTP/2 frames) of that. Each property prints its seed when
it starts, and a failure repeats it with the shrunk counterexample, plus
the bytes or frames exchanged for the live-server tests. Replay with
`ENSO_PROPERTY_SEED`.

## Coverage-guided fuzzing

Six [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) targets
in `fuzz/java/com/s_exp/enso/fuzz/` instrument `com.s_exp.enso.**`:

| Target | Drives | Fails on |
|---|---|---|
| `HpackDecoderFuzz` | `Hpack.Decoder` with header-list limits and a dynamic table across up to 4 blocks | an exception other than `IOException`; an accepted block that changes when re-encoded |
| `QpackDecoderFuzz` | the production `QpackDecoder`, warm, against `QpackFieldSection.decode` | an exception other than `QpackException`; the decoders disagreeing; a warm decode differing from a cold one |
| `Http1RequestFuzz` | `HttpConnection.run()` on an in-memory socket | an exception out of `run()`; output that doesn't start with a status line; a 500; a hang |
| `WebSocketFrameFuzz` | `WebSocketConnection.run()`, with and without compression | an exception out of `run()`; `onClose` not called exactly once; the socket left open; invalid output frames |
| `Http2ConnectionFuzz` | `Http2Connection.run()` (h2c) on an in-memory socket, from frame operations decoded from the input, with low limits | see below |
| `Http3StreamFuzz` | HTTP/3 control and request stream bytes, delivered in fuzz-chosen chunks and whole | see below |

A hang is Jazzer's 10 s per-input timeout. The connection targets borrow
the config and timer of a server started on a loopback port, and drive
connections directly.

`Http2ConnectionFuzz` fails on an exception out of `run()`, a WARNING log,
the socket left open, threads still running after `run()`, a hang, or any
output that breaks the protocol: frames that aren't whole and well
formed, SETTINGS not first, missing ACKs, interleaved header blocks, a
500, DATA before the head or after END_STREAM, our RST_STREAM,
Content-Length or the client's windows, and streams above, or a rising,
GOAWAY last-stream-id.

`Http3StreamFuzz` fails when control streams, frame readers or QPACK
raise anything but their protocol exception (with an RFC 9114 or 9204
code for control streams), when chunked and whole delivery disagree, or
when the body pipe loses, reorders or invents bytes, ends wrongly, or
leaves memory budget charged. `Http3RequestReader` itself needs a live
quiche connection, so its own checks are covered by h3spec and
`s-exp.enso-h3-e2e-test`.

```
clojure -T:build javac
script/fuzz.sh Http1RequestFuzz 300            # fuzz for 300 s
script/fuzz.sh QpackDecoderFuzz 0 target/fuzz/findings/QpackDecoderFuzz/crash-<sha>   # replay one input
```

New corpus entries go to `target/fuzz/corpus/<target>/` and are reused.
Seeds are checked in under `fuzz/corpus/<target>/`, dictionaries in
`fuzz/dict/<target>.dict`. Findings, with a standalone Java reproducer,
go to `target/fuzz/findings/<target>/`. Arguments after the duration are
passed to Jazzer (for example `--keep_going=20`).

## Sanitizer run

The HTTP/3 namespaces can run against an AddressSanitizer and
UndefinedBehaviorSanitizer build of the shim, where every UB report
aborts:

```
native/enso_quiche/build-libquiche.sh /tmp/quiche
make -C native/enso_quiche QUICHE_STATIC=1 SANITIZE=1 \
  QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
script/sanitizer-test.sh                      # the four HTTP/3 namespaces
```

The JVM itself isn't instrumented. `script/sanitizer-test.sh` gives the
Clojure CLI a java wrapper (`JAVA_CMD`) that preloads the sanitizer
runtime into the test JVMs only: `LD_PRELOAD` of gcc's `libasan.so` on
Linux, `DYLD_INSERT_LIBRARIES` of clang's
`libclang_rt.asan_osx_dynamic.dylib` on macOS. `ASAN_OPTIONS` leaves
SIGSEGV and SIGBUS to the JVM (implicit null checks, safepoint polls) and
turns leak detection off. On macOS the wrapper must start the JDK's own
`bin/java`, because `/usr/bin/java` is SIP-protected and drops `DYLD_*`
variables. The script refuses a shim without an ASan dependency, and fails
on a test failure or on any report written to `target/sanitizer/`.
Rebuild the normal shim afterwards.

## Soak test

`s-exp.enso-soak-test` churns `ENSO_SOAK_CONNECTIONS` (10000 by default)
connections across HTTP/1.1 (graceful, keep-alive, aborted mid-head,
aborted mid-body, idle until the server's timeout), HTTP/2 (a fresh TLS
session per connection) and HTTP/3 (when the shim loads; half of them
abandoned with a request in flight). After a warm-up baseline it checks
that open file descriptors, live threads and post-GC heap return close to
the baseline.

It is excluded from the default run, and its tests carry `^:soak` for
test-runner `:excludes`:

```
script/test.sh s-exp.enso-soak-test
```

On macOS raise the file descriptor limit first (`ulimit -n 10240`).

## Conformance suites

| Suite | Runner | Expectations | Needs |
|---|---|---|---|
| h2spec 2.6.0, HTTP/2 over TLS | `bench/h2spec/run.sh` | `bench/h2spec/expected-failures.txt` | downloaded and checksum-verified on Linux x86-64 and Intel macs; `brew install h2spec` on Apple Silicon; elsewhere set `H2SPEC_BIN` |
| h2spec 2.6.0, cleartext prior knowledge | `bench/h2spec/run.sh h2c` | `bench/h2spec/expected-failures-h2c.txt` | as above |
| Autobahn TestSuite 25.10.1, WebSocket fuzzingclient | `bench/autobahn/run.sh` | `bench/autobahn/expected-failures.txt` | Docker (image pinned by digest) |
| h3spec 0.1.14, QUIC and HTTP/3 | `bench/h3spec/run.sh` | `bench/h3spec/expected-failures.txt` | the JNI shim; binary downloaded and checksum-verified (linux-x86_64, mac-arm64; on Linux it needs `libgmp10` and `zlib1g`) |

Current results with the default server options:

| Suite | Cases | Pass | Expected failures |
|---|---:|---:|---|
| h2spec over TLS | 146 | 146 | none |
| h2spec cleartext | 146 | 145 | 3.5/2, by design (below) |
| Autobahn | 517 | 517 | none |
| h3spec | 77 | 75 | two reserved-bit checks inside libquiche ([h3-conformance.md](h3-conformance.md)) |

The h2c failure, 3.5/2 (invalid connection preface), is deliberate. An
`:http2c` port also serves HTTP/1.1, so bytes that aren't the HTTP/2
preface are treated as an HTTP/1.1 request and answered 400, where h2spec
expects a GOAWAY.

Each runner boots `s-exp.enso-test-server` (`clojure -M:test-server`) in
its own JVM, runs the pinned suite and compares the results with its
expectations file, which lists the cases allowed to fail and the suite
size (`total-cases: N`). It exits 1 if the tool crashed, the report is
missing or the case count differs (a truncated run, or a suite change to
confirm by hand). It exits 2 if an unlisted case fails or a listed case
passes; remove the line in that case. Filtered runs (`--match` for
h3spec, `AUTOBAHN_CASES`) skip the count check. `bench/conformance-lib-test.sh`
tests this logic. Reports go to `target/conformance/<suite>/`, tool
binaries are cached in `target/tools/`.

`ENSO_SERVER_OPTS` passes extra `run-server` options as an EDN map:

```
ENSO_SERVER_OPTS='{:max-header-bytes 131072}' bench/h2spec/run.sh
```

For Autobahn the echo server defaults to
`{:ws-compression true :ws-max-message-bytes 16777216}`, so that cases
12.* and 13.* use permessage-deflate and the suite's 16 MiB messages fit;
`ENSO_SERVER_OPTS` replaces it. On Apple Silicon the client runs emulated,
and the largest 12.5 cases take 30-45 s each. Under other CPU load the
emulated client can hit its own connection timeout ("User timeout caused
connection failure"), which shows up as an incomplete run. Rerun those
groups alone, for example `AUTOBAHN_CASES='["12.5.*"]'`. CI runs the
client natively.

### QUIC interop

`bench/quic-interop-runner/run.sh [CLIENTS]` runs enso as a server in the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner),
at a pinned commit, against the given clients (default
`quiche,ngtcp2,quic-go,neqo,quinn`). The endpoint image
(`bench/quic-interop-runner/Dockerfile`) uses a static shim built from the
pinned inputs, as released. Results are checked against
`bench/quic-interop-runner/expected-results.txt` by `check_results.py`
(exit 1 if nothing ran, 2 on any difference). Logs, pcaps and
`results.json` go to `target/conformance/quic-interop/`. The nightly
`interop` job runs it on `ubuntu-24.04`.

Only the `http3` case applies. The runner's other cases use the
`hq-interop` ALPN (HTTP/0.9 over QUIC), which enso doesn't speak, so the
endpoint reports them as unsupported (exit 127).

quic-go, ngtcp2, neqo and quinn pass. quiche's client image is amd64-only:
emulated on Apple Silicon, it can't turn off checksum offload, and the
server's kernel drops its datagrams, so on Apple Silicon run the other
four (`... run.sh quic-go,ngtcp2,neqo,quinn`). The expectations file
records the result on a native x86-64 host. The enso endpoint itself turns
off checksum offload (`ethtool -K eth0 tx off` in `run_endpoint.sh`, as
the standard endpoint images do), otherwise its packets never reach the
client's socket.

Requirements: Docker with Compose, Python 3.10+ and tshark 4.5+, and on
Linux `sudo modprobe ip6table_filter`. On macOS the runner can't run
natively (Docker Desktop doesn't share `/tmp`, and the system `openssl` is
LibreSSL), so run it from a Linux container talking to the host daemon.
Mounting `/tmp` there gives the Docker VM's `/tmp`, which is what the
simulator sees:

```
docker build -t enso-qir-host -f bench/quic-interop-runner/runner.Dockerfile bench/quic-interop-runner
docker build -t enso-interop:latest -f bench/quic-interop-runner/Dockerfile .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp \
  -v "$PWD:$PWD" -w "$PWD" -e INTEROP_IMAGE=enso-interop:latest \
  enso-qir-host bench/quic-interop-runner/run.sh quic-go,ngtcp2
```

## Performance harness

```
clojure -M:perf                                         # all scenarios, 10 s each
clojure -M:perf '{:duration-s 5 :scenarios [:h1-get]}'  # quick run
```

Results go to `target/perf/latest.{edn,json,md}`, plus a timestamped
copy. Methodology is in [performance.md](performance.md#methodology).

### Allocation gate

Throughput and latency on shared runners are only a trend line, but bytes
allocated per request are a property of the code path, stable to a few
percent between runs. `s-exp.enso-perf-gate` compares a run with
`bench/perf/baseline.edn`:

```
clojure -M:perf-gate                    # check target/perf/latest.edn
clojure -M:perf-gate update             # record this run as the platform's baseline
```

A scenario fails above `baseline * ratio + slack-bytes` (`:tolerance`,
1.2 and 48 bytes), or when it was skipped. A result far below the
baseline is reported as an improvement to record. Baselines are per
platform (`os.name os.arch`); a platform without one fails the gate and
prints the entry to add. "Mac OS X aarch64" (development machines) and
"Linux amd64" (the nightly job) are recorded.

Raise a baseline only for an intended allocation, in the same change that
introduces it.

Allocation per request also depends on how much work each wake-up
batches, and so on the platform and CPU count. HTTP/2 allocates about 40%
more per request on 2 CPUs than on 8 (1640 against 1150 B/req on the same
Mac with `-XX:ActiveProcessorCount=2`), and Linux and macOS differ by a
few percent elsewhere. Record a baseline on hardware shaped like where the
gate runs. The Linux entry comes from a container run:

```
bench/perf/linux-baseline.sh                  # linux/amd64 (emulated on Apple Silicon), Ubuntu 24.04, Temurin 25, h2load
clojure -M:perf-gate update target/perf-linux-amd64/latest.edn
```

Emulated with 2 CPUs, that run is only an upper bound for the 4-vCPU
`ubuntu-24.04` runner, so the nightly gate may first report "improved".
In that case record the nightly run's own numbers: download the
`perf-results` artifact and run
`clojure -M:perf-gate update perf-results/latest.edn`.

## CI

`.github/workflows/test.yml` runs on pushes to main and on pull requests,
and `release.yml` calls it, so nothing is published unless it passes. It:

- builds the static shim natively on x86-64 and arm64 (libquiche cached per pinned inputs and architecture) and checks THIRD-PARTY-NOTICES against the lockfile;
- runs every test namespace in its own JVM with HTTP/3 enabled, on JDK 21 and 25 (x86-64) and JDK 25 (arm64, `ubuntu-24.04-arm`, against the arm64 shim);
- runs the same namespaces with JaCoCo for the coverage report (`coverage`, informational, never fails the workflow);
- runs the HTTP/3 namespaces against an ASan/UBSan shim built in that job;
- runs the conformance suites as separate jobs and uploads their reports: h2spec over TLS and h2c (after the verdict self-test `bench/conformance-lib-test.sh`), Autobahn and h3spec.

The conformance suites run on x86-64 only. Neither h2spec 2.6.0 nor h3spec
ships a Linux arm64 binary, and what they check is protocol logic in
Java, the same on every architecture. The HTTP/3 namespaces exercise the
arm64 native path.

`.github/workflows/release.yml` builds the five shims (the Linux ones in
AlmaLinux 8 and Alpine containers), checks and load-tests each in a JVM
on the machine that built it (`native/enso_quiche/check-shim.sh`, see
[build.md](build.md#http3-shim)), runs the HTTP/3 end-to-end namespaces on
macOS against the darwin shim being shipped, then packages and publishes.

`.github/workflows/nightly.yml` runs at 03:17 UTC daily, and manually
through `workflow_dispatch` with knobs. It doesn't gate anything. It runs:

- the soak test;
- the deep property and fuzz run (2000 trials, HTTP/2 frame fuzzing included), even if the soak failed;
- each Jazzer target for 15 minutes, with its corpus carried over between runs (saved even when the run found something) and findings uploaded;
- the perf harness, with the report in the run summary, and the allocation gate (a missing "Linux amd64" baseline fails);
- the QUIC interop run;
- `cargo audit` of the quiche lockfile.

Every job fails on a regression and uploads its logs or reports. When a
scheduled run fails, a last job opens (or comments on) a "Nightly
workflow failing" issue.

`.github/dependabot.yml` sends weekly grouped updates of the SHA-pinned
Actions, in workflows and composite actions. Dependabot has no ecosystem
for `deps.edn` or a bare `Cargo.lock`, so Clojure and Maven test
dependencies are bumped by hand, and the shim's crates are covered by the
nightly `cargo audit` (see [SECURITY.md](../SECURITY.md)).

### Recommended GitHub settings

These need a repository admin (Settings → Branches / Rules, and Settings
→ Code security). For `main`:

- Require a pull request before merging, with direct pushes off for admins too, so release tags always point at reviewed, tested commits. Require one approval once there is more than one maintainer.
- Require status checks to pass and branches to be up to date. The required checks are the `test.yml` jobs `shim (amd64)`, `shim (arm64)`, `test (JDK 21)`, `test (JDK 25)`, `test (JDK 25, arm64)`, `sanitizer`, `h2spec`, `autobahn` and `h3spec`. `coverage` is informational and `nightly.yml` reports through its issue, so neither is required.
- Require linear history, and block force pushes and branch deletion.
- Protect `v*` tags with a ruleset so only admins can create or delete them, since a `v*` tag publishes to Clojars.
- Keep the Clojars credentials in a `release` environment restricted to `v*` tags instead of repository-wide secrets (the `package` job in `release.yml` would then declare `environment: release`).
- Enable private vulnerability reporting (referenced by `SECURITY.md`), Dependabot alerts and Dependabot security updates.
- Allow only the actions pinned in the workflows (GitHub-owned, `DeLaGuardo/setup-clojure`, `dtolnay/rust-toolchain`, `docker/setup-docker-action`), and set the default `GITHUB_TOKEN` permissions to read-only; the workflows request more per job where needed.

When a job is renamed or a matrix leg added, update the required checks
in the same change, or pull requests will wait for a check that no longer
exists.

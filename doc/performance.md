# Performance

Two sets of numbers, from two tools:

- [Current numbers](#current-numbers): the separate-process harness
  (`clojure -M:perf`), the server in its own JVM, allocation measured
  exactly inside it. These track the code and are the ones to quote.
- [Comparison with other servers](#comparison-with-other-servers): the
  in-process bench (`bench/enso/bench.clj`), every server booted in the
  same JVM as the load generator. Relative rankings only.

## Current numbers

`clojure -M:perf` on an Apple M-series laptop (8 CPUs), JDK 25, 10 s per
scenario after 5 s of warm-up, server `-Xmx1g`, unlimited keep-alive,
every response `200` with the 13-byte body `Hello, World!`. Server and load
generator share the CPUs, so throughput moves by about 10% run to run;
allocation per request is stable to a few bytes.

| scenario | req/s | alloc B/req | p50 ms | p99 ms | p99.9 ms | load |
|---|---:|---:|---:|---:|---:|---|
| h1-get | 102,903 | 393 | 0.51 | 2.10 | 10.05 | 64 connections, closed loop |
| h1-get-rate | 19,997 | 397 | 0.18 | 1.53 | 3.94 | open model, 20k req/s over 64 connections, CO-corrected |
| h1-pipelined | 1,147,825 | 235 | 0.19 | 0.72 | 3.18 | 16 connections × depth 16, latency per batch |
| h2-get | 644,036 | 1,125 | 0.28 | 1.46 | – | h2load `-c 8 -m 32` over TLS, closed loop |
| h3-get | 69,786 | 799 | 1.89 | 2.87 | 3.47 | 4 QUIC connections × 32 requests in flight, closed loop |
| ws-echo | 423,076 | 334 | 1.13 | 2.70 | 13.62 | 64 WebSockets × 8 messages of 128 bytes in flight (one request = one message echoed) |

Allocation is everything the server JVM allocated in the measured window
divided by the requests completed, so it includes the Ring request map,
the handler's response map, TLS and the JDK's virtual thread bookkeeping.
What the request path itself allocates, item by item, is in
[architecture.md](architecture.md#allocation-budget), where tests hold
each path to a bound.

The allocation gate (`clojure -M:perf-gate`, see
[testing.md](testing.md#allocation-gate)) compares a run with the
per-platform baselines in `bench/perf/baseline.edn`.

### Methodology

`clojure -M:perf` (namespace `s-exp.enso-perf`) is the regression
harness. It addresses the weaknesses of the in-process bench:

- **Separate processes.** The server (`s-exp.enso-test-server`) runs in
  its own JVM (`-Xmx1g` by default, `:server-jvm-opts` to change); the load
  generator runs in the harness JVM. They still share the host's CPUs —
  on Linux, pin them apart (e.g. `taskset`) for lower variance.
- **Allocation per request is measured in the server process**, not
  sampled: the delta of `ThreadMXBean#getTotalThreadAllocatedBytes`
  (every thread, carrier threads of virtual threads included — verified
  by allocating a known amount on a virtual thread) across the measured
  window, divided by requests completed in it. Warm-up traffic is
  excluded. The number covers everything the server JVM allocated in
  that window (parser, handler adapter, response writer, TLS, GC
  bookkeeping), so it is an upper bound for enso's own code.
- **Latency.** `h1-get-rate` is open-model: each connection sends on a
  fixed schedule and latency is measured from the intended send time,
  so a server stall inflates the percentiles instead of silently
  lowering the request rate (coordinated-omission correction, as in
  wrk2). The closed-loop scenarios (`h1-get`, `h1-pipelined`, `h2-get`)
  are throughput tests; their percentiles are reported but are not
  CO-corrected. `h2-get` uses h2load (median/p99 with nghttp2 >= 1.62,
  min/max/mean with older versions). `h3-get` drives `:h3-connections` (4) QUIC
  connections, each keeping `:h3-in-flight` (32) requests open, from a
  lean load client (`s-exp.h3-load`: quiche through the enso shim, one
  platform thread per connection); it is closed-loop and not
  CO-corrected either. `ws-echo` keeps `:ws-depth` (8) text messages of
  `:ws-message-bytes` (128) in flight on each of the connections against
  the WebSocket echo endpoint; a "request" is one message read,
  dispatched and written back, so its allocation includes the message
  String and the echo's encoded bytes. Part of it is the JDK's: a
  virtual thread parking in a socket read with a timeout (every read
  here, bounded by `:idle-timeout`) allocates a scheduler task, so a
  server that drains each batch sooner parks, and allocates, more often.
- **Output.** `target/perf/latest.{edn,json,md}` plus a timestamped copy:
  git revision, JVM, OS, CPU count, configuration, and per scenario
  requests, req/s, allocated bytes/request, GC count/time, percentiles.
  The nightly CI job uploads them as artifacts (shared runners: use them
  as a trend line).

```
clojure -M:perf                                          # all scenarios
clojure -M:perf '{:duration-s 30 :scenarios [:h1-get-rate] :rate 50000}'
```

## Comparison with other servers

Measured in August 2026 with the in-process bench (`bench/enso/bench.clj`,
see [Reproduce](#reproduce)) on an earlier version of the code: loopback
on an M-series laptop, JDK 25, every server booted in the same JVM and
sharing cores with the load generator. Read them as relative rankings
under identical conditions, not as capacity: server and client compete
for the same CPUs, GC and JIT, and closed-loop tools (wrk, h2load) do not
correct for coordinated omission. The bench handler answers 404 with a
2-byte body on HTTP/1.1 and HTTP/3; the Netty and Jetty HTTP/3 servers
answer 200 with the same body.

### HTTP/1.1

wrk against a plain 404 responder.

| Workload | Ensō | http-kit | Jetty | Aleph |
|---|---|---|---|---|
| non-pipelined, `-c64` | **126.9k** | 123.1k | 111.6k | 85.8k |
| pipelined depth 16 | **1.88M** | 523k | 232k | 71k |
| pipelined depth 64 | **5.19M** | 561k | 247k | 73k |

Ensō leads across the board, especially on pipelined workloads.

### HTTP/2

Localhost `h2load` over TLS, 5-byte body, self-signed cert.

| Config | rps |
|---|---:|
| `-c 32 -m 32` | 661k |
| `-c 16 -m 64` | 788k |
| `-c 8 -m 128` | **916k** |
| `-c 4 -m 256` | 849k |

10-run distribution at `-c 8 -m 128`, 500k requests each:
min 763k, median **894k**, best 907k.

### HTTP/3

Localhost `quiche-client` fanout, 64 concurrent QUIC connections × 5000
streams each = **320,000 requests total**. Self-signed cert, 2-byte
plaintext body. Same JVM, same host, all three servers boot in-process.

| Server | rps | wall (ms) |
|---|---:|---:|
| **Ensō** | **58,356** | 5484 |
| Netty h3 (incubator 0.0.28, native quic 0.0.66, BoringSSL, vendored quiche master) | 43,268 | 7396 |
| Jetty h3 (12.0.14, JNA quiche) | 2,804 | 114,142 |

Ensō ~35% ahead of Netty (both use libquiche + JNI), ~21× Jetty (JNA path).
0 failures across all runs.

### Allocation, HTTP/1.1 vs http-kit

Sampled with `clj-async-profiler` `:event :alloc` at its default rate
(about one sample per 1 MB TLAB fill), so these are ratios, not bytes.

| Workload | Ensō samples/req | http-kit samples/req | Ratio |
|---|---|---|---|
| non-pipelined | 0.0013 | 0.0102 | **7.8× less** |
| pipelined d=64 | 0.00072 | 0.0104 | **14.3× less** |

### Reproduce

```
clojure -M:bench      # starts nREPL
```

Then in the REPL:

```clojure
(require 'enso.bench)
(enso.bench/start!)
(enso.bench/compare! {:duration "10s" :depth 64})
(enso.bench/profile-alloc! "http://127.0.0.1:8080/nope" {:duration "10s" :depth 64})

;; HTTP/3 comparison across all three servers
(enso.bench/compare-h3! {:clients 32 :per-client 1000})
```

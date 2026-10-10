# Performance

There are two sets of numbers here, from two tools:

- [Current numbers](#current-numbers) come from the regression harness (`clojure -M:perf`), with the server in its own JVM and allocation measured exactly inside it. They track the code; quote these.
- [Comparison with other servers](#comparison-with-other-servers) runs the same harness against other JVM servers, each in its own JVM, so allocation is measured the same way for all of them.

## Current numbers

`clojure -M:perf` on an Apple M1 Pro laptop (8 CPUs), JDK 25, 10 s per
scenario after 5 s of warm-up, server `-Xmx1g`, unlimited keep-alive.
Every response is a 200 with the 13-byte body `Hello, World!`. Server and
load generator share the CPUs, so throughput varies by about 10% between
runs. Allocation per request is stable to a few bytes. Each figure is the
median of three runs at revision 8100538 (October 2026).

| Scenario | req/s | alloc B/req | p50 ms | p99 ms | p99.9 ms | Load |
|---|---:|---:|---:|---:|---:|---|
| h1-get | 119,600 | 393 | 0.47 | 1.22 | 7.18 | 64 connections, closed loop |
| h1-get-rate | 19,994 | 396 | 0.29 | 0.93 | 2.16 | open model, 20k req/s over 64 connections, CO-corrected |
| h1-pipelined | 1,428,232 | 235 | 0.16 | 0.50 | 2.03 | 16 connections × depth 16, latency per batch |
| h2-get | 775,097 | 1,098 | 0.24 | 0.79 | – | h2load `-c 8 -m 32` over TLS, closed loop |
| h3-get | 72,060 | 800 | 1.82 | 2.71 | 3.06 | 4 QUIC connections × 32 requests in flight, closed loop |
| ws-echo | 424,786 | 334 | 1.14 | 2.31 | 12.66 | 64 WebSockets × 8 messages of 128 bytes in flight; one request is one message echoed |

### Uploads

16 MiB POST bodies read to the end by the handler, one connection, one
or four requests in flight. These scenarios run only when named:

```
clojure -M:perf '{:scenarios [:h2-upload :h2-upload-4 :h3-upload :h3-upload-4]}'
```

On the same laptop, over loopback:

| Scenario | MiB/s | alloc per MiB |
|---|---:|---:|
| h2-upload (1 stream, TLS) | 1,045 | 114 KiB |
| h2-upload-4 (4 streams, TLS) | 1,096 | 116 KiB |
| h3-upload (1 stream) | 154 | 25 KiB |
| h3-upload-4 (4 streams) | 168 | 30 KiB |

The HTTP/3 figures are limited by the load client (`s-exp.h3-load`), not
the server.

Receive windows start small and grow while the handler keeps up, so
round-trip time matters more than loopback shows. With 50 ms of added
round-trip time (`tc netem` in a 2-CPU Linux container, so not comparable
with the table above):

| Scenario | MiB/s |
|---|---:|
| h2-upload | 34 |
| h2-upload-4 | 61 |
| h3-upload | 32 |
| h3-upload-4 | 117 |

With windows fixed at their initial sizes, as with a stock libquiche,
the HTTP/3 figures drop to 2.7 and 5.3 MiB/s.

Allocation is everything the server JVM allocated during the measured
window, divided by the requests completed. It includes the Ring request
map, the handler's response map, TLS and the JDK's virtual thread
bookkeeping. What the request path itself allocates is broken down in
[architecture.md](architecture.md#allocation-budget), where tests hold
each path to a bound.

The allocation gate (`clojure -M:perf-gate`, see
[testing.md](testing.md#allocation-gate)) compares a run against the
per-platform baselines in `bench/perf/baseline.edn`.

### Methodology

The harness lives in `s-exp.enso-perf`.

The server (`s-exp.enso-test-server`) runs in its own JVM, `-Xmx1g` by
default (`:server-jvm-opts` to change it). The load generator runs in the
harness JVM. The two still share the host's CPUs; on Linux, pin them apart
(with `taskset`, for example) for less variance.

Allocation is measured in the server process, not sampled. It is the
change in `ThreadMXBean#getTotalThreadAllocatedBytes` across the measured
window, which covers every thread including the carriers of virtual
threads (checked by allocating a known amount on a virtual thread). Warm-up
traffic is excluded. Since it counts everything the server JVM allocated
(parser, handler adapter, response writer, TLS, GC bookkeeping), it is an
upper bound for enso's own code.

`h1-get-rate` is an open-model test. Each connection sends on a fixed
schedule and latency is measured from the intended send time, so a server
stall shows up in the percentiles instead of silently lowering the
request rate (coordinated-omission correction, as in wrk2). The other
scenarios are closed-loop throughput tests; their percentiles are
reported but not CO-corrected.

- `h2-get` uses h2load, which reports median and p99 from nghttp2 1.62 on, and only min, max and mean before.
- `h3-get` drives `:h3-connections` (4) QUIC connections, each keeping `:h3-in-flight` (32) requests open, from a lean load client (`s-exp.h3-load`: quiche through the enso shim, one platform thread per connection).
- `ws-echo` keeps `:ws-depth` (8) text messages of `:ws-message-bytes` (128) in flight on each connection against the echo endpoint. A request is one message read, dispatched and written back, so its allocation includes the message String and the echo's encoded bytes. Part of it is the JDK's: a virtual thread parking in a socket read with a timeout (every read here, bounded by `:idle-timeout`) allocates a scheduler task, so a server that drains each batch sooner parks, and allocates, more often.

Results go to `target/perf/latest.{edn,json,md}`, plus a timestamped
copy: git revision, JVM, OS, CPU count, configuration, and per scenario
the request count, req/s, bytes allocated per request, GC count and time,
and percentiles. The nightly CI job uploads them as artifacts. Shared
runners are noisy, so treat those as a trend line.

```
clojure -M:perf                                          # all scenarios
clojure -M:perf '{:duration-s 30 :scenarios [:h1-get-rate] :rate 50000}'
```

## Comparison with other servers

`clojure -M:bench/compare` runs the scenarios below against Ensō and other
JVM servers. Every server runs in its own JVM, started from its own deps
alias, on the same JDK (Oracle GraalVM 25.0.4) with the same flags
(`-Xmx1g`, nothing else). The load generators run in other processes.
Allocation is measured inside each server JVM, as described in
[Methodology](#methodology). Each figure below is the median of three
rounds, with the lowest and highest round as the range.

Measured in October 2026 at revision 8100538, on the same laptop as the
current numbers.

### Servers

| Server | Version | Configuration |
|---|---|---|
| Ensō | 8100538 | the perf test server, defaults, unlimited keep-alive requests; handlers on virtual threads |
| http-kit | 2.8.1 | defaults: 4 worker threads |
| Jetty | 12.1.14, through ring-jetty9-adapter 0.40.5 | adapter defaults: a pool of 8 to 50 platform threads |
| Jetty, virtual threads | same | `:virtual-threads? true` |
| Aleph | 0.9.11 (Netty 4.1.137) | defaults: handlers on Aleph's executor (up to 512 threads), NIO |
| Netty (HTTP/3 only) | 4.2.19 HTTP/3 codec and native QUIC | one event loop; flow-control windows and stream limits set to Ensō's defaults, since Netty's are zero |

Jetty appears twice because its default platform thread pool and its
virtual thread option perform quite differently, and both are common in
production.

Every server answers `GET /` with a 200 and the 13-byte body
`Hello, World!`, `content-type: text/plain`. Servers add their own
headers: all send `Date`, http-kit, Jetty and Aleph also send `Server`,
and Aleph adds a charset and `Connection: Keep-Alive`. Before measuring
each scenario, the harness fetches one response over that protocol and
checks the status and the body. Load generators count failed requests and
non-2xx responses. Every cell below had zero of both, in every round.

TLS (HTTP/2) uses the JDK's provider and the same self-signed RSA 2048
certificate on Ensō, Jetty and Aleph. All three HTTP/3 servers use quiche:
Ensō through its JNI shim, Netty through its own JNI build, Jetty through
FFM.

### HTTP/1.1

wrk with 4 threads. Non-pipelined: 64 connections. Pipelined: 16
connections with 16 requests per batch, sent by a wrk script. wrk's
percentiles are not reliable with pipelining (it reports a p99 of 0), so
only throughput is given there.

Non-pipelined:

| Server | req/s | range | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Ensō | 134,415 | 133,207–135,055 | 393 | 0.36 | 1.62 |
| Jetty, virtual threads | 129,374 | 129,073–129,796 | 4,030 | 0.32 | 7.28 |
| http-kit | 127,989 | 126,890–128,889 | 3,604 | 0.43 | 0.97 |
| Jetty | 119,730 | 119,303–119,890 | 3,583 | 0.28 | 6.79 |
| Aleph | 86,406 | 86,227–86,812 | 3,623 | 0.33 | 121 |

Pipelined, depth 16:

| Server | req/s | range | alloc B/req |
|---|---:|---:|---:|
| Ensō | 1,734,320 | 1,724,285–1,737,618 | 235 |
| http-kit | 378,682 | 369,854–381,492 | 4,345 |
| Jetty | 352,036 | 350,025–354,434 | 3,481 |
| Jetty, virtual threads | 343,600 | 342,380–345,307 | 3,465 |
| Aleph | 71,149 | 70,854–71,628 | 3,264 |

Without pipelining, all servers fall between 120k and 135k req/s except
Aleph. Ensō has the second lowest p99, after http-kit. It allocates 393
bytes per request, where the others allocate 3,600 to 4,000.

### HTTP/2

h2load over TLS, the `h2-get` settings: `-c 8 -m 32 -t 2`. http-kit has no
HTTP/2 server.

| Server | req/s | range | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Ensō | 855,236 | 837,785–875,238 | 1,138 | 0.21 | 0.89 |
| Jetty, virtual threads | 408,110 | 407,115–408,454 | 8,045 | 0.43 | 3.11 |
| Jetty | 158,581 | 157,211–160,573 | 6,383 | 1.14 | 7.51 |
| Aleph | 38,005 | 30,139–38,272 | 14,471 | 4.20 | 56.53 |

### HTTP/3

The `h3-get` scenario for every server: `s-exp.h3-load`, 4 QUIC
connections with 32 requests in flight each. The client checks the status
of every response. http-kit and Aleph have no HTTP/3 server.

| Server | req/s | range | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Ensō | 72,854 | 71,606–73,586 | 797 | 1.78 | 2.72 |
| Netty | 64,551 | 61,532–65,599 | 4,084 | 1.89 | 2.75 |
| Jetty | 23,666 | 23,576–23,753 | 10,444 | 3.93 | 41.88 |
| Jetty, virtual threads | 9,610 | 9,470–9,687 | 15,146 | 12.80 | 21.59 |

Ensō is 13% faster than Netty, with the same p99. The load client runs one
platform thread per connection and may limit both. That was not measured
separately.

Jetty's HTTP/3 connector is set up as the Jetty 12.1 documentation shows
(`HTTP3ServerQuicConfiguration` and `HTTP3ServerConnectionFactory`) and
serves the same Ring handler. The adapter's own `:http3?` option does not
answer requests in these versions: it installs a raw HTTP/3 connection
factory with an empty session listener and keeps Jetty's QUIC defaults of
zero unidirectional streams.

### WebSocket

The `ws-echo` scenario: 64 WebSockets, 8 messages of 128 bytes in flight
on each. One request is one message echoed.

| Server | msg/s | range | alloc B/msg | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| http-kit | 534,943 | 531,429–536,908 | 847 | 0.93 | 1.68 |
| Ensō | 422,721 | 421,004–425,475 | 334 | 1.15 | 2.31 |
| Jetty | 379,908 | 379,723–380,306 | 5,229 | 0.81 | 6.84 |
| Jetty, virtual threads | 373,828 | 372,964–374,610 | 5,290 | 1.02 | 8.92 |
| Aleph | 48,292 | 45,444–48,942 | 2,655 | 8.33 | 49.84 |

http-kit echoes 27% more messages per second than Ensō, with lower
latency. Ensō allocates less per message.

The echo handlers differ by server. Ensō uses its `WebSocketSocket` send
methods, Jetty the Ring WebSocket API (`ring.websocket/send`), http-kit
`as-channel` and `send!`, and Aleph a Manifold stream connected to itself.

### Caveats

- Server and load generator share one laptop's 8 CPUs. A server that
  needs less CPU leaves more for the client, which helps it in every
  closed-loop scenario.
- wrk, h2load, `s-exp.h3-load` and the WebSocket client are closed-loop:
  each connection waits for responses before sending more. Their
  percentiles are not corrected for coordinated omission.
- Allocation covers the whole server JVM during the measured window
  (adapter, server, TLS, the JDK's own bookkeeping), so it includes work
  each adapter does to build the Ring request map.
- Before each server run, the driver waited for the 1-minute load average
  to drop below 4. Every run started between 3.35 and 3.98. The 5-minute
  average stayed between 4 and 8.6 because of the benchmark itself. An
  editor and a browser stayed open during the runs.
- The WebSocket client opens its connections one at a time. With 64
  simultaneous connects, http-kit's listen backlog (50, the JDK default,
  which it does not let you change) overflows and macOS resets the extra
  connections.

### Reproduce

```
clojure -M:bench/compare
clojure -M:bench/compare '{:rounds 5 :servers [:enso :jetty] :scenarios [:h2-get]}'
```

Needs `wrk`, `h2load` and `quiche-client` (for the HTTP/3 response check)
on the `PATH`, and the Ensō quiche shim. The driver is
`bench/enso/compare.clj`. The peer servers are under `bench/enso/peer/`,
each with its own deps alias (`:bench/http-kit`, `:bench/jetty`,
`:bench/aleph`, `:bench/netty`), so that Aleph's Netty 4.1 and Netty 4.2
never share a classpath. Results go to `target/compare/summary.{edn,md}`,
along with each run's own perf results and the load average for each run.
The Netty dependency lists native QUIC builds for macOS and Linux on
x86_64 and aarch64.

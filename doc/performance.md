# Performance

There are two sets of numbers here, from two tools:

- [Current numbers](#current-numbers) come from the regression harness (`clojure -M:perf`), with the server in its own JVM and allocation measured exactly inside it. They track the code.
- [Comparison with other servers](#comparison-with-other-servers) runs the same harness against other JVM servers, each in its own JVM, so allocation is measured the same way for all of them.

## Current numbers

`clojure -M:perf` on an Apple M1 Pro laptop (8 CPUs), Temurin 25.0.2
(HotSpot, C2), 10 s per scenario after 5 s of warm-up, server `-Xmx1g`,
unlimited keep-alive. Every response is a 200 with the 13-byte body
`Hello, World!`. Server and load generator share the CPUs, so throughput
varies by about 10% between runs. Allocation per request is stable to a
few bytes. Each figure is the median of three runs, measured on October
23, 2026.

| Scenario | req/s | alloc B/req | p50 ms | p99 ms | p99.9 ms | Load |
|---|---:|---:|---:|---:|---:|---|
| h1-get | 133,580 | 289 | 0.46 | 0.79 | 3.41 | 64 connections, closed loop |
| h1-get-rate | 19,997 | 292 | 0.32 | 0.87 | 1.02 | open model, 20k req/s over 64 connections, CO-corrected |
| h1-pipelined | 1,522,354 | 228 | 0.16 | 0.35 | 1.37 | 16 connections × depth 16, latency per batch |
| h2-get | 822,935 | 1,098 | 0.21 | 0.72 | – | h2load `-c 8 -m 32` over TLS, closed loop |
| h3-get | 71,819 | 800 | 1.86 | 2.79 | 3.14 | 4 QUIC connections × 32 requests in flight, closed loop |
| ws-echo | 1,061,040 | 320 | 0.46 | 0.84 | 3.48 | 64 WebSockets × 8 messages of 128 bytes in flight; one request is one message echoed |

### Browser-sized request heads

The `h2-get` and `h3-get` rows send a tiny request head. A browser sends
more. The `h2-get-browser` and `h3-get-browser` scenarios send a 16-field
head (user-agent, accept, accept-language, accept-encoding, cookie,
referer, the four `sec-ch-ua*` and three `sec-fetch-*` fields,
upgrade-insecure-requests, dnt, cache-control, pragma) to the same
handler. They run only when named:

```
clojure -M:perf '{:scenarios [:h2-get-browser :h3-get-browser]}'
```

On the same laptop, median of three rounds, server and load generator
sharing the CPUs, measured on October 23, 2026:

| Scenario | req/s | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|
| h2-get-browser | 692,201 | 2,241 | 0.24 | 1.00 |
| h3-get-browser | 51,110 | 2,296 | 1.63 | 3.43 |

A 16-field head fits in a PersistentArrayMap, which now holds up to 32
fields where it used to hold 8. The head allocates about 970 bytes less
per request on HTTP/2 and about 900 less on HTTP/3 than the hash map it
replaces, measured end to end over three before/after rounds each.
Throughput does not drop: looking a name up by scanning the array costs
less than building and hashing the map. The small-head rows above are
unchanged by the wider array map.

### Uploads

16 MiB POST bodies read to the end by the handler, one connection, one
or four requests in flight. These scenarios run only when named:

```
clojure -M:perf '{:scenarios [:h2-upload :h2-upload-4 :h3-upload :h3-upload-4]}'
```

On the same laptop, over loopback:

| Scenario | MiB/s | alloc per MiB |
|---|---:|---:|
| h2-upload (1 stream, TLS) | 1,074 | 114 KiB |
| h2-upload-4 (4 streams, TLS) | 1,117 | 118 KiB |
| h3-upload (1 stream) | 162 | 23 KiB |
| h3-upload-4 (4 streams) | 170 | 29 KiB |

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
- `ws-echo` keeps `:ws-depth` (8) text messages of `:ws-message-bytes` (128) in flight on each connection against the echo endpoint. A request is one message read, dispatched and written back, so its allocation includes the message String and the echo's encoded bytes.

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
alias, on the same JDK (Temurin 25.0.2, HotSpot with C2) with the same flags
(`-Xmx1g`, nothing else). The load generators run in other processes.
Allocation is measured inside each server JVM, as described in
[Methodology](#methodology). Each figure below is the median of three
rounds, with the lowest and highest round as the range.

Measured on October 23, 2026 at revision e64a31d, on the same laptop as the
current numbers.

### Servers

| Server | Version | Configuration |
|---|---|---|
| Ensō | e64a31d | the perf test server, defaults, unlimited keep-alive requests; handlers on virtual threads |
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
non-2xx responses. Every cell below had zero of both, in every round,
except two wrk timeouts for Ensō: one in a non-pipelined round and one in
a pipelined round, out of 3.9 and 46 million requests. Neither was a slow
response. wrk times requests with the wall clock (`gettimeofday`), which
macOS steps back by a few microseconds now and then, and a request that
completes within such a step gets a negative latency that wrk counts as a
timeout. Rerunning both kinds of run with a wrk build that prints the
latency of each timeout showed -8 and -19 µs.

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
| Ensō | 128,405 | 128,357–128,721 | 289 | 0.37 | 1.07 |
| Jetty, virtual threads | 127,113 | 126,453–127,598 | 4,149 | 0.32 | 4.39 |
| http-kit | 126,342 | 126,111–127,780 | 3,627 | 0.44 | 0.96 |
| Jetty | 120,788 | 120,329–121,323 | 3,570 | 0.27 | 5.12 |
| Aleph | 88,089 | 87,773–89,159 | 3,313 | 0.47 | 49.39 |

Pipelined, depth 16:

| Server | req/s | range | alloc B/req |
|---|---:|---:|---:|
| Ensō | 1,511,371 | 1,509,445–1,528,437 | 228 |
| http-kit | 411,912 | 402,864–412,112 | 3,880 |
| Jetty | 380,129 | 378,455–380,670 | 3,465 |
| Jetty, virtual threads | 371,824 | 368,127–376,735 | 3,584 |
| Aleph | 71,515 | 71,455–72,212 | 3,000 |

Without pipelining, all servers fall between 120k and 128k req/s except
Aleph. Ensō has the second lowest p99, after http-kit. It allocates 289
bytes per request, where the others allocate 3,300 to 4,200.

### HTTP/2

h2load over TLS, the `h2-get` settings: `-c 8 -m 32 -t 2`. http-kit has no
HTTP/2 server.

| Server | req/s | range | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Ensō | 830,285 | 826,442–835,618 | 1,105 | 0.22 | 0.70 |
| Jetty, virtual threads | 419,251 | 416,876–419,903 | 7,639 | 0.43 | 2.49 |
| Jetty | 162,443 | 161,330–163,873 | 6,349 | 1.16 | 6.86 |
| Aleph | 39,447 | 38,980–41,318 | 14,027 | 4.06 | 53.53 |

### HTTP/3

The `h3-get` scenario for every server: `s-exp.h3-load`, 4 QUIC
connections with 32 requests in flight each. The client checks the status
of every response. http-kit and Aleph have no HTTP/3 server.

| Server | req/s | range | alloc B/req | p50 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Ensō | 72,323 | 72,048–72,906 | 805 | 1.80 | 2.74 |
| Netty | 56,038 | 55,953–57,677 | 4,281 | 2.28 | 2.81 |
| Jetty | 23,550 | 9,769–23,743 | 12,614 | 3.96 | 42.63 |
| Jetty, virtual threads | 9,545 | 9,473–9,766 | 17,618 | 12.91 | 20.51 |

Ensō is 29% faster than Netty, with a slightly lower p99. The load client runs one
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
| Ensō | 1,058,454 | 1,050,719–1,058,961 | 320 | 0.46 | 0.83 |
| http-kit | 526,831 | 524,601–533,142 | 871 | 0.95 | 1.65 |
| Jetty | 382,962 | 381,082–383,783 | 5,277 | 0.80 | 6.73 |
| Jetty, virtual threads | 379,770 | 377,046–383,525 | 5,338 | 1.02 | 8.29 |
| Aleph | 53,099 | 51,098–62,110 | 2,685 | 7.34 | 54.30 |

Ensō echoes twice as many messages per second as http-kit, at half the
latency, and allocates less per message.

Most of the cost here is in the kernel, one write per TCP segment. Ensō
writes the replies to the messages it has read in one write. http-kit
writes each reply on its own but leaves Nagle's algorithm on, so the
kernel joins its small writes into fewer segments. Ensō sets
`TCP_NODELAY` (`:so-nodelay`).

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
  to drop below 4. Every run started between 3.60 and 3.96. The 5-minute
  average stayed between 6.1 and 8.9 because of the benchmark itself. An
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

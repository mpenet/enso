# Performance

Loopback bench on an M-series laptop, JDK 25. All servers boot in the same
JVM, sharing cores with the load generator.

## HTTP/1.1 throughput

wrk against a plain 404 responder.

| Workload | Ensō | http-kit | Jetty | Aleph |
|---|---|---|---|---|
| non-pipelined, `-c64` | **126.9k** | 123.1k | 111.6k | 85.8k |
| pipelined depth 16 | **1.88M** | 523k | 232k | 71k |
| pipelined depth 64 | **5.19M** | 561k | 247k | 73k |

Ensō leads across the board, especially on pipelined workloads.

## HTTP/2 throughput

Localhost `h2load` over TLS, 5-byte body, self-signed cert.

| Config | rps |
|---|---:|
| `-c 32 -m 32` | 661k |
| `-c 16 -m 64` | 788k |
| `-c 8 -m 128` | **916k** |
| `-c 4 -m 256` | 849k |

10-run distribution at `-c 8 -m 128`, 500k requests each:
min 763k, median **894k**, best 907k.

## HTTP/3 throughput

Localhost `quiche-client` fanout, 64 concurrent QUIC connections × 5000
streams each = **320,000 requests total**. Self-signed cert, plaintext
200 response. Same JVM, same host, all three servers boot in-process.

| Server | rps | wall (ms) |
|---|---:|---:|
| **Ensō** | **58,356** | 5484 |
| Netty h3 (incubator 0.0.28, native quic 0.0.66, BoringSSL, vendored quiche master) | 43,268 | 7396 |
| Jetty h3 (12.0.14, JNA quiche) | 2,804 | 114,142 |

Ensō ~35% ahead of Netty (both use libquiche + JNI), ~21× Jetty (JNA path).
0 failures across all runs.

## Allocation

Sampled via `clj-async-profiler` `:event :alloc` at default rate
(~1 MB TLAB fill per sample). Lower is better.

### HTTP/1.1 vs http-kit

| Workload | Ensō samples/req | http-kit samples/req | Ratio |
|---|---|---|---|
| non-pipelined | 0.0013 | 0.0102 | **7.8× less** |
| pipelined d=64 | 0.00072 | 0.0104 | **14.3× less** |

### HTTP/2

h2load `-c 8 -m 128`, 500k requests over TLS.

| Ensō samples/req | ≈ bytes/req |
|---:|---:|
| **0.0042** | ~4.2 KB |

Extra HTTP/2 cost vs HTTP/1.1: HPACK `HeaderField` per decoded header,
one `Http2Stream` per request, per-frame byte[] for the writer queue, TLS
record scratch. Wire bytes drop ~50% vs HTTP/1.1 for the same responses
thanks to HPACK indexed emission.

### HTTP/3

`quiche-client` fanout `-c 32 × 2000`, 64k requests.

| Ensō samples/req | ≈ bytes/req |
|---:|---:|
| **0.0044** | ~4.4 KB |

Profile dominated by one `VirtualThread` per request, Ring
`PersistentArrayMap` for headers, per-connection QPACK decode `String[]`
pairs. Zero allocation in the recv path
(`H3FrameReader.feed(byte[], off, len)`); QPACK encode folds directly
into the outbound frame scratch buffer; a single `stream_send` per
response (HEADERS + DATA concatenated).

## Reproduce

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

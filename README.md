# Ensō

Fast, low-allocation, zero-dependency HTTP/1.1 + HTTP/2 Ring server adapter for
Clojure. Java core optimized for Ring, not a wrapper. 
Built on/for virtual threads. Plain sync handler.

- **Zero third-party dependencies.** Java core + thin Clojure adapter. Clojure runtime is the only requirement.
- **Virtual threads, sync API.** One virtual thread per connection, blocking I/O. Handler is a plain Ring function — no async arity, no callbacks.
- **HTTP/1.1 complete.** Keep-alive, pipelining, chunked transfer (request + response), 100-Continue, `Expect`, TLS via `SSLContext`.
- **HTTP/2.** ALPN-negotiated over TLS (`:http2 true`). HPACK, flow control, CONTINUATION reassembly, streaming request/response bodies. Same Ring handler contract as HTTP/1.1 — `:protocol` becomes `"HTTP/2.0"`, everything else unchanged. 145/146 h2spec pass.
- **WebSocket.** Ring 1.5+ listener shape. Text + binary, ping/pong, close handshake.
- **SSE / long-poll.** Response body can be a function receiving a `ChunkedWriter` — push events over time with `flush!`.
- **`StreamableResponseBody`.** Optional support for `ring.core.protocols` — user-extensible response body types.
- **Fast.** ~5M rps pipelined depth 64 on a laptop (HTTP/1.1); ~894k rps HTTP/2 over TLS.
- **Low allocation.** ~0.001 sample/req at 1 MB TLAB interval — near-zero GC pressure on hot paths.
- **Sendfile.** `File` response bodies dispatch via `FileChannel.transferTo(SocketChannel)` — zero-copy on plain HTTP.
- **Correct.** Rejects request smuggling variants (duplicate `Content-Length`, `TE + CL`, obs-fold), header injection in responses, slowloris (per-request deadline), and enforces body-size caps.

## Requirements

- JDK 21+ 
- Clojure 1.12+

## Quick start

```clojure
(require '[s-exp.enso :as enso])

(def server
  (enso/run-server
    (fn [req] {:status 200 :body "hello"})
    {:port 8080}))

(enso/stop server)
```

## Options

Network:
- `:port` (8080), `:host` ("0.0.0.0"), `:backlog` (1024)

Timeouts:
- `:idle-timeout` — per-read socket timeout in ms (30000). 0 disables.
- `:request-timeout` — wall-clock deadline for reading a full request (30000). Slowloris protection.
- `:shutdown-timeout` — graceful drain of in-flight requests (10000).

TLS:
- `:ssl-context` — `javax.net.ssl.SSLContext`. When set, listens over TLS.
- `:ssl-need-client-auth`, `:ssl-want-client-auth` — mTLS.

HTTP/2 (requires `:ssl-context`):
- `:http2` (false) — enables ALPN "h2" advertisement. Clients that prefer HTTP/1.1 still get it.
- `:http2-max-concurrent-streams` (100)
- `:http2-initial-window-size` (1 MiB) — bytes; spec default 64 KiB starves throughput on non-LAN paths
- `:http2-max-frame-size` (16384) — spec minimum; raise for fewer send syscalls on large bodies
- `:http2-max-header-list-size` (8192) — bytes; peer that exceeds it gets `GOAWAY(ENHANCE_YOUR_CALM)`. 0 disables.

Handler:
- `:error-handler` — `(fn [request throwable])` returning a Ring response. Runs when the main handler throws or returns nil.

Limits (tune only if you know why):
- `:request-buffer-size` (16384) — initial request parse buffer
- `:max-header-bytes` (65536) — 431 above
- `:max-request-body-bytes` (10 MiB) — 413 above
- `:max-inline-body` (16384) — response bodies at or below this size are inlined into the header write for one-syscall dispatch
- `:coalesce-high-water` (32768) — pipelined batch flush trigger
- `:chunk-buffer-size` (8192) — chunked streaming read chunk
- `:max-drain-bytes` (65536) — ignored-body drain limit before conn close

## Response body types

- `String`, `byte[]` — inlined or single-write
- `java.io.InputStream` — chunked (HTTP/1.1) or close-delimited. If the response has a `Content-Length` header, sent as a fixed-length body.
- `java.io.File` — zero-copy via `FileChannel.transferTo(SocketChannel)` on plain HTTP. User-space copy on TLS.
- `clojure.lang.ISeq` — concatenated to a String.
- `(fn [ChunkedWriter])` — streaming writer for SSE, long-poll, incremental output. Handler drives writes with `enso/write!` + `enso/flush!`.
- Anything satisfying `ring.core.protocols/StreamableResponseBody` — optional, dispatched only when `ring.core.protocols` is on the classpath. Fast paths above take priority.

## Streaming (SSE)

```clojure
(defn sse [req]
  {:status 200
   :headers {"content-type" "text/event-stream"}
   :body (fn [w]
           (dotimes [i 5]
             (enso/write! w (str "data: tick " i "\n\n"))
             (enso/flush! w)
             (Thread/sleep 1000)))})
```

## WebSocket (Ring 1.5+ shape)

```clojure
(defn ws [req]
  {:ring.websocket/listener
   {:on-open    (fn [socket] ...)
    :on-message (fn [socket msg] (.sendText socket (str "echo: " msg)))
    :on-close   (fn [socket code reason] ...)}})
```

`socket` is a `com.s_exp.enso.WebSocketSocket`. Text and binary messages, ping/pong (auto-pong on ping unless `:on-ping` is provided), close handshake.

## Performance

Loopback bench on an M-series laptop, JDK 25, wrk against a plain 404 responder. All four servers boot in the same JVM, sharing cores with wrk.

### HTTP/1.1 throughput

| Workload | Ensō | http-kit | Jetty | Aleph |
|---|---|---|---|---|
| non-pipelined, `-c64` | **127.8k** | 123.8k | 110.5k | 85.8k |
| pipelined depth 16 | **1.88M** | 523k | 232k | 71k |
| pipelined depth 64 | **5.13M** | 550k | 244k | 73k |

Ensō leads throughput across the board, especially on pipelined workloads.

### HTTP/2 throughput

Localhost h2load over TLS, 5-byte body, self-signed cert:

| Config | rps |
|---|---:|
| `-c 32 -m 32` | 661k |
| `-c 16 -m 64` | 788k |
| `-c 8 -m 128` | **916k** |
| `-c 4 -m 256` | 849k |

10-run distribution at `-c 8 -m 128`, 500k requests each: min 763k, median **894k**, best 907k.

### Allocation

Sampled via `clj-async-profiler` `:event :alloc` at default rate (~1 MB TLAB fill per sample). Lower is better.

HTTP/1.1 vs http-kit:

| Workload | Ensō samples/req | http-kit samples/req | Ratio |
|---|---|---|---|
| non-pipelined | 0.0013 | 0.0102 | **7.8x less** |
| pipelined d=64 | 0.00072 | 0.0104 | **14.3x less** |

HTTP/2 (h2load `-c 8 -m 128`, 500k requests over TLS):

| Ensō samples/req | ≈ bytes/req |
|---:|---:|
| **0.0042** | ~4.2 KB |

Extra HTTP/2 cost vs HTTP/1.1: HPACK `HeaderField` per decoded header, one `Http2Stream` per request, per-frame byte[] for the writer queue, and TLS record scratch buffers. Wire bytes drop ~50% vs HTTP/1.1 for the same responses thanks to HPACK indexed emission.

Reproduce with `clojure -M:bench` (starts nREPL), then in the REPL:

```clojure
(require 'enso.bench)
(enso.bench/start!)
(enso.bench/compare! {:duration "10s" :depth 64})
(enso.bench/profile-alloc! "http://127.0.0.1:8080/nope" {:duration "10s" :depth 64})
```

## Status

* HTTP/1.1 + HTTP/2 + keep-alive + chunked transfer + TLS + WebSocket + SSE.
* No HTTP/3 (it's on our todo)
* No compression. No async Ring arity (sync handler only — virtual threads make it moot). 
* No h2c (cleartext HTTP/2), no Server Push, no PRIORITY (all deprecated or receive-side only per RFC 9113).

## Build

```
clojure -T:build javac
clojure -X:test
```

Java sources compile to `target/classes`. `deps.edn` includes it on the classpath.

## Prior art

The HTTP/2 write architecture — dedicated writer vthread, bounded frame queue, fair lock around HPACK, `SSLEngine` over `SocketChannel` — is inspired by [Helidon Níma](https://github.com/helidon-io/helidon) ([Apache 2.0](https://github.com/helidon-io/helidon/blob/main/LICENSE.txt)). Ensō re-implements the pattern from scratch, no code copied.

## License

Copyright © 2026 Max Penet.

Ensō is distributed under the [Mozilla Public License 2.0](LICENSE). You can use, modify, and redistribute it under the terms of the MPL 2.0. The full text is in [LICENSE](LICENSE); the summary at <https://www.mozilla.org/en-US/MPL/2.0/FAQ/> covers the practical implications.

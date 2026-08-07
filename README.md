# Ensō

Zero-dependency, Ring-compliant HTTP/1.1 server for Clojure leveraging modern
jvm features.

- **Zero third-party dependencies.** Java core + thin Clojure adapter. Clojure runtime is the only requirement.
- **Virtual threads, sync API.** One virtual thread per connection, blocking I/O. Handler is a plain Ring function — no async arity, no callbacks.
- **HTTP/1.1 complete.** Keep-alive, pipelining, chunked transfer (request + response), 100-Continue, `Expect`, TLS via `SSLContext`.
- **WebSocket.** Ring 1.5+ listener shape. Text + binary, ping/pong, close handshake.
- **SSE / long-poll.** Response body can be a function receiving a `ChunkedWriter` — push events over time with `flush!`.
- **`StreamableResponseBody`.** Optional support for `ring.core.protocols` — user-extensible response body types.
- **Fast.** ~5M rps pipelined depth 64 on a laptop, ~128k rps non-pipelined.
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

### Throughput

| Workload | Ensō | http-kit | Jetty | Aleph |
|---|---|---|---|---|
| non-pipelined, `-c64` | **127.8k** | 123.8k | 110.5k | 85.8k |
| pipelined depth 16 | **1.88M** | 523k | 232k | 71k |
| pipelined depth 64 | **5.13M** | 550k | 244k | 73k |

Ensō leads throughput across the board, especially on pipelined workloads.

### Allocation

Sampled via `clj-async-profiler` `:event :alloc` at default rate (~1 MB TLAB fill per sample). Lower is better.

| Workload | Ensō samples/req | http-kit samples/req | Ratio |
|---|---|---|---|
| non-pipelined | 0.0013 | 0.0102 | **7.8x less** |
| pipelined d=64 | 0.00072 | 0.0104 | **14.3x less** |

Reproduce with `clojure -M:bench` (starts nREPL), then in the REPL:

```clojure
(require 'enso.bench)
(enso.bench/start!)
(enso.bench/compare! {:duration "10s" :depth 64})
(enso.bench/profile-alloc! "http://127.0.0.1:8080/nope" {:duration "10s" :depth 64})
```

## Status

HTTP/1.1 + keep-alive + chunked transfer + TLS + WebSocket + SSE. No HTTP/2, no
HTTP/3 (for now) — terminate at a proxy (see above). No compression. No async
Ring arity (sync handler only — virtual threads make it moot).

## Build

```
clojure -T:build javac
clojure -X:test
```

Java sources compile to `target/classes`. `deps.edn` includes it on the classpath.

## License

Copyright © 2026 Max Penet.

Ensō is distributed under the [Mozilla Public License 2.0](LICENSE). You can use, modify, and redistribute it under the terms of the MPL 2.0. The full text is in [LICENSE](LICENSE); the summary at <https://www.mozilla.org/en-US/MPL/2.0/FAQ/> covers the practical implications.

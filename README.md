# Ensō

Fast, low-allocation, zero-dependency HTTP/1.1 + HTTP/2 + HTTP/3 Ring server
adapter for Clojure. Java core optimized for Ring, not a wrapper.
Built on/for virtual threads. Plain sync handler.

- **Zero third-party Java dependencies.** Java core + thin Clojure adapter. Clojure runtime is the only requirement. HTTP/3 pulls in system `libquiche` (dlopen'd via a small JNI shim shipped in the jar) and is opt-in.
- **Virtual threads, sync API.** One virtual thread per connection, blocking I/O. Handler is a plain Ring function — no async arity, no callbacks.
- **HTTP/1.1 complete.** Keep-alive, pipelining, chunked transfer (request + response), 100-Continue, `Expect`, TLS via `SSLContext`.
- **HTTP/2.** ALPN-negotiated over TLS (`:http2 true`). HPACK, flow control, CONTINUATION reassembly, streaming request/response bodies. Same Ring handler contract as HTTP/1.1 — `:protocol` becomes `"HTTP/2.0"`, everything else unchanged. 145/146 h2spec pass.
- **HTTP/3.** Cloudflare `libquiche` over UDP via JNI shim, pure-Java QPACK + H3 framing on top of quiche's transport primitives. Same Ring handler contract — `:protocol` becomes `"HTTP/3.0"`. Alt-Svc advertised automatically from h1/h2 responses when h3 is enabled. **Faster than Netty h3 in bench (see below).**
- **WebSocket.** Ring 1.5+ listener shape. Text + binary, ping/pong, close handshake.
- **SSE / long-poll.** Response body can be a function receiving a `ChunkedWriter` — push events over time with `flush!`.
- **`StreamableResponseBody`.** Optional support for `ring.core.protocols` — user-extensible response body types.
- **Fast.** ~5M rps pipelined depth 64 on a laptop (HTTP/1.1); ~894k rps HTTP/2 over TLS; ~53k rps HTTP/3 (edges out Netty by ~2%, ~19x Jetty).
- **Low allocation.** ~0.001 sample/req at 1 MB TLAB interval — near-zero GC pressure on hot paths.
- **Sendfile.** `File` response bodies dispatch via `FileChannel.transferTo(SocketChannel)` — zero-copy on plain HTTP.
- **Correct.** Rejects request smuggling variants (duplicate `Content-Length`, `TE + CL`, obs-fold), header injection in responses, slowloris (per-request deadline), and enforces body-size caps.

## Requirements

- JDK 21+ (HTTP/3 requires 22+ for FFM-free JNI; see below)
- Clojure 1.12+
- For HTTP/3: system `libquiche` (Cloudflare quiche 0.29.x). macOS: `brew install cloudflare-quiche`. Linux: build from https://github.com/cloudflare/quiche with `--features ffi`.

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

HTTP/3 (requires PEM cert + key, uses its own UDP socket; can co-exist with h1/h2 on the same TCP port):
- `:http3` (false) — enables HTTP/3 listener. Advertised via `Alt-Svc` on h1/h2 responses when both are enabled.
- `:http3-port` — UDP port. Defaults to same value as `:port`.
- `:http3-cert-path`, `:http3-key-path` — PEM cert chain + private key. Required.
- `:http3-max-idle-timeout-ms` (30000) — quiche idle timeout in ms.
- `:http3-max-udp-payload-size` (1350) — MTU-safe default.
- `:http3-initial-max-data` (10 MiB) — connection-level flow control window.
- `:http3-initial-max-streams-bidi` (100) — concurrent request streams per connection.
- `:http3-stateless-retry` (false) — force clients to prove reachability before we allocate connection state (RFC 9000 §8.1.2). Enable under DDoS.

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

`socket` is a `com.s_exp.enso.websocket.WebSocketSocket`. Text and binary messages, ping/pong (auto-pong on ping unless `:on-ping` is provided), close handshake.

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

### HTTP/3 throughput

Localhost `quiche-client` fanout, 64 concurrent QUIC connections × 5000 streams
each = **320,000 requests total**, self-signed cert, plaintext 200 response.
Same JVM, same host, all three h3 servers boot in-process for apples-to-apples:

| Server | rps | wall (ms) |
|---|---:|---:|
| **Ensō** | **53,235** | 6011 |
| Netty h3 (incubator 0.0.28, native quic 0.0.66, BoringSSL, vendored quiche master snapshot) | 52,253 | 6124 |
| Jetty h3 (12.0.14, JNA quiche) | 2,766 | 115,707 |

Ensō ~2% ahead of Netty (both use libquiche + JNI), ~19× Jetty (JNA path). 0 failures across all runs.

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

HTTP/3 (`quiche-client` fanout `-c 32 × 2000`, 64k requests):

| Ensō samples/req | ≈ bytes/req |
|---:|---:|
| **0.0044** | ~4.4 KB |

Similar allocation profile to HTTP/2, dominated by one `VirtualThread` per request, the Ring `PersistentArrayMap` for headers, and the per-connection QPACK decode `String[]` pairs. Zero allocation in the recv path (`H3FrameReader.feed(byte[], off, len)`); QPACK encode folds directly into the outbound frame scratch buffer; a single `stream_send` per response (HEADERS + DATA concatenated).

Reproduce with `clojure -M:bench` (starts nREPL), then in the REPL:

```clojure
(require 'enso.bench)
(enso.bench/start!)
(enso.bench/compare! {:duration "10s" :depth 64})
(enso.bench/profile-alloc! "http://127.0.0.1:8080/nope" {:duration "10s" :depth 64})
```

## Status

* HTTP/1.1 + HTTP/2 + HTTP/3 + keep-alive + chunked transfer + TLS + WebSocket + SSE.
* HTTP/3 uses a small JNI shim over cloudflare `libquiche` (pure-Java QPACK + H3 framing on top of quiche's transport primitives). FFM path was tried but hit a JDK 25 libmalloc corruption bug on macOS ARM64 (matches what Netty steers around in `CleanerJava25.java`); the JNI migration eliminated it. Graceful `CONNECTION_CLOSE` on shutdown, stateless retry, GOAWAY monotonicity, control-stream parser with connection-level error propagation, RFC 9114 header validation. h3spec / quic-interop-runner pass pending.
* No compression. No async Ring arity (sync handler only — virtual threads make it moot).
* No h2c (cleartext HTTP/2), no Server Push, no PRIORITY (all deprecated or receive-side only per RFC 9113).
* No HTTP/3 trailers (Ring 1.x has no trailer surface anyway).

## Build

```
clojure -T:build javac
clojure -X:test
```

Java sources compile to `target/classes`. `deps.edn` includes it on the classpath.

### HTTP/3 (optional)

The h3 layer needs a small JNI shim (`native/enso_quiche/enso_quiche.c`) that
links against system `libquiche`:

```
brew install cloudflare-quiche              # macOS
make -C native/enso_quiche                  # builds target/native/<os>-<arch>/libenso_quiche.<ext>
clojure -T:build javac-bench                # optional: builds the Netty+Jetty bench servers
```

The built `.dylib`/`.so` is bundled under `META-INF/native/<os>-<arch>/` in the
release jar; at load time `Quiche.java` extracts the shim into a per-JVM temp
directory (unique random name — safe for multiple JVMs on the same host)
before `System.load`ing it.

Platform classifier resolution:
- macOS → `darwin-arm64` / `darwin-amd64`
- Linux glibc → `linux-arm64` / `linux-amd64`
- Linux musl (Alpine, Wolfi, Chimera) → `linux-musl-arm64` / `linux-musl-amd64`, with fallback to `linux-*` if the musl-built shim isn't present. Detection checks for `/lib/ld-musl-*.so.1`.

Override for local dev: `-Denso.quiche.shim=/abs/path/to/libenso_quiche.dylib`.

## Prior art

The HTTP/2 write architecture — dedicated writer vthread, bounded frame queue, fair lock around HPACK, `SSLEngine` over `SocketChannel` — is inspired by [Helidon Níma](https://github.com/helidon-io/helidon) ([Apache 2.0](https://github.com/helidon-io/helidon/blob/main/LICENSE.txt)). Ensō re-implements the pattern from scratch, no code copied.

## License

Copyright © 2026 Max Penet.

Ensō is distributed under the [Mozilla Public License 2.0](LICENSE). You can use, modify, and redistribute it under the terms of the MPL 2.0. The full text is in [LICENSE](LICENSE); the summary at <https://www.mozilla.org/en-US/MPL/2.0/FAQ/> covers the practical implications.

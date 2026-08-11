# Ensō

/!\ WIP

Fast, low-allocation, zero-dependency* HTTP/1.1 + HTTP/2 + HTTP/3 Ring
server adapter for Clojure. 

Java core optimized for Ring, not a wrapper.  Built on/for virtual
threads. Plain sync handler.

- **Fast.** ~5.2M rps pipelined depth 64 (HTTP/1.1); ~894k rps HTTP/2 over
  TLS; ~58k rps HTTP/3 (~35% faster than Netty, ~21× Jetty).
- **Low allocation.** ~0.001 sample/req at 1 MB TLAB interval — near-zero
  GC pressure on hot paths.
- **Zero third-party Java dependencies.** Java core + thin Clojure adapter.
  Clojure runtime is the only requirement (for http1+2). Release jars bundle a
  JNI shim per platform with libquiche statically linked in — no system
  libquiche install needed. HTTP/3 remains opt-in.
- **Virtual threads, sync API.** One vthread per connection, blocking I/O.
  Handler is a plain Ring function — no async arity, no callbacks.
- **HTTP/1.1 complete.** 
- **HTTP/2.** ALPN over TLS (`:http2 true`). h2spec pass.
- **HTTP/3.** Cloudflare `libquiche` over UDP via JNI shim. Pure-Java
  QPACK + H3 framing on top of quiche's transport primitives. Alt-Svc
  auto-advertised from h1/h2 responses when h3 enabled. **~35% faster
  than Netty h3 in bench** — see [doc/performance.md](doc/performance.md).
- **WebSocket.** Ring 1.5+ listener shape. 
- **SSE / long-poll.** Streaming writer 
- **Correct.** Rejects request smuggling, header injection, slowloris.
  CVE-2023-44487 rapid-reset mitigation. Body-size caps enforced.

## Requirements

- JDK 21+ (HTTP/3 requires 22+).
- Clojure 1.12+.
- HTTP/3: add a matching classifier — see below.

## deps.edn

[![Clojars Project](https://img.shields.io/clojars/v/com.s-exp/enso.svg)](https://clojars.org/com.s-exp/enso)

```clojure
;; core only, no h3
{:deps {com.s-exp/enso {:mvn/version "..."}}}

;; core + per-platform http3 shim
{:deps {com.s-exp/enso              {:mvn/version "..."}
        com.s-exp/enso$darwin-arm64 {:mvn/version "..."}}}
```

Classifiers: `darwin-arm64`, `linux-{amd64,arm64}`,
`linux-musl-{amd64,arm64}`. Full detail in [doc/http3.md](doc/http3.md).

## Quick start

```clojure
(require '[s-exp.enso :as enso])

(def server
  (enso/run-server
    (fn [req] {:status 200 :body "hello"})
    {:port 8080}))

(enso/stop server)
```

## Documentation

- [doc/options.md](doc/options.md) — full configuration reference (network,
  timeouts, keep-alive, TCP, TLS, HTTP/2, HTTP/3, limits).
- [doc/handlers.md](doc/handlers.md) — response body types, WebSocket, SSE,
  error handling, correctness notes.
- [doc/http3.md](doc/http3.md) — HTTP/3 setup, release-jar distribution,
  dev build against system libquiche.
- [doc/performance.md](doc/performance.md) — bench numbers vs http-kit /
  Jetty / Aleph / Netty; allocation profile; reproduction steps.
- [doc/build.md](doc/build.md) — build tasks, jar flavors, release CI.
- [doc/h3-conformance.md](doc/h3-conformance.md) — h3spec suite results
  (39/49 pass; all 10 residuals are libquiche 0.29.3 transport-layer
  limitations; HTTP/3 + QPACK layers 100%).

## Prior art

The HTTP/2 write architecture — dedicated writer vthread, bounded frame
queue, fair lock around HPACK, `SSLEngine` over `SocketChannel` — is
inspired by [Helidon Níma](https://github.com/helidon-io/helidon)
([Apache 2.0](https://github.com/helidon-io/helidon/blob/main/LICENSE.txt)).
Ensō re-implements the pattern from scratch, no code copied.

## License

Copyright © 2026 Max Penet.

Ensō is distributed under the [Mozilla Public License 2.0](LICENSE).
Practical summary: <https://www.mozilla.org/en-US/MPL/2.0/FAQ/>.

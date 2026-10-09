# Ensō

Status: alpha. The API and option names may still change between
releases (see [CHANGELOG.md](CHANGELOG.md)).

Fast, low-allocation HTTP/1.1, HTTP/2, HTTP/3 and WebSocket server for
Clojure Ring handlers, with no dependency beyond Clojure itself. A Java
core written for Ring, on virtual threads, behind a thin Clojure adapter.

- **Fast.** Measured with the separate-process harness on one laptop
  (8 CPUs, server and load generator sharing them): ~103k req/s HTTP/1.1
  GET over 64 connections, ~1.15M req/s pipelined (depth 16), ~644k req/s
  HTTP/2 over TLS, ~70k req/s HTTP/3, ~423k WebSocket echoes/s. Details,
  latency percentiles and a comparison with http-kit, Jetty, Aleph and
  Netty in [doc/performance.md](doc/performance.md).
- **Low allocation.** About 390 bytes allocated by the whole server JVM
  per HTTP/1.1 GET (Ring request and response maps included), ~1.1 KB per
  HTTP/2 GET over TLS, ~800 bytes per HTTP/3 GET; tests hold each request
  path to a bound ([doc/architecture.md](doc/architecture.md#allocation-budget)).
- **No third-party dependencies.** Clojure is the only dependency. HTTP/3
  is opt-in: add the classifier jar for your platform, which carries a JNI
  shim with libquiche statically linked in (no system libquiche needed).
- **Virtual threads, plain handlers.** One virtual thread per connection
  (per stream on HTTP/2 and HTTP/3), blocking I/O. A handler is a plain
  Ring function; Ring asynchronous handlers work with `:async true`.
- **HTTP/1.1.** Keep-alive, pipelining, chunked bodies and trailers,
  `Expect: 100-continue`, zero-copy file bodies on plain HTTP, lingering
  close so clients read error responses instead of a reset.
- **HTTP/2.** Over TLS with ALPN (`:http2`) or cleartext with prior
  knowledge (`:http2c`). h2spec: 146/146 over TLS; 145/146 cleartext,
  where the one failure (3.5/2, invalid preface) is by design: on an
  `:http2c` port bytes that aren't the HTTP/2 preface are an HTTP/1.1
  request, answered 400 rather than with a GOAWAY.
- **HTTP/3.** Cloudflare `libquiche` over UDP through a JNI shim, QPACK
  and HTTP/3 framing in Java, event loops sharded per core on Linux,
  certificate rotation without restart. `Alt-Svc` is advertised on
  HTTP/1.1 and HTTP/2 responses when HTTP/3 is on. h3spec: 47/49 (the two
  failures are reserved-bit checks inside libquiche,
  [doc/h3-conformance.md](doc/h3-conformance.md)).
- **WebSocket.** HTTP/1.1 upgrade with the Ring 1.11+ WebSocket API
  (listener maps, and `ring.websocket.protocols` listeners and sockets
  when that library is on the classpath), sync and async sends with
  back-pressure, RFC 6455 closing handshake, opt-in permessage-deflate
  (RFC 7692), same-origin check by default. Autobahn TestSuite: 517/517.
  Over HTTP/2 and HTTP/3 a WebSocket response is answered 501.
- **Streaming.** `(fn [ChunkedWriter])` bodies for SSE and long-poll
  (chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3), lazy seqs, and
  `ring.core.protocols/StreamableResponseBody`.
- **Hardened.** Rejects request smuggling and response header injection;
  one timeout model on every protocol (handshake, header, read, write,
  idle, handler: slowloris and slow readers are cut off); header, body and
  WebSocket message limits on every protocol; connection caps (global and
  per client address, TCP and QUIC); a server-wide cap on bytes buffered
  for peers; HTTP/2 rapid-reset (CVE-2023-44487), MadeYouReset
  (CVE-2025-8671) and CONTINUATION flood mitigations; HTTP/3 stateless
  Retry under handshake floods.
- **Observable.** `:server-events` hook (connections, requests, protocol
  errors) at no cost when absent; JDK Flight Recorder events on every
  protocol.

Supported API: the `s-exp.enso` namespace, `com.s_exp.enso.EnsoServer` and
the `com.s_exp.enso.api` package (Ring request / response types,
`ChunkedWriter`, `ServerEvents`, `Config`, and the WebSocket socket,
listener and exception types). Every other package (`core`, `http1`,
`http2`, `http3`, `websocket`, `quiche`, `util`) is the server's internals
and may change in any release; exceptions it throws at handlers extend
`java.io.IOException`, so catch that.

## Requirements

- JDK 21+.
- Clojure 1.12+.
- HTTP/3: the classifier jar matching the platform (below); glibc 2.28+
  or musl on Linux, macOS 11+ on Apple Silicon. On JDK 24+ add
  `--enable-native-access=ALL-UNNAMED` to the JVM options
  ([doc/http3.md](doc/http3.md#native-access-jdk-24)).

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

## Security notes

- WebSocket handshakes are accepted from the server's own origin only
  (the `Origin` host must equal `Host`). Behind a proxy that rewrites
  `Host`, or for cross-origin clients, list the allowed origins in
  `:ws-allowed-origins`. Authenticate in the handler before returning the
  listener.
- The defaults bound what one client can make the server hold: 64 KiB
  request heads, 10 MiB request bodies, 1 MiB WebSocket messages, 10000
  connections, a quarter of the heap for buffered peer data and the
  flow-control credit promised to peers (shared fairly under pressure),
  request bodies no slower than 240 bytes/s after 5 s of waiting
  (`:min-data-rate-bytes`). Review
  [doc/options.md](doc/options.md#limits) for your traffic.
- Set `:max-connections-per-ip` when clients reach the server directly:
  without it one address can take every connection slot. Leave it off
  behind a load balancer or NAT, where clients share addresses, and limit
  per client there.
- Set `:handler-timeout` in production: it is off by default (a
  handler's duration is application policy), and without it a handler
  stuck on a slow dependency holds its connection (or HTTP/2 / HTTP/3
  stream slot) and virtual thread until it returns.
- HTTP/3: prefer an ECDSA (P-256) certificate. Each QUIC handshake signs
  on an event loop thread, and ECDSA signing costs a fraction of RSA's,
  which matters under a connection flood.

## Documentation

- [doc/options.md](doc/options.md) — full configuration reference (network,
  timeouts, limits, TCP, TLS, HTTP/2, HTTP/3, WebSocket, observability,
  logging).
- [doc/architecture.md](doc/architecture.md) — layering, threading, the
  shared core contracts (exchange, memory budget, timer, watchdog,
  response / request heads, limits, shutdown, events), each protocol
  driver, and the allocation budget.
- [doc/handlers.md](doc/handlers.md) — request map, response body types,
  async handlers, SSE, WebSocket, error handling, correctness notes.
- [doc/http3.md](doc/http3.md) — HTTP/3 setup, certificate rotation, how
  the event loops run, limits, release-jar distribution, dev build against
  system libquiche.
- [doc/performance.md](doc/performance.md) — harness numbers (throughput,
  latency, allocation per request), comparison with http-kit / Jetty /
  Aleph / Netty, methodology and reproduction steps.
- [doc/build.md](doc/build.md) — build tasks, jar flavors, release CI.
- [doc/h3-conformance.md](doc/h3-conformance.md) — h3spec suite results
  (47/49 pass; the 2 failures are reserved-bit checks inside libquiche
  0.29.3; HTTP/3 + QPACK layers 100%).
- [doc/testing.md](doc/testing.md) — running the tests, property and
  coverage-guided fuzzing, sanitizer and soak runs, conformance suites
  (h2spec, Autobahn, h3spec), the perf harness and CI.
- [CHANGELOG.md](CHANGELOG.md) — changes per release.

## Prior art

The `SSLEngine` over `SocketChannel` TLS layer is inspired by
[Helidon Níma](https://github.com/helidon-io/helidon)
([Apache 2.0](https://github.com/helidon-io/helidon/blob/main/LICENSE.txt)).
Ensō re-implements the pattern from scratch, no code copied.

## License

Copyright © 2026 Max Penet.

Ensō is distributed under the [Mozilla Public License 2.0](LICENSE).
Practical summary: <https://www.mozilla.org/en-US/MPL/2.0/FAQ/>.

# Ensō

[![Clojars Project](https://img.shields.io/clojars/v/com.s-exp/enso.svg)](https://clojars.org/com.s-exp/enso)

An HTTP/1.1, HTTP/2, HTTP/3 and WebSocket server for Clojure Ring
handlers, with no dependency besides Clojure. The core is written in Java
for Ring and runs on virtual threads.

Status: alpha. Option names and the API may still change between releases
(see the [changelog](CHANGELOG.md)).

## Installation

```clojure
{:deps {com.s-exp/enso {:mvn/version "1.0.0-alphaN"}}}
```

HTTP/3 is optional. It needs a second artifact for your platform, which
contains a JNI shim with libquiche linked in, so there is nothing to
install on the system:

```clojure
{:deps {com.s-exp/enso             {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-amd64 {:mvn/version "1.0.0-alphaN"}}}
```

Classifiers: `linux-amd64`, `linux-arm64`, `linux-musl-amd64`,
`linux-musl-arm64`, `darwin-arm64`.

## Quick start

```clojure
(require '[s-exp.enso :as enso])

(def server
  (enso/run-server (fn [req] {:status 200 :body "hello"})
                   {:port 8080}))

(enso/stop server)
```

With TLS, HTTP/2 and HTTP/3:

```clojure
(enso/run-server handler
  {:port 8443
   :ssl-context ssl-context ; a javax.net.ssl.SSLContext
   :http2 true
   :http3 true
   :http3-cert-path "cert.pem"
   :http3-key-path "key.pem"})
```

## Features

- HTTP/1.1 with keep-alive, pipelining, chunked bodies and trailers,
  `Expect: 100-continue` and zero-copy file bodies.
- HTTP/2 over TLS, or cleartext with prior knowledge (`:http2c`).
- HTTP/3 through Cloudflare's quiche, advertised with `Alt-Svc`, with
  certificate reloading.
- WebSocket over HTTP/1.1, with optional permessage-deflate.
- Ring sync and async handlers, the Ring 1.11 WebSocket API,
  `StreamableResponseBody`, and a streaming body for SSE and long-poll.
- One virtual thread per connection (per stream on HTTP/2 and HTTP/3),
  with blocking I/O.
- The same timeouts and limits on every protocol, and connection,
  request and error events through a callback map or JFR.

Conformance: h2spec 146/146 over TLS, Autobahn TestSuite 517/517, h3spec
75/77 (the two failures are checks inside libquiche). Benchmarks are in
[doc/performance.md](doc/performance.md).

Requirements: JDK 21 or later and Clojure 1.12 or later. HTTP/3 runs on
Linux (glibc 2.28+ or musl) and macOS 11+ on Apple Silicon, and on JDK 24+
needs `--enable-native-access=ALL-UNNAMED`.

## Documentation

- [Options](doc/options.md): every `run-server` option and its default.
- [Handlers](doc/handlers.md): the request map, response bodies, streaming, async handlers, errors, WebSocket, and the supported API.
- [Deployment](doc/deployment.md): production checklist, default limits, what the server protects against.
- [HTTP/3](doc/http3.md): setup, certificates, how the QUIC event loops work, native shim.
- [Performance](doc/performance.md): throughput, latency and allocation numbers, and how to reproduce them.
- [Architecture](doc/architecture.md): how the server is built, for people working on it.
- [Testing](doc/testing.md): the test suite, fuzzing, conformance suites, benchmarks and CI.
- [HTTP/3 conformance](doc/h3-conformance.md): h3spec results.
- [Building](doc/build.md): build tasks, jars, the native shim and releases.
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## Prior art

The TLS layer (`SSLEngine` over `SocketChannel`) follows the pattern used
by [Helidon Níma](https://github.com/helidon-io/helidon)
([Apache 2.0](https://github.com/helidon-io/helidon/blob/main/LICENSE.txt)).
Ensō implements it from scratch; no code was copied.

## License

Copyright © 2026 Max Penet.

Distributed under the [Mozilla Public License 2.0](LICENSE)
([FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)).

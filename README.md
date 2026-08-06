# Enso

Zero-dependency, Ring-compliant HTTP/1.1 server for Clojure. Blocking I/O on virtual threads. Java core, Clojure adapter.

Licensed under [MPL 2.0](LICENSE).

## Requirements

- JDK 25+ (virtual threads, `SocketChannel` sendfile)
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

## Build

```
clojure -T:build javac
clojure -X:test
```

Java sources compile to `target/classes`. `deps.edn` includes it on the classpath.

## Performance

Loopback bench on an M-series laptop, JDK 25, wrk against a plain 404 responder. Enso and http-kit boot in the same JVM, sharing cores.

### Throughput

| Workload | Enso | http-kit | Ratio |
|---|---|---|---|
| `-t4 -c64 -d8s` (non-pipelined) | 128.7k rps | 122.3k rps | **1.05x** |
| pipelined depth 16 | 1.90M rps | 519k rps | **3.66x** |
| pipelined depth 64 | 5.23M rps | 547k rps | **9.56x** |


### Allocation

Sampled via `clj-async-profiler` `:event :alloc` at default rate (~1 MB TLAB fill per sample). Lower is better.

| Workload | Enso samples/req | http-kit samples/req | Ratio |
|---|---|---|---|
| non-pipelined | 0.014 | 0.090 | **6.4x less** |
| pipelined d=64 | 0.010 | 0.089 | **8.9x less** |

### Caveats

- Loopback synthetic ceiling: no client-side network cost, no routing / JSON / DB work.
- Both servers share cores with wrk on the same machine — perf headroom exists on real deployments.
- macOS TCP loopback is slower than Linux; Linux numbers likely 2-3x higher on the same hardware.
- Benchmarks against Jetty, Aleph, Helidon pending.

Reproduce with `clojure -M:bench` (starts nREPL), then in the REPL:

```clojure
(require 'enso.bench)
(enso.bench/start!)
(enso.bench/compare! {:duration "8s" :depth 64})
(enso.bench/profile-alloc! "http://127.0.0.1:8080/nope" {:duration "10s" :depth 64})
```

## HTTP/2 + HTTP/3

Enso speaks HTTP/1.1 only, by design. For HTTP/2 or HTTP/3, terminate at a reverse proxy and forward to Enso over HTTP/1.1. The proxy handles ALPN, HPACK/QPACK, streams, flow control, and QUIC — Enso stays a tight sync-Ring core.

### Caddy

```caddy
example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Auto-provisions certs, enables HTTP/2 and HTTP/3 out of the box, keep-alive to the origin.

### nginx

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 443 quic reuseport;   # HTTP/3
    listen [::]:443 quic reuseport;

    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    add_header Alt-Svc 'h3=":443"; ma=86400';

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik

```yaml
http:
  routers:
    enso:
      rule: "Host(`example.com`)"
      service: enso
      tls:
        certResolver: letsencrypt
  services:
    enso:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

Traefik enables HTTP/2 and HTTP/3 (`--experimental.http3=true`) transparently; the origin still sees HTTP/1.1.

## Status

HTTP/1.1 + keep-alive + chunked transfer + TLS + WebSocket + SSE. No HTTP/2, no HTTP/3 — terminate at a proxy (see above). No compression. No async Ring arity (sync handler only — virtual threads make it moot).

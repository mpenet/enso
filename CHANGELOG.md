# Changelog

## Unreleased

Changes since 1.0.0-alpha56. This release reworks the server core: one
request / response policy shared by HTTP/1.1, HTTP/2 and HTTP/3, one
timeout model, a validated option table, much fuller WebSocket support,
cleartext HTTP/2, Ring async handlers, observability hooks and broad
hardening. Many options were renamed; read the breaking changes first.

### Breaking changes

#### Options

- **Options are validated.** An unknown key throws `ex-info` with a "did
  you mean" suggestion; a wrong type or invalid value throws `ex-info`
  whose `ex-data` holds `:type`, `:option` and `:value`. Unknown keys used
  to be ignored and invalid values threw `IllegalArgumentException`: code
  catching that from `run-server` must catch `ExceptionInfo`. A nil value
  means the default.
- **Naming scheme:** durations end in `-timeout` and are milliseconds,
  sizes end in `-bytes`, TLS options start with `:ssl-`. Renames are listed
  in the table below.
- **Timeout model:** `:handshake-timeout`, `:header-timeout`,
  `:read-timeout`, `:write-timeout`, `:idle-timeout`, `:handler-timeout`,
  each with one meaning on every protocol
  ([doc/options.md](doc/options.md#timeouts)).
  - `:request-timeout` is removed. On HTTP/1.1 it bounded reading the
    whole request: that is now `:header-timeout` (10 s, the head, wall
    clock from its first byte) plus `:read-timeout` (30 s without body
    progress). On HTTP/2 and HTTP/3 it bounded the handler and answered
    408: handlers now run unbounded by default, and `:handler-timeout`
    (default 0 = off) answers **503**.
  - `:idle-timeout` changes meaning and default: it was a per-read socket
    timeout (30 s); it is now how long a connection may sit with no
    request in progress (75 s): HTTP/1.1 between requests, HTTP/2 and
    HTTP/3 with no open stream, a WebSocket with no frame from the client.
  - `:keep-alive-timeout` is removed (folded into `:idle-timeout`).
  - `:http3-max-idle-timeout` is removed: QUIC's `max_idle_timeout` is
    `:idle-timeout`, so its default goes from 30 s to 75 s.
- **One request-head limit on every protocol:** `:http2-max-header-list-size`
  (8192) and `:http3-max-field-section-size` are removed;
  `:max-header-bytes` (65536) applies to HTTP/2 and HTTP/3 too (431 per
  request; the connection ends only above 4× that, at least 64 KiB).
- **Removed without replacement:** `:request-buffer-size`,
  `:max-inline-body`, `:coalesce-high-water`, `:chunk-buffer-size`,
  `:max-drain-bytes` (HTTP/1.1 buffer tuning), `:http3-qpack-max-table-capacity`,
  `:http3-qpack-blocked-streams` (QPACK uses the static table only),
  `:worker-executor` (handlers always run on virtual threads).
- **Changed defaults and rules:**
  - `:http3-initial-max-data-bytes`: 1 GiB → 4 MiB, now a hard bound that
    also caps the request-body bytes buffered per connection.
  - `:http2-initial-window-bytes` must be at least 65535.
  - `:max-request-body-bytes` no longer applies to WebSocket frames; use
    `:ws-max-message-bytes`.
  - `:ssl-alpn-protocols` defaults to `["http/1.1"]` without `:http2`
    (it was the JVM default).
- **Checked at startup:** `:ssl-alpn-protocols`, `:ssl-cipher-suites`,
  `:ssl-protocols` and client auth need TLS, and offering "h2" needs
  `:http2`; `:http3-port` and `:advertise-alt-svc true` need `:http3`;
  `:http3` with `:port 0` needs `:http3-port` (or `:advertise-alt-svc
  false`); `:server-header` must be a valid field value; `:http2` needs
  TLS (cleartext HTTP/2 is `:http2c`).

| alpha56 option | now |
|---|---|
| `:idle-timeout` (30000, per read) | `:idle-timeout` (75000, connection idle); per-read bounds are `:read-timeout` / `:write-timeout` |
| `:request-timeout` | removed: `:header-timeout` + `:read-timeout` (HTTP/1.1), `:handler-timeout` (HTTP/2, HTTP/3; 503, off by default) |
| `:keep-alive-timeout` | removed (`:idle-timeout`) |
| `:so-rcv-buf` | `:so-rcv-buf-bytes` |
| `:so-snd-buf` | `:so-snd-buf-bytes` |
| `:alpn-protocols` | `:ssl-alpn-protocols` |
| `:enabled-cipher-suites` | `:ssl-cipher-suites` |
| `:enabled-tls-protocols` | `:ssl-protocols` |
| `:http2-initial-window-size` | `:http2-initial-window-bytes` |
| `:http2-max-frame-size` | `:http2-max-frame-bytes` |
| `:http2-max-header-list-size` | removed (`:max-header-bytes`) |
| `:http3-max-idle-timeout` | removed (`:idle-timeout`) |
| `:http3-initial-max-data` (1 GiB) | `:http3-initial-max-data-bytes` (4 MiB) |
| `:http3-max-udp-payload-size` | `:http3-max-udp-payload-bytes` |
| `:http3-initial-max-stream-data-bidi-local` | `:http3-initial-max-stream-data-bidi-local-bytes` |
| `:http3-initial-max-stream-data-bidi-remote` | `:http3-initial-max-stream-data-bidi-remote-bytes` |
| `:http3-initial-max-stream-data-uni` | `:http3-initial-max-stream-data-uni-bytes` |
| `:http3-max-field-section-size` | removed (`:max-header-bytes`) |
| `:http3-qpack-max-table-capacity` | removed |
| `:http3-qpack-blocked-streams` | removed |
| `:request-buffer-size`, `:max-inline-body`, `:coalesce-high-water`, `:chunk-buffer-size`, `:max-drain-bytes` | removed |
| `:worker-executor` | removed |

Unchanged: `:port` `:host` `:backlog` `:shutdown-timeout`
`:max-header-bytes` `:max-request-body-bytes` `:max-keep-alive-requests`
`:so-nodelay` `:so-reuse-addr` `:so-linger` `:ssl-context`
`:ssl-context-provider` `:ssl-need-client-auth` `:ssl-want-client-auth`
`:ssl-session-cache-size` `:http2` `:http2-max-concurrent-streams`
`:http2-stream-reset-limit` `:http2-continuation-limit` `:http3`
`:http3-port` `:http3-cert-path` `:http3-key-path`
`:http3-initial-max-streams-bidi` `:http3-initial-max-streams-uni`
`:http3-stateless-retry` `:http3-ack-delay-exponent` `:http3-max-ack-delay`
`:http3-active-connection-id-limit` `:advertise-alt-svc` `:alt-svc-max-age`
`:server-header` `:error-handler`.

#### Java API

- `WebSocketListener` and `WebSocketSocket` moved from
  `com.s_exp.enso.websocket` to `com.s_exp.enso.api`. `WebSocketSocket`
  gained `sendTextAsync`, `sendBinaryAsync` and `SendCallback`; new
  `api.WebSocketException` (with `code()`).
- The supported API is the `s-exp.enso` namespace, `EnsoServer` and the
  `com.s_exp.enso.api` package; every other package is internal.
- `Config.Builder` setters follow the option names (`soRcvBuf` →
  `soRcvBufBytes`, `alpnProtocols` → `sslAlpnProtocols`,
  `http2InitialWindowSize` → `http2InitialWindowBytes`,
  `http3InitialMaxData` → `http3InitialMaxDataBytes`, ...); setters of
  removed options are gone. `build()` throws `Config.InvalidOptionException`
  (an `IllegalArgumentException` with `option()` and `value()`).
- `EnsoServer`: constructors no longer throw `IOException`, `start()`
  does; `register` / `unregister` are removed.
- `ChunkedWriter`: `write` declares `IOException` (it may flush);
  `closeInternal()` is removed; `charset(Charset)` and `bytesWritten()`
  are added.

#### Request map

- `:body` is nil when the request has no body, on every protocol (HTTP/2
  and HTTP/3 always passed an `InputStream`).
- `:scheme` is `:https` on TLS connections (it was always `:http`).
- `:server-name` without a Host header is the local address (it was
  "localhost").
- `:remote-addr` writes IPv6 in the RFC 5952 short form.

#### Responses (all protocols; a violation is a 500 or `:error-handler`)

- `:status` must be an integer in 200-599 (101 only for a WebSocket
  upgrade); a present but nil or non-integer `:status` is a handler error.
  A missing `:status` still means 200.
- Header names must be RFC 9110 tokens; values may not contain control
  characters (HTAB allowed) or characters above U+00FF. alpha56 rejected
  only CR, LF and NUL.
- A handler `Transfer-Encoding` is dropped (the server frames the body);
  a handler `Content-Length` is dropped when the server knows the length;
  two different `Content-Length` values are an error.
- String bodies are encoded with the `Content-Type` charset (UTF-8 when
  none); an unknown charset is a 500. alpha56 always used UTF-8.

### New options

- `:max-connections` (10000), `:max-connections-per-ip` (0): connection
  caps, TCP and QUIC together.
- `:handshake-timeout` (10000), `:header-timeout` (10000), `:read-timeout`
  (30000), `:write-timeout` (30000), `:handler-timeout` (0).
- `:max-header-fields` (100): request header fields per head, 431 above.
- `:max-buffered-bytes` (0 = a quarter of the heap): server-wide budget for
  bytes buffered on behalf of peers, enforced by backpressure.
- `:http2c` (false): cleartext HTTP/2 with prior knowledge next to
  HTTP/1.1.
- `:http3-cert-reload-interval` (10000): HTTP/3 certificate rotation.
- `:http3-retry-threshold` (256), `:http3-max-half-open` (1024),
  `:http3-stream-reset-limit` (400): HTTP/3 flood protection.
- `:http3-event-loops` (0 = one per core on Linux, one elsewhere),
  `:http3-so-rcv-buf-bytes` / `:http3-so-snd-buf-bytes` (4194304).
- `:ws-max-message-bytes` (1048576), `:ws-max-queued-bytes` (1048576),
  `:ws-close-timeout` (5000), `:ws-compression` (false),
  `:ws-ping-interval` (0), `:ws-allowed-origins` (same origin).
- `:async` (false): Ring asynchronous handlers.
- `:server-events` (nil): connection, request and protocol-error
  callbacks.

### Features and behaviour changes

- **Ring async handlers** with `:async true`; `raise` goes to
  `:error-handler`, `:handler-timeout` applies.
- **Cleartext HTTP/2** (`:http2c`) with prior knowledge on the plain
  listener, next to HTTP/1.1; no `Upgrade: h2c`. Reported as protocol
  "h2c".
- **HTTP/3 certificate rotation:** changed PEM files are loaded for new
  connections without a restart.
- **HTTP/3 on several cores:** connections are sharded over event loops
  (Linux `SO_REUSEPORT` with BPF steering); a failed loop is restarted.
- **`:error-handler` on HTTP/2 and HTTP/3** (it was HTTP/1.1 only).
- **`Expect: 100-continue` on every protocol**, answered on the handler's
  first body read; any other expectation gets 417 without the handler.
- **The same limits on every protocol:** 413 for a declared body over
  `:max-request-body-bytes` without running the handler, 431 for heads
  over `:max-header-bytes` / `:max-header-fields`.
- **The same error responses on every protocol:** 400, 408, 413, 417, 431,
  500, 501 and 503 decided by the server carry a `text/plain;
  charset=utf-8` reason phrase.
- **Request-body errors are the client's:** a broken, oversized or stalled
  body is answered 400 / 413 / 408 whatever the handler does with the
  exception, and `:error-handler` isn't called.
- **Header values:** nil values are skipped; a seq sends one field per
  non-nil element.
- **`write!` and seq bodies** encode Strings with the response charset.
- **Lingering close** on HTTP/1.1, HTTP/2 and WebSocket: output is shut
  down and input read for up to 2 s, so clients read the last response
  instead of a TCP reset.
- **Graceful shutdown:** `:shutdown-timeout` is one deadline for the
  whole server; HTTP/2 and HTTP/3 drain in two GOAWAYs; streams in flight
  when a peer sends GOAWAY finish.
- **WebSocket:** `ring.websocket.protocols` support (`Listener`,
  `PingListener`, `Socket`, `AsyncSocket`); asynchronous sends with
  back-pressure; permessage-deflate; server pings; idle close with 1001;
  CLOSE 1001 on server stop; a listener exception closes with 1011 and its
  message stays on the server; handler `:headers` are sent on the 101; a
  WebSocket response on HTTP/2 or HTTP/3 is answered 501.
- **Observability:** `api.ServerEvents` (`connectionOpened`,
  `connectionClosed`, `requestCompleted`, `protocolError`) for HTTP/1.1,
  h2, h2c, h3, WebSocket, TCP and TLS; JFR events
  `com.s_exp.enso.Connection`, `Request` and `ProtocolError` on every
  protocol.
- **Logging:** client-caused failures at FINE; server faults at WARNING,
  rate-limited to one record per second per call site.
- **Options taking a function accept a var** (`#'handler`).
- **Stricter request parsing:** Content-Length must be digits and appear
  once (even with equal values); an HTTP/1.1 request without Host is 400;
  the request target and Host authority are validated; HTTP/2 and HTTP/3
  heads follow the same rules; a well-formed CONNECT gets 501.

### Security fixes

- HTTP/1.1: a chunk size overflowing a long is rejected; control
  characters in chunk extensions are rejected and chunk-size lines are
  capped; the trailer size cap holds after the buffer compacts and trailer
  lines are validated; building the header map stays linear with many
  distinct names.
- HTTP/2: closed-stream bookkeeping is bounded with constant-time lookup;
  the reset limit (CVE-2023-44487) is a rate refilling every 30 s and
  counts reset streams while their handler runs; resets caused by peer
  frames share that budget (CVE-2025-8671); header blocks hit a hard
  ceiling before buffering; HPACK integer overflow is rejected; empty DATA
  floods and control-frame floods from a peer that doesn't read are cut
  off; a shut flow-control window is bounded by `:write-timeout`; padding
  is credited on a length mismatch; HEADERS on a forgotten stream id is a
  connection error; trailers are validated; repeated SETTINGS are applied
  in one pass; request and response buffers count against
  `:max-buffered-bytes`.
- HTTP/3 / QUIC: Retry tokens are bound to the address family and the
  Retry connection id; Retry is required automatically past
  `:http3-retry-threshold` and half-open connections are capped; Initials
  with a destination connection id under 8 bytes are dropped; rapid-reset
  protection; unread request bodies are bounded per connection;
  control-stream rules (CANCEL_PUSH, MAX_PUSH_ID, SETTINGS first, critical
  streams) are enforced; QPACK checks Huffman lengths before allocating,
  caps decoded sections and rejects overlong integers; partial header
  sections share a per-connection budget and a timeout; QUIC connections
  count against `:max-connections`; the JNI shim bounds-checks its
  arguments and connection teardown is idempotent.
- WebSocket: same-origin check by default (cross-site WebSocket
  hijacking); pongs to a ping flood are coalesced; a claimed frame length
  isn't allocated up front; deflate bombs are bounded; a message must
  complete within `:read-timeout`.
- Core / TLS: global and per-address connection limits; a write watchdog
  for peers that stop reading; a TLS handshake timeout; TLS 1.2 client
  renegotiation is refused; a TLS read timeout no longer replays
  plaintext.
- Native loader: the development library probe only looks next to a
  classes directory, never relative to the working directory; on musl the
  glibc shim is never tried; the Java side checks the shim's ABI version.

### Performance

Current numbers from the separate-process harness (`clojure -M:perf`,
Apple M-series laptop, 8 CPUs, JDK 25; [doc/performance.md](doc/performance.md#current-numbers)):

| scenario | req/s | allocated per request (whole server JVM) |
|---|---:|---:|
| HTTP/1.1 GET, 64 connections | 102,903 | 393 B |
| HTTP/1.1 pipelined, depth 16 | 1,147,825 | 235 B |
| HTTP/2 GET over TLS (h2load `-c 8 -m 32`) | 644,036 | 1,125 B |
| HTTP/3 GET, 4 connections × 32 in flight | 69,786 | 799 B |
| WebSocket echo, 128-byte messages | 423,076 | 334 B |

Measured during this rework, each against the code before the change
([doc/architecture.md](doc/architecture.md#allocation-budget)):

- HTTP/1.1 GET: 497 → 392 bytes per request, pipelined 339 → 235, at the
  same throughput; over TLS 1.3 3510 → 3280 bytes per request.
- Heap per idle HTTP/1.1 keep-alive connection: 32.4 → 9.7 KiB plain,
  98.6 → 16.1 KiB over TLS 1.3. Every protocol gives back grown buffers
  after a second idle (idle HTTP/2: about 11 KB cleartext, 23 KB over TLS;
  WebSocket 16 / 25 KiB; HTTP/3 about 3 KB).
- HTTP/2 GET on the in-process test path: about 760 bytes per request,
  from 3108.

### Build and distribution

- Artifacts: the core jar and five classifier jars (`darwin-arm64`,
  `linux-amd64`, `linux-arm64`, `linux-musl-amd64`, `linux-musl-arm64`)
  on Clojars; the all-platform jar is a release-run artifact only.
- Linux glibc shims are built on AlmaLinux 8 (glibc 2.28 or later); the
  macOS shim needs macOS 11 or later. libquiche 0.29.3, its crate lockfile
  and the Rust toolchain are pinned.
- Every release shim is checked (exported symbols, RELRO / BIND_NOW /
  non-executable stack, glibc symbol ceiling, macOS minimum, a JVM load
  test) and built with hardening flags.
- Jars carry `Automatic-Module-Name: com.s_exp.enso`, LICENSE, NOTICE and
  THIRD-PARTY-NOTICES.
- JDK 21+ for every protocol, tested on JDK 21 and 25. On JDK 24+ add
  `--enable-native-access=ALL-UNNAMED` for HTTP/3.
- The shim extraction directory can be set with `enso.quiche.tmpdir` /
  `ENSO_QUICHE_TMPDIR` (for `noexec` temp directories).
- Releases are gated on the full test workflow: every namespace on JDK 21
  and 25, HTTP/3 under ASan/UBSan, h2spec (TLS and h2c), h3spec and
  Autobahn. A nightly job runs the soak test, deep property tests, Jazzer
  fuzzing (HPACK, QPACK, HTTP/1.1, WebSocket frames) and the
  allocation-per-request gate.

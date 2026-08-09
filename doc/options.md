# Configuration options

All options passed as a map to `s-exp.enso/run-server`. Grouped by concern; defaults in parens.

## Network

- `:port` (8080) — listen port. 0 = ephemeral.
- `:host` ("0.0.0.0") — bind address.
- `:backlog` (1024) — accept queue length.

## Timeouts

- `:idle-timeout` (30000) — per-read socket timeout in ms. 0 disables.
- `:request-timeout` (30000) — wall-clock deadline for reading a full request. Slowloris protection.
- `:shutdown-timeout` (10000) — graceful drain of in-flight requests during `stop`.

## HTTP/1.1 keep-alive

- `:max-keep-alive-requests` (1000) — cap on requests per connection. 0 = unlimited.
- `:keep-alive-timeout` (0) — between-request idle timeout in ms. 0 falls back to `:idle-timeout`. Distinct from mid-request idle.

## TCP socket options

Applied to acceptor + accepted sockets.

- `:so-nodelay` (true) — TCP_NODELAY.
- `:so-reuse-addr` (true) — SO_REUSEADDR.
- `:so-linger` (-1) — SO_LINGER seconds. -1 disables.
- `:so-rcv-buf` (0) — SO_RCVBUF. 0 = OS default.
- `:so-snd-buf` (0) — SO_SNDBUF. 0 = OS default.

## TLS

- `:ssl-context` — `javax.net.ssl.SSLContext`. When set, listens over TLS.
- `:ssl-need-client-auth` (false) — require valid client cert.
- `:ssl-want-client-auth` (false) — request but don't require client cert.
- `:alpn-protocols` — seq of ALPN protocol IDs. Defaults to `["h2" "http/1.1"]` when `:http2`, else JVM default.
- `:enabled-cipher-suites` — seq of cipher suite names. Nil = JVM default.
- `:enabled-tls-protocols` — seq of TLS protocol versions. Nil = JVM default.
- `:ssl-session-cache-size` (0) — 0 = JVM default.

## HTTP/2

Requires `:ssl-context`. Cleartext h2c not supported.

- `:http2` (false) — enables ALPN "h2" advertisement.
- `:http2-max-concurrent-streams` (100).
- `:http2-initial-window-size` (1 MiB) — spec default 64 KiB starves throughput on non-LAN paths.
- `:http2-max-frame-size` (16384) — spec min. Raise for fewer send syscalls on large bodies.
- `:http2-max-header-list-size` (8192) — bytes. Peer over the limit gets `GOAWAY(ENHANCE_YOUR_CALM)`. 0 disables.
- `:http2-stream-reset-limit` (400) — RST_STREAM cap per connection. CVE-2023-44487 mitigation (matches Nginx). 0 disables.
- `:http2-continuation-limit` (64) — CONTINUATION frames per HEADERS.
- `:http2-ping-interval` (0) — server-initiated PING interval in ms. 0 disables.
- `:http2-ping-timeout` (10000) — PING timeout in ms.
- `:http2-enable-push` (false) — advertise SETTINGS_ENABLE_PUSH. We never push.

## HTTP/3

Requires PEM cert + key. Uses its own UDP socket; co-exists with h1/h2 on the same TCP port.

- `:http3` (false) — enables HTTP/3 listener. Advertised via `Alt-Svc` on h1/h2 responses when both enabled.
- `:http3-port` — UDP port. Defaults to `:port`.
- `:http3-cert-path`, `:http3-key-path` — PEM cert chain + private key. **Required.**
- `:http3-max-idle-timeout-ms` (30000) — quiche idle timeout.
- `:http3-max-udp-payload-size` (1350) — MTU-safe.
- `:http3-initial-max-data` (10 MiB) — connection flow control window.
- `:http3-initial-max-streams-bidi` (100) — concurrent request streams per connection.
- `:http3-initial-max-streams-uni` (8) — peer unidirectional stream credit. Min 3 (control + qpack enc/dec).
- `:http3-stateless-retry` (false) — force clients to prove reachability before allocating conn state (RFC 9000 §8.1.2). Enable under DDoS.
- `:http3-max-field-section-size` (64 KiB) — SETTINGS_MAX_FIELD_SECTION_SIZE. Inbound cap advertised to peer. 0 = no limit.
- `:http3-qpack-max-table-capacity` (0) — SETTINGS_QPACK_MAX_TABLE_CAPACITY. 0 = static-table only.
- `:http3-qpack-blocked-streams` (0) — SETTINGS_QPACK_BLOCKED_STREAMS.
- `:http3-initial-max-stream-data-bidi-local` (-1) — per-stream flow window. -1 = derive from `:http3-initial-max-data` / stream count.
- `:http3-initial-max-stream-data-bidi-remote` (-1) — same, remote side.
- `:http3-initial-max-stream-data-uni` (-1) — same, uni streams.
- `:http3-ack-delay-exponent` (-1) — RFC 9000 ack_delay_exponent, [0, 20]. -1 = quiche default.
- `:http3-max-ack-delay` (-1) — RFC 9000 max_ack_delay ms, [0, 16383]. -1 = quiche default.
- `:http3-active-connection-id-limit` (-1) — RFC 9000 active_connection_id_limit, ≥ 2. -1 = quiche default.

### Alt-Svc

- `:advertise-alt-svc` — override auto-behavior. Auto = true iff `:http3` enabled.
- `:alt-svc-max-age` (86400) — `ma=` field in the emitted `Alt-Svc` header (seconds).

## Handler

- `:error-handler` — `(fn [request throwable])` returning a Ring response. Runs when the main handler throws or returns nil.

## Server-wide

- `:server-header` — value emitted as `Server:` response header. Nil/empty omits. Handler-supplied `Server` header wins.
- `:worker-executor` — `java.util.concurrent.Executor` for request-handler tasks. Nil = built-in virtual-thread-per-task. Server does not `shutdown()` a user-supplied executor.

## Limits

Tune only with a specific reason.

- `:request-buffer-size` (16384) — initial request parse buffer.
- `:max-header-bytes` (65536) — 431 above.
- `:max-request-body-bytes` (10 MiB) — 413 above. 0 disables. Also caps WebSocket frame size.
- `:max-inline-body` (16384) — response bodies ≤ this size inline into header write for one-syscall dispatch.
- `:coalesce-high-water` (32768) — pipelined batch flush trigger.
- `:chunk-buffer-size` (8192) — chunked streaming read chunk.
- `:max-drain-bytes` (65536) — ignored-body drain limit before conn close.

### Interaction notes

- `:request-buffer-size ≤ :max-header-bytes` — otherwise initial buffer caps at `:max-header-bytes` and pipelined batches larger than that get fragmented reads.
- `:max-inline-body ≤ :coalesce-high-water` — otherwise a single large response triggers a flush before the next pipelined request can coalesce.
- `:request-timeout` interacts with `:idle-timeout`: per-read timeout is `min(idle, remaining-request-budget)`.

## Logging

Errors route through `java.util.logging` under loggers `com.s_exp.enso.http1.HttpConnection`, `com.s_exp.enso.EnsoServer`, `com.s_exp.enso.http2.Http2Connection`, `com.s_exp.enso.http3.*`. Wire an SLF4J bridge in your app to redirect.

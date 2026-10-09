# Configuration options

All options are passed as a map to `s-exp.enso/run-server`; defaults in
parentheses. The option table in `s-exp.enso` is the source of truth: it
validates every key (unknown keys throw `ex-info` with a "did you mean"
suggestion, wrong types and invalid values throw `ex-info` naming the
option, its `ex-data` holding `:option` and `:value`), builds the
`com.s_exp.enso.api.Config`, and renders the `run-server` docstring. A
test keeps this page in sync with it. Options taking a function also take
a var (`#'my-error-handler`), so a redefinition applies without a restart.

Naming: durations end in `-timeout` and are milliseconds (0 disables);
sizes end in `-bytes`; TLS options start with `:ssl-`. Socket and protocol
parameters that have a unit of their own keep it (`:so-linger` seconds,
`:alt-svc-max-age` seconds, `:http3-max-ack-delay` milliseconds).

## Network

- `:port` (8080) — listen port. 0 picks an ephemeral port (TCP only, see `:http3-port`).
- `:host` ("0.0.0.0") — bind address.
- `:backlog` (1024) — accept queue length.
- `:max-connections` (10000) — open connections server-wide, TCP and QUIC together, 0 = unlimited. Over the limit a TCP connection is closed right after accept, before it gets a thread or a TLS handshake, and a QUIC Initial is dropped.
- `:max-connections-per-ip` (0) — open connections per client address, 0 = unlimited. Leave it off behind a load balancer or NAT, where many clients share one address.

## Timeouts

One meaning per timeout, on every protocol:

| Option | Bounds | Kind |
|---|---|---|
| `:handshake-timeout` | TLS handshake; HTTP/2 preface + first SETTINGS; QUIC handshake | wall clock from accept |
| `:header-timeout` | a complete request head (HTTP/1.1 request line + headers; HTTP/2 / HTTP/3 header block) | wall clock from its first byte |
| `:read-timeout` | request body; a WebSocket message | longest wait without read progress; a WebSocket message's first to last frame, wall clock |
| `:write-timeout` | any response or frame write | longest wait without write progress |
| `:idle-timeout` | no request in progress | since the last activity |
| `:handler-timeout` | the Ring handler | wall clock, opt-in |

Where each one is enforced:

| Option | HTTP/1.1 | WebSocket | HTTP/2 | HTTP/3 |
|---|---|---|---|---|
| `:handshake-timeout` | TLS | (TLS) | TLS (h2) + preface + first SETTINGS | QUIC handshake |
| `:header-timeout` | yes | — | yes (header block over CONTINUATION) | yes (request HEADERS) |
| `:read-timeout` | yes | yes (message deadline) | yes | yes |
| `:write-timeout` | yes | yes | yes (socket writes, flow-control stalls) | yes (stalled response producers; QUIC loss recovery underneath) |
| `:idle-timeout` | yes | yes | yes | yes (max_idle_timeout) |
| `:handler-timeout` | yes | — | yes | yes |

- `:handshake-timeout` (10000) — ms to complete the TLS handshake (plus the HTTP/2 preface and first SETTINGS, or the QUIC handshake). The connection is closed.
- `:header-timeout` (10000) — ms to receive a complete request head, from its first byte. Slowloris protection; answered with 408.
- `:read-timeout` (30000) — longest ms without progress while reading a request body. The read fails (a handler that doesn't catch it yields 408) and the connection is not reused. Also bounds head reads when `:header-timeout` is 0. On a WebSocket it is a deadline: a message must arrive whole within it, wall clock from its first frame, so a client trickling bytes can't hold a message buffer (CLOSE 1008 "message timeout").
- `:write-timeout` (30000) — longest ms without write progress: a peer that stopped reading. The connection is force-closed (TLS without close_notify). Progress is measured per 256 KiB slice. On HTTP/2 it also bounds a peer that keeps its flow-control window shut: a stream that can't send for this long is reset with CANCEL, a connection window shut this long ends the connection with GOAWAY(ENHANCE_YOUR_CALM).
- `:idle-timeout` (75000) — ms a connection may sit with no request in progress: HTTP/1.1 between requests and before the first one, HTTP/2 and HTTP/3 with no open stream (GOAWAY, or QUIC's idle timeout), a WebSocket with no frame from the client (closing handshake with 1001 "idle timeout").
- `:handler-timeout` (0) — ms a handler may run, 0 = off. On expiry the client gets 503 (nothing of the response was sent yet), the handler thread is interrupted and, on HTTP/1.1, the connection closes. Streaming bodies are not covered: once the handler returned, `:write-timeout` applies.
- `:shutdown-timeout` (10000) — ms `stop` waits for in-flight requests across all connections (one deadline for the whole server) before force-closing what is left.

Why these defaults:

- Handshake 10 s: Netty's SslHandler default; a real handshake takes a few RTTs, anything slower is an attack or a dead peer (nginx allows 60 s, Go none unless ReadHeaderTimeout is set).
- Header 10 s: request heads fit in one or two packets. Tighter than nginx's 60 s `client_header_timeout`, in line with Go's commonly recommended `ReadHeaderTimeout` of a few seconds and Apache mod_reqtimeout's 20 s first bound.
- Read and write 30 s of no progress: Jetty's idle timeout; half of nginx's `client_body_timeout` / `send_timeout`, both "between two operations" like ours.
- Idle 75 s: nginx's `keepalive_timeout`. Longer than the 60 s idle timeout of common load balancers (AWS ALB), so the server is never the side that closes a connection the balancer is about to reuse.
- Handler off: a handler's duration is application policy (Go's `TimeoutHandler` and Jetty's request timeout are opt-in too).

## Limits

- `:max-header-bytes` (65536) — request head size cap on every protocol, 431 above: the HTTP/1.1 head (and chunked trailers), the decoded HTTP/2 header list (advertised as SETTINGS_MAX_HEADER_LIST_SIZE) and the decoded HTTP/3 field section (SETTINGS_MAX_FIELD_SECTION_SIZE). Over a hard ceiling of 4× this (at least 64 KiB) an HTTP/2 connection ends with GOAWAY(ENHANCE_YOUR_CALM) and an HTTP/3 stream is reset with H3_EXCESSIVE_LOAD (the section is never buffered).
- `:max-header-fields` (100) — request header fields per head on every protocol, 431 above (the default of Apache's LimitRequestFields and Tomcat's maxHeaderCount).
- `:max-request-body-bytes` (10485760) — request body cap on every protocol, 0 = none. A larger Content-Length gets 413 without running the handler; a body without one fails mid-stream. WebSocket messages have their own cap, `:ws-max-message-bytes`.
- `:max-keep-alive-requests` (1000) — requests per HTTP/1.1 connection, 0 = unlimited (nginx's default). The last response carries `Connection: close`.
- `:max-buffered-bytes` (0) — bytes the server buffers for peers, server-wide: unread request bodies (HTTP/2, HTTP/3), streamed HTTP/2 response bytes waiting for the peer, queued WebSocket asynchronous sends, and incoming WebSocket messages past their first 64 KiB while they are assembled (until the listener's `on-message` returns). 0 = a quarter of the maximum heap (`-Xmx`): these buffers are transient, the rest of the heap stays for handlers. Past it the server pushes back rather than failing: HTTP/2 grants no more flow-control credit (stream and connection windows) and lets a streamed response hold one frame before its producer waits, HTTP/3 stops reading request streams until handlers read what is buffered, and a WebSocket stops reading a large message (TCP pushes back on the client) until there is room again, within the message's `:read-timeout` (else CLOSE 1008); a WebSocket asynchronous send fails at once (its fail callback runs). The limit is approximate by the flow-control credit already granted when it fills (64 KiB per WebSocket reading a message).

`:max-connections` 10000: each connection costs a virtual thread and a few
tens of KiB of buffers while it is busy (more with TLS), so the cap bounds
memory under a connection flood at a few hundred MiB. Both caps count every
connection the server holds: TCP (HTTP/1.1, WebSocket, HTTP/2) and QUIC
(HTTP/3, from admission until its last handler returns).

## TCP

- `:so-nodelay` (true) — TCP_NODELAY on accepted sockets, plain and TLS.
- `:so-reuse-addr` (true) — SO_REUSEADDR on the listening socket.
- `:so-linger` (-1) — SO_LINGER on accepted sockets in seconds (the socket option's unit), -1 = off.
- `:so-rcv-buf-bytes` (0) — SO_RCVBUF, set on the listening socket before bind so accepted sockets inherit it (and TCP window scaling can use it). 0 = OS default.
- `:so-snd-buf-bytes` (0) — SO_SNDBUF on accepted sockets. 0 = OS default.

## TLS

Every TLS connection, HTTP/1.1 or HTTP/2, goes through an `SSLEngine` over
the accepted `SocketChannel`; the handshake and ALPN run on the
connection's virtual thread under `:handshake-timeout`.

- `:ssl-context` (none) — `javax.net.ssl.SSLContext`. When set, the TCP listener speaks TLS. File bodies then go through user space (zero-copy `sendfile` needs plain HTTP).
- `:ssl-context-provider` (none) — fn (or `java.util.function.Supplier`) returning an `SSLContext`, called at startup and for every accepted connection (on its virtual thread, before the handshake), so rotated certificates apply to new connections without a restart. Return a cached context and replace it when the certificates change: a context built per call costs its construction on every connection and loses TLS session resumption. A nil return closes that connection. Exclusive with `:ssl-context`.
- `:ssl-need-client-auth` (false) — require a valid client certificate.
- `:ssl-want-client-auth` (false) — request a client certificate without requiring one. Exclusive with `:ssl-need-client-auth`.
- `:ssl-alpn-protocols` (none) — ALPN protocol ids offered. Default `["h2" "http/1.1"]` with `:http2`, else `["http/1.1"]`. Offering "h2" needs `:http2`.
- `:ssl-cipher-suites` (none) — enabled cipher suites, nil = JVM default.
- `:ssl-protocols` (none) — enabled TLS protocol versions, nil = JVM default.
- `:ssl-session-cache-size` (0) — server TLS session cache entries, set on every context the server uses (provider contexts included). 0 = JVM default.

The `:ssl-alpn-protocols`, `:ssl-cipher-suites`, `:ssl-protocols` and
client-auth options need `:ssl-context` or `:ssl-context-provider`.

## HTTP/2

Over TLS + ALPN (`:http2`) or cleartext with prior knowledge (`:http2c`); the settings below apply to both.

- `:http2` (false) — serve "h2" over TLS. Needs `:ssl-context` (or `:ssl-context-provider`).
- `:http2c` (false) — cleartext HTTP/2 with prior knowledge on a plain listener, next to HTTP/1.1 (a connection opening with the HTTP/2 preface is HTTP/2). No `Upgrade: h2c` (deprecated by RFC 9113). Not with `:ssl-context` or `:ssl-context-provider`.
- `:http2-max-concurrent-streams` (100) — SETTINGS_MAX_CONCURRENT_STREAMS.
- `:http2-initial-window-bytes` (1048576) — per-stream receive window, [65535, 2^31-1]; the spec's 64 KiB default starves throughput beyond a LAN. The connection window is 4× this, so one handler that doesn't read its body can't stall uploads on the others. Credit returns as handlers read.
- `:http2-max-frame-bytes` (16384) — SETTINGS_MAX_FRAME_SIZE, [16384, 16777215].
- `:http2-stream-reset-limit` (400) — client RST_STREAMs allowed per connection, refilling at that many per 30 seconds; above it the connection ends with ENHANCE_YOUR_CALM (CVE-2023-44487 rapid reset; nginx's number). 0 = off.
- `:http2-continuation-limit` (64) — CONTINUATION frames per header block.

## HTTP/3

QUIC via libquiche over its own UDP socket. Needs a PEM certificate and key
on disk (quiche loads them itself, not from the `SSLContext`).
`:idle-timeout` is QUIC's max_idle_timeout and `:handshake-timeout` bounds
the QUIC handshake.

- `:http3` (false) — serve HTTP/3. Needs `:http3-cert-path` and `:http3-key-path`.
- `:http3-port` (0) — UDP port; 0 = the `:port` number. With `:port` 0, set it (or `:advertise-alt-svc` false): `Alt-Svc` must name a fixed port. Needs `:http3`.
- `:http3-cert-path` (none) — PEM certificate chain.
- `:http3-key-path` (none) — PEM private key.
- `:http3-initial-max-data-bytes` (4194304) — connection flow-control window, a hard bound: quiche doesn't autotune past it. Also bounds the request-body bytes buffered per connection while handlers don't read.
- `:http3-initial-max-streams-bidi` (100) — concurrent request streams per connection. Handlers of reset requests are interrupted but may keep running; once twice this many handlers are live on a connection, new requests are refused with H3_REQUEST_REJECTED.
- `:http3-initial-max-streams-uni` (8) — peer unidirectional stream credit, at least 3 (control + QPACK encoder/decoder).
- `:http3-max-udp-payload-bytes` (1350) — max UDP payload, [1200, 65527]; the default is MTU-safe.
- `:http3-stateless-retry` (false) — make clients prove their address before any connection state is allocated (RFC 9000 §8.1.2), always. Without it, Retry still kicks in automatically past `:http3-retry-threshold`.
- `:http3-cert-reload-interval` (10000) — milliseconds between checks of the certificate and key files (modification time, size, inode); a changed pair is loaded for new connections, existing connections keep theirs; a pair that fails to load is logged and the current one kept. 0 = off.
- `:http3-retry-threshold` (256) — handshaking connections from which a client Initial without a valid token gets a stateless Retry: a spoofed flood can't make the server allocate connections or sign handshakes beyond it.
- `:http3-max-half-open` (1024) — handshaking connections above which new Initials are dropped. 0 = unlimited.
- `:http3-stream-reset-limit` (400) — peer stream resets allowed per connection, refilling at that many per 30 seconds; above it the connection is closed (rapid reset). 0 = off.
- `:http3-event-loops` (0) — event loop threads owning QUIC connections, [0, 64]. 0 = one per core on Linux (one `SO_REUSEPORT` socket each), 1 elsewhere.
- `:http3-so-rcv-buf-bytes` (4194304) — UDP socket receive buffer requested, best effort (Linux caps it at `net.core.rmem_max`). 0 = OS default.
- `:http3-so-snd-buf-bytes` (4194304) — UDP socket send buffer requested, best effort. 0 = OS default.
- `:http3-initial-max-stream-data-bidi-local-bytes` (-1) — per-stream window. -1 = max(1 MiB, `:http3-initial-max-data-bytes` / `:http3-initial-max-streams-bidi`), never above `:http3-initial-max-data-bytes`, so 1 MiB by default.
- `:http3-initial-max-stream-data-bidi-remote-bytes` (-1) — same, for peer-initiated streams.
- `:http3-initial-max-stream-data-uni-bytes` (-1) — same, for unidirectional streams.
- `:http3-ack-delay-exponent` (-1) — RFC 9000 ack_delay_exponent, [0, 20]. -1 = quiche default.
- `:http3-max-ack-delay` (-1) — RFC 9000 max_ack_delay, in milliseconds as the transport parameter, [0, 16383]. -1 = quiche default.
- `:http3-active-connection-id-limit` (-1) — RFC 9000 active_connection_id_limit, ≥ 2. -1 = quiche default.
- `:advertise-alt-svc` (none) — send `Alt-Svc` on HTTP/1.1 and HTTP/2 responses so clients discover the HTTP/3 endpoint. nil = whenever `:http3` is on; true needs `:http3`.
- `:alt-svc-max-age` (86400) — `ma` parameter of the `Alt-Svc` header, in seconds.

## WebSocket

- `:ws-max-message-bytes` (1048576) — largest message once reassembled and decompressed. A larger one fails the connection with CLOSE 1009; the server keeps reading (and discarding) until the client's CLOSE so the 1009 isn't lost to a TCP reset. Messages are buffered whole, as UTF-8 bytes for text (validated as they arrive), and handed to the listener as a String (text) or ByteBuffer (binary).
- `:ws-max-queued-bytes` (1048576) — payload bytes asynchronous sends (`ring.websocket/send` with callbacks, `sendTextAsync` / `sendBinaryAsync`) may queue per connection, 0 = unlimited. Each queued frame counts 64 bytes on top of its payload (so empty frames can't queue without bound). A send that would go over fails at once (its fail callback runs): back-pressure for a client that reads slower than the server produces. One message larger than the limit is accepted when nothing is queued. Pongs that find a write in progress don't queue up: a pending one takes the payload of the latest ping (RFC 6455 §5.5.3).
- `:ws-close-timeout` (5000) — ms a closing handshake the server started (`close`, a protocol failure, the idle timeout, server shutdown) waits for the client's CLOSE before dropping TCP. At least 1. On shutdown, `:shutdown-timeout` still force-closes what is left.
- `:ws-compression` (false) — negotiate permessage-deflate (RFC 7692) when the client offers it. Messages of 256 bytes and more are sent compressed (deflate level 1); compressed messages from the client are inflated up to `:ws-max-message-bytes`, so a small "zip bomb" fails with 1009 without being expanded. Compressed messages larger than 64 KiB go out as several frames, so compressing one holds a bounded buffer. With context takeover (the default) a compressing connection holds a Deflater and an Inflater, about 300 KiB of native memory, for its lifetime. When the client asks for `server_no_context_takeover` (or a `server_max_window_bits` below 15) the Deflater keeps nothing between messages, so it is borrowed from a server-wide pool per message instead.
- `:ws-ping-interval` (0) — ms without a frame from the client after which the server sends an empty PING, and again every interval while the client stays silent; 0 = never. Browsers and most clients answer pings on their own, and a PONG is a frame, so a live client that never sends anything (a server-push socket) outlasts `:idle-timeout`, and proxies that drop quiet TCP connections see traffic. A client that stops answering is still closed by `:idle-timeout` (1001), so the interval must be less than it. Pings never wait behind a stalled write.
- `:ws-allowed-origins` (none) — origins allowed to open a WebSocket: a collection of origins as browsers send them (`["https://app.example.com"]`, `"*"` for any) or a fn of the `Origin` value returning truthy. nil = same origin: the `Origin` host must equal the `Host` header. A handshake without `Origin` is not from a browser and is allowed; a refused one gets 403.

Why these defaults:

- Messages 1 MiB: messages are buffered whole, so the cap bounds memory per connection. At a message's end the buffer and what the listener receives exist together: up to 2× the cap for binary or Latin-1 text, 3× for other text (a String holding non-Latin-1 characters takes 2 bytes per char), plus the JDK's transient buffers while it decodes the text, briefly, per connection receiving one; the part past 64 KiB counts against `:max-buffered-bytes`, which bounds the total. It is generous next to Netty's and Jetty's 64 KiB defaults; raise it for bulk transfers.
- Compression off: it costs CPU per message and ~300 KiB per connection, and compressing attacker-influenced data next to secrets has the usual CRIME/BREACH caveats. Node's `ws` server and Netty leave it off too. Turn it on for chatty text protocols over slow links.
- Same-origin by default: a browser attaches cookies to a cross-site WebSocket handshake and WebSockets bypass CORS, so accepting any origin lets any web page open an authenticated socket (cross-site WebSocket hijacking). gorilla/websocket, Spring and Phoenix check the origin by default as well. Behind a proxy that rewrites `Host`, list the public origins.

## Handler and observability

- `:async` (false) — `handler` is a Ring asynchronous handler, `(fn [request respond raise])`. It runs on the request's virtual thread, which waits until `respond` or `raise` is called (from any thread); `raise` goes to `:error-handler`. Only the first call counts. The wait has no bound of its own, as a synchronous handler may run without one: `:handler-timeout` bounds both (503), and stopping the server interrupts it. A `ring.core.protocols/StreamableResponseBody` returned this way may write after `write-body-to-stream` returns, from any thread; the body ends when it closes the stream (Ring's contract), so one that never closes it holds its connection or stream until the server stops.
- `:error-handler` (none) — `(fn [request throwable])` returning a Ring response, run when the handler throws or returns nil, on every protocol. If it throws or returns nil too, a plain 500 is sent.
- `:server-header` (none) — `Server` response header value. Nil or empty omits it; a handler-supplied `Server` wins. Must be a valid field value.
- `:server-events` (none) — a map of fns, any subset of `{:connection-opened (fn [protocol remote-addr]) :connection-closed (fn [protocol remote-addr nanos]) :request-completed (fn [protocol method status request-bytes response-bytes nanos]) :protocol-error (fn [protocol kind])}`, or a `com.s_exp.enso.api.ServerEvents`. Unknown keys are rejected (with a "did you mean"), values must be fns. `remote-addr` is formatted as the request's `:remote-addr` (IPv6 in RFC 5952 form; `com.s_exp.enso.api.Request/formatAddress` for a `ServerEvents`). `request-bytes` / `response-bytes` are body bytes received / sent; `method` is nil for a request head refused before it was parsed. Protocols are "http/1.1", "h2" (over TLS), "h2c" (cleartext, `:http2c`), "h3"; "websocket" for a connection upgraded to WebSocket (opened at the 101, closed when the WebSocket ends, inside its "http/1.1" connection's events); protocol errors before any HTTP runs use "tcp" (a connection refused at accept: "connection-limit") and "tls" ("handshake", "handshake-timeout", "renegotiation"). Kinds include "bad-request", "header-timeout", "header-too-large", "body-too-large", "read-timeout", "write-timeout", "handler-timeout", "not-implemented", "unsupported-version"; HTTP/2 adds "handshake-timeout", "flow-control-timeout", "reset-flood" and, for connection errors, "protocol-error", "flow-control-error", "compression-error", "frame-size-error", "stream-closed", "enhance-your-calm"; HTTP/3 adds "handshake-timeout", "handshake-limit", "connection-limit", "rapid-reset", "protocol-error" and "event-loop-failure" (an event loop failed and was restarted, its connections closed). Called on connection threads (timeouts: right after the timer fired), so keep them fast; an exception thrown by a fn is logged (WARNING, rate-limited) and ignored, it never affects the connection. No cost when absent.

JDK Flight Recorder events, on every protocol: `com.s_exp.enso.Connection`
(one per TCP or QUIC connection, its lifetime, with the protocol it
settled on: "http/1.1", "h2", "h2c", "h3"), `com.s_exp.enso.ProtocolError`
(the same protocol and kind as `:server-events`), and
`com.s_exp.enso.Request` (one per request, off unless a recording enables
it explicitly). Nothing is allocated for an event no recording wants.

## Logging

Errors go through `java.util.logging` under `com.s_exp.enso.*`
(`com.s_exp.enso.EnsoServer`, `com.s_exp.enso.http1.HttpConnection`,
`com.s_exp.enso.http2.Http2Connection`, `com.s_exp.enso.http3.*`,
`com.s_exp.enso.api.RingErrorHandler`, `com.s_exp.enso.core.Timer`).
Failures a client can cause (malformed requests, resets, timeouts, peers
that vanish, handler exceptions caused by I/O errors) log at FINE; server
faults (handler exceptions, invalid responses, internal errors) at
WARNING, rate-limited per call site to one record per second with a count
of the suppressed ones. Wire an SLF4J bridge in your application to
redirect them.

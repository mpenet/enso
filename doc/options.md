# Configuration options

Options are passed as a map to `s-exp.enso/run-server`. Defaults are in
parentheses.

```clojure
(enso/run-server handler {:port 8080 :max-request-body-bytes (* 50 1024 1024)})
```

Every key is validated. An unknown key throws `ex-info` with a "did you
mean" suggestion. A wrong type or an invalid value throws `ex-info` naming
the option, with `:option` and `:value` in its `ex-data`. A nil value means
the default. Options that take a function also accept a var
(`#'my-error-handler`), so redefining it takes effect without a restart.

The option table in `s-exp.enso` is the source of truth. It also renders
the `run-server` docstring, and a test keeps this page in sync with it.

Naming conventions:

- durations end in `-timeout` and are in milliseconds, 0 disables;
- sizes end in `-bytes`;
- TLS options start with `:ssl-`.

A few options keep the unit of the thing they set: `:so-linger` and
`:alt-svc-max-age` are in seconds, `:http3-max-ack-delay` in milliseconds,
`:min-data-rate-bytes` in bytes per second and `:min-data-rate-grace` in
milliseconds.

## Network

- `:port` (8080): listen port. 0 picks an ephemeral port (TCP only, see `:http3-port`).
- `:host` ("0.0.0.0"): bind address.
- `:backlog` (1024): accept queue length.
- `:max-connections` (10000): open connections server-wide, TCP and QUIC together. 0 means unlimited. A TCP connection over the limit is closed right after accept, before it gets a thread or a TLS handshake. A QUIC Initial over the limit is dropped.
- `:max-connections-per-ip` (0): open connections per client address, 0 means unlimited. Set it when clients connect directly, otherwise one address can take every slot. Leave it off behind a load balancer or NAT, where many clients share an address.

Each connection costs a virtual thread and a few tens of KiB of buffers
while busy (more with TLS), so the default of 10000 keeps a connection
flood to a few hundred MiB. Both caps count every connection the server
holds: TCP (HTTP/1.1, WebSocket, HTTP/2) and QUIC (from admission until
its last handler returns).

## Timeouts

Each timeout means the same thing on every protocol.

| Option | Bounds | Measured as |
|---|---|---|
| `:handshake-timeout` | TLS handshake; HTTP/2 preface and first SETTINGS; QUIC handshake | wall clock from accept |
| `:header-timeout` | a complete request head | wall clock from its first byte |
| `:read-timeout` | request body; a WebSocket message | longest wait without progress; for a WebSocket message, wall clock from first to last frame |
| `:min-data-rate-bytes` | request body | bytes per second of waiting, after `:min-data-rate-grace` |
| `:write-timeout` | any response or frame write | longest wait without progress |
| `:idle-timeout` | time with no request in progress | since the last activity |
| `:handler-timeout` | the Ring handler | wall clock, off by default |

Where each applies:

| Option | HTTP/1.1 | WebSocket | HTTP/2 | HTTP/3 |
|---|---|---|---|---|
| `:handshake-timeout` | TLS | TLS | TLS, preface, first SETTINGS | QUIC handshake |
| `:header-timeout` | yes | no | yes, including CONTINUATION | yes |
| `:read-timeout` | yes | message deadline | yes | yes |
| `:min-data-rate-bytes` | yes | no | yes | yes |
| `:write-timeout` | yes | yes | socket writes and flow-control stalls | stalled response producers |
| `:idle-timeout` | yes | yes | yes | yes (QUIC max_idle_timeout) |
| `:handler-timeout` | yes | no | yes | yes |

- `:handshake-timeout` (10000): time allowed for the TLS handshake, plus the HTTP/2 preface and first SETTINGS, or the QUIC handshake. The connection is closed when it runs out.
- `:header-timeout` (10000): time allowed to receive a complete request head, counted from its first byte. Protects against slowloris. Answered with 408.
- `:read-timeout` (30000): longest time without progress while reading a request body. The read fails (408 unless the handler catches it) and the connection is not reused. Also bounds head reads when `:header-timeout` is 0. On a WebSocket it is a deadline: a message must arrive whole within this time of its first frame, or the connection is closed with 1008 "message timeout".
- `:min-data-rate-bytes` (240): least request body bytes per second while a handler waits for them, once `:min-data-rate-grace` of waiting has passed. 0 turns it off. See [Minimum data rate](#minimum-data-rate).
- `:min-data-rate-grace` (5000): waiting time allowed before `:min-data-rate-bytes` applies.
- `:write-timeout` (30000): longest time without write progress, meaning the peer stopped reading. The connection is force-closed (TLS without close_notify). Progress is counted per 256 KiB slice. On HTTP/2 it also bounds a peer that keeps its flow-control window shut: a stream that can't send for this long is reset with CANCEL, and a connection window shut this long ends the connection with GOAWAY(ENHANCE_YOUR_CALM).
- `:idle-timeout` (75000): how long a connection may sit with no request in progress. That is HTTP/1.1 before and between requests, HTTP/2 and HTTP/3 with no open stream (GOAWAY, or QUIC's idle timeout), and a WebSocket with no frame from the client (closing handshake with 1001 "idle timeout").
- `:handler-timeout` (0): how long a handler may run, 0 means no limit. On expiry the client gets 503 if nothing was sent yet, the handler thread is interrupted, and on HTTP/1.1 the connection closes. Streaming bodies are not covered: once the handler has returned, `:write-timeout` applies. Set it in production, to a few times your slowest legitimate handler. Without it a handler stuck on a slow dependency holds its connection or stream slot until it returns.
- `:shutdown-timeout` (10000): how long `stop` waits for in-flight requests, as one deadline for the whole server, before force-closing what is left.

### Minimum data rate

`:read-timeout` restarts with every byte, so on its own it lets a client
send one byte every 29 seconds and hold a request and its handler thread
forever. `:min-data-rate-bytes` closes that gap. Only time spent waiting
for bytes counts: a handler that reads slowly, or not at all, is never
held against the client. Below the rate the read fails like a read
timeout (408 unless caught) and is reported as the protocol error
"min-data-rate". The defaults, 240 bytes/s after 5 s, are Kestrel's. It
applies to request bodies on HTTP/1.1, HTTP/2 and HTTP/3.

Responses are held to a rate by `:write-timeout`: a blocked write slice
must complete, and a blocked HTTP/2 or HTTP/3 stream must send 16 KiB per
period.

### Why these defaults

- Handshake, 10 s: Netty's SslHandler default. A real handshake takes a few round trips.
- Header, 10 s: a request head fits in a packet or two. nginx allows 60 s, Apache's mod_reqtimeout starts at 20 s, and Go's commonly recommended `ReadHeaderTimeout` is a few seconds.
- Read and write, 30 s without progress: Jetty's idle timeout, and half of nginx's `client_body_timeout` and `send_timeout`, which also count between operations.
- Idle, 75 s: nginx's `keepalive_timeout`. It is longer than the 60 s idle timeout of common load balancers such as AWS ALB, so the server is never the side that closes a connection the balancer is about to reuse.
- Handler, off: how long a handler may take is application policy. Go's `TimeoutHandler` and Jetty's request timeout are opt-in too.

## Limits

- `:max-header-bytes` (65536): request head size on every protocol, 431 above. This covers the HTTP/1.1 head and chunked trailers, the decoded HTTP/2 header list (advertised as SETTINGS_MAX_HEADER_LIST_SIZE) and the decoded HTTP/3 field section (SETTINGS_MAX_FIELD_SECTION_SIZE). Above a hard ceiling of 4× this (at least 64 KiB), an HTTP/2 connection ends with GOAWAY(ENHANCE_YOUR_CALM) and an HTTP/3 stream is reset with H3_EXCESSIVE_LOAD before the section is buffered.
- `:max-header-fields` (100): request header fields per head on every protocol, 431 above. Same default as Apache's LimitRequestFields and Tomcat's maxHeaderCount.
- `:max-request-body-bytes` (10485760): request body size on every protocol, 0 means no limit. A larger Content-Length gets 413 without running the handler. A body without one fails mid-stream. WebSocket messages have their own limit, `:ws-max-message-bytes`.
- `:max-keep-alive-requests` (1000): requests per HTTP/1.1 connection, 0 means unlimited (nginx's default). The last response carries `Connection: close`.
- `:max-buffered-bytes` (0): server-wide cap on the bytes held, or promised as flow-control credit, on behalf of peers. 0 means a quarter of the maximum heap (`-Xmx`), at least 1 MiB. See [Memory budget](#memory-budget).

### Memory budget

`:max-buffered-bytes` counts:

- unread request bodies on HTTP/2 and HTTP/3, and the HTTP/2 connection credit granted for them;
- streamed HTTP/2 response bytes waiting for the peer;
- HTTP/3 response bytes quiche hasn't taken yet;
- HTTP/3 receive credit held natively by quiche (below);
- queued WebSocket asynchronous sends;
- incoming WebSocket messages past their first 64 KiB, until the listener's `on-message` returns.

These buffers are transient, which is why the default leaves three
quarters of the heap to handlers.

Credit is paid for before it is granted. An HTTP/2 connection window grows
past the protocol's 65535 octets only once request body bytes arrive, and
only as far as the budget allows.

From three quarters of the limit (the low-water mark), a connection
holding more than its fair share (the limit divided by the number of
connections holding bytes) is throttled, while the others carry on. At the
limit every connection is throttled. Throttling pushes back instead of
failing:

- HTTP/2 grants connection credit only up to the initial 65535 octets, and a streamed response holds one frame before its producer waits;
- HTTP/3 stops reading request streams until handlers read what is buffered;
- a WebSocket stops reading a large message (TCP pushes back on the client) until there is room, within the message's `:read-timeout`, else it closes with 1008;
- a WebSocket asynchronous send fails at once and its fail callback runs.

The limit can be exceeded by what the protocols grant without asking: the
initial 65535-octet window of an HTTP/2 connection receiving a body, and
64 KiB per WebSocket reading a message.

HTTP/3 receive credit lives in quiche's native memory, up to one
connection window per connection. While a connection reads a request body
its initial window is charged to the budget. Window growth past it
(release builds only, see `:http3-max-window-bytes`) is reserved before
quiche may use it and stays charged until the connection closes. A
connection reading no body costs nothing. New QUIC connections are refused
while the budget is exhausted.

## TCP

- `:so-nodelay` (true): TCP_NODELAY on accepted sockets, plain and TLS.
- `:so-reuse-addr` (true): SO_REUSEADDR on the listening socket.
- `:so-linger` (-1): SO_LINGER on accepted sockets, in seconds. -1 turns it off.
- `:so-rcv-buf-bytes` (0): SO_RCVBUF, set on the listening socket before bind so accepted sockets inherit it and TCP window scaling can use it. 0 keeps the OS default.
- `:so-snd-buf-bytes` (0): SO_SNDBUF on accepted sockets. 0 keeps the OS default.

## TLS

TLS for HTTP/1.1 and HTTP/2 uses the JDK's `SSLEngine` over the accepted
`SocketChannel`. The handshake and ALPN run on the connection's virtual
thread, under `:handshake-timeout`.

- `:ssl-context` (none): a `javax.net.ssl.SSLContext`. When set, the TCP listener speaks TLS. File bodies then go through user space, since zero-copy `sendfile` needs plain HTTP.
- `:ssl-context-provider` (none): a fn (or `java.util.function.Supplier`) returning an `SSLContext`. It is called at startup and for every accepted connection, on that connection's virtual thread before the handshake, so rotated certificates apply to new connections without a restart. Return a cached context and replace it when the certificates change; building one per call costs that on every connection and loses session resumption. A nil return closes the connection. Exclusive with `:ssl-context`.
- `:ssl-need-client-auth` (false): require a valid client certificate.
- `:ssl-want-client-auth` (false): ask for a client certificate without requiring one. Exclusive with `:ssl-need-client-auth`.
- `:ssl-alpn-protocols` (none): ALPN protocol ids offered. Defaults to `["h2" "http/1.1"]` with `:http2`, else `["http/1.1"]`. Offering "h2" requires `:http2`.
- `:ssl-cipher-suites` (none): enabled cipher suites. nil keeps the JVM default.
- `:ssl-protocols` (none): enabled TLS protocol versions. nil keeps the JVM default.
- `:ssl-session-cache-size` (0): server TLS session cache size, set on every context the server uses, provider contexts included. 0 keeps the JVM default.

`:ssl-alpn-protocols`, `:ssl-cipher-suites`, `:ssl-protocols` and the
client-auth options require `:ssl-context` or `:ssl-context-provider`.

## HTTP/2

These settings apply to HTTP/2 over TLS (`:http2`) and to cleartext
HTTP/2 (`:http2c`).

- `:http2` (false): serve "h2" over TLS. Requires `:ssl-context` or `:ssl-context-provider`.
- `:http2c` (false): serve cleartext HTTP/2 with prior knowledge on the plain listener, next to HTTP/1.1. A connection that opens with the HTTP/2 preface is HTTP/2. `Upgrade: h2c` is not supported (RFC 9113 deprecated it). Not compatible with `:ssl-context` or `:ssl-context-provider`.
- `:http2-max-concurrent-streams` (100): SETTINGS_MAX_CONCURRENT_STREAMS.
- `:http2-initial-window-bytes` (262144): receive window a stream starts with, between 65535 and 2^31-1. The spec's 64 KiB default starves throughput beyond a LAN. See [HTTP/2 flow control](#http2-flow-control).
- `:http2-max-window-bytes` (8388608): the largest a stream's receive window grows to, between `:http2-initial-window-bytes` and 2^31-1. The connection window grows to twice this (16 MiB by default). 8 MiB lets one stream upload about 160 MiB/s over a 50 ms round trip. Set it equal to `:http2-initial-window-bytes` for fixed windows.
- `:http2-max-frame-bytes` (16384): SETTINGS_MAX_FRAME_SIZE, between 16384 and 16777215.
- `:http2-stream-reset-limit` (400): client RST_STREAMs allowed per connection, refilling at that many per 30 seconds. Above it the connection ends with ENHANCE_YOUR_CALM. This is the CVE-2023-44487 (rapid reset) mitigation, with nginx's number. 0 turns it off.
- `:http2-continuation-limit` (64): CONTINUATION frames allowed per header block.

### HTTP/2 flow control

Receive windows tune themselves to the round trip and to how fast the
handler reads, the way quic-go, quiche and Linux TCP do. Each time a
stream's handler has read half of its window, the server returns the
credit. If the previous return was less than two round trips earlier, the
window also doubles, up to `:http2-max-window-bytes`. In other words, a
window grows when the handler keeps up with more than a quarter of it per
round trip. A stream that reads slowly keeps the window it started with,
and a grown window ends with its stream.

The round trip is measured from the SETTINGS acknowledgement, then
refreshed by a PING at most once a second while windows are being
returned.

The connection window starts at 65535 octets and grows to 4× the initial
stream window (1 MiB by default, as in Go and Kestrel) once request body
bytes arrive. One handler that doesn't read its body therefore can't stall
uploads on the others. It then doubles by the same rule, up to twice
`:http2-max-window-bytes`. Every increase is paid for from
`:max-buffered-bytes` first. When the budget can't pay, or the connection
is over its fair share under pressure, windows stay as they are.

Once no request body is open on the connection, its window goes back to
that 4× baseline. A connection that finished an upload keeps paying only
for the credit the peer still holds, which shrinks to the baseline as the
peer spends it. A body that declares a Content-Length is never granted
credit past what it has left to send. While every open body declares one,
the connection isn't either (beyond the baseline), so such an upload
leaves no grown window behind.

## HTTP/3

HTTP/3 runs QUIC through libquiche on its own UDP socket. It needs a PEM
certificate and key on disk, since quiche loads them itself rather than
from the `SSLContext`. `:idle-timeout` sets QUIC's max_idle_timeout and
`:handshake-timeout` bounds the QUIC handshake. Setup and runtime
behaviour are in [http3.md](http3.md).

- `:http3` (false): serve HTTP/3. Requires `:http3-cert-path` and `:http3-key-path`.
- `:http3-port` (0): UDP port. 0 means the same number as `:port`. With `:port` 0, set this (or `:advertise-alt-svc` false), because `Alt-Svc` must name a fixed port. Requires `:http3`.
- `:http3-cert-path` (none): PEM certificate chain.
- `:http3-key-path` (none): PEM private key.
- `:http3-initial-max-data-bytes` (524288): connection flow-control window a connection starts with. It also caps the request body bytes buffered per connection while handlers aren't reading. With a stock libquiche it never grows, so one connection uploads at most this much per round trip (512 KiB per 50 ms is about 10 MiB/s). See [HTTP/3 flow control](#http3-flow-control).
- `:http3-initial-max-streams-bidi` (100): concurrent request streams per connection. Handlers of reset requests are interrupted but may keep running. Once twice this many handlers are live on a connection, new requests are refused with H3_REQUEST_REJECTED.
- `:http3-initial-max-streams-uni` (8): peer unidirectional stream credit, at least 3 (control, QPACK encoder and decoder).
- `:http3-max-udp-payload-bytes` (1350): largest UDP payload, between 1200 and 65527. The default is safe for common MTUs.
- `:http3-stateless-retry` (false): always make clients prove their address with a stateless Retry before any connection state is allocated (RFC 9000 §8.1.2). Without it, Retry still starts automatically past `:http3-retry-threshold`.
- `:http3-cert-reload-interval` (10000): milliseconds between checks of the certificate and key files (modification time, size, inode). A changed pair is loaded for new connections; existing ones keep theirs. A pair that fails to load is logged and the current one kept. 0 turns it off.
- `:http3-retry-threshold` (256): number of handshaking connections from which a client Initial without a valid token gets a stateless Retry. A spoofed flood can't make the server allocate connections or sign handshakes beyond it.
- `:http3-max-half-open` (1024): number of handshaking connections above which new Initials are dropped. 0 means unlimited.
- `:http3-stream-reset-limit` (400): peer stream resets allowed per connection, refilling at that many per 30 seconds. Above it the connection is closed (rapid reset). 0 turns it off.
- `:http3-event-loops` (0): event loop threads owning QUIC connections, between 0 and 64. 0 means one per core on Linux, each with its own `SO_REUSEPORT` socket, and 1 elsewhere.
- `:http3-so-rcv-buf-bytes` (4194304): UDP receive buffer requested, best effort. Linux caps it at `net.core.rmem_max`. 0 keeps the OS default.
- `:http3-so-snd-buf-bytes` (4194304): UDP send buffer requested, best effort. 0 keeps the OS default.
- `:http3-initial-max-stream-data-bidi-local-bytes` (-1): per-stream window. -1 means half of `:http3-initial-max-data-bytes`, 256 KiB by default, the same as HTTP/2's initial stream window. A stream whose handler doesn't read can then never take the whole connection window and stall the connection's other requests. With fixed windows, one stream uploads at most this much per round trip.
- `:http3-initial-max-stream-data-bidi-remote-bytes` (-1): the same, for peer-initiated streams.
- `:http3-initial-max-stream-data-uni-bytes` (-1): the same, for unidirectional streams.
- `:http3-max-window-bytes` (8388608): the largest a stream's receive window grows to, at least the per-stream initial windows. A connection's window grows to twice this (16 MiB by default). Requires the patched libquiche of the release builds (`Quiche.RECV_WINDOW_CONTROL`) and is ignored with a stock libquiche, where windows keep their initial sizes.
- `:http3-ack-delay-exponent` (-1): RFC 9000 ack_delay_exponent, between 0 and 20. -1 keeps quiche's default.
- `:http3-max-ack-delay` (-1): RFC 9000 max_ack_delay in milliseconds, between 0 and 16383. -1 keeps quiche's default.
- `:http3-active-connection-id-limit` (-1): RFC 9000 active_connection_id_limit, at least 2. -1 keeps quiche's default.
- `:advertise-alt-svc` (none): send `Alt-Svc` on HTTP/1.1 and HTTP/2 responses so clients discover the HTTP/3 endpoint. nil means whenever `:http3` is on. true requires `:http3`.
- `:alt-svc-max-age` (86400): the `ma` parameter of the `Alt-Svc` header, in seconds.

### HTTP/3 flow control

With the release builds, windows autotune with quiche's rule: a window
doubles when the handler has read half of it within two round trips. Each
doubling of a connection window is paid for from `:max-buffered-bytes`
first. quiche holds received data in native memory, up to a connection
window per connection, and the initial window is only charged to the
budget while the connection reads a body. In the worst case that unpaid
initial window adds up to about 5 GiB for 10000 connections at the
default (625 MiB for HTTP/2). Lower `:http3-initial-max-data-bytes` or
`:max-connections` where that much native memory isn't available. Details
in [http3.md](http3.md#flow-control-and-memory).

## WebSocket

- `:ws-max-message-bytes` (1048576): largest message once reassembled and decompressed. A larger one fails the connection with 1009. The server keeps reading and discarding until the client's CLOSE, so the 1009 isn't lost to a TCP reset. Messages are buffered whole (text as UTF-8 bytes, validated as they arrive) and handed to the listener as a String or a ByteBuffer.
- `:ws-max-queued-bytes` (1048576): payload bytes that asynchronous sends may queue per connection, 0 means unlimited. Each queued frame also counts 64 bytes, so empty frames can't queue without bound. A send that would go over fails at once and its fail callback runs: back-pressure for a client that reads slower than the server writes. A single message larger than the limit is accepted when nothing is queued. Pongs don't pile up behind a write in progress: a pending pong takes the payload of the latest ping (RFC 6455 §5.5.3).
- `:ws-close-timeout` (5000): how long a closing handshake started by the server (`close`, a protocol failure, the idle timeout, shutdown) waits for the client's CLOSE before dropping TCP. At least 1. On shutdown, `:shutdown-timeout` still force-closes what is left.
- `:ws-compression` (false): negotiate permessage-deflate (RFC 7692) when the client offers it. See [Compression](#compression).
- `:ws-ping-interval` (0): after this long without a frame from the client, the server sends an empty PING, and again at every interval while the client stays silent. 0 means never. Clients answer pings on their own, and a PONG counts as a frame, so a live client that never sends anything (a server-push socket) outlasts `:idle-timeout`, and proxies that drop quiet connections see traffic. A client that stops answering is still closed by `:idle-timeout` with 1001, so the interval must be shorter than it. Pings never wait behind a stalled write.
- `:ws-allowed-origins` (none): origins allowed to open a WebSocket, as a collection of origins as browsers send them (`["https://app.example.com"]`, or `"*"` for any) or a fn of the `Origin` value returning truthy. nil means same origin only: the `Origin` host must equal the `Host` header. A handshake without `Origin` doesn't come from a browser and is allowed. A refused one gets 403.

### Compression

Messages of 256 bytes or more are sent compressed (deflate level 1).
Compressed messages from the client are inflated only up to
`:ws-max-message-bytes`, so a small "zip bomb" fails with 1009 without
being expanded. Compressed messages over 64 KiB go out as several frames,
so compressing one needs a bounded buffer.

With context takeover, the default, a compressing connection holds a
Deflater and an Inflater for its lifetime, about 300 KiB of native memory.
When the client asks for `server_no_context_takeover`, or a
`server_max_window_bits` below 15, the Deflater keeps no state between
messages and is borrowed from a server-wide pool for each message.

### Why these defaults

- Messages, 1 MiB: messages are buffered whole, so the limit bounds memory per connection. When a message completes, the buffer and the value handed to the listener exist together: up to 2× the limit for binary or Latin-1 text, 3× for other text (a String with non-Latin-1 characters uses 2 bytes per char), plus the JDK's transient buffers while decoding. The part past 64 KiB counts against `:max-buffered-bytes`, which bounds the total. Netty and Jetty default to 64 KiB; raise it for bulk transfers.
- Compression, off: it costs CPU per message and about 300 KiB per connection, and compressing attacker-influenced data next to secrets carries the usual CRIME/BREACH caveats. Node's `ws` and Netty leave it off too. Turn it on for chatty text protocols over slow links.
- Origin, same-origin only: browsers attach cookies to cross-site WebSocket handshakes and WebSockets bypass CORS, so accepting any origin lets any web page open an authenticated socket (cross-site WebSocket hijacking). gorilla/websocket, Spring and Phoenix check the origin by default too. Behind a proxy that rewrites `Host`, list the public origins.

## Handler and observability

- `:async` (false): `handler` is a Ring asynchronous handler, `(fn [request respond raise])`. See [handlers.md](handlers.md#async-handlers).
- `:error-handler` (none): `(fn [request throwable])` returning a Ring response, called when the handler throws or returns nil, on every protocol. If it also throws or returns nil, a plain 500 is sent.
- `:server-header` (none): value of the `Server` response header. nil or empty omits it, and a `Server` header set by the handler wins. Must be a valid field value.
- `:server-events` (none): callbacks for connections, requests and protocol errors, as a map of fns or a `com.s_exp.enso.api.ServerEvents`. See [Server events](#server-events).

### Server events

```clojure
{:connection-opened (fn [protocol remote-addr])
 :connection-closed (fn [protocol remote-addr nanos])
 :request-completed (fn [protocol method status request-bytes response-bytes nanos])
 :protocol-error    (fn [protocol kind])}
```

Any subset of the keys may be given. Unknown keys are rejected with a
"did you mean" suggestion, and values must be fns. `remote-addr` is
formatted like the request's `:remote-addr`, with IPv6 in RFC 5952 form
(`com.s_exp.enso.api.Request/formatAddress` does the same for a
`ServerEvents`). `request-bytes` and `response-bytes` count body bytes.
A request head refused before it was parsed is reported only as a
protocol error.

Protocols are "http/1.1", "h2" (over TLS), "h2c" (cleartext) and "h3".
An upgraded WebSocket connection is reported as "websocket", opened at the
101 and closed when the WebSocket ends, inside the events of its
"http/1.1" connection. Errors before any HTTP is spoken use "tcp" (a
connection refused at accept) and "tls".

Protocol error kinds:

| Protocol | Kinds |
|---|---|
| all HTTP | "bad-request", "header-timeout", "header-too-large", "body-too-large", "read-timeout", "min-data-rate", "write-timeout", "handler-timeout", "not-implemented", "unsupported-version" |
| http/1.1 | "uri-too-long" (a request line over `:max-header-bytes`, 414) |
| h2, h2c | "handshake-timeout", "flow-control-timeout", "reset-flood"; connection errors "protocol-error", "flow-control-error", "compression-error", "frame-size-error", "stream-closed", "enhance-your-calm" |
| h3 | "handshake-timeout", "handshake-limit", "connection-limit", "rapid-reset", "protocol-error", "event-loop-failure" (a loop failed and was restarted, its connections closed) |
| tcp | "connection-limit" |
| tls | "handshake", "handshake-timeout", "renegotiation" |

The fns never run on a server thread. Events go into a preallocated queue
(nothing is allocated per event) and are delivered in order by one daemon
thread, `enso-events`, so a slow fn only delays later events. Past 8192
queued events, new ones are dropped and counted:
`EnsoServer.droppedEvents()`, a WARNING log record and a JFR
`com.s_exp.enso.EventsDropped` event. Stopping the server delivers what is
still queued, waiting at most a second. An exception thrown by a fn is
logged (WARNING, rate-limited) and ignored. Without `:server-events`
there is no cost and no thread.

### JDK Flight Recorder

Events on every protocol:

- `com.s_exp.enso.Connection`: one per TCP or QUIC connection, covering its lifetime, with the protocol it settled on ("http/1.1", "h2", "h2c", "h3").
- `com.s_exp.enso.ProtocolError`: the same protocol and kind as `:server-events`.
- `com.s_exp.enso.Request`: one per request. Disabled unless a recording enables it explicitly.

Nothing is allocated for an event no recording wants.

## Logging

Errors go through `java.util.logging`, under `com.s_exp.enso.*`
(`com.s_exp.enso.EnsoServer`, `com.s_exp.enso.http1.HttpConnection`,
`com.s_exp.enso.http2.Http2Connection`, `com.s_exp.enso.http3.*`,
`com.s_exp.enso.api.RingErrorHandler`, `com.s_exp.enso.core.Timer`).

Failures a client can cause (malformed requests, resets, timeouts, peers
that vanish, handler exceptions caused by I/O errors) log at FINE. Server
faults (handler exceptions, invalid responses, internal errors) log at
WARNING, rate-limited per call site to one record per second with a count
of suppressed records. Install an SLF4J bridge in your application to
route them elsewhere.

# Handlers, response bodies, WebSocket, SSE

Standard Ring 1.x handler signature: `(fn [request] response)`, or a Ring
async handler with `:async true` (see below).
Same request map across HTTP/1.1, HTTP/2, HTTP/3. `:protocol` reflects the
negotiated version (`"HTTP/1.0"`, `"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3.0"`);
`:scheme` is `:https` on TLS connections (always for HTTP/3) and `:http`
on cleartext ones, h2c included. Response bodies and `:error-handler`
behave the same on every protocol; WebSocket is HTTP/1.1 only (a
WebSocket response on HTTP/2 or HTTP/3 is answered 501).

## Response body types

- `String`, `byte[]` — inlined or single-write. Strings are encoded with
  the `charset` of the `Content-Type` header, UTF-8 when there is none (as
  Ring does); an unknown charset is a 500.
- `java.io.InputStream` — streamed (see below), closed by the server.
- `java.io.File` — zero-copy via `FileChannel.transferTo(SocketChannel)`
  on cleartext HTTP/1.1; a user-space copy on TLS, HTTP/2 (h2c included)
  and HTTP/3.
- `clojure.lang.ISeq` — streamed: each element `str`'d and encoded like a
  String body, buffered (8 KiB) and sent as the buffer fills.
- `(fn [ChunkedWriter])` — an enso extension (not part of the Ring
  spec): a streaming writer for SSE, long-poll, incremental output, on
  every protocol. The fn drives writes with `enso/write!` (Strings
  encoded with the response charset, like String bodies), which buffers,
  and `enso/flush!`, which pushes everything buffered to the client; the
  body ends when the fn returns.
- Anything satisfying `ring.core.protocols/StreamableResponseBody` —
  dispatched only when `ring.core.protocols` is on the classpath. The
  types above take priority (a fn is always the streaming writer). The
  body writes to an `OutputStream` whose `flush` pushes bytes to the
  client. From a synchronous handler the body ends when
  `write-body-to-stream` returns; from an asynchronous one it may keep
  writing from other threads and ends when it closes the stream (Ring's
  contract).

Streamed bodies (InputStream, seq, fn, StreamableResponseBody) use
chunked encoding on a keep-alive HTTP/1.1 connection, are close-delimited
when the connection ends after the response (HTTP/1.0, `Connection:
close`), and go out as DATA frames on HTTP/2 and HTTP/3. With a handler
`Content-Length` they are sent as exactly that many bytes; a shorter body
aborts the response (connection closed or stream reset).

`:status` is an integer; a response without `:status` gets 200 (as with
Ring's Jetty adapter). A `:status` that is present but nil or not an
integer is a handler error (500, or `:error-handler`), as is an unknown
charset on a seq or fn body.

Header values may be a string, a list / vector / seq (one field per
non-nil element), or any other value, sent as its `str`; nil values are
skipped, on every protocol. A status outside 200-599 (101 only with a
WebSocket listener), a header name that isn't a token, a value with
control characters or characters above U+00FF, an unknown charset on a
String body, or any other body type is a plain 500, logged at WARNING;
`:error-handler` is not called for these. A handler `Transfer-Encoding`
is dropped (the server frames the body) and a handler `Content-Length` is
replaced when the server knows the length.

## Request map

Ring SPEC keys, the same on every protocol: `:server-port`,
`:server-name` (from the Host header, else the local address),
`:remote-addr` (IPv6 in the RFC 5952 short form), `:uri`,
`:query-string`, `:scheme`, `:request-method` (a lowercase keyword,
extension methods included), `:protocol`, `:headers` (lowercase names,
repeated fields joined with ", ", cookies with "; "), `:body` (an
`InputStream`, nil when the request has no body: on HTTP/1.1 no
Transfer-Encoding and no or a zero Content-Length, on HTTP/2 and HTTP/3
a HEADERS frame that ends the stream) and
`:ssl-client-cert`
(the client's `X509Certificate` when TLS verified one, else nil; HTTP/3
has none). The map is computed lazily and stays lazy through `assoc` /
`dissoc` by middleware.

## Async handlers

With `:async true`, `handler` is a Ring asynchronous handler,
`(fn [request respond raise])`. It runs on the request's virtual thread,
which then waits for `respond` or `raise`, called from any thread; `raise`
goes to `:error-handler`, and `:handler-timeout` applies as for a sync
handler. Without it the wait is unbounded, as a sync handler's run is: a
handler that never calls `respond` or `raise` holds its connection
(HTTP/1.1) or stream until the server stops. Virtual threads make
blocking cheap, so a sync handler is the simpler choice; async exists for
middleware stacks written for it.

## SSE / long-poll

```clojure
(defn sse [req]
  {:status 200
   :headers {"content-type" "text/event-stream"}
   :body (fn [w]
           (try
             (loop [i 0]
               (enso/write! w (str "data: tick " i "\n\n"))
               (enso/flush! w)
               (Thread/sleep 1000)
               (recur (inc i)))
             (catch java.io.IOException _)        ; client gone
             (catch InterruptedException _)))})   ; stream reset (h2, h3) or server stop
```

The fn learns that the client went away from an exception, never from a
return value. On every protocol `write!` or `flush!` throws an
`IOException`: on HTTP/1.1 once a write reaches the dead socket (from
`flush!`, or from `write!` when the buffer fills; usually the second flush
after the client left, since the first may still be accepted by the
kernel), on HTTP/2 and HTTP/3 once the stream was reset or the
connection lost. On HTTP/2 and HTTP/3 a reset also interrupts the body's
thread, so a blocking call between writes (`Thread/sleep`, a queue take)
throws `InterruptedException` at once. On HTTP/1.1 a fn waiting between
writes notices only at its next flush, so send a comment line
(`": keep-alive\n\n"`) periodically to find out sooner. Return to end
the body (letting the `IOException` through works too: it is treated as
the client going away, not as a server fault); other exceptions escaping
the fn may be logged as server faults (on HTTP/2 at WARNING), so catch
`InterruptedException`.

## WebSocket (Ring 1.11+ shape)

HTTP/1.1 only (`Upgrade: websocket`). On HTTP/2 and HTTP/3 a listener
response gets 501. On HTTP/1.1 a request that isn't a valid upgrade gets
400 (426 for a WebSocket version other than 13), a refused `Origin` 403,
and a `:ring.websocket/protocol` the client didn't offer is a 500.

```clojure
(require '[ring.websocket :as ws]) ; org.ring-clojure/ring-websocket-protocols

(defn handler [req]
  {:ring.websocket/listener
   {:on-open    (fn [socket] ...)
    :on-message (fn [socket msg] (ws/send socket (str "echo: " msg)))
    :on-close   (fn [socket code reason] ...)}
   :ring.websocket/protocol "chat"}) ; optional subprotocol
```

Without ring-websocket-protocols, use the socket directly with a type
hint (no reflection): `(.sendText ^com.s_exp.enso.api.WebSocketSocket socket msg)`.

The listener is either a map of `:on-open` `:on-message` `:on-ping`
`:on-pong` `:on-error` `:on-close` fns, or — when
`org.ring-clojure/ring-websocket-protocols` is on the classpath — anything
implementing `ring.websocket.protocols/Listener` (and optionally
`PingListener`). Any other value is a handler error (500, or
`:error-handler`).

`socket` is a `com.s_exp.enso.api.WebSocketSocket`. With
ring-websocket-protocols on the classpath it also implements
`ring.websocket.protocols/Socket` and `AsyncSocket`, so `ring.websocket/send`,
`ping`, `pong`, `close` and `open?` work on it.

- Text and binary messages; fragmented messages are reassembled. A
  message is capped by `:ws-max-message-bytes` (1 MiB) and must arrive
  within `:read-timeout` from its first frame; past either the connection
  fails with 1009 / 1008.
- Sends from any thread, in call order. A synchronous send writes on the
  calling thread, bounded by `:write-timeout`. An asynchronous send
  (`ring.websocket/send` with callbacks, `.sendTextAsync` /
  `.sendBinaryAsync`) queues the message and returns at once; a writer
  virtual thread sends it, then calls succeed. Past `:ws-max-queued-bytes`
  queued, it fails at once (back-pressure). A `ByteBuffer` sent
  asynchronously must not be modified until its callback ran. The writer
  thread exists only while there is something to write (it ends after a
  second idle).
- Every send after the server's CLOSE (or once the connection is gone)
  throws `IOException` "WebSocket closed"; async sends call fail.
- Ping/pong: auto-pong on ping unless `:on-ping` (or `PingListener`) is
  provided. Pings and pongs never wait behind a stalled writer: they are
  queued behind it. Payloads are limited to 125 bytes
  (`IllegalArgumentException` above).
- Failures: protocol violations close with 1002, invalid UTF-8 or
  corrupt compressed data with 1007, an expired message deadline with
  1008, a message over the cap with 1009, an exception from `:on-open`,
  `:on-message`, `:on-ping` or `:on-pong` with 1011 "internal error" (its
  message stays on the server), whatever it throws: an `IOException` from
  the listener's own I/O is its failure, not the connection's. Exceptions
  from `:on-error` and `:on-close` are ignored. The CLOSE carries a short reason. `:on-error` receives a
  `com.s_exp.enso.api.WebSocketException` (`.code`) for protocol
  failures, the listener's exception otherwise; `:on-close` then gets the
  failure code. The server keeps reading until the client's CLOSE (or
  `:ws-close-timeout`) so its CLOSE isn't lost to a TCP reset.
- `(.close socket code reason)` / `ring.websocket/close` sends CLOSE, then
  waits up to `:ws-close-timeout` (5 s) for the peer's CLOSE before
  dropping TCP; `:on-close` receives the peer's code (1006 if it never
  answered). Codes must be 1000-1003, 1007-1014 or 3000-4999 and the
  reason at most 123 UTF-8 bytes (`IllegalArgumentException` otherwise).
- `:idle-timeout` (75 s by default, 0 disables) bounds how long no frame
  may arrive from the client. When it passes the server starts the
  closing handshake with 1001 "idle timeout". For server-push sockets
  whose clients stay silent, set `:ws-ping-interval` below it: the server
  pings a quiet client and its pongs keep the connection alive.
- On server stop, open WebSockets are sent CLOSE 1001 "server shutting
  down" and get until `:shutdown-timeout` to finish the closing handshake.
- permessage-deflate (RFC 7692) with `:ws-compression true`: negotiated
  when the client offers it (any client window size; for a server
  window under 15 bits, which `java.util.zip` can't compress with, only
  messages that fit the window are compressed, each on its own).
  Inflation stops at `:ws-max-message-bytes`. Messages under 256 bytes
  are sent uncompressed; a message whose compressed form exceeds 64 KiB
  is sent as several frames.
- A connection quiet for a second gives back its grown buffers (message
  assembly, compression, TLS records); the next message regrows them.

### Security

- Origin: browsers attach cookies to cross-site WebSocket handshakes and
  WebSockets aren't covered by CORS. By default only the server's own
  origin (its `Host`) may open a WebSocket; list others with
  `:ws-allowed-origins` (a collection of origins, `["*"]` for public,
  cookie-less endpoints, or a predicate fn). A handshake without `Origin`
  is not from a browser and is accepted; a refused origin gets 403.
  Authenticate in the handler before returning the listener: the
  upgrade request carries the cookies and headers.
- Limits: `:ws-max-message-bytes`, `:read-timeout` (message deadline),
  `:idle-timeout`, `:ws-max-queued-bytes` and `:max-connections` bound
  what one client can make the server hold.

## Error handling

`:error-handler` — `(fn [request throwable])` returning a Ring response.
Runs when the main handler throws or returns nil. If the error handler
itself throws or returns nil, a fallback 500 text response is sent. Applies
to HTTP/1.1, HTTP/2 and HTTP/3 alike.

A request body the client got wrong is the client's error, on every
protocol: reading it throws an `IOException` (400 for broken or truncated
framing, 413 above `:max-request-body-bytes`) or a
`java.net.SocketTimeoutException` (no progress for `:read-timeout`, 408),
and once the handler returns the server answers that status, whatever the
handler did with the exception (rethrown, wrapped or swallowed). The
error handler is not called for it. (The concrete classes,
`RequestBodyException` and `RequestBodyTimeoutException`, are internal:
catch the supertypes.) HTTP/1.1 then closes the connection; HTTP/2
(RST_STREAM NO_ERROR) and HTTP/3 (STOP_SENDING) tell the client to stop
sending the body once the response is out.

Responses the server decides itself (400, 408, 413, 417, 431, 500, 501,
503, and 505 on HTTP/1.1) are the same on every protocol: the status and a
`text/plain; charset=utf-8` body holding its reason phrase ("Content Too
Large", "Service Unavailable", ...).

`Expect: 100-continue` is answered (a 100 interim response) when the
handler first reads the body, on HTTP/1.1, HTTP/2 and HTTP/3; a handler
that never reads it gets no body sent (HTTP/1.1 then closes the
connection after its response). Any other expectation gets 417 without
running the handler (an HTTP/1.0 request's expectations are ignored).

## Correctness

- Rejects request smuggling variants: duplicate `Content-Length` (even
  with equal values, on every protocol), `TE + CL`, obs-fold.
- Rejects header injection in responses (CR/LF/NUL in name or value).
- One timeout model on every protocol: `:handshake-timeout`,
  `:header-timeout` (wall clock from the first byte of a request head:
  slowloris protection), `:read-timeout` and `:write-timeout` (no
  progress), `:idle-timeout` and the opt-in `:handler-timeout` (503).
  See [options.md](options.md#timeouts).
- Connection caps: `:max-connections` and `:max-connections-per-ip`.
- Response policy shared by every protocol: status 200-599 (101 only for
  a WebSocket upgrade) else 500, token header names and RFC 9110 values
  else 500, a `Date` header unless the handler sent one.
- Request heads on HTTP/2 and HTTP/3 are validated with the same rules
  (pseudo-headers, `:scheme`, `:authority` / `Host`, connection-specific
  fields, `TE`, `Content-Length`); a well-formed CONNECT gets 501, as on
  HTTP/1.1.
- Enforces `:max-request-body-bytes` upfront (Content-Length → 413
  without running the handler) or mid-stream (the handler's body read
  fails; 413), the same on every protocol.
- One request-head limit on every protocol: `:max-header-bytes` and
  `:max-header-fields`, 431 above.
- HTTP/2: CVE-2023-44487 rapid-reset mitigation via
  `:http2-stream-reset-limit`, CONTINUATION-flood mitigation via
  `:http2-continuation-limit`.
- HTTP/3: RFC 9114 header validation, GOAWAY monotonicity,
  control-stream parser with connection-level error propagation,
  graceful `CONNECTION_CLOSE` on shutdown.

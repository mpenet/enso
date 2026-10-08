# Handlers, response bodies, WebSocket, SSE

Standard Ring 1.x handler signature: `(fn [request] response)`.
Same request map across HTTP/1.1, HTTP/2, HTTP/3. `:protocol` reflects the
negotiated version (`"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3.0"`); `:scheme` is
`:https` on TLS connections (always for HTTP/2 and HTTP/3), `:http`
otherwise. Response bodies and `:error-handler` behave the same on every
protocol; WebSocket is HTTP/1.1 only.

## Response body types

- `String`, `byte[]` — inlined or single-write. Strings are encoded with
  the `charset` of the `Content-Type` header, UTF-8 when there is none (as
  Ring does); an unknown charset is a 500.
- `java.io.InputStream` — chunked (HTTP/1.1) or close-delimited. When the
  response has a `Content-Length` header, sent as a fixed-length body.
- `java.io.File` — zero-copy via `FileChannel.transferTo(SocketChannel)`
  on plain HTTP. User-space copy on TLS.
- `clojure.lang.ISeq` — streamed element by element (each `str`'d and
  encoded like a String body) with chunked transfer encoding on HTTP/1.1,
  DATA frames on HTTP/2 and HTTP/3.
- `(fn [ChunkedWriter])` — streaming writer for SSE, long-poll,
  incremental output. Handler drives writes with `enso/write!` +
  `enso/flush!`.
- Anything satisfying `ring.core.protocols/StreamableResponseBody` —
  dispatched only when `ring.core.protocols` is on the classpath. The
  types above take priority.

Header values may be a string or a seq of strings (one field per value).
A header name that isn't a token, a value with control characters, or any
other body type makes the response a 500.

## SSE / long-poll

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

## WebSocket (Ring 1.11+ shape)

HTTP/1.1 only (`Upgrade: websocket`).

```clojure
(defn ws [req]
  {:ring.websocket/listener
   {:on-open    (fn [socket] ...)
    :on-message (fn [socket msg] (.sendText socket (str "echo: " msg)))
    :on-close   (fn [socket code reason] ...)}
   :ring.websocket/protocol "chat"}) ; optional subprotocol
```

The listener is either a map of `:on-open` `:on-message` `:on-ping`
`:on-pong` `:on-error` `:on-close` fns, or — when
`org.ring-clojure/ring-websocket-protocols` is on the classpath — anything
implementing `ring.websocket.protocols/Listener` (and optionally
`PingListener`). Any other value fails the request with a 500.

`socket` is a `com.s_exp.enso.websocket.WebSocketSocket`. With
ring-websocket-protocols on the classpath it also implements
`ring.websocket.protocols/Socket` and `AsyncSocket`, so `ring.websocket/send`,
`ping`, `pong`, `close` and `open?` work on it; async sends complete on the
calling thread before invoking the callback.

- Text + binary messages; fragmented messages are reassembled. Messages
  are capped by `:max-request-body-bytes` (10 MiB when that is 0); larger
  ones close the connection with 1009.
- Ping/pong: auto-pong on ping unless `:on-ping` (or `PingListener`) is
  provided. Ping/pong payloads are limited to 125 bytes
  (`IllegalArgumentException` above).
- Protocol violations close with 1002, invalid UTF-8 with 1007.
- `(.close socket code reason)` sends CLOSE, then waits up to 5 s for the
  peer's CLOSE before dropping TCP; `:on-close` receives the peer's code.
  Codes must be 1000-1003, 1007-1014 or 3000-4999 and the reason at most
  123 UTF-8 bytes (`IllegalArgumentException` otherwise).
- `:idle-timeout` (30 s by default, 0 disables) bounds how long no frame
  may arrive from the client. When it passes the server sends CLOSE 1001
  "idle timeout" and drops TCP; `:on-close` receives 1001. Server-push
  sockets whose clients stay silent need client pings or a larger value.
- On server stop, open WebSockets are sent CLOSE 1001 "server shutting
  down" and get until `:shutdown-timeout` to finish the closing handshake.

## Error handling

`:error-handler` — `(fn [request throwable])` returning a Ring response.
Runs when the main handler throws or returns nil. If the error handler
itself throws or returns nil, a fallback 500 text response is sent. Applies
to HTTP/1.1, HTTP/2 and HTTP/3 alike.

## Correctness

- Rejects request smuggling variants: duplicate `Content-Length`, `TE + CL`,
  obs-fold.
- Rejects header injection in responses (CR/LF/NUL in name or value).
- Slowloris protection via `:request-timeout` (wall-clock deadline per
  request).
- Enforces `:max-request-body-bytes` upfront (Content-Length → 413) or
  mid-stream (the handler's body read fails; 413 on HTTP/1.1 and HTTP/2,
  stream reset on HTTP/3).
- HTTP/2: CVE-2023-44487 rapid-reset mitigation via
  `:http2-stream-reset-limit`, CONTINUATION-flood mitigation via
  `:http2-continuation-limit`.
- HTTP/3: RFC 9114 header validation, GOAWAY monotonicity,
  control-stream parser with connection-level error propagation,
  graceful `CONNECTION_CLOSE` on shutdown.

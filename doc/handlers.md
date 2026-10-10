# Handlers

A handler is a plain Ring function, `(fn [request] response)`. With
`:async true` it is a Ring asynchronous handler instead (see
[Async handlers](#async-handlers)). The request map, response bodies and
`:error-handler` behave the same on HTTP/1.1, HTTP/2 and HTTP/3.
WebSocket is HTTP/1.1 only: a WebSocket response on HTTP/2 or HTTP/3 is
answered 501.

## Request map

The Ring SPEC keys, on every protocol:

| Key | Value |
|---|---|
| `:server-port` | local port |
| `:server-name` | from the Host header, else the local address |
| `:remote-addr` | client address, IPv6 in RFC 5952 short form |
| `:uri`, `:query-string` | from the request target |
| `:scheme` | `:https` on TLS connections (always for HTTP/3), `:http` otherwise, h2c included |
| `:request-method` | lowercase keyword, extension methods included |
| `:protocol` | `"HTTP/1.0"`, `"HTTP/1.1"`, `"HTTP/2.0"` or `"HTTP/3.0"` |
| `:headers` | lowercase names; repeated fields joined with `", "`, cookies with `"; "` |
| `:body` | an `InputStream`, or nil when the request has no body |
| `:ssl-client-cert` | the client's `X509Certificate` when TLS verified one, else nil (always nil on HTTP/3) |

A request has no body on HTTP/1.1 when it has no Transfer-Encoding and no
(or a zero) Content-Length, and on HTTP/2 and HTTP/3 when its HEADERS frame
ends the stream.

The map is built lazily and stays lazy through middleware `assoc` and
`dissoc`.

## Responses

`:status` is an integer. A response without one gets 200, as with Ring's
Jetty adapter. A `:status` that is present but nil or not an integer is a
handler error: 500, or `:error-handler` if set.

Header values may be a string, a collection (one field per non-nil
element) or any other value, which is sent as its `str`. nil values are
skipped.

The server frames the body itself. A handler's `Transfer-Encoding` is
dropped, and a handler's `Content-Length` is replaced when the server knows
the length.

The following are sent as a plain 500 and logged at WARNING, without
calling `:error-handler`:

- a status outside 200-599 (101 is allowed only with a WebSocket listener);
- a header name that isn't an RFC 9110 token;
- a header value with control characters (HTAB is fine) or characters above U+00FF;
- two `Content-Length` headers with different values;
- an unknown charset on a String body;
- a body of an unsupported type.

A response to HEAD with a nil body (what Ring's `wrap-head` produces)
carries no Content-Length.

### Body types

| Body | How it is sent |
|---|---|
| `String` | encoded with the `charset` of `Content-Type`, UTF-8 if none (as Ring does) |
| `byte[]` | as is |
| `java.io.InputStream` | streamed, closed by the server |
| `java.io.File` | zero-copy (`FileChannel.transferTo`) on cleartext HTTP/1.1; copied through user space on TLS, HTTP/2 and HTTP/3 |
| `clojure.lang.ISeq` | streamed; each element is `str`'d and encoded like a String, buffered 8 KiB at a time |
| `(fn [ChunkedWriter])` | enso's streaming writer, see [Streaming](#streaming) |
| `ring.core.protocols/StreamableResponseBody` | when `ring.core.protocols` is on the classpath |

The types above `StreamableResponseBody` in the table take priority, so a
fn is always treated as the streaming writer. A `StreamableResponseBody`
writes to an `OutputStream` whose `flush` pushes bytes to the client. From
a synchronous handler the body ends when `write-body-to-stream` returns.
From an asynchronous one it may keep writing from other threads and ends
when it closes the stream, as Ring specifies.

An unknown charset on a seq or fn body is a handler error (500 or
`:error-handler`).

Streamed bodies (InputStream, seq, fn, `StreamableResponseBody`) are sent
chunked on a keep-alive HTTP/1.1 connection, delimited by the connection
closing on HTTP/1.0 or after `Connection: close`, and as DATA frames on
HTTP/2 and HTTP/3. If the handler set a `Content-Length`, exactly that
many bytes are sent; a body that comes up short aborts the response
(connection closed or stream reset).

## Streaming

A fn body receives a `ChunkedWriter`. Write with `enso/write!`, which
buffers (Strings are encoded with the response charset), and push to the
client with `enso/flush!`. The body ends when the fn returns. This works on
every protocol and is meant for SSE, long-poll and incremental output. It
is an enso extension, not part of the Ring spec.

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

The fn finds out that the client left from an exception, not a return
value: `write!` or `flush!` throws an `IOException`.

- On HTTP/1.1 that happens once a write reaches the dead socket, either from `flush!` or from `write!` when the buffer fills. It is usually the second flush after the client left, because the kernel may still accept the first. A fn that waits between writes only notices at its next flush, so send a comment line (`": keep-alive\n\n"`) periodically to find out sooner.
- On HTTP/2 and HTTP/3 it happens once the stream is reset or the connection lost. A reset also interrupts the body's thread, so a blocking call between writes (`Thread/sleep`, a queue take) throws `InterruptedException` right away.

Return from the fn to end the body. Letting the `IOException` escape is
also fine: it is treated as the client going away. Other exceptions may be
logged as server faults (at WARNING on HTTP/2), so catch
`InterruptedException`.

## Async handlers

With `:async true`, the handler is `(fn [request respond raise])`. It runs
on the request's virtual thread, which then waits until `respond` or
`raise` is called, from any thread. Only the first call counts. `raise`
goes to `:error-handler`.

The wait has no bound of its own, just as a synchronous handler's run has
none. `:handler-timeout` bounds both (503), and stopping the server
interrupts the wait. Without a timeout, a handler that never calls
`respond` or `raise` holds its connection (HTTP/1.1) or stream until the
server stops.

Virtual threads make blocking cheap, so a synchronous handler is usually
the simpler choice. Async support exists for middleware written for it.

## Errors

`:error-handler` is `(fn [request throwable])` returning a Ring response.
It runs when the handler throws or returns nil, on every protocol. If it
throws or returns nil too, a plain 500 is sent.

A request body the client got wrong is the client's error. Reading it
throws an `IOException` (400 for broken or truncated framing, 413 over
`:max-request-body-bytes`) or a `java.net.SocketTimeoutException` (408, no
progress for `:read-timeout`, or a body slower than
`:min-data-rate-bytes`). Once the handler returns, the server answers with
that status whatever the handler did with the exception: rethrown, wrapped
or swallowed. The error handler is not called. Catch the supertypes; the
concrete classes are internal. After the response, HTTP/1.1 closes the
connection, HTTP/2 sends RST_STREAM(NO_ERROR) and HTTP/3 STOP_SENDING, so
the client stops sending the body.

Responses the server produces itself (400, 408, 413, 417, 431, 500, 501,
503, and 505 on HTTP/1.1) look the same on every protocol: the status and
a `text/plain; charset=utf-8` body with the reason phrase ("Content Too
Large", "Service Unavailable", ...).

`Expect: 100-continue` is answered with a 100 interim response when the
handler first reads the body, on every protocol. If the handler never reads
it, the client never sends the body, and HTTP/1.1 closes the connection
after the response. Any other expectation gets 417 without running the
handler. Expectations on HTTP/1.0 requests are ignored.

## WebSocket

WebSocket uses the Ring 1.11 API, over HTTP/1.1 (`Upgrade: websocket`)
only.

```clojure
(require '[ring.websocket :as ws]) ; org.ring-clojure/ring-websocket-protocols

(defn handler [req]
  {:ring.websocket/listener
   {:on-open    (fn [socket] ...)
    :on-message (fn [socket msg] (ws/send socket (str "echo: " msg)))
    :on-close   (fn [socket code reason] ...)}
   :ring.websocket/protocol "chat"}) ; optional subprotocol
```

The listener is a map of `:on-open`, `:on-message`, `:on-ping`,
`:on-pong`, `:on-error` and `:on-close` fns. When
`org.ring-clojure/ring-websocket-protocols` is on the classpath it may
also be anything implementing `ring.websocket.protocols/Listener` (and
optionally `PingListener`). Any other value is a handler error.

`socket` is a `com.s_exp.enso.api.WebSocketSocket`. With
ring-websocket-protocols on the classpath it also implements
`ring.websocket.protocols/Socket` and `AsyncSocket`, so
`ring.websocket/send`, `ping`, `pong`, `close` and `open?` work on it.
Without that library, call the socket directly with a type hint:
`(.sendText ^com.s_exp.enso.api.WebSocketSocket socket msg)`.

A request that isn't a valid upgrade gets 400 (426 for a WebSocket version
other than 13), a refused `Origin` gets 403, and a
`:ring.websocket/protocol` the client didn't offer is a 500. Headers set by
the handler are sent on the 101.

### Messages and sends

Text and binary messages are supported, and fragmented messages are
reassembled. A message may be at most `:ws-max-message-bytes` (1 MiB) and
must arrive within `:read-timeout` of its first frame. Past either the
connection fails with 1009 or 1008.

Sends may come from any thread and go out in call order. A synchronous
send writes on the calling thread, bounded by `:write-timeout`. A
synchronous send from `:on-message`, made while more of the client's
messages are already read, waits in the buffer so the replies to them
share one write. It goes out before the server waits for more input, or
after about 10 ms if a handler takes longer. An
asynchronous send (`ring.websocket/send` with callbacks, `.sendTextAsync`,
`.sendBinaryAsync`) queues the message and returns at once. A writer
virtual thread sends it and calls the success callback. Once
`:ws-max-queued-bytes` are queued, further sends fail at once. Don't modify
a `ByteBuffer` sent asynchronously until its callback has run. The writer
thread only exists while there is something to write and ends after a
second idle.

After the server sent CLOSE, or once the connection is gone, every send
throws `IOException` "WebSocket closed", and asynchronous sends call their
fail callback.

Pings are answered automatically unless `:on-ping` (or `PingListener`) is
provided. Pings and pongs never wait behind a stalled write; they queue
behind it. Their payload is limited to 125 bytes
(`IllegalArgumentException` above).

### Closing and failures

`(.close socket code reason)` or `ring.websocket/close` sends CLOSE, then
waits up to `:ws-close-timeout` (5 s) for the client's CLOSE before
dropping TCP. `:on-close` receives the client's code, or 1006 if it never
answered. Codes must be 1000-1003, 1007-1014 or 3000-4999, and the reason
at most 123 UTF-8 bytes (`IllegalArgumentException` otherwise).

Close codes the server sends:

| Code | Cause |
|---|---|
| 1001 | `:idle-timeout` passed ("idle timeout"), or the server is stopping ("server shutting down") |
| 1002 | protocol violation |
| 1007 | invalid UTF-8 or corrupt compressed data |
| 1008 | message not complete within `:read-timeout` |
| 1009 | message over `:ws-max-message-bytes` |
| 1011 | `:on-open`, `:on-message`, `:on-ping` or `:on-pong` threw ("internal error") |

A listener exception closes with 1011 whatever it is, including an
`IOException` from the listener's own I/O, and its message stays on the
server. Exceptions from `:on-error` and `:on-close` are ignored.
`:on-error` receives a `com.s_exp.enso.api.WebSocketException` (with
`.code`) for protocol failures and the listener's exception otherwise;
`:on-close` then gets the failure code. After a failure the server keeps
reading until the client's CLOSE, or `:ws-close-timeout`, so its own CLOSE
isn't lost to a TCP reset.

`:idle-timeout` (75 s) bounds how long the client may send nothing. For
server-push sockets whose clients stay silent, set `:ws-ping-interval`
below it: the server pings quiet clients and their pongs keep the
connection open.

On server stop, open WebSockets get CLOSE 1001 and have until
`:shutdown-timeout` to finish the closing handshake.

### Compression

With `:ws-compression true`, permessage-deflate (RFC 7692) is negotiated
when the client offers it, with any client window size. For a server
window under 15 bits, which `java.util.zip` can't produce, only messages
that fit the window are compressed, each on its own. Inflation stops at
`:ws-max-message-bytes`. Messages under 256 bytes are sent uncompressed,
and a message whose compressed form exceeds 64 KiB is sent as several
frames.

A connection quiet for a second gives back its grown buffers (message
assembly, compression, TLS records); the next message grows them again.

### Origin and authentication

Browsers attach cookies to cross-site WebSocket handshakes, and WebSockets
aren't covered by CORS. By default only the server's own origin (its
`Host`) may open a WebSocket. List others in `:ws-allowed-origins`: a
collection of origins, `["*"]` for public cookie-less endpoints, or a
predicate fn. A handshake without `Origin` doesn't come from a browser and
is accepted.

Authenticate in the handler before returning the listener. The upgrade
request carries the cookies and headers.

`:ws-max-message-bytes`, `:read-timeout`, `:idle-timeout`,
`:ws-max-queued-bytes` and `:max-connections` bound what one client can
make the server hold.

## Supported API

The supported API is the `s-exp.enso` namespace,
`com.s_exp.enso.EnsoServer` and the `com.s_exp.enso.api` package: the Ring
request and response types, `ChunkedWriter`, `ServerEvents`, `Config`, and
the WebSocket socket, listener and exception types.

The other packages (`core`, `http1`, `http2`, `http3`, `websocket`,
`quiche`, `util`) are internal and may change in any release. Exceptions
they throw at handlers extend `java.io.IOException`, so catch that.

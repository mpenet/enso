# Architecture

How the server is put together, the contracts of the shared core every
protocol driver builds on, how each driver uses them, and the allocation
budget. Written for people changing the drivers.

## Layering

```
s-exp.enso (Clojure)      option table → Config; Ring response coercion (->response);
                          WebSocket listener adaptation; Ring protocols via vars
com.s_exp.enso.api        Config, Request (the Ring request map), Response, StreamingBody,
                          RingHandler, RingErrorHandler, ChunkedWriter, ChunkedOutputStream,
                          ServerEvents, WebSocketListener, WebSocketSocket, WebSocketException
com.s_exp.enso            EnsoServer: lifecycle, acceptor, limiter, TLS + ALPN, h2c detection,
                          shutdown
com.s_exp.enso.core       protocol-neutral pieces shared by drivers (below)
com.s_exp.enso.util       RingHeaders (Ring header maps for every protocol), Long2ObjectHashMap
com.s_exp.enso.http1      HttpConnection (HTTP/1.1, WebSocket upgrade), RequestReader, ResponseWriter
com.s_exp.enso.websocket  WebSocketConnection, WebSocketHandshake, PerMessageDeflate, Utf8, ZlibPool
com.s_exp.enso.http2      Http2Connection (framer, state), Http2Writer (scheduling, output),
                          Http2Exchange (Ring mapping), Http2Stream, Http2StreamTable,
                          ClosedStreams, RequestBody, HPACK
com.s_exp.enso.http3      Http3Listener, Http3Loop (sharded event loops), Http3Connection,
                          Http3ControlStreams, Http3RequestReader, Http3BodyPipe,
                          Http3ResponseWriter, Http3ResponseBody, Http3Exchange, QPACK
com.s_exp.enso.quiche     JNI bindings to libquiche, UDP socket I/O (batched, GSO, reuseport
                          steering), Retry tokens, stateless Initial close
```

Drivers depend on `core`, `api` and `util`, plus two deliberate links:
the HTTP/1.1 driver hands an upgraded connection to `websocket`, and
QPACK reuses HPACK's Huffman code (`http2.HpackHuffman`, the same RFC 7541
table). HTTP/1.1 and HTTP/2 use `EnsoServer` for its protocol names and
`forceClose`; HTTP/3 sits on `quiche`. `core` and `api` depend on each
other (`api` types use `RequestHead`, `TlsSocket`, `Causes`, `LogLimiter`
and `ChunkedWriters`; `core` uses the api request, response, handler,
event and config types) and on nothing protocol-specific. `util` builds
Clojure maps.

## Threading

| Thread | Kind | Runs |
|---|---|---|
| `enso-acceptor` | platform, daemon | `accept()`, limiter check, dispatch. Never blocks on a connection. |
| `enso-timer` | platform, daemon | the shared `Timer` wheel; callbacks only (never block). |
| connection thread | virtual, one per TCP connection | socket options, TLS handshake + ALPN (or, with `:http2c`, a look at the first bytes for the HTTP/2 preface), then the driver |
| HTTP/1.1 | the connection thread | parse, handler, write, keep-alive loop; a WebSocket read loop after an upgrade |
| WebSocket sends | any thread | synchronous: the caller, under the connection's write lock |
| WebSocket writer | virtual, started by an asynchronous send; ends after a second with nothing queued | queued (async) frames and pongs that found a write in progress |
| HTTP/2 framer | the connection thread | frame reads, HPACK decode, request-head validation, dispatch |
| HTTP/2 output | whichever thread has output and finds no writer active (usually the handler that just answered), else a parked producer it is handed to, or a short-lived virtual flusher; there is no writer thread | packs control frames and stream output into batches and writes them (`Http2Writer`) |
| HTTP/2 handlers | virtual, one per stream | handler + response body |
| HTTP/3 event loops (`enso-h3-loop-<i>`) | platform, daemon, `:http3-event-loops` of them (default one per core on Linux, one elsewhere) | for the connections each owns: receive and send batches, routing by connection id, `quiche_accept`, quiche I/O, H3 framing, QPACK, request-head validation, responses, connection deadlines |
| HTTP/3 handlers | virtual, one per stream | handler; streamed bodies hand slices to the connection's loop |
| `enso-h3-cert-watcher` | virtual, one per HTTP/3 listener with `:http3-cert-reload-interval` | checks the certificate files between sleeps, loads a changed pair |
| timeout responders, closers | short-lived virtual | a 503 / close started from a timer callback, the HTTP/2 graceful close and final GOAWAY, the HTTP/1.1 held-output flush, the WebSocket close timeout, the HTTP/3 listener's close during `EnsoServer.close()` |

## Lifecycle (EnsoServer)

- The constructor records its arguments and binds nothing.
- `start()` creates the `Timer`, the connection executor, configures the
  TLS context, binds the TCP listener (`SO_REUSEADDR` and `SO_RCVBUF`
  before bind), starts the HTTP/3 listener with `:http3` (the JNI shim
  loads only when it starts, so without `:http3` no native code is
  loaded) and the acceptor. Any failure
  releases everything already started and rethrows; a server is started
  at most once.
- The acceptor admits each connection through the `ConnectionLimiter`,
  then runs it on a virtual thread (`Accepted`). If dispatch throws, the
  slot is released and the socket closed. `Accepted` registers itself with
  the `ConnectionRegistry` before anything can block, applies
  `TCP_NODELAY` / `SO_LINGER` / `SO_SNDBUF` to the `SocketChannel`, runs
  the TLS handshake (`TlsSocket`: `SSLEngine` over the channel, wall-clock
  deadline, ALPN, provider rotation, session cache) and the driver, and
  in `finally` force-closes, unregisters, releases the limiter slot and
  reports the connection's end. Plain HTTP keeps the channel's socket, so
  file bodies use `FileChannel.transferTo` (zero-copy).
- h2c (`:http2c`): on a plain listener `Accepted` reads up to the 24
  bytes of the HTTP/2 preface, stopping at the first byte that can't
  belong to it (the first byte bounded by `:idle-timeout`, the rest by
  `:header-timeout`, as an HTTP/1.1 head would be). A full preface starts
  the HTTP/2 driver with the preface consumed (protocol "h2c", its first
  SETTINGS still bounded by `:handshake-timeout`); anything else goes to
  HTTP/1.1 with the bytes read so far replayed first. Prior knowledge only
  (RFC 9113 §3.3): `Upgrade: h2c` is not offered, RFC 9113 deprecated it.
- TLS (`TlsSocket`): renegotiation started by the client after the
  initial handshake (TLS 1.2 and below) is refused and fails the
  connection; TLS 1.3 post-handshake messages (KeyUpdate) are driven
  through. Handshake failures are reported as "tls" protocol errors:
  "handshake-timeout" (deadline or a silent peer), "handshake",
  "renegotiation". `shutdownOutput()` sends close_notify then FIN and
  keeps the input open (lingering close); `releaseIdleBuffers()` swaps
  the ~16 KiB record buffers for 512-byte ones while a connection is
  idle (they grow back through the underflow / overflow paths).
- `close()`: see Graceful shutdown.
- The `:server-events` listener is wrapped by `core.GuardedEvents` in the
  server's `Service`: every call swallows and logs (WARNING,
  rate-limited) what the listener throws, so a faulty listener can't kill
  the acceptor, a connection or an HTTP/3 event loop, and no call site
  needs its own guard. `start()` builds the server's `core.Service`.

## Shared core contracts

### Service (`core.Service`)

One per server (and per standalone HTTP/3 listener), built by `start()`:
the Ring handler and error handler, `Config`, the `Timer`, the guarded
event listener and the memory budget. Drivers report through it
(`protocolError` to the listener and JFR, `connectionOpened` / `Closed`
to the listener; the JFR connection event is the driver's own)
and ask it the response policy every protocol shares: Date unless the
handler sent one (`addsDate`), the `:server-header` value
(`serverField`), Alt-Svc on HTTP/1.1 and HTTP/2 (`altSvcField`). Each
driver only encodes the answer its own way (cached `Date:` line bytes,
HPACK, pre-encoded QPACK lines).

### Exchange (`core.Exchange`)

The protocol-neutral part of serving one request. Drivers extend it with
the object they already have per request, so it costs no extra object:
HTTP/1.1 an inner `Call` per connection, reused (`reset()` per request);
HTTP/2 the `Http2Stream`; HTTP/3 the request stream (`Http3Stream` extends
it, the control streams are a `Control` subclass that never serves).
Drivers parse heads and frame bytes; the exchange decides what to send.

- The exchange is a `Timer.Task`: the `:handler-timeout` node.
- Claim (one CAS): exactly one of the handler (`HANDLER`), the timeout
  (`TIMED_OUT`) or a cancel (`CANCELLED`: reset, connection gone) owns
  the response. `onTimeout()` claims and calls the driver's
  `handlerTimedOut()` (timer thread, must not block: HTTP/1.1 writes the
  503 from a virtual thread, HTTP/2 queues it, HTTP/3 signals the loop);
  `cancel()` claims for nobody and interrupts `handlerThread`.
- `serve(handler)` runs the handler on the calling thread and returns the
  response to send, or null when the timeout or a cancel won (whatever
  the handler returned is closed). `outcome` says which kind:
  `RESPONSE` (the handler's, or the error handler's for a failure),
  `CLIENT_ERROR`, `SERVER_ERROR` (no error handler response: 500).
- Client errors, one taxonomy for every protocol: a request body read
  fails with `RequestBodyException` (400 framing / truncated, 413 over
  `:max-request-body-bytes`) or `RequestBodyTimeoutException` (a
  `SocketTimeoutException`, 408); a handler may also throw `HttpError`.
  The driver's body records the first failure (`bodyFailure()`), so the
  status is answered whether the handler rethrew, wrapped (cause chain,
  bounded by `core.Causes`) or swallowed it; the error handler isn't
  called; reported as a protocol error ("bad-request", "body-too-large",
  "read-timeout"), logged at FINE.
- Error responses: `HttpStatus.error(status)`, shared prebuilt responses
  (status, `text/plain; charset=utf-8`, the reason phrase as body), the
  same bytes on every protocol (HTTP/1.1 adds `Connection: close`).
- Reporting: `begin()` when the head is complete (a timestamp and a JFR
  event only while traced), `complete()` once the response is finished:
  `requestCompleted(protocol, method, status, requestBytes,
  responseBytes, nanos)` and the JFR event. Primitive arguments and
  objects the request holds: nothing is allocated for it.
- Allocation: none. The claim is one CAS per request; the error handler
  path and error responses use shared objects.

### Memory budget (`core.MemoryBudget`)

`:max-buffered-bytes` (default a quarter of the max heap, at least
1 MiB): one atomic counter for every byte buffered on behalf of peers,
server-wide. HTTP/3 also gives each connection a budget of its own, its
connection window, that caps what that connection's request bodies hold
together.
`tryReserve(n)` refuses past the limit (for buffers that can say no);
`charge(n)` keeps bytes that already arrived (the peer was entitled to
send them) and lets the counter go over; `release(n)` gives back and,
when that leaves room, wakes the registered `Waiter`s (intrusive nodes,
lock-free stack; callbacks run on the releasing thread and must not
block). `exhausted()` is the backpressure signal. Allocation-free.

Adopted:
- HTTP/2 request bodies (`RequestBody`): buffered DATA charged until
  read or dropped; while exhausted, credit for read bytes is held back
  (stream and connection WINDOW_UPDATEs) and granted by a waiter once the
  budget has room. Overshoot is bounded by credit already granted.
- HTTP/2 streamed responses (`Http2Writer`): bytes copied into a
  stream's ring are charged until written or dropped; while exhausted a
  ring holds one frame, so its producer waits.
- HTTP/3 request bodies (`Http3BodyPipe`): charged, to the server's
  budget and to the connection's, until read or discarded (the
  exchange's end discards what's left); `hasRoom()` is false while either
  is exhausted, so the loop stops reading request streams (QUIC flow
  control pushes back), and `resumeWhenDrained` registers a waiter that
  signals the stream's loop.
- WebSocket asynchronous sends: `tryReserve` per queued frame, a send
  over budget fails at once (its fail callback runs); released once
  written or dropped.
- WebSocket incoming messages: what a message holds past its first
  64 KiB is charged until `on-message` returns; while exhausted the read
  loop stops reading the message (TCP pushes back), within the message's
  `:read-timeout`.

Not charged: HTTP/3 response bytes quiche didn't take yet (a fixed body
is sent from the handler's array; a streamed body is a blocking hand-off,
so it holds only the producer's buffer). A buffer joins the budget by
charging what it holds for a peer, releasing it on every path the bytes
leave (read, written, dropped at close), and pausing its credit / reads
while `exhausted()` with a `Waiter` to resume.

### Timer (`core.Timer`)

One per server; a standalone HTTP/3 listener has its own. HTTP/3 uses it
only for `:handler-timeout`: its connection deadlines live in each event
loop's heap. A hashed timing wheel: 512 slots of 10 ms (one rotation is 5.12 s; longer delays wait in
their slot for later rotations).

- `Timer.Task` is an intrusive node: extend it (or hold one) per
  connection or per stream; reuse it for every request.
- `schedule(task, ms)` arms or re-arms: at most one pending expiry, never
  earlier than the delay, at most about one tick (10 ms) late.
  Shortening, or arming a disarmed task, pushes the node on a lock-free
  incoming stack for the timer thread; lengthening only moves the
  deadline (one CAS) and the timer thread re-buckets the node when its old
  slot comes up. So a keep-alive connection re-arming per request costs
  the timer thread one visit per timeout period.
- `cancel(task)` is one CAS; true when it disarmed the task before it
  fired. Exactly one of a cancel and the expiry wins. The node stays in
  its slot until the wheel passes it (up to one rotation), which keeps
  what it references reachable for that long.
- `retire(task)` is `cancel` plus an unlink on the next tick. Use it for
  per-request nodes (h2 streams, h3 exchanges) and for a connection's
  nodes when the connection closes, so a closed connection and its
  buffers aren't kept alive by the wheel.
- `onTimeout()` runs on the timer thread and must not block: flip state,
  interrupt, enqueue, or start a virtual thread for anything that may
  block (writing a 503, closing a socket with `SO_LINGER`). It may re-arm
  its own task. Exceptions are logged (rate-limited) and swallowed.
- Allocation: none for schedule / cancel / expiry.

### Write watchdog (`core.WriteWatchdog`, `core.WatchedOutputStream`)

`:write-timeout`: a write that makes no progress for the timeout means
the peer stopped reading; the connection is force-closed, which fails the
blocked write.

- One `WriteWatchdog` (a `Timer.Task`) per connection. Bracket every
  blocking write with `enter()` / `exit()`, or write through a
  `WatchedOutputStream`, which also slices writes to 256 KiB so one huge
  write still reports progress. One writer at a time.
- Per write: two volatile increments and a flag; the timer is touched
  only when the node is disarmed (at most once per timeout period). A
  write younger than the timeout is never declared stalled; a stalled
  one is caught within two timeouts.
- `onStall()` runs on the timer thread: start a virtual thread that
  force-closes (`WriteWatchdog.forceCloseAsync` or the driver's own).
- Allocation: none per write.

### Response head (`core.ResponseHead`)

The response policy, computed once from `api.Response` into reusable
storage that a driver serialises from. One instance per connection
(HTTP/1.1) or per writer; `prepare(response, headRequest, mode)` then
`release()` (or `disownBody()` before streaming a body the driver closes).
`prepare` throws `IllegalArgumentException` for a handler error, leaving
the body the caller's to close; the driver answers 500 instead.

- Status: 200-599, or 101 only with a WebSocket listener.
- Names: RFC 9110 tokens. Values: no CTL but HTAB, nothing above U+00FF;
  non-String values are snapshot once with `String.valueOf` and that
  snapshot is validated and sent (Long / Integer stay numbers, written
  without a String). nil values are skipped; a `List` value is one field
  per non-nil element.
- Framing is the server's: `Transfer-Encoding` is dropped; a handler
  `Content-Length` is dropped when the length is known, kept (and must be
  1*DIGIT) for stream bodies, HEAD and 304; never on 1xx / 204.
  `declaredLength()` is a handler length the driver must honour exactly
  (send that many bytes or abort).
- `MULTIPLEXED` mode (h2 / h3) drops Connection, Keep-Alive,
  Proxy-Connection and Upgrade and lowercases names; `HTTP1` keeps them
  and reports `Connection: close` (`closeRequested()`).
- Date, Server and Alt-Svc are only noticed (`hasDate()` ...): the driver
  adds its own when absent, in its cheapest encoding (`HttpDates.dateLine()`
  bytes for HTTP/1.1, `HttpDates.now()` for header blocks).
- Two Content-Length keys (differing in case) with different values are
  a handler error (which length frames the body would be a guess).
- Body kinds: `BODY_NONE`, `BODY_BYTES`, `BODY_ASCII` (a String whose
  chars are ASCII in an ASCII-compatible charset: written one byte per
  char, no encoding), `BODY_FILE` (opened here so the length and the
  transfer agree), `BODY_STREAM`, `BODY_STREAMING`. `bodyAllowed()` is
  false for HEAD, 1xx, 204, 304.
- Allocation: none for the common shapes once its arrays have grown
  (Clojure map headers with String values, String / byte[] / nil bodies).
  Clojure maps are walked with `IKVReduce` and one reused visitor, never
  `entrySet`. Exceptions are listed in the class doc (lowercasing a
  mixed-case name in multiplexed mode, non-String values, non-ASCII text,
  file bodies).

### Request head (`core.RequestHead`)

Validates an HTTP/2 or HTTP/3 request field section as it is decoded,
field by field, with no allocation. One instance per connection, `reset()`
per request, used by the thread that decodes headers.

- `add(name, value)` returns `PSEUDO` (consumed), `FIELD` (put it in the
  Ring map), `HOST` (kept; put `authority()` under "host" once) or
  `MALFORMED`.
- `finish()` returns `OK`, `MALFORMED`, or `NOT_IMPLEMENTED` for a
  well-formed CONNECT (answer 501). A malformed request is a stream error:
  h2 RST_STREAM(PROTOCOL_ERROR), h3 H3_MESSAGE_ERROR. `failure()` names
  the broken rule.
- Rules: pseudo-headers first, once each, only :method :scheme
  :authority :path; :method a token; :scheme http or https; :path
  origin-form, "*" only for OPTIONS; :authority host[:port] without
  userinfo; :authority or Host present and equal ignoring case; names
  lowercase tokens; values without CTL (HTAB allowed), nothing above
  U+00FF, no leading / trailing whitespace; Connection, Keep-Alive,
  Proxy-Connection, Transfer-Encoding, Upgrade forbidden; TE only
  "trailers"; Content-Length 1*DIGIT, once (a repeat is malformed even
  with an equal value, as HTTP/1.1 answers 400: RFC 9110 §8.6 permits
  rejecting, one rule everywhere).
- `uri()` / `query()` split :path for the Ring request (lazily, so
  validation stays allocation-free): the one place HTTP/2 and HTTP/3 do
  it. HTTP/1.1 splits on its parse bytes, reusing the last Strings.
- Header limits shared by every protocol: `:max-header-bytes` (the
  HTTP/1.1 head; the decoded HTTP/2 header list, advertised as
  SETTINGS_MAX_HEADER_LIST_SIZE; the decoded HTTP/3 field section,
  SETTINGS_MAX_FIELD_SECTION_SIZE) and `:max-header-fields`: 431 over
  either. Over a hard ceiling of 4x (at least 64 KiB) HTTP/2 ends the
  connection (GOAWAY ENHANCE_YOUR_CALM), HTTP/3 resets the stream
  before buffering it.
- Ring header maps: `RingHeaders.mergeDuplicates` (joins repeats, unique
  names out) then `RingHeaders.toMap`: an array map over the array
  itself up to 8 fields (no second duplicate scan), a hash map beyond,
  so building and looking up stay linear in the field count.
- `HeaderNames.index` / `name` / `COUNT`: known request header names by
  index, so the HTTP/1.1 parser keeps per-name state (the last value) in
  a plain array.
- Shared with HTTP/1.1: `isValidAuthority` (Host, absolute-form),
  `isOriginForm`, `isFieldValue`, `parseAbsoluteForm` (RFC 9112 §3.2.2;
  rare, allocates).

### Connection limits (`core.ConnectionLimiter`)

`tryAcquire(address)` on accept, `release(address)` exactly once per
successful acquire. `:max-connections` (global) is one atomic increment,
allocation-free; `:max-connections-per-ip` costs a map update (a node per
address with open connections) and is only on when configured. One limiter
counts TCP and QUIC connections together. A refused TCP connection is
closed before it gets a thread or a TLS handshake ("tcp"
"connection-limit" protocol error); a refused QUIC Initial is dropped
before any connection state exists ("h3" "connection-limit").

### Graceful shutdown (`core.Drainable`, `core.ConnectionRegistry`)

Every connection is registered from accept (before TLS) to close and
leaves only once nothing of it runs any more, its handler threads
included (an HTTP/2 framer waits for its handlers at teardown; a freed
QUIC connection's last handler unregisters it): leaving the registry is
what "drained" means, and an empty registry means every handler thread
was joined. Keeping the entry also keeps the `ConnectionLimiter` slot,
so closing a connection can't leave its handlers running while new
connections open more (the connection-level rapid-reset bypass).
`EnsoServer.close()` closes the TCP listener (the acceptor exits), starts
the HTTP/3 listener's close in parallel (same budget split), calls
`beginDrain()` on every live connection and waits for the registry to
empty until the last part of `:shutdown-timeout` (a quarter, at most one
second); then it `forceClose()`s the rest, which interrupts their
handlers, interrupts the connection threads (HTTP/1.1 handlers run
there) and waits for the registry until the deadline. Handlers still
running then ignore their interrupt: logged, left behind. After a clean
drain it also joins the connection threads, so no connection thread
outlives `close()`. Registry loops visit every entry whatever one throws.

- `beginDrain()`: stop taking requests, finish in-flight ones, close.
  HTTP/1.1 closes an idle connection at once (a TLS close_notify bounded by
  the write watchdog) and sends `Connection: close` on the response in
  flight; HTTP/2 sends GOAWAY(NO_ERROR) and closes when
  its handlers are done; a WebSocket starts the closing handshake with 1001;
  HTTP/3 sends a GOAWAY that refuses nothing, then, after twice the RTT
  (10 ms to 1 s), a second one naming the first refused request, and
  closes once the requests below it are answered. A connection still in
  its TLS or QUIC handshake is force-closed.
- `forceClose()`: close now, without waiting for any writer (TLS: no
  close_notify). Idempotent.
- Both are called from the closing thread, race with the connection's own
  threads and must return promptly: anything that may block runs on a
  virtual thread.
- The HTTP/3 listener's close stops its certificate watcher, drains its
  connections as above until the last quarter of its budget (at most one
  second), force-closes the rest, then stops and joins the event loops;
  quiche configurations and sockets are freed only once every loop has
  exited.

### Observability (`api.ServerEvents`, `core.Jfr`, `core.LogLimiter`)

- `ServerEvents` (`:server-events`): `connectionOpened`,
  `connectionClosed`, `requestCompleted` (protocol, method, status,
  request and response body bytes, duration), `protocolError`. Called on
  the connection's threads through `GuardedEvents` (exceptions swallowed
  and logged). With no listener a driver makes no call and takes no
  timestamp. Protocols: "http/1.1", "h2", "h2c" (cleartext, `:http2c`),
  "h3"; "websocket" for an
  upgraded connection (opened at the 101, closed when it ends, inside
  the "http/1.1" connection's own events); "tcp" and "tls" for errors
  before any HTTP (connection limit, handshake failures).
- JFR: `Connection`, `Request` (disabled by default: one event per
  request, on every protocol, from `Exchange`), `ProtocolError`. `Jfr.requests()` etc. are static volatile
  flags following recordings, so the cost without a recording is a field
  read; an event object is only allocated when wanted.
- Logging: client-caused failures at FINE; WARNING only for server
  faults, through a `LogLimiter` per call site (one record per second,
  with a count of suppressed ones). Nothing a client can trigger logs a
  stack trace at INFO or above.

### TLS socket (`core.TlsSocket`)

Besides its stream view, two calls for drivers that manage their own
output:

- `writeRecords(src, off, len, net)` encrypts a byte range as TLS
  records into a caller-owned buffer (at least one packet), as many
  records per channel write as the buffer holds. HTTP/2 pools these
  buffers process-wide, so an idle connection holds none.
- `shutdownOutput()` sends close_notify and half-closes the channel
  while input stays readable, for a lingering close; `close()` still
  closes the channel. The `AdapterSocket` forwards `shutdownOutput`.

### Configuration

The option table in `s-exp.enso` (key, group, default, Config field,
coercion, setter, doc) drives `Config` building, keyword-phrased errors,
unknown-key rejection with a did-you-mean, the `run-server` docstring and
a test that keeps `doc/options.md` in sync. `Config.Builder.build()`
validates ranges and contradictions (ALPN h2 without `:http2`, Alt-Svc
without `:http3`, `:port` 0 with Alt-Svc, an invalid `:server-header`,
`:http2-initial-window-bytes` below 65535, ...).

### Ring protocols

`ring.core.protocols` and `ring.websocket.protocols` are optional. The
adapter holds their vars and reads the root at use (one volatile read),
so types extended with `extend-protocol` after `s-exp.enso` loaded are
honoured.

## Allocation budget

Measured with `ThreadMXBean#getCurrentThreadAllocatedBytes` on the thread
doing the work, after warm-up, so the numbers are exact rather than
sampled. The tests assert the bounds.

| Path | Bytes per operation | Test |
|---|---:|---|
| `Timer` schedule + cancel, re-arm | 0 | `enso-core-test/timer-arm-and-cancel-allocate-nothing` |
| `WatchedOutputStream` write + flush | 0 | `enso-core-test/watched-writes-allocate-nothing` |
| `ResponseHead` prepare + release (2 headers, String body; 20 headers, byte[] body; multiplexed) | 0 | `enso-core-test/response-head-allocates-nothing-per-response` |
| `RequestHead` reset + 8 fields + finish | 0 | `enso-core-test/request-head-validation-allocates-nothing` |
| `ConnectionLimiter` global acquire + release | 0 | `enso-core-test/limiter-unlimited-and-allocation-free` |
| HTTP/1.1 GET, 3 request headers and a query, String body, in-memory socket, whole path incl. Ring adapter, calling thread | ~176-184 (bound 300) | `enso-http1-test/h1-get-allocation-budget` |

Across a whole server JVM (every thread, sockets, the Ring adapter, the
JDK's virtual thread bookkeeping) the separate-process harness measures
393 bytes per HTTP/1.1 GET over 64 keep-alive connections, 235 pipelined,
1,125 per HTTP/2 GET over TLS and 799 per HTTP/3 GET
([performance.md](performance.md#current-numbers); the allocation gate
holds them to `bench/perf/baseline.edn`).

What a GET still allocates, each justified: the `Request` (the Ring
request map itself, one object), the header map (`PersistentArrayMap` and
its `Object[]`), and the `api.Response` that `->response` builds from the
handler's map. These are the Ring contract: a handler receives a
persistent map of Strings. Header names are interned through
`HeaderNames`; a value String is only allocated when it differs from the
last one this connection saw for that name (a keep-alive client repeats
Host, User-Agent, Accept*, Cookie), and likewise the path and query.
Nothing is allocated for timeouts, the write watchdog, response
validation, the Date header (cached bytes), status lines (pre-built) or
the response head (written into a reused buffer).

Per connection (amortized): the parse buffer (4 KiB, grows up to
`:max-header-bytes`), the output buffer (1 KiB, grows: the response head
is built in it and small writes join it, so there is no second buffer),
the watchdog node, the `Accepted` runnable and the virtual thread. A
connection idle for a second gives back what it grew (parse buffer down to
1 KiB, output buffer, body copy buffer, cached values, TLS record
buffers) and waits out `:idle-timeout` with only that.

Heap per idle connection (one request served, or one message echoed,
then idle past the one-second release; 2000 connections, server heap
after full GC divided by the count, the virtual thread's stack included).
Measured once per protocol with a one-off client against
`s-exp.enso-test-server` in its own JVM (`jcmd GC.heap_info`); no test
asserts these:

| Protocol | plain | TLS 1.3 |
|---|---:|---:|
| HTTP/1.1 keep-alive | 9.7 KiB | 16.1 KiB |
| HTTP/2 (h2c / h2) | about 11 KB | about 23 KB |
| WebSocket | 16 KiB | 25 KiB |
| HTTP/3 (QUIC, always encrypted) | – | about 3 KB |

What each driver gives back when idle: HTTP/1.1 shrinks its parse buffer
to 1 KiB and drops grown output and body buffers, cached values and TLS
records; HTTP/2 forgets retired streams and shrinks its input buffer,
header-block buffer, HPACK scratch, field array, TLS records and the
writer's control and encoder buffers (`h2-idle-connection-gives-back-its-buffers`);
a WebSocket keeps a 512-byte read buffer and drops message, compression
and TLS buffers (`ws-idle-connection-gives-back-its-buffers`); an HTTP/3
connection keeps its per-connection scratch on its event loop rather
than on itself, and swaps a stream map that grew past 16 entries.

HTTP/2 GET with 6 request fields answered with a String body, whole path
(framing, HPACK, Ring request, handler adapter, response head and DATA,
handler thread) with no TLS, held to a bound by
`h2-get-allocation-budget` (every thread counted): about 760
bytes/request (bound 1000). What remains, each justified: the
`Http2Stream` (its own timer node and handler `Runnable`, so the handler
timeout and the thread start cost no extra object), the handler's virtual
thread (the JDK allocates the `VirtualThread`, its continuation, a
ForkJoin task and, while `jdk.trackAllThreads` is on (the JDK default),
a node in the root thread container), the Ring `Request`, its header map
and one String per literal header value (values found in the HPACK
dynamic table are shared), the uri String and the `api.Response`.
Nothing is allocated per request for HPACK encoding (reused buffer,
numbers written as digits), the response head (pooled `ResponseHead`),
DATA framing (frames are packed into a pooled batch buffer), the request
body of a GET (`:body` is nil, as Ring wants for a request without one)
or timeouts. Over TLS the JDK's
AES-GCM allocates about 1.3 KB per record written; batching packs several
responses per record when streams are concurrent.

HTTP/3 per request, held to a bound by `h3-get-allocation-budget`
(about 730 bytes with compressed oops, bound 900; about 1050 without,
bound 1300): the request stream
(`Http3Exchange`, which is also the shared `Exchange` and its timer
node), one virtual thread, the decoded header fields, the Ring request
and the handler's `Response`.

The shared `Exchange` adds no object per request on any protocol (it is
the object each driver already had); its claim is one CAS. When it was
introduced, the in-process tests measured no change on HTTP/1.1 (176 B
per GET, 183 B pipelined), a difference within carrier noise on HTTP/2
and 8 bytes on HTTP/3 (the request stream object grew by one alignment
step); wrk against both versions in their own JVMs (4 threads, 64
connections, three alternating rounds) measured 133.9k req/s for both
non-pipelined and 1.90M / 1.91M req/s pipelined at depth 16, within
run-to-run noise.

## How a driver adopts the core

### HTTP/1.1 (adopted)

One connection is three objects plus its reused `Call` exchange (only
`HttpConnection` is public), all
used from the connection's virtual thread but for the timer-driven
handler-timeout 503 and held-output flush:

- `HttpConnection` (the public entry point, `Runnable` + `Drainable`):
  the request loop. Waits for a request, runs the handler, decides
  keep-alive (Connection header, `:max-keep-alive-requests`, server
  stopping, whether the unread body lets the connection survive), drains
  or lingers, and owns the `:handler-timeout` state machine, the WebSocket
  handshake checks and hand-off, `beginDrain` / `forceClose`, the write
  watchdog, events and JFR.
- `RequestReader`: the input side. The parse buffer and its cursors, socket
  reads under the phase's timeout, the idle wait (and giving back grown
  buffers), request line and header parsing, framing headers and
  `Expect`, the request bodies (`FixedLengthBody`, `ChunkedBody`, chunk
  lines and trailers), the lingering-close discard loop, and the bytes
  already buffered behind a WebSocket handshake. The parsing loops only
  touch this object's fields.
- `ResponseWriter`: the output side. The output buffer and the `Output`
  stream over it, the `ResponseHead`, pre-built status lines, the response
  head and body (inline, chunked, fixed-length, `transferTo` file
  transfer, `ChunkedWriter` bodies), error responses, the 100 Continue,
  the 101 Switching Protocols head, and the held-output timer that lets
  pipelined responses share a write.

The reader calls the writer before each socket read (held output taken
back, pending responses flushed), shares its body copy buffer for drains,
and calls the connection for the 100 Continue (ordered with the
handler-timeout 503) and to clear `idle` on a request's first byte.

- Timeouts are socket read timeouts per phase: `:idle-timeout` before the
  first byte of a request (split in two: after one second idle the
  connection gives back its grown buffers, then waits out the rest),
  the remaining `:header-timeout` (wall clock from that byte) while the
  head is incomplete, `:read-timeout` for body reads. No timer operation
  on the common path.
- Writes go through `WatchedOutputStream`; `FileChannel.transferTo` calls
  are bracketed with the watchdog by hand, one slice at a time (a
  transferTo that moves nothing hands the rest to a user-space copy).
- Output: one buffer. The response head is built in it, small writes
  (100 Continue, chunk framing, error responses, WebSocket frames) join
  it, writes of 8 KiB or more go straight to the transport. Chunked
  bodies are framed in place (size line in reserved room in front of the
  data), so a chunk is one write; `ChunkedWriter` uses the connection's
  body buffer instead of its own.
- Pipelining: responses to pipelined requests share a write while the
  next request is already buffered. While its handler runs, held bytes
  are on a one-tick (10 ms) timer: a handler returning first takes them
  back, a slower one doesn't delay them (a virtual thread writes them).
- `:handler-timeout`: the connection's `Call` exchange is the timer
  node; a 503 is written from a virtual thread only if the timeout won the
  claim, then the handler thread is interrupted, then that is published:
  the connection thread waits for it and only then clears its interrupt,
  so the interrupt can't land later (in the lingering close).
- `ResponseHead.prepare(..., HTTP1)`, serialised straight into the head
  buffer; Date from `HttpDates.dateLine()`.
- Request head: `:max-header-bytes` bounds the whole head (request line,
  field lines, CRLFs, empty lines before it), `:max-header-fields` field
  lines at most. Field values without CTL but HTAB. Host and absolute-form
  targets through `RequestHead.isValidAuthority` / `parseAbsoluteForm`;
  origin-form must start with '/', '*' only for OPTIONS, authority-form
  only for CONNECT, which is answered 501.
- Request bodies: chunk-size lines (BWS before ';' allowed) capped at
  4 KiB, extension bytes count against `:max-request-body-bytes`. A body
  error (framing 400, size 413, read timeout 408, early EOF 400) is kept
  on the body as a `RequestBodyException` / `RequestBodyTimeoutException`
  and answered by the exchange after the handler returns (see Exchange).
  `Expect: 100-continue` is answered on the body's first read, ordered
  with the timeout's 503 by a `ReentrantLock` (a monitor would pin the
  carrier while writing on JDKs before 24).
- Unread bodies: whether the connection survives is decided before the
  response head (so `Connection: close` is announced): buffered bytes are
  drained without blocking; a known remainder up to 64 KiB is drained
  after the response; otherwise (a larger or chunked remainder, a 100
  Continue never sent) the connection closes.
- Lingering close after an error response, an unread body, or a close
  the client didn't ask for (keep-alive cap, drain, the handler's
  `Connection: close` on an HTTP/1.1 request without `Connection:
  close`), and whenever input is buffered or readable at close: output
  shut down (FIN, close_notify over TLS), input discarded for up to 2 s
  or until the peer closes, so the client reads the responses instead of
  a reset.
- `Drainable`, `ServerEvents` and JFR wired: every parsed request ends in
  `requestCompleted` (error responses, 503, WebSocket handshake errors
  included); protocol errors "header-timeout", "read-timeout",
  "bad-request", "body-too-large", "header-too-large", "not-implemented",
  "unsupported-version", "handler-timeout", "write-timeout". The
  connection's timer nodes are retired at close.

Measured with `clojure -M:perf` when the design above landed, against
the code before it (10 s after 5 s warm-up, two alternating rounds each;
the load generator shares the CPUs, so throughput differences under ~5%
are noise):

| scenario | req/s before | req/s after | alloc B/req before | alloc B/req after |
|---|---:|---:|---:|---:|
| h1-get | 118.7k / 123.8k | 121.5k / 118.8k | 497 / 499 | 392 / 393 |
| h1-pipelined | 1.30M / 1.27M | 1.32M / 1.32M | 339 / 339 | 235 / 235 |

HTTP/1.1 over TLS 1.3 (h2load `--h1 -c 32`, 10 s), the same comparison:
77.8k req/s and 3510 B/req before, 77.4k req/s and 3280 B/req after. Most of what
remains per request is the JDK's `SSLEngine` (results, record and cipher
state). A direct (off-heap) outbound record buffer was tried: ~5% more
throughput but ~370 B/req more allocated (the cipher copies through a
heap array for a direct destination) and a costly re-allocation after
each idle release, so the buffers stay on the heap. Inbound records are
read through the socket adaptor's stream, the only blocking read that
honours `SO_TIMEOUT`, so they need a heap array.

### WebSocket (adopted through HTTP/1.1)

- Writes go through the upgraded connection's watched stream, so
  `:write-timeout` applies to every write. Reads between messages are
  bounded by `:idle-timeout` (closing handshake with 1001 "idle
  timeout"); reads inside a frame or message by the `:read-timeout`
  message deadline (wall clock from its first frame, CLOSE 1008).
- Sends: synchronous ones write on the caller's thread under the write
  lock; asynchronous ones queue (bounded by `:ws-max-queued-bytes`) for a
  writer virtual thread. Whoever holds the lock writes the queue before
  its own frame, so frames leave in call order. Pings and pongs that find
  the lock taken queue behind the write instead of waiting, so the read
  loop never waits on a stalled writer; the CLOSE it sends waits for the
  lock at most `:ws-close-timeout`.
- Failures (1002/1007/1008/1009/1011) send CLOSE with a reason, then keep
  reading until the client's CLOSE (frames intact) or half-close and
  drain (frames broken), so the CLOSE isn't destroyed by a reset.
- The closing-handshake timer (`:ws-close-timeout`) is a `Timer.Task`,
  retired at close.
- Handshake policy (`websocket.WebSocketHandshake`): same-origin check or
  `:ws-allowed-origins` (403), permessage-deflate negotiation
  (`websocket.PerMessageDeflate`, `:ws-compression`), server-owned
  `Sec-WebSocket-*` response headers.
- Drain: `beginDrain` on the HTTP/1.1 connection starts the closing
  handshake with 1001.
- Asynchronous sends are charged to the memory budget while queued (a
  send over it fails at once); `ServerEvents` see the WebSocket as its
  own connection, protocol "websocket", from the 101 to its end.

### HTTP/2 (adopted)

- One driver for both transports: "h2" after TLS + ALPN, "h2c" on a
  plain listener after the preface (see Lifecycle). The only difference
  is the output path: over TLS a batch is encrypted into pooled record
  buffers (`TlsSocket.writeRecords`), in cleartext it is written to the
  socket as packed. Ring `:scheme` is `:https` or `:http` accordingly.
- Threads: the connection thread is the framer (frame reads, HPACK
  decode, stream admission) and never blocks on output; one virtual
  thread per stream runs the handler. There is no writer thread.
- Output (`Http2Writer`): pull scheduling with a combining writer.
  Handlers queue their response on their own stream (a fixed body is
  handed over whole through a lock-free inbox, a streamed body is copied
  into a per-stream ring of at most 64 KiB); the framer queues control
  frames (SETTINGS / PING ACKs, WINDOW_UPDATE, RST_STREAM, GOAWAY) on a
  priority lane, count-capped (a peer that makes us queue more without
  reading gets GOAWAY(ENHANCE_YOUR_CALM)). Whoever has output and finds
  no writer active packs a batch (control lane first, then one frame per
  ready stream in round robin, up to 64 KiB, four TLS records) under the
  writer lock and writes it outside the lock, encrypting several records
  per channel write (`TlsSocket.writeRecords`). HPACK encoding happens
  while packing, so header blocks reach the wire in encoding order and
  are never encoded for a stream already reset. A reset purges the
  stream's output at once. Producers wait only on their own stream.
- Flow control: streams without credit wait on a blocked list. Credit
  below 1 KiB (and below what the stream has pending) is pooled for
  20 ms (CVE-2019-9511 data dribble). One deadline per connection covers
  stalls: a stream whose window stays shut for `:write-timeout` is reset
  with CANCEL, a connection window shut that long ends the connection
  with GOAWAY(ENHANCE_YOUR_CALM). Socket writes are bracketed by a
  `WriteWatchdog`.
- State machines: the connection moves HANDSHAKE → OPEN → DRAINING →
  CLOSING → CLOSED by CAS; each stream OPEN → HALF_CLOSED_(REMOTE|LOCAL)
  → CLOSED by CAS, recording why it closed. Closed streams are
  remembered (`ClosedStreams`: the last 2× the concurrency limit, between
  64 and 8192, in a ring and a hash table grown as streams close) with
  that reason:
  frames after the peer's END_STREAM are a connection error
  STREAM_CLOSED, after the peer's RST_STREAM a stream error
  STREAM_CLOSED (charged to the reset budget), after ours ignored. DATA
  on a closed stream always returns its connection credit; header blocks
  are always decoded so HPACK stays in sync.
- Request side: `RequestHead` validates every head (CONNECT → 501); the
  request body is a per-stream byte ring bounded by the receive window
  (tiny DATA frames cost no object each), read with `:read-timeout` and
  charged to the memory budget; a header block over CONTINUATION frames
  is bounded by `:header-timeout`. A decoded field section over
  `:max-header-bytes` or with more than `:max-header-fields` fields is
  answered 431 on its stream up to the hard ceiling (4x, at least 64
  KiB), above which the connection ends. A declared body over
  `:max-request-body-bytes` gets 413 and an unknown expectation 417,
  both without the handler; `Expect: 100-continue` gets an interim
  HEADERS (:status 100, its own block, never END_STREAM) queued on the
  stream at the handler's first body read.
- Cancellation: a stream closed by a reset (either side) or the
  connection's teardown cancels its exchange, interrupting the handler
  (or the producer of its streamed body); a stream reset before its
  handler starts never runs it. The admission slot is held until the
  response is complete or the handler is gone; after a timeout's 503, a
  handler that ignores its interrupt keeps its slot until its thread
  exits. At teardown the framer waits for every handler of the
  connection before returning, so the connection keeps its limiter slot
  and registry entry meanwhile.
- Responses are serialised from `ResponseHead` in `MULTIPLEXED` mode
  (status validation, no DATA for HEAD / 204 / 304, Date, Server,
  Alt-Svc).
- Resets: peer RST_STREAM and the resets its frames cause (stream
  errors, CVE-2025-8671 MadeYouReset) share one token bucket
  (`:http2-stream-reset-limit`).
- Shutdown: `Drainable`; a graceful close is two-phase (GOAWAY(2^31-1)
  and a PING, then GOAWAY with the last stream served), followed by a
  lingering close (output shut down, input read out for up to 2 s) so
  the final GOAWAY isn't lost to a TCP reset.
- `ServerEvents` and JFR request / protocol-error events. Every deadline
  of a connection is one `Timer` node; each stream is its own node for
  `:handler-timeout`.

### HTTP/3 (adopted)

- Threads: `:http3-event-loops` platform threads, each owning a shard of
  connections (the first byte of the connection ids the server issues
  names the loop; on Linux each loop has its own `SO_REUSEPORT` socket and
  a BPF program steers datagrams to it, elsewhere loop 0 receives and
  hands datagrams over). Every quiche call for a connection happens on
  its loop, so quiche needs no locking; connection deadlines (quiche's
  timer, pacing, handshake, idle, header, write) are a binary heap per
  loop. Handlers run on virtual threads and signal the loop (a lock-free
  push and a wake-up) when they have output. See
  [http3.md](http3.md#how-it-runs).
- Exchanges: the request stream (`Http3Exchange`) is the shared
  `Exchange`: handler, claim against the timeout (503 through the loop)
  and abandons, client errors, error handler, reporting. Responses the
  server decides (413, 417, 431, 500, 501, 503) are the shared
  `HttpStatus` ones prepared through `ResponseHead` like any response.
- Limits as on the other protocols: `:max-header-bytes` /
  `:max-header-fields` (431; over the hard ceiling the stream is reset
  with H3_EXCESSIVE_LOAD before anything is buffered); declared body over
  `:max-request-body-bytes` 413 without the handler; a body growing past
  it fails the handler's reads with a 413 and the stream is no longer
  read; `Expect: 100-continue` (a 100 HEADERS frame sent by the loop on
  the handler's first body read, before any response); 417 otherwise.
- `Drainable` per QUIC connection, registered with the server's
  `ConnectionRegistry` and counted by the `ConnectionLimiter`; both are
  released by the connection's teardown or, when handlers still run, by
  the last of them.
- Event loops contain failures: per connection (datagram, timer,
  processing, teardown: H3_INTERNAL_ERROR for that connection only) and
  per loop-wide step (logged, the iteration goes on). Anything escaping
  reaches the loop's supervisor: SEVERE log, an "event-loop-failure"
  protocol error, the loop's connections closed, the loop restarted on
  the same thread after 100 ms.
- Request bodies: an `Http3BodyPipe` per request holds at most 64 KiB
  and is charged to the server's memory budget and to the connection's
  own (its connection window), so unread bodies can't exceed the window
  however many streams are open; past either the loop stops reading
  those streams.
- Shutdown and `:idle-timeout` drain in two GOAWAYs (RFC 9114 §5.2), as
  under Graceful shutdown.
- Certificates: quiche loads the PEM pair itself, into a quiche
  configuration that every connection accepted with it references. Every
  `:http3-cert-reload-interval` a virtual thread compares the files'
  modification time, size and file key with the pair last loaded and, on
  a change, builds a new configuration for new connections; existing
  connections keep theirs, freed with the last of them. A pair that fails
  to load is logged and the current one kept (retried when the files
  change again); `Http3Listener.reloadCertificates()` forces a reload.
- `ServerEvents` and JFR as the other drivers, through `Service`.

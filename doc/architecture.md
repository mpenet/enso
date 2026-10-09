# Architecture

How the server is put together: the shared core every protocol driver
builds on, how each driver uses it, and what a request allocates. This is
for people changing the code. User-facing behaviour is described in
[options.md](options.md), [handlers.md](handlers.md) and
[http3.md](http3.md), and isn't repeated here.

## Layering

```
s-exp.enso (Clojure)      option table → Config; Ring response coercion (->response);
                          WebSocket listener adaptation; Ring protocols via vars
com.s_exp.enso.api        Config, Request (the Ring request map), Response, StreamingBody,
                          RingHandler, RingErrorHandler, ChunkedWriter, ChunkedOutputStream,
                          ServerEvents, WebSocketListener, WebSocketSocket, WebSocketException
com.s_exp.enso            EnsoServer: lifecycle, acceptor, limiter, TLS + ALPN, h2c detection,
                          shutdown
com.s_exp.enso.core       protocol-neutral pieces shared by the drivers (below)
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

Drivers depend on `core`, `api` and `util`. Two cross-links are
deliberate: the HTTP/1.1 driver hands upgraded connections to
`websocket`, and QPACK reuses HPACK's Huffman code
(`http2.HpackHuffman`, the same RFC 7541 table). HTTP/1.1 and HTTP/2 use
`EnsoServer` for its protocol names and `forceClose`; HTTP/3 sits on
`quiche`. `core` and `api` depend on each other and on nothing
protocol-specific. `util` builds Clojure maps.

## Threads

| Thread | Kind | Runs |
|---|---|---|
| `enso-acceptor` | platform, daemon | `accept()`, limiter check, dispatch. A failing iteration is logged and backed off from. |
| `enso-timer` | platform, daemon | the `Timer` wheel. Callbacks never block. Restarts itself on failure. |
| `enso-events` | platform, daemon, only with `:server-events` | delivers queued events in order; the only thread running listener code |
| connection thread | virtual, one per TCP connection | socket options, TLS handshake and ALPN or the h2c preface check, then the driver: HTTP/1.1's request loop (and the WebSocket read loop after an upgrade) or HTTP/2's framer |
| WebSocket writer | virtual, while async sends are queued | queued frames, and pongs that found a write in progress |
| HTTP/2 output | no dedicated thread | whichever thread has output and finds no writer active, usually the handler that just answered |
| HTTP/2 and HTTP/3 handlers | virtual, one per stream | handler and response body |
| `enso-h3-loop-<i>` | platform, daemon, `:http3-event-loops` | everything quiche-related for the connections it owns |
| `enso-h3-cert-watcher` | virtual, one per HTTP/3 listener | certificate reloads |
| short-lived workers | virtual | anything a timer callback starts that may block (503s, closes, flushes), and memory budget wake-ups |

## Lifecycle

The `EnsoServer` constructor only records its arguments. `start()`
creates the `Timer` and connection executor, configures TLS, binds the TCP
listener, starts the HTTP/3 listener if enabled, then the acceptor. The
JNI shim is loaded only when the HTTP/3 listener starts. On failure,
whatever was started is released and the exception rethrown. A server
starts at most once.

The acceptor admits a connection through the `ConnectionLimiter` and runs
it on a virtual thread (`Accepted`). `Accepted` registers with the
`ConnectionRegistry` before anything can block, sets socket options, runs
the TLS handshake and the driver, and in `finally` force-closes,
unregisters, releases the limiter slot and reports the end. Plain HTTP
keeps the channel's socket so file bodies can use
`FileChannel.transferTo`.

With `:http2c`, `Accepted` reads up to the 24 bytes of the HTTP/2
preface, stopping at the first byte that can't belong to it. A full
preface starts the HTTP/2 driver; anything else goes to HTTP/1.1 with the
bytes read so far replayed.

TLS goes through `TlsSocket`, an `SSLEngine` over the channel. TLS 1.2
client renegotiation is refused. A TLS 1.3 KeyUpdate asking for ours stays
queued in the engine and goes out ahead of the next record written
(RFC 8446 §4.6.3), so the read path never writes and never waits behind a
writer blocked on a peer that doesn't read. While a connection is idle,
`releaseIdleBuffers()` swaps the ~16 KiB record buffers for 512-byte ones.

Other `TlsSocket` calls drivers use:

- `writeRecords(src, off, len, net)` encrypts into a caller-owned buffer, several records per channel write. HTTP/2 pools these buffers process-wide.
- `shutdownOutput()` sends close_notify and half-closes, keeping input readable for a lingering close.
- `setReadDeadline(nanos)` puts a wall-clock bound on a read. SO_TIMEOUT alone bounds one wait for ciphertext, and a read only returns whole records, so a peer trickling a record a byte at a time could otherwise hold a read forever.
- `inputPending()` tells whether closing now would be answered with a reset.

`isHealthy()` checks that the acceptor, the timer and every HTTP/3 event
loop are alive.

## Shared core

### Service

`core.Service` is built by `start()`, one per server (and per standalone
HTTP/3 listener). It holds the handler, error handler, `Config`, `Timer`,
guarded event listener and memory budget. Drivers report events through
it and ask it the shared response policy: whether to add Date, the
`:server-header` value, Alt-Svc on HTTP/1.1 and HTTP/2. Each driver
encodes the answer its own way: cached `Date:` line bytes, HPACK,
pre-encoded QPACK lines.

### Exchange

`core.Exchange` is the protocol-neutral part of serving one request.
Drivers parse; the exchange decides what to send. Each driver extends it
with the object it already has per request, so it costs nothing extra:
an inner `Call` per HTTP/1.1 connection (reused), the `Http2Stream`, and
the HTTP/3 request stream.

The exchange is a `Timer.Task` for `:handler-timeout`. One CAS decides who
owns the response: the handler, the timeout, or a cancel (stream reset,
connection gone). `onTimeout()` claims it on the timer thread and calls
the driver's non-blocking `handlerTimedOut()`. `cancel()` claims it for
nobody and interrupts the handler thread. `serve(handler)` runs the
handler and returns the response to send, or null if the timeout or a
cancel won.

Client errors have one taxonomy on every protocol. A body read fails with
`RequestBodyException` (400 or 413) or `RequestBodyTimeoutException`
(408), or the handler throws `HttpError`. The driver's body records the
first failure, so the status is sent whatever the handler did with the
exception, without calling the error handler. Error responses are the
shared prebuilt `HttpStatus.error(status)` objects.

`begin()` and `complete()` report the request to `ServerEvents` and JFR
using primitives and objects the request already holds. The exchange
allocates nothing per request.

### Memory budget

`core.MemoryBudget` implements `:max-buffered-bytes` with atomic counters
for bytes held for peers and for credit granted to them.

- Credit is reserved before it is granted (`tryReserve`, or `Account.tryReserve` per connection) and released when the bytes leave or the credit is abandoned. Bytes arriving within credit a protocol grants unasked, such as HTTP/2's initial 65535-octet windows, are `charge`d instead, which may exceed the limit by that much.
- `exhausted()` is true at the limit, `pressured()` from the low-water mark at three quarters.
- Each connection holds bytes through an `Account`. Under pressure an account over its fair share is refused and `throttled()`, while smaller ones may still reserve up to the limit.
- `await(waiter)` registers a waiter unless usage is already below the low-water mark, in which case the caller carries on. Waiters are woken by a short-lived virtual thread holding no lock, never by the releasing thread. A release under one connection's locks would otherwise run another connection's callback, which takes that connection's locks, and two HTTP/2 connections could deadlock.
- `cancel(waiter)` unregisters, so closed streams don't stay reachable.

A buffer joins the budget by charging what it holds to its connection's
account, releasing it on every exit path, and pausing credit or reads
while throttled with a waiter to resume. Current users: HTTP/2 request
bodies and connection credit, HTTP/2 streamed responses, HTTP/3 request
bodies, HTTP/3 receive credit, HTTP/3 response bytes quiche hasn't taken,
WebSocket async sends, and WebSocket messages past 64 KiB. The protocol
sections below describe each.

### Timer

`core.Timer` is a hashed timing wheel of 512 slots of 10 ms (5.12 s per
rotation), one per server. HTTP/3 uses it only for `:handler-timeout`;
its other deadlines live in each event loop's heap.

- `Timer.Task` is an intrusive node, one per connection or stream, reused across requests.
- `schedule(task, ms)` arms or re-arms. Expiry is never early and at most about a tick late. Shortening, or arming a disarmed task, pushes the node on a lock-free stack for the timer thread. Lengthening only moves the deadline with one CAS, and the timer thread re-buckets the node when its old slot comes up, so re-arming per keep-alive request costs one timer visit per timeout period.
- `cancel(task)` is one CAS, and exactly one of cancel and expiry wins. The node stays in its slot until the wheel passes, keeping what it references reachable for up to one rotation. `retire(task)` also unlinks it on the next tick; use it for per-request nodes and for a closing connection's nodes.
- `onTimeout()` runs on the timer thread and must not block: flip state, interrupt, enqueue, or start a virtual thread. Exceptions are logged and swallowed, and an error escaping the loop restarts it after 10 ms, so the server never runs without timeouts.

Nothing is allocated to schedule, cancel or expire.

### Write watchdog

`core.WriteWatchdog`, one `Timer.Task` per connection, implements
`:write-timeout`. Blocking writes are bracketed with `enter()` and
`exit()`, or go through `WatchedOutputStream`, which also slices them to
256 KiB so a huge write still shows progress. A write costs two volatile
increments and a flag; the timer is touched at most once per period. A
stalled write is caught within two timeouts and the connection
force-closed from a virtual thread.

### Response head

`core.ResponseHead` applies the response policy once to an `api.Response`,
into reusable storage that drivers serialise from. Use
`prepare(response, headRequest, mode)` then `release()`, or
`disownBody()` before streaming a body the driver closes. `prepare`
throws `IllegalArgumentException` for a handler error; the driver
answers 500.

It validates status, names and values (see
[handlers.md](handlers.md#responses)), owns framing (drops
`Transfer-Encoding`, keeps a handler `Content-Length` only where the
server can't know the length), and exposes `declaredLength()`, which the
driver must honour exactly. `MULTIPLEXED` mode drops connection-specific
fields and lowercases names; `HTTP1` keeps them and reports
`Connection: close`. Date, Server and Alt-Svc are only noted, so each
driver adds its own in its cheapest encoding. The body is classified as
none, bytes, ASCII (a String written one byte per char without
encoding), file (opened here so length and transfer agree), stream or
streaming.

Once its arrays have grown it allocates nothing for the common shapes.
Clojure maps are walked with `IKVReduce` and a reused visitor. The
exceptions (lowercasing a mixed-case name, non-String values, non-ASCII
text, file bodies) are listed in the class doc.

### Request head

`core.RequestHead` validates an HTTP/2 or HTTP/3 field section as it is
decoded, one field at a time, without allocating. `add(name, value)`
returns `PSEUDO`, `FIELD`, `HOST` or `MALFORMED`, and `finish()` returns
`OK`, `MALFORMED`, or `NOT_IMPLEMENTED` for CONNECT (501). Malformed
requests are stream errors. `failure()` names the broken rule. The rules
are those of RFC 9113 §8 and RFC 9114 §4, plus one shared with HTTP/1.1:
a repeated Content-Length is malformed even with an equal value (RFC 9110
§8.6 permits rejecting it).

`uri()` and `query()` split :path lazily for the Ring request. HTTP/1.1
splits on its own parse bytes and reuses the last Strings. It shares
`isValidAuthority`, `isOriginForm`, `isFieldValue` and
`parseAbsoluteForm` with this class.

Ring header maps are built by `RingHeaders`: duplicates joined, then an
array map over the field array up to 8 fields and a hash map beyond.
HTTP/1.1 keeps array maps up to 32 fields; a browser sends 10 to 20, and a
hash map of 14 costs about 1.2 KB more per request than scanning them.
`HeaderNames` indexes known names so the HTTP/1.1 parser keeps per-name
state in a plain array.

### Connection limits

`core.ConnectionLimiter` counts TCP and QUIC connections together.
`tryAcquire(address)` on accept, `release(address)` exactly once after a
successful acquire. The global count is one atomic increment. The
per-address count costs a map update and is only active when configured.

### Graceful shutdown

`core.Drainable` and `core.ConnectionRegistry`. A connection stays
registered from accept until nothing of it runs any more, its handler
threads included, so an empty registry means every handler has finished.
It also keeps its limiter slot that long, so closing connections can't
leave their handlers running while new connections start more.

`EnsoServer.close()` closes the TCP listener and starts closing the HTTP/3
listener in parallel. It calls `beginDrain()` on every connection and
waits for the registry to empty, until the last quarter of
`:shutdown-timeout` (at most a second). Then it `forceClose()`s the rest,
interrupting handlers and connection threads, and waits until the
deadline. Handlers still running are logged and left behind. After a
clean drain it also joins the connection threads.

`beginDrain()` means: stop taking requests, finish the ones in flight,
close. HTTP/1.1 closes an idle connection at once; going idle and the
first byte of a request race on one CAS, so an arriving request is never
cut. HTTP/2 sends GOAWAY and closes once handlers are done and responses
sent. A WebSocket starts the closing handshake with 1001. HTTP/3 drains
in two GOAWAYs. A connection still handshaking is force-closed.

`forceClose()` closes at once without waiting for writers and is
idempotent. Both run on the closing thread, race with the connection's
own threads, and must return promptly.

The HTTP/3 listener's close stops the certificate watcher, drains and
force-closes as above, then stops and joins the event loops. quiche
configurations and sockets are freed only after every loop has exited.

### Events and logging

`GuardedEvents` wraps the `:server-events` listener. A call puts the
arguments into a preallocated slot of a bounded multi-producer queue
(Vyukov's: a CAS on the tail, field writes, an unpark only when the
consumer is parked) and returns. The `enso-events` thread delivers in
order. With 8192 waiting, events are dropped and counted. With no
listener, drivers make no call and take no timestamp.

JFR events are committed inline, since they run no user code.
`Jfr.requests()` and the like are static volatile flags that follow
recordings, so without a recording the cost is a field read.

`LogLimiter` rate-limits each WARNING call site to one record per second.
`LogLimiter.log` never throws.

### Minimum data rate

`core.DataRate` bounds the time a reader spends waiting for body bytes to
one second per rate's worth received. The reader keeps two primitives
(bytes, nanoseconds waited) and shortens each wait it already makes by
`DataRate.allowanceNanos`: an HTTP/1.1 socket timeout, an HTTP/2 park,
an HTTP/3 condition wait. No object, no timer, one clock read on each
side of a wait.

### Configuration and Ring protocols

The option table in `s-exp.enso` drives `Config` building, error
messages, unknown-key suggestions, the `run-server` docstring and the test
that keeps [options.md](options.md) in sync. `Config.Builder.build()`
checks ranges and contradictions.

`ring.core.protocols` and `ring.websocket.protocols` are optional. The
adapter holds their vars and reads the root at use, so types extended
after `s-exp.enso` loaded are honoured.

## Allocation budget

Measured with `ThreadMXBean#getCurrentThreadAllocatedBytes` after
warm-up, so the numbers are exact. Tests assert the bounds.

| Path | Bytes per operation | Test |
|---|---:|---|
| `Timer` schedule and cancel, re-arm | 0 | `enso-core-test/timer-arm-and-cancel-allocate-nothing` |
| `WatchedOutputStream` write and flush | 0 | `enso-core-test/watched-writes-allocate-nothing` |
| `ResponseHead` prepare and release (2 headers and a String body; 20 headers and a byte[] body; multiplexed) | 0 | `enso-core-test/response-head-allocates-nothing-per-response` |
| `RequestHead` reset, 8 fields, finish | 0 | `enso-core-test/request-head-validation-allocates-nothing` |
| `ConnectionLimiter` global acquire and release | 0 | `enso-core-test/limiter-unlimited-and-allocation-free` |
| HTTP/1.1 GET, 3 headers and a query, String body, in-memory socket, whole path including the Ring adapter, calling thread | ~176-184 (bound 300) | `enso-http1-test/h1-get-allocation-budget` |
| The same, reading `:remote-addr`, `:server-name`, `:server-port` and a header; 3 fields, then a 14-field browser-like head | ~240 (bound 300); ~329 (bound 400) | `enso-http1-test/h1-get-allocation-with-ring-keys-and-many-fields` |
| HTTP/2 GET, 6 fields, String body, no TLS, whole path, every thread | ~760 (bound 1000) | `h2-get-allocation-budget` |
| The same with a 13-byte `ByteArrayInputStream` body | as above (bound 1200) | `h2-small-stream-body-allocation-budget` |
| HTTP/3 GET | ~730 with compressed oops (bound 900), ~1050 without (bound 1300) | `h3-get-allocation-budget` |

The harness, counting the whole server JVM, measures 393 bytes per
HTTP/1.1 GET, 235 pipelined, 1,125 per HTTP/2 GET over TLS and 799 per
HTTP/3 GET ([performance.md](performance.md#current-numbers)). The
allocation gate holds these to `bench/perf/baseline.edn`.

What remains per request is mostly the Ring contract, since a handler
receives a persistent map of Strings:

- HTTP/1.1: the `Request`, the header map and its array, and the `api.Response` built from the handler's map. Header names are interned through `HeaderNames`. A value String is only allocated when it differs from the previous request's value for that name on the connection, and the same goes for the path and query. Unknown names and their values are cached by position (up to 16), since clients send fields in the same order. Values derived from the connection (`:remote-addr`, `:server-port`, `:ssl-client-cert`, and `:server-name` while Host is unchanged) are computed once per connection.
- HTTP/2: the `Http2Stream` (also its timer node and the handler `Runnable`), the handler's virtual thread (the JDK allocates the thread, its continuation, a ForkJoin task and, with `jdk.trackAllThreads` on, a thread-container node), the Ring request, its header map, one String per literal header value (dynamic-table hits are shared), the uri and the `api.Response`. Over TLS the JDK's AES-GCM adds about 1.3 KB per record written; batching puts several responses in one record when streams are concurrent.
- HTTP/3: the request stream (`Http3Exchange`, also the exchange and timer node), one virtual thread, the decoded fields, the Ring request and the `Response`.

Nothing is allocated per request for timeouts, the write watchdog,
response validation, Date (cached bytes), status lines, the response head
(reused buffer), HPACK encoding or HTTP/2 framing (pooled batch buffers).

HTTP/1.1 over TLS 1.3 allocates about 3280 bytes per request, mostly in
the JDK's `SSLEngine`. A direct outbound record buffer was tried: about 5%
more throughput, but about 370 B/req more allocation (the cipher copies
through a heap array for a direct destination) and a costly
re-allocation after each idle release. Inbound records need a heap array
because they are read through the socket adaptor's stream, the only
blocking read that honours `SO_TIMEOUT`.

### Idle connections

A connection idle for a second gives back what it grew. HTTP/1.1 shrinks
its parse buffer to 1 KiB and drops its grown output and body buffers,
cached values and TLS records. HTTP/2 forgets retired streams and shrinks
its input, header-block, HPACK, field, TLS and writer buffers
(`h2-idle-connection-gives-back-its-buffers`). A WebSocket keeps a
512-byte read buffer (`ws-idle-connection-gives-back-its-buffers`). An
HTTP/3 connection keeps its scratch space on its event loop and replaces a
stream map that grew past 16 entries.

Heap per idle connection, measured once with 2000 connections against
`s-exp.enso-test-server` (heap after full GC divided by the count, virtual
thread stacks included; not asserted by a test):

| Protocol | Plain | TLS 1.3 |
|---|---:|---:|
| HTTP/1.1 keep-alive | 9.7 KiB | 16.1 KiB |
| HTTP/2 (h2c / h2) | about 11 KB | about 23 KB |
| WebSocket | 16 KiB | 25 KiB |
| HTTP/3 | – | about 3 KB |

## HTTP/1.1

`HttpConnection` (the public class) runs the request loop on the
connection's virtual thread: wait for a request, run the handler, decide
keep-alive, drain or linger. It owns the `:handler-timeout` state
machine, the WebSocket handshake and hand-off, draining, the write
watchdog, events and JFR. `RequestReader` is the input side (parse buffer,
head parsing, request bodies, the lingering-close discard loop) and
`ResponseWriter` the output side (output buffer, response head and body
encodings, 100 Continue, 101, pipelined output).

Timeouts are socket read timeouts per phase, with no timer operation on
the common path: `:idle-timeout` before a request's first byte (after one
second the connection gives back its buffers, then waits out the rest),
then the rest of `:header-timeout`, then `:read-timeout` for body reads.
Over TLS each read also gets a wall-clock deadline through
`TlsSocket.setReadDeadline`.

Output goes through one buffer. The response head is built in it, small
writes join it, and writes of 8 KiB or more go straight to the socket.
Chunk size lines are written into room reserved in front of the data, so
a chunk is one write. File bodies use `transferTo` slice by slice,
bracketed by the watchdog.

Pipelined responses share a write while the next request is already
buffered. While a handler runs, held bytes sit on a one-tick (10 ms)
timer: a handler that returns first takes them back, and a slower one
doesn't delay them.

`:handler-timeout` uses one timer node per connection, armed per request
and never cancelled, so the next request's arm only moves the deadline.
An expiry may therefore belong to an earlier request. The node records
when the current request started, and an expiry only claims the exchange
(one CAS) if that request has run the whole timeout. If the timeout wins,
a virtual thread writes the 503, then the handler thread is interrupted.
The connection thread waits for that before clearing its interrupt, so the
interrupt can't land later during the lingering close. It is never
delivered during a socket read, which would close an interruptible
channel; the handler's next read fails with `InterruptedIOException`
instead.

Request heads: `:max-header-bytes` bounds the whole head and
`:max-header-fields` the field lines; a request line too long on its own
is 414. A bare LF is 400 as soon as it is seen. Origin-form targets must
start with '/', '*' is for OPTIONS only, and authority-form for CONNECT
only (answered 501). Chunk-size lines are capped at 4 KiB, and chunk
extension bytes count against `:max-request-body-bytes`. Body errors are
kept on the body and answered by the exchange after the handler returns.

`Expect: 100-continue` is answered on the first body read, ordered with
the timeout's 503 by a `ReentrantLock`; a monitor would pin the carrier
while writing on JDKs before 24.

Whether the connection survives an unread body is decided before the
response head, so `Connection: close` can be announced. Buffered bytes are
drained without blocking. A known remainder of up to 64 KiB is drained
after the response within 2 s. Anything larger, or chunked, closes the
connection.

A body of unknown length is chunked on HTTP/1.1 even when the connection
closes after it, so truncation is visible. On HTTP/1.0 a failed body ends
the connection with a reset.

Lingering close applies after error responses, unread bodies, closes the
client didn't ask for, and whenever input is pending at close: output is
shut down and input discarded for up to 2 s, so the client reads the
response instead of a reset. Over TLS the shutdown is a write, bounded by
the watchdog.

## WebSocket

The WebSocket driver runs on the upgraded HTTP/1.1 connection and writes
through its watched stream.

Synchronous sends write on the caller's thread under the write lock.
Async sends queue for a writer virtual thread. Whoever holds the lock
writes the queue before its own frame, so frames leave in call order.
Pings and pongs that find the lock taken queue instead of waiting, so the
read loop never waits on a stalled writer. The CLOSE it sends waits for
the lock at most `:ws-close-timeout`.

After a failure the driver sends CLOSE, then keeps reading until the
client's CLOSE if frames are intact, or half-closes and drains if they
aren't, so the CLOSE isn't destroyed by a reset.

`WebSocketHandshake` applies the origin check, negotiates
permessage-deflate (`PerMessageDeflate`) and writes the
`Sec-WebSocket-*` headers.

## HTTP/2

One driver serves "h2" (after TLS and ALPN) and "h2c" (after the
preface). Only the output path differs: over TLS, batches are encrypted
into pooled record buffers. The connection thread is the framer: it reads
frames, decodes HPACK and admits streams, and it never blocks on output
while the connection is open. Handlers run on one virtual thread per
stream.

### Output

`Http2Writer` uses pull scheduling with a combining writer. Handlers
queue output on their own stream: a fixed body (or a `ByteArrayInputStream`
of up to a frame) is handed over whole through a lock-free inbox; a
streamed body is copied into a ring of at most 64 KiB, from a server-wide
pool, sized at once for a body of known length. The framer queues control
frames on a priority lane with a count cap; a peer that makes the server
queue too many without reading gets GOAWAY(ENHANCE_YOUR_CALM).

Whoever has output and finds no writer active packs a batch under the
writer lock (control lane first, then one frame per ready stream in round
robin, up to 64 KiB or four TLS records) and writes it outside the lock.
HPACK encoding happens while packing, so header blocks reach the wire in
encoding order and are never encoded for a stream already reset. A reset
purges a stream's output at once.

Streamed bytes in rings are charged to the connection's budget account.
While the account is throttled a ring holds one frame, so the producer
waits.

### Receive flow control

Autotuning is described in [options.md](options.md#http2-flow-control).
Implementation details:

- Every DATA byte is held by the connection's account from arrival until it leaves the stream's buffer (`creditConnection`). Leaving bytes are granted again as credit unless the account is throttled. Then only enough to keep the window at 65535 is granted, the rest is released and owed, and a budget waiter grants it later in pieces of at least a frame.
- `RequestBody.credit` returns a stream's credit once half its window is read, and doubles the window if the previous return was less than `4 × smoothed RTT × fraction read` ago. `autotuneConnectionWindow` applies the same rule to the connection over epochs of half its size. Connection growth is reserved from the account first and skipped if that fails. Stream growth needs no reservation, since the paid connection window bounds the peer; it is skipped while throttled.
- The RTT comes from the SETTINGS acknowledgement, then a PING sent with a stream WINDOW_UPDATE when the last sample is over a second old (RFC 6298 smoothing). This costs one `System.nanoTime` per window update.
- A body with a Content-Length is never granted stream credit past what it has left plus 256 octets, so a padding peer can always send its next frame.
- Request bodies cost no object per DATA frame: up to 8 KiB in a ring of the stream's own, then a chain of pooled 64 KiB segments, each returned once read.

### Send flow control

Streams without credit wait on one of two lists: their own window shut,
or their own open but the connection's shut. A connection WINDOW_UPDATE
reschedules only the second list, and only once the window opens or
reaches 1 KiB, so tiny updates cost constant work. Credit below 1 KiB is
pooled for 20 ms (CVE-2019-9511). One deadline per connection catches
stalls: a stream shut for `:write-timeout` is reset with CANCEL, a
connection shut that long gets GOAWAY(ENHANCE_YOUR_CALM).

### State

The connection moves HANDSHAKE → OPEN → DRAINING → CLOSING → CLOSED, and
streams OPEN → HALF_CLOSED → CLOSED, both by CAS. `ClosedStreams`
remembers the last 2× the concurrency limit (64 to 8192) closed streams
and why they closed: frames after the peer's END_STREAM are a connection
error, frames after the peer's RST_STREAM a stream error charged to the
reset budget, frames after ours are ignored. DATA on a closed stream
still returns its connection credit, and header blocks are always decoded
to keep HPACK in sync.

A reset or teardown cancels the stream's exchange, interrupting its
handler or body producer. A stream's admission slot is held until its
response is complete or its handler is gone. At teardown the framer
waits for every handler, so the connection keeps its limiter slot and
registry entry meanwhile.

Peer RST_STREAMs and the resets its frames cause (CVE-2025-8671) share
one token bucket. A graceful close sends GOAWAY(2^31-1) and a PING, then
GOAWAY with the last stream served, and finishes with a lingering close
so the final GOAWAY isn't lost to a reset.

## HTTP/3

The runtime is described in [http3.md](http3.md#how-it-runs). In code
terms:

- `Http3Loop` instances each own a shard of connections. Every quiche call for a connection happens on its loop, so quiche needs no locking. Deadlines are a binary heap per loop. Handler threads signal the loop with a lock-free push and a wake-up.
- `Http3Exchange` is the shared `Exchange`. Server-decided responses (413, 417, 431, 500, 501, 503) are the shared `HttpStatus` ones, prepared through `ResponseHead`.
- Each QUIC connection is a `Drainable` in the server's registry and limiter, released by its teardown or by its last handler.
- The loop supervisor catches anything escaping a loop: SEVERE log, "event-loop-failure", the loop's connections closed, restart on the same thread after 100 ms. Nothing it calls can escape it.
- `Http3BodyPipe` buffers at most 64 KiB per request, charged to the connection's account and to its window-sized connection budget. `hasRoom()` false stops the loop reading that connection's request streams; `resumeWhenDrained` registers a waiter that signals the loop.
- Receive credit: while a body is being read (`Http3Connection.bodyStarted` to the last `readDone`) the initial window is charged, not reserved, since it was granted in the handshake. With `Quiche.RECV_WINDOW_CONTROL`, `growConnectionWindow` reserves each doubling and passes it to `quiche_conn_set_max_connection_window`, up to twice `:http3-max-window-bytes`; the reservation is held until the connection goes. New connections are refused only while the budget is exhausted: from the low-water mark, fair shares already stop a connection over its share from growing, and refusing there would turn away GET traffic for bodies it doesn't send.
- Response bytes quiche hasn't taken (`Http3Connection.defer`, `bodyHeld`) are charged without throttling: a fixed body is already in memory and a streamed producer already blocks on its hand-off, so the charge only adds pressure on other buffers.
- Each certificate pair becomes a quiche configuration referenced by the connections accepted with it, and freed with the last of them.

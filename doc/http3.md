# HTTP/3

HTTP/3 rides Cloudflare `libquiche` over UDP via a small JNI shim
(`native/enso_quiche/enso_quiche.c`). Pure-Java QPACK + H3 framing on top
of quiche's transport primitives. Same Ring handler contract as h1/h2 —
`:protocol` becomes `"HTTP/3.0"`, `:scheme` is `:https` — except that
WebSocket is not available (a WebSocket response is answered 501).

## From a release jar (zero libquiche install)

Every release publishes the core and per-classifier jars to Clojars. The
fat jar exceeds Clojars' file-size limit; it is built by release CI as a
workflow artifact and locally with `clojure -T:build jar-all`.
Three consumption patterns.

### Core only, no h3 (~450 KB)

```clojure
{:deps {com.s-exp/enso {:mvn/version "1.0.0-alphaN"}}}
```

### Per-platform classifier (~3.5 MB for darwin-arm64)

Add core plus the classifier matching your deploy target. `tools.deps`
resolves the classifier artifact via the `$<classifier>` coord suffix.

```clojure
{:deps {com.s-exp/enso                 {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$darwin-arm64    {:mvn/version "1.0.0-alphaN"}}}
```

Available classifiers:

- `darwin-arm64`
- `linux-amd64`, `linux-arm64`
- `linux-musl-amd64`, `linux-musl-arm64`

On musl (detected by `/lib/ld-musl-*.so.1`: Alpine, Wolfi, Chimera) only
the musl shim is loaded: a glibc build can't run there, so it is never
tried as a fallback and a missing musl classifier is a clear load error.

Minimums: the glibc shims need glibc 2.28 or later (they are built on
AlmaLinux 8), the darwin shim macOS 11 or later.

For multi-platform uber-jars, declare multiple classifier deps side by side:

```clojure
{:deps {com.s-exp/enso                    {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$darwin-arm64       {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-amd64        {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-musl-amd64   {:mvn/version "1.0.0-alphaN"}}}
```

`Quiche.java` picks the matching shim from the classpath at load time.

### Native access (JDK 24+)

The shim is loaded with `System.load`, a restricted method: JDK 24 and
later warn (and a future release will refuse) unless native access is
enabled for the code loading it. Add `--enable-native-access=ALL-UNNAMED`
to the JVM options (`--enable-native-access=com.s_exp.enso`, the jar's
`Automatic-Module-Name`, when enso runs as a named module);
with the Clojure CLI `clojure -J--enable-native-access=ALL-UNNAMED ...` or
`:jvm-opts` in an alias. JDK 21 needs nothing.

## Enabling h3

```clojure
(enso/run-server handler
  {:port 8443
   :ssl-context ctx                 ;; for h1/h2 on the TCP port
   :http2 true
   :http3 true
   :http3-cert-path "/path/cert.pem"
   :http3-key-path  "/path/key.pem"})
```

- Uses its own UDP socket(s); can co-exist with h1/h2 on the same port number.
- `Alt-Svc` auto-advertised on h1/h2 responses when h3 enabled.
- See [options.md](options.md#http3) for full knob list.
- Prefer an ECDSA (P-256) certificate: the TLS handshake signs once per
  connection, on the connection's event loop thread, and an ECDSA
  signature costs a small fraction of an RSA-2048 one, which matters most
  under a connection flood.
- Certificate rotation: every `:http3-cert-reload-interval` (10 s by
  default, 0 disables) the certificate and key files are checked
  (modification time, size, inode, so a symlink swap as Kubernetes does
  for secrets is seen too). A changed pair is loaded and new connections
  are accepted with it; existing connections keep the configuration they
  were accepted with, which is freed with the last of them. A pair that
  doesn't load (a file half written, a key that doesn't match the
  certificate) is logged at WARNING (rate-limited) and the current one
  kept; it is
  retried when the files change again. Replace the two files atomically
  (write elsewhere, then rename) so a check never sees a mixed pair.
  `Http3Listener.reloadCertificates()` forces a reload.

```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj /CN=example.org
```

## How it runs

### Event loops and sharding

QUIC connections are served by `N` event loops (`:http3-event-loops`;
by default one per core on Linux, at most 64, one elsewhere). A loop is a platform
thread that owns a shard of connections: every quiche call for a
connection happens on its loop, so quiche (not thread-safe) needs no
locking. Handlers run on virtual threads, one per request, as on HTTP/2.

The server picks the connection ids its clients address it with (16
bytes); the first byte names the owning loop (its index modulo `N`, plus
a random multiple of `N`).

- **Linux**: every loop has its own `SO_REUSEPORT` socket bound to the
  port, and a classic BPF program (`SO_ATTACH_REUSEPORT_CBPF`) makes the
  kernel deliver each datagram to the socket of the loop named by the
  first byte of its destination connection id (offset 1 in a short
  header, 6 in a long one). A client's first Initial carries a random id
  of its own choosing: the same rule spreads new connections across loops
  and keeps its retransmissions (and the Initial after a Retry, whose id
  the loop chose) on one loop. Packets never change threads. If the
  program can't be attached the kernel's 4-tuple hash applies instead:
  Initials are then accepted by the loop that received them, and the rare
  datagram that lands elsewhere (after a NAT rebinding) is copied to its
  owner's inbox.
- **Elsewhere** (macOS, dev): one socket; loop 0 receives every datagram
  and hands those of other loops' connections to their inbox. With the
  default single loop nothing is handed over. This is a development
  setup: one thread receives, runs TLS handshakes and serves every
  connection. Giving each connection its own connected UDP socket after
  its handshake would spread receiving, but needs a descriptor per
  connection, kqueue registrations instead of one `poll` per loop, and a
  fallback to the shared socket whenever a peer's address changes (NAT
  rebinding), so it isn't done: run production servers on Linux.

### Per iteration

A loop receives a batch of datagrams (`recvmmsg` on Linux) straight into
a direct-memory slab, routes each by connection id, and feeds it to
quiche in place: no copy per datagram, no Java object per datagram. It
then takes datagrams other loops handed over and the connections that
handler threads signalled (a lock-free push plus one write to the loop's
wake-up eventfd/pipe when it is parked), fires expired timers (a binary
heap of connections by deadline: quiche's timer, pacing, handshake, idle,
header and write timeouts), and processes each connection that had any
of this: request streams are read straight from the receive buffer
(`quiche_conn_stream_readable_next`), responses encoded (QPACK, HEADERS
with a minimal length, small bodies inline in the same `stream_send` as
the FIN), streams that were waiting for flow-control credit resumed as
quiche reports them writable (`quiche_conn_stream_writable_next`), and
quiche's packets written into the send slab and sent in batches: on
Linux one `sendmmsg` per batch (up to 64 messages), each message a single
datagram or, when the kernel supports UDP GSO, a run of equal-size
packets to the same peer (up to 64 segments) that the kernel segments; a
device that refuses GSO turns it off for the socket. One `sendmsg` per
packet elsewhere. Receive offload (GRO) isn't used. Then it parks in
`poll` until the socket is readable, it is woken, or the next deadline; a
wake-up that found the socket not readable skips the receive call.

- Pacing: when quiche's pacer (`send_info.at`, Linux) wants a packet more
  than 1 ms later, that packet is held back and the connection resumes
  sending at its release time. macOS has no pacing: quiche doesn't report
  release times there.
- Acknowledgements: quiche acknowledges a request at once. After starting
  handlers the connection's packets wait up to 0.5 ms (well within the
  `max_ack_delay` it advertises, 25 ms unless `:http3-max-ack-delay`
  sets it) so a quick response carries that
  ACK: one datagram per request instead of two.
- Sending: a datagram the kernel refuses for a transient reason (buffer
  exhaustion, firewall, unreachable peer) is counted as lost; quiche's
  loss recovery resends what matters. A full socket buffer pauses sending
  until it is writable.
- Bound to a wildcard address on Linux, each datagram's destination
  address is recorded (`IP_PKTINFO` / `IPV6_PKTINFO`) and the reply leaves
  from it, so a multi-homed host answers from the address the client used.
  Elsewhere bind a specific address on multi-homed hosts.
- Socket buffers: `:http3-so-rcv-buf-bytes` / `:http3-so-snd-buf-bytes`
  (4 MiB requested by default, best effort: on Linux a process with
  CAP_NET_ADMIN gets it outright (`SO_RCVBUFFORCE`), otherwise Linux
  clamps to `net.core.rmem_max` / `wmem_max` and a smaller grant is logged
  at INFO; raise those for high-throughput servers. macOS halves the
  request until the kernel accepts it).

### Admission

Datagrams shorter than 1200 bytes never create state or get an answer,
and an unsupported QUIC version gets Version Negotiation. A client
Initial for an unknown connection id is answered statelessly or admitted:

0. An Initial whose Destination Connection ID is shorter than 8 bytes is
   dropped (RFC 9000 §7.2).
1. A token that verifies (our Retry token, bound to the client address
   and its family, the original and the Retry connection ids, 10 s
   lifetime) skips the Retry. An expired or misdirected token of ours gets
   CONNECTION_CLOSE(INVALID_TOKEN) in a small server Initial built without
   any state (RFC 9000 §8.1.2); another server's token counts as absent.
2. Without a valid token, a stateless Retry is required while
   `:http3-retry-threshold` (256) or more connections are handshaking, or
   always with `:http3-stateless-retry`. A spoofed flood therefore can't
   make the server allocate connections or sign handshakes beyond the
   threshold.
3. Past `:http3-max-half-open` (1024) handshaking connections, Initials are
   dropped.
4. Every connection takes a slot of the server's connection limiter for
   its whole life: `:max-connections` and `:max-connections-per-ip` count
   TCP and QUIC connections together. Past either limit the Initial is
   dropped ("connection-limit").

Handshaking connections are dropped at `:handshake-timeout`.

### Limits and timeouts

- Flow control: `:http3-initial-max-data-bytes` (4 MiB) is a hard bound on
  what quiche buffers per connection, per-stream windows (1 MiB derived)
  per stream: quiche's window autotuning is capped at the configured
  values.
- Header sections: `:max-header-bytes` (advertised as
  SETTINGS_MAX_FIELD_SECTION_SIZE) and `:max-header-fields`, as on the
  other protocols: a decoded section over either is answered 431 without
  the handler; a HEADERS frame over the hard ceiling (4x, at least 64 KiB)
  is reset with H3_EXCESSIVE_LOAD before anything is buffered. Bytes of
  incomplete sections buffered across a connection's streams are bounded
  by that ceiling (further streams get H3_REQUEST_REJECTED); a section not
  complete within `:header-timeout` gets H3_REQUEST_REJECTED.
- `:max-request-body-bytes`: a larger Content-Length is answered 413
  without the handler; a body growing past it fails the handler's reads
  with a 413 (`RequestBodyException`), answered as such, and the rest of
  the stream is no longer read.
- `Expect: 100-continue` gets a 100 interim response on the handler's
  first body read; any other expectation 417.
- Request bodies waiting for their handler: at most 64 KiB per request
  and, together, at most the connection window
  (`:http3-initial-max-data-bytes`) per connection, whatever the number
  of streams; past either, the loop stops reading those streams (QUIC flow
  control pushes back) until handlers read. Bytes moved into these
  buffers give the client its flow-control credit back, so this, not
  quiche's windows, is the bound (quiche holds at most a window more).
- `:max-buffered-bytes`: request-body bytes buffered for handlers count
  against the server-wide budget too; while it is exhausted the loop stops
  reading request streams until handlers read. A closed connection gives
  back what its requests still held, read or not.
- `:read-timeout`: a handler waiting longer for body bytes gets a
  `RequestBodyTimeoutException` (a `SocketTimeoutException`); 408.
- `:write-timeout`: a response whose bytes make no progress (the client
  stopped reading) for that long is reset (H3_REQUEST_CANCELLED) and its
  streamed body's producer fails.
- `:idle-timeout`: quiche's `max_idle_timeout`, and a connection with no
  request in flight for that long sends GOAWAY and closes, even when the
  client keeps it alive with PINGs.
- `:http3-stream-reset-limit` (400 per 30 s): peer stream resets beyond
  it close the connection with H3_EXCESSIVE_LOAD (rapid reset).
- Handlers running per connection are capped at twice
  `:http3-initial-max-streams-bidi` (handlers of reset requests that
  ignore interrupts included); past it, requests get H3_REQUEST_REJECTED.
  A request reset before its handler started never runs it. A closed
  connection keeps its `:max-connections` slot (and its place in the
  server's registry) until its last handler returns, so closing
  connections can't leave unbounded handlers running.
- Event loops contain failures: one connection's failure closes it
  (H3_INTERNAL_ERROR) and nothing else; a failure escaping the loop is
  logged at SEVERE, reported as the protocol error "event-loop-failure",
  closes that loop's connections and restarts the loop.
- A request stream that ends or is reset before its header section is
  complete gets H3_REQUEST_INCOMPLETE, releasing the stream.
- A request whose HEADERS frame ends the stream has no `:body`. When the
  client ends the stream separately (a FIN in a later packet), the
  handler, started on the header section, gets a body stream at EOF.
- Response header sections: one larger than the client's
  SETTINGS_MAX_FIELD_SECTION_SIZE isn't sent; the response becomes a 500,
  or the stream is reset (H3_INTERNAL_ERROR) when even that doesn't fit.
- Control streams (RFC 9114 §6.2.1, §7.2): a first frame other than
  SETTINGS (a reserved type included) is H3_MISSING_SETTINGS; CANCEL_PUSH
  (the server never pushes) and a decreasing MAX_PUSH_ID are H3_ID_ERROR;
  STOP_SENDING on one of our control or QPACK streams is
  H3_CLOSED_CRITICAL_STREAM (checked at most every 100 ms while packets
  arrive).

### Shutdown

On server close every QUIC connection (registered with the server like a
TCP one) drains in two GOAWAYs (RFC 9114 §5.2): the first carries the
largest stream id, so requests the client sent before learning of it are
still served; one round trip later (twice the RTT estimate, between 10 ms
and 1 s) the second names the first request it won't process, and newer
ones are refused (H3_REQUEST_REJECTED). In-flight requests finish; the
connection also waits for requests below the GOAWAY id still on their way
(a reordered or lost and resent stream), then (up to 2 s in all) for the
responses to be acknowledged, then closes with H3_NO_ERROR. A connection
closed by `:idle-timeout` drains the same way. For the last part of
`:shutdown-timeout` (a quarter, at most a second) connections still open
are closed, interrupting their handlers, which are waited for until the
deadline. The loops are stopped then and joined until the deadline (plus
0.1 s); the quiche configurations and sockets are freed only once every
loop exited (a loop that didn't, e.g. blocked in a `:server-events`
callback, is left holding them, and logged, rather than risk a
use-after-free), so `close` returns at `:shutdown-timeout` either way.

### Observability

`:server-events` and JFR receive connection open/close (protocol "h3"),
completed requests (method, status, body bytes each way, duration) and
protocol errors: `bad-request`, `body-too-large`, `header-too-large`,
`read-timeout`, `handler-timeout`, `protocol-error`, `rapid-reset`,
`header-timeout`, `write-timeout`, `handshake-timeout`,
`connection-limit`, `handshake-limit`, `event-loop-failure`. Peer-caused failures log at FINE through rate limiters.

## Native shim

`native/enso_quiche/enso_quiche.c` wraps libquiche and the UDP socket
I/O. Its natives are package-private in `com.s_exp.enso.quiche`;
`QuicheConfig`, `QuicheConnection` and `UdpSocket` own the raw handles
and refuse use after free; `NativeBuffer` hands the shim a direct
buffer's address and keeps the buffer reachable for the call. Packets and per-datagram
metadata live in direct memory passed as (address, capacity) and
range-checked by the shim; stream payloads cross as `byte[]` in critical
regions that span exactly one quiche call (a copy, never the handshake).
Loading checks that the shim implements the JNI contract of the classes
loading it (`Quiche.SHIM_ABI`, the shim's `ENSO_SHIM_ABI`, bumped whenever
a native or a record layout changes), so a stale build is refused with a
clear error, and that libquiche is the release the shim's header came from
(`Quiche.QUICHE_VERSION`), since struct layouts change between releases.
Only `Java_*` symbols are exported; builds use `-fstack-protector-strong`,
`-D_FORTIFY_SOURCE=2`, stack-clash protection, full RELRO and a
non-executable stack on Linux, CET (x86-64 Linux) or PAC/BTI (arm64); see
[build.md](build.md#http3-shim).

## Dev build (dynamic-link against system libquiche)

```
brew install cloudflare-quiche              # macOS (must be 0.29.3: checked at load)
make -C native/enso_quiche                  # → target/native/<os>-<arch>/libenso_quiche.<ext>
clojure -T:build javac-bench                # optional: Netty+Jetty bench servers
```

## Release / distributable build

Static-link libquiche 0.29.3 into the shim so the resulting `.dylib`/`.so`
has no runtime dep on system libquiche. Release CI
(`.github/workflows/release.yml`) does this across five platforms,
packages each shim into its classifier jar (published with the core
jar) and all of them into the fat jar (a run artifact only).

To reproduce locally (pinned commit, lockfile and toolchain; see
[build.md](build.md#http3-shim)):

```
native/enso_quiche/build-libquiche.sh /tmp/quiche
make -C native/enso_quiche QUICHE_STATIC=1 \
     QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
```

The built shim is bundled at `META-INF/native/<os>-<arch>/`. At load time
`Quiche.java` extracts the shim into a per-JVM directory (unique random
name — safe for multi-JVM hosts) then `System.load`s it. The directory is
created under the `enso.quiche.tmpdir` system property, else the
`ENSO_QUICHE_TMPDIR` environment variable, else `java.io.tmpdir`: set one
where the temp directory is mounted `noexec`.

Candidates are tried in order, each failure recorded and the next tried;
when none loads, the error lists every candidate and why it failed:
`-Denso.quiche.shim` (alone, when set), the classpath resource of the
platform, in a development checkout `target/native/<os>-<arch>/` next to
the `target/classes` directory the classes were loaded from (never a path
relative to the working directory, and never when running from a jar),
then `java.library.path`.

## Platform classifier resolution

- macOS → `darwin-arm64` (Apple Silicon only; Intel Macs need a
  dev/dynamic build via `make -C native/enso_quiche`)
- Linux glibc → `linux-arm64` / `linux-amd64`
- Linux musl (Alpine, Wolfi, Chimera) → `linux-musl-*` only. Detection:
  `/lib/ld-musl-*.so.1`.

Override for local dev:
`-Denso.quiche.shim=/abs/path/to/libenso_quiche.dylib`.

## Notes on the JNI vs FFM choice

An FFM binding was tried first and showed heap corruption reported by
libmalloc on macOS. The cause was in that binding, not in FFM or the
JDK: it allocated 64 bytes for `quiche_send_info`, a 288-byte struct
(two `sockaddr_storage`, their lengths and a `timespec`), so every
`quiche_conn_send` wrote past the allocation. The move to the JNI shim
fixed it as a side effect: the shim declares the struct in C, so its
size comes from quiche's own header.

## Tuning

- Each request runs on its own virtual thread. While
  `jdk.trackAllThreads` is on (the JDK default) every virtual thread is
  also recorded in a thread container for thread dumps, a node allocated
  and removed per request; `-Djdk.trackAllThreads=false` saves that, at
  the cost of those threads missing from `jcmd Thread.dump_to_file`.

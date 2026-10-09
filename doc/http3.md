# HTTP/3

HTTP/3 runs on Cloudflare's libquiche over UDP, through a small JNI shim
(`native/enso_quiche/enso_quiche.c`). quiche provides the QUIC transport;
HTTP/3 framing and QPACK are implemented in Java on top of it.

Handlers see the same Ring request as on HTTP/1.1 and HTTP/2, with
`:protocol` `"HTTP/3.0"` and `:scheme` `:https`. WebSocket isn't available:
a WebSocket response is answered 501.

## Installation

The core jar has no native code. HTTP/3 needs a classifier jar for each
platform you deploy to, which contains the shim with libquiche statically
linked in:

```clojure
{:deps {com.s-exp/enso              {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$darwin-arm64 {:mvn/version "1.0.0-alphaN"}}}
```

| Classifier | Platform |
|---|---|
| `darwin-arm64` | macOS 11+ on Apple Silicon |
| `linux-amd64`, `linux-arm64` | Linux with glibc 2.28+ (the shims are built on AlmaLinux 8) |
| `linux-musl-amd64`, `linux-musl-arm64` | Alpine, Wolfi, Chimera and other musl distributions |

The core jar is about 450 KB, a classifier jar about 3.5 MB
(darwin-arm64). For an uberjar that runs on several platforms, list several
classifiers side by side; the right shim is picked at load time:

```clojure
{:deps {com.s-exp/enso                  {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$darwin-arm64     {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-amd64      {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-musl-amd64 {:mvn/version "1.0.0-alphaN"}}}
```

On musl only the musl shim is loaded. musl is detected from the libc
mapped into the JVM (`/proc/self/maps`, else `/lib/ld-musl-*.so.1`), so a
glibc host that merely has the musl package installed isn't mistaken for
one. A glibc shim can't run on musl, so it is never tried as a fallback,
and a missing musl classifier gives a clear load error.

Intel Macs have no classifier jar; build the shim locally (see
[Development builds](#development-builds)).

A jar with every shim (`enso-<version>-all.jar`) is too large for Clojars.
Release CI keeps it as a workflow artifact, and `clojure -T:build jar-all`
builds it locally.

### Native access (JDK 24+)

The shim is loaded with `System.load`, a restricted method. JDK 24 and
later print a warning (and a future release will refuse) unless native
access is enabled for the code loading it. Add this JVM option:

```
--enable-native-access=ALL-UNNAMED
```

Use `--enable-native-access=com.s_exp.enso` (the jar's
`Automatic-Module-Name`) if enso runs as a named module. With the Clojure
CLI, pass `-J--enable-native-access=ALL-UNNAMED` or add it to `:jvm-opts`
in an alias. JDK 21 needs nothing.

## Enabling HTTP/3

```clojure
(enso/run-server handler
  {:port 8443
   :ssl-context ctx       ; for HTTP/1.1 and HTTP/2 on the TCP port
   :http2 true
   :http3 true
   :http3-cert-path "/path/cert.pem"
   :http3-key-path  "/path/key.pem"})
```

HTTP/3 uses its own UDP sockets and can share the port number with the
TCP listener. When it is on, HTTP/1.1 and HTTP/2 responses carry an
`Alt-Svc` header so clients find it. All options are listed in
[options.md](options.md#http3).

### Certificates

quiche reads the PEM certificate and key itself, from disk. Prefer an
ECDSA (P-256) certificate. The handshake signs once per connection, on the
connection's event loop thread, and an ECDSA signature costs a small
fraction of an RSA-2048 one, which matters most under a connection flood.

```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj /CN=example.org
```

Every `:http3-cert-reload-interval` (10 s by default, 0 disables) the
files are checked for a change in modification time, size or inode, so a
symlink swap like the one Kubernetes does for secrets is noticed. A changed
pair is loaded and used for new connections. Existing connections keep the
configuration they were accepted with, which is freed with the last of
them. A pair that doesn't load (a half-written file, a key that doesn't
match the certificate) is logged at WARNING, rate-limited, and the current
one is kept until the files change again. Replace both files atomically
(write elsewhere, then rename) so a check never sees a mixed pair.
`Http3Listener.reloadCertificates()` forces a reload.

## How it runs

### Event loops and sharding

QUIC connections are served by event loops, one per core on Linux by
default (at most 64) and one elsewhere (`:http3-event-loops`). A loop is a
platform thread that owns a shard of connections. Every quiche call for a
connection happens on its loop, so quiche, which isn't thread-safe, needs
no locking. Handlers run on virtual threads, one per request, as on
HTTP/2.

The server chooses the 16-byte connection ids clients use to address it.
The first byte names the owning loop: its index modulo the loop count,
plus a random multiple of the count.

On Linux each loop has its own `SO_REUSEPORT` socket on the port, and a
classic BPF program (`SO_ATTACH_REUSEPORT_CBPF`) makes the kernel deliver
each datagram to the socket of the loop named by its destination
connection id (byte 1 of a short header, byte 6 of a long one). Initial
and 0-RTT packets are the exception. Their id is chosen by the client, and
must not pick the loop: a client could aim every handshake at one loop,
and ids would spread unevenly when 256 isn't a multiple of the loop count.
The program leaves those to the kernel's 4-tuple hash, and the loop that
receives one accepts it. Retransmissions, and the Initial after a Retry,
come from the same 4-tuple and reach the same loop; one addressed to an
id another loop generated for its Retry is handed to that loop. Packets
never change threads otherwise. If the BPF program can't be attached, the
4-tuple hash applies to every datagram, and the rare one that lands on the
wrong loop (after a NAT rebinding) is copied to its owner's inbox.

Elsewhere (macOS, development) there is one socket. Loop 0 receives every
datagram and hands other loops' datagrams to their inboxes; with the
default single loop nothing is handed over. One thread then receives, runs
TLS handshakes and serves every connection. Giving each connection its own
connected UDP socket would spread the work, but needs a descriptor per
connection, kqueue registrations instead of one `poll` per loop, and a
fallback to the shared socket whenever a peer's address changes. That
isn't done; run production servers on Linux.

### The event loop

Each iteration, a loop:

1. Receives a batch of datagrams (`recvmmsg` on Linux) into a direct-memory slab, routes each by connection id and feeds it to quiche in place, with no copy and no Java object per datagram.
2. Takes datagrams handed over by other loops, and connections signalled by handler threads (a lock-free push, plus a write to the loop's wake-up eventfd or pipe when it is parked).
3. Fires expired deadlines from a binary heap of connections: quiche's timer, pacing, handshake, idle, header and write timeouts.
4. Processes each connection that had any of the above. Request streams are read straight from the receive buffer (`quiche_conn_stream_readable_next`). Responses are encoded: QPACK, HEADERS with a minimal length, and small bodies inline in the same `stream_send` as the FIN. Streams that were waiting for flow-control credit resume as quiche reports them writable (`quiche_conn_stream_writable_next`).
5. Writes quiche's packets into the send slab and sends them in batches. On Linux that is one `sendmmsg` per batch of up to 64 messages, each a single datagram or, when the kernel supports UDP GSO, a run of up to 64 equal-size packets to the same peer that the kernel segments. A device that refuses GSO turns it off for the socket. Elsewhere it is one `sendmsg` per packet. Receive offload (GRO) isn't used.
6. Parks in `poll` until the socket is readable, it is woken, or the next deadline. A wake-up that finds the socket not readable skips the receive call.

Details:

- Pacing: on Linux, when quiche's pacer (`send_info.at`) wants a packet sent more than 1 ms later, the packet is held and the connection resumes sending at its release time. macOS has no pacing, because quiche doesn't report release times there.
- Acknowledgements: quiche acknowledges a request at once. After starting handlers, a connection's packets wait up to 0.5 ms so that a quick response carries the ACK, giving one datagram per request instead of two. That is well within the `max_ack_delay` it advertises (25 ms unless `:http3-max-ack-delay` is set).
- A datagram the kernel refuses for a transient reason (buffer exhaustion, firewall, unreachable peer) is counted as lost, and quiche's loss recovery resends what matters. A full socket buffer pauses sending until it is writable.
- Bound to a wildcard address on Linux, the server records each datagram's destination address (`IP_PKTINFO` / `IPV6_PKTINFO`) and replies from it, so a multi-homed host answers from the address the client used. On other systems, bind a specific address on multi-homed hosts.
- Socket buffers (`:http3-so-rcv-buf-bytes`, `:http3-so-snd-buf-bytes`, 4 MiB by default) are best effort. On Linux a process with CAP_NET_ADMIN gets them outright (`SO_RCVBUFFORCE`); otherwise the kernel clamps them to `net.core.rmem_max` / `wmem_max` and a smaller grant is logged at INFO, so raise those on high-throughput servers. macOS halves the request until the kernel accepts it.

### Admission

Datagrams shorter than 1200 bytes never create state or get an answer. A
long header with an unsupported version gets Version Negotiation from
whichever loop receives it, whatever its connection id lengths (0 to 255
bytes, RFC 8999) and the rest of its first byte. It is built in Java,
without quiche, and never sent in reply to a Version Negotiation packet.

A client Initial for an unknown connection id goes through these checks,
in order:

1. A Destination Connection ID shorter than 8 bytes: dropped (RFC 9000 §7.2).
2. A token that verifies (our Retry token, bound to the client address and its family, the original and the Retry connection ids, valid 10 s) skips the Retry. An expired or misdirected token of ours gets CONNECTION_CLOSE(INVALID_TOKEN) in a small server Initial built without any state (RFC 9000 §8.1.2). Another server's token counts as no token.
3. Without a valid token, a stateless Retry is required when `:http3-retry-threshold` (256) or more connections are handshaking, always with `:http3-stateless-retry`, and always when `:max-connections-per-ip` is set (a per-address slot taken for a spoofed address would lock that address out, so the address is proven first). A spoofed flood therefore can't make the server allocate connections or sign handshakes beyond the threshold.
4. Past `:http3-max-half-open` (1024) handshaking connections, the Initial is dropped. The check takes the slot, so loops admitting at the same time can't overshoot it.
5. While `:max-buffered-bytes` is exhausted, the Initial is dropped ("connection-limit"). Nothing is reserved at admission, so an idle connection costs no budget.
6. Each connection holds a slot of the server's connection limiter for its whole life. `:max-connections` and `:max-connections-per-ip` count TCP and QUIC connections together. Past either, the Initial is dropped ("connection-limit").

Connections still handshaking at `:handshake-timeout` are dropped.

### Flow control and memory

Connections start with a 512 KiB window (`:http3-initial-max-data-bytes`)
and streams with half of that, 256 KiB, the same as HTTP/2's initial
stream window. A stream whose handler doesn't read therefore can't stall
the connection's other requests.

Release builds link libquiche with two patches
(`native/enso_quiche/patches/`, see [build.md](build.md#http3-shim)).
With them (`Quiche.RECV_WINDOW_CONTROL`), windows autotune as quiche's do:
a window doubles when the handler has read half of it within two round
trips. A stream's window grows up to `:http3-max-window-bytes` (8 MiB,
about 160 MiB/s at 50 ms), a connection's up to twice that. The second
patch bounds the out-of-order fragments quiche buffers per stream, so the
data it holds stays within the connection window plus a small overhead
(about 1.5 MiB in all at the defaults).

With a stock libquiche (a distribution's build, used for development)
windows keep their initial sizes: one stream uploads at most 256 KiB per
round trip (about 5 MiB/s at 50 ms), a connection 512 KiB. Stock libquiche
also doesn't bound out-of-order buffering. Use it for development only.

quiche's buffers are native memory, charged to `:max-buffered-bytes`
through the connection's account:

- The initial window is charged while the connection reads a request body, from its first body until no body is being read.
- Each doubling of the connection window is reserved before quiche may use it, once quiche has grown the window to its current bound and handlers have read a window of body bytes since. It is skipped while the account can't pay, and held until the connection goes, like HTTP/2's grown connection window.
- Stream windows need no reservation, because the connection window bounds what the peer may send across its streams.
- A connection reading no body costs nothing, so idle and GET-only connections don't limit how many are admitted.

The unpaid part is the initial window, promised in the handshake like
HTTP/2's initial 65535 octets. A peer can only fill it by sending data the
server isn't reading while no body on its connection is being read
(out-of-order data, or requests waiting for the connection's buffered
bodies to be read). That is at most 512 KiB per connection, about 5 GiB
for the default 10000 connections (HTTP/2: 625 MiB), with or without the
patches. Lower the initial window or `:max-connections` where that much
native memory isn't available.

Request bodies waiting for their handler are buffered in Java: at most
64 KiB per request and, together, at most the connection window per
connection, however many streams are open. Past either, the loop stops
reading those streams until handlers read, and QUIC flow control pushes
back on the client. Moving bytes into these buffers is what returns the
client's credit, so they, not quiche's windows, are the bound; quiche holds
at most one window more. These bytes also count against
`:max-buffered-bytes` through the connection's fair share. While the
connection is throttled (the budget exhausted, or past its low-water mark
with this connection over its share) the loop stops reading its request
streams until handlers catch up.

Response bytes held for the client's flow control count too: writes quiche
hasn't taken yet (a copy, or the handler's body array kept alive for them)
and the part of a streamed body waiting to be sent. They are released as
they are sent, when the stream is reset or stopped, and when the
connection goes. A closed connection releases whatever its requests still
held.

### Limits and timeouts

- Header sections: `:max-header-bytes` (advertised as SETTINGS_MAX_FIELD_SECTION_SIZE) and `:max-header-fields` apply as on the other protocols. A decoded section over either gets 431 without running the handler. A HEADERS frame over the hard ceiling (4×, at least 64 KiB) is reset with H3_EXCESSIVE_LOAD before anything is buffered. Bytes of incomplete sections across a connection's streams are bounded by that ceiling, and further streams get H3_REQUEST_REJECTED. A section not complete within `:header-timeout` gets H3_REQUEST_REJECTED. Time the server spends not reading a stream (because its connection's body buffers are full) doesn't count: the clock restarts when reading resumes.
- `:max-request-body-bytes`: a larger Content-Length gets 413 without running the handler. A body that grows past it fails the handler's reads with a 413, and the rest of the stream isn't read.
- `Expect: 100-continue` gets a 100 interim response on the handler's first body read. Any other expectation gets 417.
- `:read-timeout`: a handler waiting longer for body bytes gets a `SocketTimeoutException`, answered 408. So does a body slower than `:min-data-rate-bytes` once `:min-data-rate-grace` of waiting has passed.
- `:write-timeout`: a response that makes no progress for that long (the client stopped reading) is reset with H3_REQUEST_CANCELLED and its streamed body's producer fails. Progress means 16 KiB sent, so a client handing out credit a few bytes at a time makes none.
- `:idle-timeout`: sets quiche's `max_idle_timeout`. A connection with no request in flight for that long also sends GOAWAY and closes, even if the client keeps it alive with PINGs.
- `:http3-stream-reset-limit` (400 per 30 s): peer stream resets beyond it close the connection with H3_EXCESSIVE_LOAD.
- Running handlers per connection are capped at twice `:http3-initial-max-streams-bidi`, counting handlers of reset requests that ignore their interrupt. Past it, requests get H3_REQUEST_REJECTED. A request reset before its handler started never runs it. A closed connection keeps its `:max-connections` slot, and its place in the server's registry, until its last handler returns, so closing connections can't leave an unbounded number of handlers running.
- A request stream that ends or is reset before its header section is complete gets H3_REQUEST_INCOMPLETE.
- A request whose HEADERS frame ends the stream has a nil `:body`. When the client ends the stream separately (a FIN in a later packet), the handler, already started, gets a body stream at EOF.
- A response header section larger than the client's SETTINGS_MAX_FIELD_SECTION_SIZE isn't sent. The response becomes a 500, or the stream is reset (H3_INTERNAL_ERROR) when even that doesn't fit.
- Control streams (RFC 9114 §6.2.1, §7.2): a first frame other than SETTINGS, a reserved type included, is H3_MISSING_SETTINGS. CANCEL_PUSH (the server never pushes) and a decreasing MAX_PUSH_ID are H3_ID_ERROR. STOP_SENDING on one of our control or QPACK streams is H3_CLOSED_CRITICAL_STREAM, checked at most every 100 ms while packets arrive.

Failures are contained. A failure in one connection closes only that
connection, with H3_INTERNAL_ERROR. A failure escaping the loop itself is
logged at SEVERE and reported as the protocol error
"event-loop-failure"; the loop's connections are closed and freed (each
teardown step guarded, so a broken timer or table entry can't keep one
alive) and the loop restarts with fresh tables, timers and send batch. A
handler thread that fails to start is answered 503 and not counted as
running.

### Shutdown

On server close every QUIC connection drains in two GOAWAYs (RFC 9114
§5.2). The first carries the largest stream id, so requests the client
sent before seeing it are still served. One round trip later (twice the
RTT estimate, between 10 ms and 1 s), the second names the first request
that won't be processed, and newer ones are refused with
H3_REQUEST_REJECTED. Requests in flight finish. The connection also waits
for requests below the GOAWAY id that are still on their way (reordered,
or lost and resent), then, up to 2 s in all, for the responses to be
acknowledged, and closes with H3_NO_ERROR. A connection closed by
`:idle-timeout` drains the same way.

In the last quarter of `:shutdown-timeout` (at most a second),
connections still open are closed and their handlers interrupted, and
waited for until the deadline. The loops are then stopped and joined until
the deadline plus 0.1 s. quiche configurations and sockets are freed only
once every loop has exited; a loop that didn't is left holding them, and
logged, rather than risk a use-after-free. Either way `close` returns at
`:shutdown-timeout`.

### Observability

`:server-events` and JFR report connections opening and closing (protocol
"h3"), completed requests and protocol errors: "bad-request",
"body-too-large", "header-too-large", "read-timeout", "min-data-rate",
"handler-timeout", "protocol-error", "rapid-reset", "header-timeout",
"write-timeout", "handshake-timeout", "connection-limit",
"handshake-limit" and "event-loop-failure". Event callbacks never run on
an event loop. Peer-caused failures log at FINE, rate-limited.

## Native shim

`native/enso_quiche/enso_quiche.c` wraps libquiche and the UDP socket I/O.
Its natives are package-private in `com.s_exp.enso.quiche`. `QuicheConfig`,
`QuicheConnection` and `UdpSocket` own the raw handles and refuse use after
free. `NativeBuffer` passes the shim a direct buffer's address and keeps
the buffer reachable during the call. Packets and per-datagram metadata
live in direct memory, passed as (address, capacity) and range-checked by
the shim. Stream payloads cross as `byte[]` in critical regions that span
exactly one quiche call (a copy, never the handshake).

When it loads the shim, the Java side checks that:

- the shim implements the JNI contract of the classes loading it (`Quiche.SHIM_ABI` against the shim's `ENSO_SHIM_ABI`, bumped whenever a native or a record layout changes), so a stale build is refused with a clear error;
- the record sizes, field offsets and flag values the shim was compiled with (its `LAYOUT` table, also cross-checked by `_Static_assert`s) match `Records` and `UdpSocket`, so a layout edited on one side only is refused by name;
- libquiche is the release the shim's header came from (`Quiche.QUICHE_VERSION`), since struct layouts change between releases.

Only `Java_*` symbols are exported. Builds use `-fstack-protector-strong`,
`-D_FORTIFY_SOURCE=2`, stack-clash protection, full RELRO and a
non-executable stack on Linux, and CET (x86-64 Linux) or PAC/BTI (arm64);
see [build.md](build.md#http3-shim).

### Loading

The shim is bundled at `META-INF/native/<os>-<arch>/`. At load time it is
extracted to a per-JVM directory with a random name, so several JVMs on a
host don't collide, then loaded with `System.load`. The directory is
created under the `enso.quiche.tmpdir` system property, else the
`ENSO_QUICHE_TMPDIR` environment variable, else `java.io.tmpdir`. Set one
of them if the temp directory is mounted `noexec`.

Candidates are tried in order, and if none loads the error lists each one
and why it failed:

1. `-Denso.quiche.shim=/abs/path/to/libenso_quiche.dylib`, alone, when set;
2. the classpath resource for the platform;
3. in a development checkout, `target/native/<os>-<arch>/` next to the `target/classes` directory the classes were loaded from (never a path relative to the working directory, and never when running from a jar);
4. `java.library.path`.

### Development builds

For development the shim can link the system libquiche dynamically:

```
brew install cloudflare-quiche   # macOS; must be 0.29.3, checked at load
make -C native/enso_quiche       # -> target/native/<os>-<arch>/libenso_quiche.<ext>
```

A stock libquiche lacks the patches the release builds apply. Receive
windows stay fixed, the tests that need receive-window control are
skipped, and out-of-order buffering is unbounded. Use it for development
only. Release shims always link the patched libquiche, and
`check-shim.sh` refuses one without the patches. To run everything
locally, build the shim the release way.

### Release builds

Release shims link libquiche 0.29.3 statically, with the patches in
`native/enso_quiche/patches/`, so they have no runtime dependency on a
system libquiche. Release CI (`.github/workflows/release.yml`) builds them
for five platforms, packages each into its classifier jar (published with
the core jar) and all of them into the all-platform jar (kept as a run
artifact). To reproduce one locally from the pinned commit, lockfile and
toolchain:

```
native/enso_quiche/build-libquiche.sh /tmp/quiche
make -C native/enso_quiche QUICHE_STATIC=1 \
     QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
```

More in [build.md](build.md#http3-shim).

### Why JNI

An FFM binding was tried first and showed heap corruption reported by
libmalloc on macOS. The bug was in that binding, not in FFM or the JDK: it
allocated 64 bytes for `quiche_send_info`, a 288-byte struct (two
`sockaddr_storage`, their lengths and a `timespec`), so every
`quiche_conn_send` wrote past the allocation. Moving to a C shim fixed it,
since the shim takes the struct's size from quiche's own header.

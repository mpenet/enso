# HTTP/3 conformance

enso runs the [h3spec](https://github.com/kazu-yamamoto/h3spec) suite
against libquiche 0.29.3, the JNI shim and the Java HTTP/3 layer. With
h3spec 0.1.14, 75 of 77 cases pass. Both failures are checks that only
libquiche can make. Every HTTP/3 and QPACK case passes.

```
bench/h3spec/run.sh
```

The runner downloads the pinned h3spec release and verifies its checksum
(see [testing.md](testing.md#conformance-suites)). The expected failures
are listed in
[`bench/h3spec/expected-failures.txt`](../bench/h3spec/expected-failures.txt).
CI fails on any other failing case, on a listed case that passes, and on
a run of other than 77 cases.

## Results

| Category | Passing |
|---|---:|
| QPACK | 4 / 4 |
| HTTP/3 critical and unidirectional streams | 8 / 8 |
| HTTP/3 frames and control stream | 10 / 10 |
| HTTP/3 requests | 12 / 12 |
| Transport parameters | 11 / 11 |
| TLS | 7 / 7 |
| Other QUIC transport errors | 23 / 23 |
| Reserved header bits | 0 / 2 |

## Expected failures

- MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2]
- MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2]

The reserved bits are under header protection, which quiche removes
internally. The shim never sees them, so only libquiche could check them.
quiche ignores the bits and processes the packet. Only a buggy or hostile
peer sets them, so the practical impact is low.

## Notes on passing categories

QPACK: static-table index, missing dynamic-table entry, dynamic-table
capacity over the limit, and Insert Count Increment 0 on the decoder
stream.

Critical and unidirectional streams: a closed control, encoder or decoder
stream, an encoder stream ending inside an instruction, a second control,
encoder or decoder stream, and a client push stream. These cases need a
fourth unidirectional stream, and `:http3-initial-max-streams-uni` is 8 by
default.

Frames and control stream: first control frame not SETTINGS, DATA or
HEADERS on the control stream, a second SETTINGS, HTTP/2 settings,
SETTINGS ending mid-parameter, reserved and repeated setting identifiers,
CANCEL_PUSH on a request stream, and a control frame declaring more than
is buffered (H3_EXCESSIVE_LOAD before any of it arrives).

Requests: DATA before HEADERS, pseudo-header validation (duplicate,
missing mandatory including `:authority` for http and https, prohibited,
after regular fields), and connection-specific fields (`connection`,
`keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, and `te`
other than `trailers` are malformed; `te: trailers` is accepted).

Transport parameters: libquiche validates the client's transport
parameters (RFC 9000 §7.3, §7.4, §18.2) while processing its first flight
and closes with TRANSPORT_PARAMETER_ERROR. It queues that CONNECTION_CLOSE
at the Handshake level, which the client can't decrypt yet because it
hasn't received a ServerHello. So when quiche refuses a client's first
flight before the server has sent anything, enso also sends the close as
a server Initial, built statelessly from the Initial keys (RFC 9000
§10.2.3), and frees the connection.

TLS: KeyUpdate in Handshake and in 1-RTT, ALPN, a missing
transport-parameters extension (two cases), EndOfEarlyData, and CRYPTO in
0-RTT. h3spec skips the 0-RTT case, since the server offers no 0-RTT, and
counts it as passing.

Other QUIC transport errors: flow control, stream limits, stream state,
frame encoding, ACK ranges and ACKs of packets never sent, empty packets,
CRYPTO buffering, retired and new connection ids, and unexpected frames
(NEW_TOKEN, HANDSHAKE_DONE, PATH_CHALLENGE, STREAM_DATA_BLOCKED and
DATA_BLOCKED in Handshake).

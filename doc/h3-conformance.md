# HTTP/3 conformance

Ensō runs the external h3spec suite (`bench/h3spec/run.sh`) against
libquiche 0.29.3 + our JNI shim + our pure-Java HTTP/3 layer. Current status: **47/49 pass, 2 failures**.
Both failures are reserved-bit checks inside libquiche 0.29.3, listed
below. The HTTP/3-layer and QPACK layers pass 100%.

Run: `bench/h3spec/run.sh` (downloads the pinned h3spec 0.1.13 release and
verifies its checksum; see [testing.md](testing.md#conformance-suites)).
Expected failures: [`bench/h3spec/expected-failures.txt`](../bench/h3spec/expected-failures.txt);
any other failing case, a listed case that passes, or a run of other than
49 cases fails CI.

## Transport-layer failures — libquiche 0.29.3 limitations

| # | h3spec test | Category |
|---|-------------|----------|
| 1 | MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2] | Reserved-bit validation |
| 2 | MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2] | Reserved-bit validation |

The reserved bits sit under header protection, which quiche removes
internally; the shim never sees them, so only libquiche can check them.

### Practical impact

Low: only a buggy or hostile peer sets reserved bits. quiche ignores
them and processes the packet.

## Invalid transport parameters

libquiche validates the client's transport parameters (RFC 9000 §7.3,
§7.4, §18.2) while processing its first flight and closes with
TRANSPORT_PARAMETER_ERROR, but queues that CONNECTION_CLOSE at the
Handshake level. The client hasn't received a ServerHello then, so it
can't decrypt it. When quiche refuses a client's first flight before the
server sent anything, Ensō also sends the close as a server Initial,
built statelessly from the Initial keys (RFC 9000 §10.2.3), and frees the
connection. All eight transport-parameter cases pass.

## Fully passing categories

- QPACK — all 4 pass (static-table index, dynamic-table capacity, Insert
  Count Increment 0 on the decoder stream, closing a critical stream).
- HTTP/3 frame and control-stream errors — all 7 pass (DATA before
  HEADERS, first control frame not SETTINGS, DATA or HEADERS on the
  control stream, second SETTINGS, HTTP/2 settings, CANCEL_PUSH on a
  request stream).
- HTTP/3 pseudo-header validation — all 4 pass (duplicate, missing
  mandatory including `:authority` for http/https, prohibited, after
  regular).
- TLS-layer errors — all 7 pass (KeyUpdate in Handshake and in 1-RTT,
  ALPN, missing transport-parameters extension twice, EndOfEarlyData,
  CRYPTO in 0-RTT; h3spec skips the 0-RTT case, since the server offers
  no 0-RTT, and counts it as passing).
- Other QUIC transport errors — all 17 pass (flow control, stream limits,
  stream state, frame encoding, unexpected frames: NEW_TOKEN,
  HANDSHAKE_DONE, PATH_CHALLENGE in Handshake).

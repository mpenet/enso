# HTTP/3 conformance

Ensō ships an h3spec suite run against libquiche 0.29.3 + our JNI shim +
our pure-Java HTTP/3 layer. Current status: **39/49 pass, 10 failures**.
All 10 failures are transport-layer, listed below as libquiche 0.29.3
limitations — fixable only by upstream. The HTTP/3-layer and QPACK
layers pass 100%.

Run: `bench/h3spec/run.sh`
Baseline snapshot: [`bench/h3spec/baseline.txt`](../bench/h3spec/baseline.txt)

## Transport-layer failures — libquiche 0.29.3 limitations

These 10 tests exercise QUIC transport-parameter validation and
short/handshake-packet reserved-bit checks. All happen strictly at the
QUIC transport layer inside libquiche — well below our JNI boundary
and pure-Java HTTP/3 code. We can't fix them without patching libquiche
itself. Cloudflare's 0.29.3 release is currently the pinned version
across our release CI + shim static links.

| # | h3spec test | Category |
|---|-------------|----------|
| 1 | MUST send TRANSPORT_PARAMETER_ERROR if `initial_source_connection_id` is missing (RFC 9000 §7.3) | Transport param validation |
| 2 | MUST send TRANSPORT_PARAMETER_ERROR if `original_destination_connection_id` is received (§18.2) | Transport param validation |
| 3 | MUST send TRANSPORT_PARAMETER_ERROR if `preferred_address` is received (§18.2) | Transport param validation |
| 4 | MUST send TRANSPORT_PARAMETER_ERROR if `retry_source_connection_id` is received (§18.2) | Transport param validation |
| 5 | MUST send TRANSPORT_PARAMETER_ERROR if `stateless_reset_token` is received (§18.2) | Transport param validation |
| 6 | MUST send TRANSPORT_PARAMETER_ERROR if `max_udp_payload_size < 1200` (§7.4, §18.2) | Transport param validation |
| 7 | MUST send TRANSPORT_PARAMETER_ERROR if `ack_delay_exponent > 20` (§7.4, §18.2) | Transport param validation |
| 8 | MUST send TRANSPORT_PARAMETER_ERROR if `max_ack_delay >= 2^14` (§7.4, §18.2) | Transport param validation |
| 9 | MUST send PROTOCOL_VIOLATION if reserved bits in Handshake packet are non-zero (§17.2) | Reserved-bit validation |
| 10 | MUST send PROTOCOL_VIOLATION if reserved bits in Short header are non-zero (§17.2) | Reserved-bit validation |

### Practical impact

Low. All ten failures cover peers sending malformed transport
parameters or malformed header bits — behavior only reachable from a
buggy or hostile client. The typical peer never triggers them. quiche
accepts and ignores the values (or the bits), then continues the
handshake — same behavior we'd see from a strict-check libquiche
version after the peer is disconnected.

### Fix path

- Upstream (Cloudflare quiche): the checks land as validation in
  `crypto/tls13_server.c` and `frame.rs` on the quiche side. We
  auto-pick up new releases via the pinned `QUICHE_VERSION` env var
  in `.github/workflows/release.yml`.
- Local: nothing we can do without carrying a fork of libquiche.

Cloudflare tracks these gaps in their h3spec compliance dashboard;
several were fixed in later master builds but not yet in 0.29.x.

## Fully passing categories

- QPACK protocol errors — all 4 pass (dynamic-capacity, insert-count,
  decoder-stream, static-table-index).
- HTTP/3 frame-type errors — all pass (DATA-before-HEADERS, duplicate
  SETTINGS, CANCEL_PUSH on request stream, control-stream misuse).
- HTTP/3 pseudo-header validation — all 4 pass (duplicate, missing
  mandatory including `:authority` for http/https, prohibited, after
  regular).
- TLS-layer errors — all 6 pass (KeyUpdate, ALPN, missing extension,
  EndOfEarlyData, CRYPTO in 0-RTT).
- QUIC frame-encoding errors — all pass (STREAM state, MAX_STREAMS,
  NEW_CONNECTION_ID, HANDSHAKE_DONE, NEW_TOKEN).

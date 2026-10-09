# Deployment

Settings to review before putting enso in front of real traffic, and what
the server already protects against. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Checklist

- Set `:handler-timeout`. It is off by default because how long a handler
  may take is application policy. Without it, a handler stuck on a slow
  dependency holds its connection (or HTTP/2 or HTTP/3 stream slot) and
  its virtual thread until it returns. A few times your slowest legitimate
  handler is a reasonable value.
- Set `:max-connections-per-ip` when clients connect directly. Without it,
  one address can take every connection slot. Leave it off behind a load
  balancer or NAT, where clients share addresses, and limit per client
  there instead.
- WebSocket handshakes are accepted only from the server's own origin: the
  `Origin` host must equal `Host`. Behind a proxy that rewrites `Host`, or
  for cross-origin clients, list the allowed origins in
  `:ws-allowed-origins`. Authenticate in the handler before returning the
  listener.
- Check the [default limits](#default-limits) against your traffic, in
  particular the 10 MiB request body limit.
- For HTTP/3, see [below](#http3).

## Default limits

The defaults bound what a single client can make the server hold.

| Limit | Default | Option |
|---|---|---|
| request head | 64 KiB | `:max-header-bytes` |
| header fields per request | 100 | `:max-header-fields` |
| request body | 10 MiB | `:max-request-body-bytes` |
| WebSocket message | 1 MiB | `:ws-max-message-bytes` |
| queued WebSocket sends | 1 MiB per connection | `:ws-max-queued-bytes` |
| open connections | 10000 | `:max-connections` |
| buffered peer data and flow-control credit | a quarter of the heap, shared fairly under pressure | `:max-buffered-bytes` |
| slowest request body | 240 bytes/s after 5 s of waiting | `:min-data-rate-bytes` |

Timeouts are listed in [options.md](options.md#timeouts).

## What the server rejects

Request parsing:

- request smuggling: duplicate `Content-Length` (even with equal values, on every protocol), `Transfer-Encoding` with `Content-Length`, obs-fold, bare LF line endings, invalid chunk sizes;
- HTTP/1.1 requests without Host, and invalid request targets or Host authorities;
- HTTP/2 and HTTP/3 request heads that break RFC 9113 / RFC 9114 rules (pseudo-headers, `:scheme`, `:authority` and `Host`, connection-specific fields, `TE`, `Content-Length`). A well-formed CONNECT gets 501, as on HTTP/1.1.

Responses:

- header injection: names must be tokens, and values may not contain CR, LF, NUL or other control characters;
- statuses outside 200-599, except 101 for a WebSocket upgrade.

Slow and stalled clients are cut off by the same timeouts on every
protocol: handshake, header (slowloris), read and minimum data rate (slow
uploads), write (peers that stop reading), idle and handler.

Floods and resource exhaustion:

- connection caps, global and per address, counting TCP and QUIC together;
- one server-wide budget for bytes buffered on behalf of peers;
- HTTP/2 rapid reset (CVE-2023-44487) and MadeYouReset (CVE-2025-8671), through `:http2-stream-reset-limit`;
- HTTP/2 CONTINUATION floods, through `:http2-continuation-limit` and the header size ceiling;
- HTTP/2 control-frame floods from peers that don't read, and data dribble (CVE-2019-9511);
- HTTP/3 rapid reset, through `:http3-stream-reset-limit`;
- QUIC handshake floods: a stateless Retry past `:http3-retry-threshold` handshaking connections, and a cap on half-open connections;
- WebSocket decompression bombs, and ping floods (pongs are coalesced);
- TLS 1.2 client-initiated renegotiation.

## Behind a proxy

- Leave `:max-connections-per-ip` off; every client shares the proxy's address.
- If the proxy rewrites `Host`, list the public origins in `:ws-allowed-origins`.
- The default `:idle-timeout` of 75 s is longer than the 60 s idle timeout of common load balancers (AWS ALB), so the balancer, not enso, closes idle connections.

## HTTP/3

- Use Linux in production. Elsewhere one thread receives every datagram
  and runs every handshake (see [http3.md](http3.md#event-loops-and-sharding)).
- Prefer an ECDSA (P-256) certificate. Each QUIC handshake signs on an
  event loop thread, and an ECDSA signature costs a fraction of an RSA
  one. That matters under a connection flood.
- Raise `net.core.rmem_max` and `net.core.wmem_max` on busy servers. The
  4 MiB UDP buffers enso asks for are clamped to them, and a smaller grant
  is logged at INFO.
- On JDK 24 and later, add `--enable-native-access=ALL-UNNAMED` to the JVM
  options ([details](http3.md#native-access-jdk-24)).
- If the temp directory is mounted `noexec`, point
  `-Denso.quiche.tmpdir` (or `ENSO_QUICHE_TMPDIR`) at one that isn't. The
  shim is extracted there at startup.
- Replace certificate files atomically (write elsewhere, then rename), so
  the reload check never sees a mismatched pair.
- Release shims bound the out-of-order data quiche buffers per stream. A
  shim built against a stock libquiche doesn't, and is for development
  only ([build.md](build.md#http3-shim)).

## Operations

- `EnsoServer.isHealthy()` is true while the server runs with its
  acceptor, timer and every HTTP/3 event loop alive. Each of these threads
  restarts itself after a failure, so false is a fault worth alerting on.
- Logs go through `java.util.logging` ([options.md](options.md#logging)).
  Client-caused failures log at FINE; WARNING means a server fault.
- `:server-events` and JDK Flight Recorder events cover connections,
  requests and protocol errors
  ([options.md](options.md#server-events)).

## Tuning

Every request runs on its own virtual thread. While
`jdk.trackAllThreads` is on (the JDK default), each virtual thread is also
recorded in a thread container for thread dumps, which costs a small
allocation per request. `-Djdk.trackAllThreads=false` saves it, but those
threads then don't appear in `jcmd Thread.dump_to_file`.

# Handlers, response bodies, WebSocket, SSE

Standard Ring 1.x handler signature: `(fn [request] response)`.
Same contract across HTTP/1.1, HTTP/2, HTTP/3. `:protocol` reflects the
negotiated version (`"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3.0"`).

## Response body types

- `String`, `byte[]` — inlined or single-write.
- `java.io.InputStream` — chunked (HTTP/1.1) or close-delimited. When the
  response has a `Content-Length` header, sent as a fixed-length body.
- `java.io.File` — zero-copy via `FileChannel.transferTo(SocketChannel)`
  on plain HTTP. User-space copy on TLS.
- `clojure.lang.ISeq` — concatenated to a String.
- `(fn [ChunkedWriter])` — streaming writer for SSE, long-poll,
  incremental output. Handler drives writes with `enso/write!` +
  `enso/flush!`.
- Anything satisfying `ring.core.protocols/StreamableResponseBody` —
  dispatched only when `ring.core.protocols` is on the classpath. Fast
  paths above take priority.

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

## WebSocket (Ring 1.5+ shape)

```clojure
(defn ws [req]
  {:ring.websocket/listener
   {:on-open    (fn [socket] ...)
    :on-message (fn [socket msg] (.sendText socket (str "echo: " msg)))
    :on-close   (fn [socket code reason] ...)}})
```

`socket` is a `com.s_exp.enso.websocket.WebSocketSocket`. Text + binary,
ping/pong (auto-pong on ping unless `:on-ping` provided), close handshake.

## Error handling

`:error-handler` — `(fn [request throwable])` returning a Ring response.
Runs when the main handler throws or returns nil. If the error handler
itself throws or returns nil, a fallback 500 text response is sent.

## Correctness

- Rejects request smuggling variants: duplicate `Content-Length`, `TE + CL`,
  obs-fold.
- Rejects header injection in responses (CR/LF/NUL in name or value).
- Slowloris protection via `:request-timeout` (wall-clock deadline per
  request).
- Enforces `:max-request-body-bytes` upfront (Content-Length) or
  mid-stream (chunked → 413).
- HTTP/2: CVE-2023-44487 rapid-reset mitigation via
  `:http2-stream-reset-limit`, CONTINUATION-flood mitigation via
  `:http2-continuation-limit`.
- HTTP/3: RFC 9114 header validation, GOAWAY monotonicity,
  control-stream parser with connection-level error propagation,
  graceful `CONNECTION_CLOSE` on shutdown.

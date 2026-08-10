# HTTP/3

HTTP/3 rides Cloudflare `libquiche` over UDP via a small JNI shim
(`native/enso_quiche/enso_quiche.c`). Pure-Java QPACK + H3 framing on top
of quiche's transport primitives. Same Ring handler contract as h1/h2 —
`:protocol` becomes `"HTTP/3.0"`.

## From a release jar (zero libquiche install)

Every release publishes core, per-classifier, and fat jars to Clojars.
Three consumption patterns.

### Core only, no h3 (~200 KB)

```clojure
{:deps {com.s-exp/enso {:mvn/version "1.0.0-alphaN"}}}
```

### Per-platform classifier (~3.5 MB)

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

Alpine/musl variants selected automatically at runtime when
`/lib/ld-musl-*.so.1` is present; falls back to glibc shim otherwise.

For multi-platform uber-jars, declare multiple classifier deps side by side:

```clojure
{:deps {com.s-exp/enso                    {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$darwin-arm64       {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-amd64        {:mvn/version "1.0.0-alphaN"}
        com.s-exp/enso$linux-musl-amd64   {:mvn/version "1.0.0-alphaN"}}}
```

`Quiche.java` picks the matching shim from the classpath at load time.

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

- Uses its own UDP socket; can co-exist with h1/h2 on the same port number.
- `Alt-Svc` auto-advertised on h1/h2 responses when h3 enabled.
- See [options.md](options.md#http3) for full knob list.

## Dev build (dynamic-link against system libquiche)

```
brew install cloudflare-quiche              # macOS
make -C native/enso_quiche                  # → target/native/<os>-<arch>/libenso_quiche.<ext>
clojure -T:build javac-bench                # optional: Netty+Jetty bench servers
```

## Release / distributable build

Static-link libquiche 0.29.3 into the shim so the resulting `.dylib`/`.so`
has no runtime dep on system libquiche. Release CI
(`.github/workflows/release.yml`) does this across five platforms and
packages every shim into the fat jar.

To reproduce locally:

```
git clone --depth 1 --branch 0.29.3 https://github.com/cloudflare/quiche.git /tmp/quiche
(cd /tmp/quiche && cargo build --release --lib --features ffi,pkg-config-meta)
make -C native/enso_quiche QUICHE_STATIC=1 \
     QUICHE_INCLUDE_DIR=/tmp/quiche/quiche/include \
     QUICHE_LIB_DIR=/tmp/quiche/target/release
```

The built shim is bundled at `META-INF/native/<os>-<arch>/`. At load time
`Quiche.java` extracts the shim into a per-JVM temp directory (unique
random name — safe for multi-JVM hosts) then `System.load`s it.

## Platform classifier resolution

- macOS → `darwin-arm64` (Apple Silicon only; Intel Macs need a
  dev/dynamic build via `make -C native/enso_quiche`)
- Linux glibc → `linux-arm64` / `linux-amd64`
- Linux musl (Alpine, Wolfi, Chimera) → `linux-musl-*`, fallback to
  `linux-*` if musl-built shim absent. Detection: `/lib/ld-musl-*.so.1`.

Override for local dev:
`-Denso.quiche.shim=/abs/path/to/libenso_quiche.dylib`.

## Notes on the JNI vs FFM choice

FFM path tried but hit a JDK 25 libmalloc corruption bug on macOS ARM64
(matches what Netty steers around in `CleanerJava25.java`). JNI migration
eliminated it.

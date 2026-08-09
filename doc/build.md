# Build

```
clojure -T:build javac
clojure -X:test
```

Java sources compile to `target/classes`. `deps.edn` puts it on the classpath.

## Jar flavors

Release build produces three jars (see [http3.md](http3.md) for detail):

- `enso-<v>.jar` — core, no native shim.
- `enso-<v>-<os>-<arch>.jar` — per-platform h3 classifier jar.
- `enso-<v>-all.jar` — fat jar with core + all shim variants.

Build tasks:

```
clojure -T:build jar-core                                  # core only
clojure -T:build jar-classifier :classifier "\"darwin-arm64\""  # per-platform
clojure -T:build jar-all                                   # fat jar
```

## HTTP/3 build

See [http3.md](http3.md#dev-build-dynamic-link-against-system-libquiche).

## Bench sources

Netty + Jetty h3 comparison servers live under `bench/java`.
Compile with:

```
clojure -T:build javac-bench
```

## Release CI

`.github/workflows/release.yml` triggers on:
- `workflow_dispatch` (manual button in Actions tab)
- tag push matching `v*`

Builds native shims across 6 platforms (macOS x2, Linux glibc x2, Linux
musl x2), assembles per-classifier + fat + core jars, attaches to the
release on tag push.

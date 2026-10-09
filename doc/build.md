# Build

```
clojure -T:build javac
script/test.sh
```

Java sources compile to `target/classes` (`--release 21`), which `deps.edn`
puts on the classpath. `script/test.sh` runs every test namespace in its
own JVM; see [testing.md](testing.md) for selecting namespaces, the
conformance suites, fuzzing and the sanitizer run.

## Using enso as a git or local dependency

`deps.edn` declares `:deps/prep-lib`, so a consumer depending on enso
through `:git/url` or `:local/root` compiles its Java sources once with:

```
clojure -X:deps prep
```

Until then the Clojure CLI refuses to build the classpath ("The following
libs must be prepared before use: [...]", naming enso by the coordinate
the consumer used).

## JDK 24+: native access

The HTTP/3 shim is loaded with `System.load`, a restricted method. JDK 24
and later print a warning for it, and a future release will refuse it,
unless native access is enabled for the code loading it. Add to the JVM
options of any application using HTTP/3:

```
--enable-native-access=ALL-UNNAMED
```

(or the module name, when enso runs as a named module). With the Clojure
CLI: `clojure -J--enable-native-access=ALL-UNNAMED ...`, or `:jvm-opts` in
an alias. JDK 21 needs nothing.

## Jar flavors

Release build produces (see [http3.md](http3.md) for detail):

- `enso-<v>.jar` — core, no native shim. Published.
- `enso-<v>-<os>-<arch>.jar` — per-platform HTTP/3 classifier jar. Published.
- `enso-<v>-all.jar` — core + every shim. Kept as a release run artifact
  only: it exceeds the Clojars per-file size limit.

Every jar carries `META-INF/LICENSE`, `META-INF/NOTICE` and
`META-INF/THIRD-PARTY-NOTICES`.

Build tasks:

```
clojure -T:build jar-core                                  # core only
clojure -T:build jar-classifier :classifier "\"darwin-arm64\""  # per-platform
clojure -T:build jar-all                                   # core + all staged shims
```

Also: `jar` (a development jar with whatever is staged under
`target/native`), `install`, `deploy-jars` (refuses a version already on
Clojars), `tag`, `clean`, `shim` (the development shim, as
`make -C native/enso_quiche`).

## HTTP/3 shim

Development builds link the system libquiche dynamically, see
[http3.md](http3.md#dev-build-dynamic-link-against-system-libquiche).

Release shims link a static libquiche (with BoringSSL) built from pinned
inputs in `native/enso_quiche/pins.env`: the quiche release and the commit
its tag points at, the Rust toolchain, and the oldest macOS supported.
Crate versions come from `native/enso_quiche/quiche-Cargo.lock` (quiche
does not ship a lockfile; builds use `--locked`).

```
native/enso_quiche/build-libquiche.sh /tmp/quiche     # fetch + build libquiche.a, stage it
make -C native/enso_quiche QUICHE_STATIC=1 \
  QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
native/enso_quiche/check-shim.sh target/native/darwin-arm64/libenso_quiche.dylib darwin-arm64
```

Linux release shims are built in baseline containers, so they run on old
distributions too:

```
docker run --rm -v "$PWD":/work -w /work almalinux:8.10 sh native/enso_quiche/build-linux.sh gnu   # glibc 2.28
docker run --rm -v "$PWD":/work -w /work alpine:3.20 sh native/enso_quiche/build-linux.sh musl     # musl
```

(the release workflow pins both images by digest).

`check-shim.sh` runs on every release shim where it was built and fails
when:

- libquiche is a dynamic dependency instead of being linked in;
- the exported symbols differ from the `native` methods of `Quiche.java`
  (exactly the JNI entry points, nothing else);
- Linux: the library lacks full RELRO / BIND_NOW or has an executable
  stack, or (glibc builds) needs a `GLIBC_x.y` symbol newer than the
  container's glibc;
- macOS: its minimum OS version is above `MACOSX_DEPLOYMENT_TARGET`;
- the libquiche it links reports a version other than
  `Quiche.QUICHE_VERSION`;
- a JVM cannot load it from the jar layout
  (`META-INF/native/<classifier>/` on the classpath, run from an empty
  directory) and create a QUIC client config through it.

Compiler and linker hardening (`native/enso_quiche/Makefile`, applied even
when `CFLAGS` / `LDFLAGS` are set in the environment): stack protector,
`_FORTIFY_SOURCE=2`, stack-clash protection (Linux), CET
(`-fcf-protection`, x86-64 Linux) or PAC/BTI
(`-mbranch-protection=standard`, arm64), `-Werror=format-security`, only
`Java_*` symbols exported, full RELRO and a non-executable stack (Linux),
a relocatable install name and pinned minimum OS (macOS). Debug sections
from libquiche.a are stripped from Linux release shims.

`make SANITIZE=1` builds an AddressSanitizer + UndefinedBehaviorSanitizer
shim for `script/sanitizer-test.sh` (see [testing.md](testing.md#sanitizer-run)).

### Bumping quiche or the toolchain

1. Update `native/enso_quiche/pins.env` (`QUICHE_COMMIT` from
   `git ls-remote https://github.com/cloudflare/quiche 'refs/tags/<version>^{}'`)
   and `Quiche.QUICHE_VERSION`.
2. Regenerate the lockfile in a checkout of that commit
   (`cargo generate-lockfile`) and copy it to
   `native/enso_quiche/quiche-Cargo.lock`.
3. Regenerate the attributions:
   `python3 native/enso_quiche/third_party_notices.py quiche-src > THIRD-PARTY-NOTICES`,
   and update the BoringSSL section of `NOTICE` if boring-sys vendors a
   different BoringSSL (its commit is the `boring-sys/deps/boringssl`
   submodule of the matching cloudflare/boring tag). The `shim` CI job
   fails while THIRD-PARTY-NOTICES is out of date.

## Bench sources

Netty + Jetty h3 comparison servers live under `bench/java`.
Compile with:

```
clojure -T:build javac-bench
```

## Release CI

`.github/workflows/release.yml` triggers on:
- `workflow_dispatch` (builds everything, publishes nothing)
- tag push matching `v*`

It runs the full test workflow, builds and checks the five shims
(macOS arm64, Linux glibc x2, Linux musl x2), runs the HTTP/3 end-to-end
namespaces on macOS against the darwin shim being shipped, assembles the
core, per-classifier and all-platform jars, and uploads them as run
artifacts. On tag push, core + per-classifier jars are published to
Clojars.

`clojure -T:build release` (clean tree only) fast-forwards to the
upstream branch, tags that commit with the version derived from it and
pushes branch and tag together.

# Building

```
clojure -T:build javac
script/test.sh
```

Java sources compile to `target/classes` (`--release 21`), which `deps.edn`
puts on the classpath. `script/test.sh` runs each test namespace in its
own JVM; [testing.md](testing.md) covers selecting namespaces, the
conformance suites, fuzzing and the sanitizer run.

## Using enso as a git or local dependency

`deps.edn` declares `:deps/prep-lib`, so a project depending on enso
through `:git/url` or `:local/root` must compile its Java sources once:

```
clojure -X:deps prep
```

Until then the Clojure CLI refuses to build the classpath ("The following
libs must be prepared before use: [...]").

HTTP/3 on JDK 24 and later also needs a JVM option, see
[http3.md](http3.md#native-access-jdk-24).

## Jars

| Jar | Contents | Published |
|---|---|---|
| `enso-<v>.jar` | core, no native code | Clojars |
| `enso-<v>-<os>-<arch>.jar` | the HTTP/3 shim for one platform | Clojars |
| `enso-<v>-all.jar` | core and every shim | release run artifact only; too large for Clojars |

Every jar carries `META-INF/LICENSE`, `META-INF/NOTICE` and
`META-INF/THIRD-PARTY-NOTICES`.

```
clojure -T:build jar-core                                       # core only
clojure -T:build jar-classifier :classifier "\"darwin-arm64\""  # one platform
clojure -T:build jar-all                                        # core and every staged shim
```

Other tasks: `jar` (a development jar with whatever is staged under
`target/native`), `install`, `deploy-jars` (refuses a version already on
Clojars), `tag`, `clean`, `shim` (the development shim, same as
`make -C native/enso_quiche`) and `javac-bench` (below).

## HTTP/3 shim

Development builds link the system libquiche dynamically, see
[http3.md](http3.md#development-builds).

Release shims link a static libquiche (with BoringSSL) built from pinned
inputs in `native/enso_quiche/pins.env`: the quiche release and the
commit its tag points at, the Rust toolchain, and the oldest supported
macOS. Crate versions come from `native/enso_quiche/quiche-Cargo.lock`;
quiche doesn't ship a lockfile, and builds use `--locked`.

```
native/enso_quiche/build-libquiche.sh /tmp/quiche     # fetch, patch and build libquiche.a
make -C native/enso_quiche QUICHE_STATIC=1 \
  QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
native/enso_quiche/check-shim.sh target/native/darwin-arm64/libenso_quiche.dylib darwin-arm64
```

Linux release shims are built in old baseline containers so they run on
old distributions too. The release workflow pins both images by digest.

```
docker run --rm -v "$PWD":/work -w /work almalinux:8.10 sh native/enso_quiche/build-linux.sh gnu   # glibc 2.28
docker run --rm -v "$PWD":/work -w /work alpine:3.20 sh native/enso_quiche/build-linux.sh musl     # musl
```

### quiche patches

`build-libquiche.sh` applies the patches in `native/enso_quiche/patches/`
in name order (`git apply`) before building, and fails if any doesn't
apply. They are part of its cache key and of CI's. They add what enso
needs beyond quiche's stock API, written in quiche's own style (doc
comments, `quiche.h`, unit tests) so they can be sent upstream as is.

- `0001-live-receive-window-maximums.patch` adds `quiche_conn_set_max_connection_window` and `quiche_conn_set_max_stream_window`, which raise the receive-window bounds of a live connection, and `quiche_conn_connection_window`, which reads its connection window. enso uses them to grow each connection's window as its memory budget pays for it (`:http3-max-window-bytes`).
- `0002-bound-out-of-order-fragments.patch` limits a stream to 64 out-of-order fragments plus one per 256 bytes of stream they span. Past that the connection is closed with FLOW_CONTROL_ERROR. quiche's stock receive buffer has no such limit. With the patch, what a connection buffers stays within its window plus about 150 bytes per allowed fragment, about 1.5 MiB at the defaults.

Since every patch is applied or the build fails, a libquiche with the
receive-window calls, which `check-shim.sh` can detect, also has the
fragment bound, which exports nothing to check.

When built against the patched header, the shim links those calls
directly (`ENSO_QUICHE_RECV_WINDOW`, set by the Makefile). Otherwise it
looks them up at load time, so it still builds and runs against a stock
libquiche with fixed windows (`Quiche.RECV_WINDOW_CONTROL` false). Release
shims must have them: `check-shim.sh` fails otherwise, and CI's test jobs
set `ENSO_H3_REQUIRE_RECV_WINDOW_CONTROL` so the tests that need them fail
instead of being skipped.

### Checks and hardening

`check-shim.sh` runs on every release shim, on the machine that built it,
and fails when:

- libquiche is a dynamic dependency instead of being linked in;
- the exported symbols differ from the `native` methods of `Quiche.java`;
- on Linux, the library lacks full RELRO or BIND_NOW, has an executable stack, or (glibc builds) needs a `GLIBC_x.y` symbol newer than the container's glibc;
- on macOS, its minimum OS version is above `MACOSX_DEPLOYMENT_TARGET`;
- the linked libquiche reports a version other than `Quiche.QUICHE_VERSION`, or lacks the receive-window control from the patches;
- a JVM can't load it from the jar layout (`META-INF/native/<classifier>/` on the classpath, run from an empty directory) and create a QUIC client config through it.

The Makefile applies compiler and linker hardening even when `CFLAGS` or
`LDFLAGS` are set in the environment: stack protector, `_FORTIFY_SOURCE=2`,
stack-clash protection (Linux), CET (`-fcf-protection`, x86-64 Linux) or
PAC/BTI (`-mbranch-protection=standard`, arm64),
`-Werror=format-security`, only `Java_*` symbols exported, full RELRO and a
non-executable stack (Linux), and a relocatable install name with a pinned
minimum OS (macOS). Debug sections from libquiche.a are stripped from
Linux release shims.

`make SANITIZE=1` builds an AddressSanitizer and UndefinedBehaviorSanitizer
shim for `script/sanitizer-test.sh` (see
[testing.md](testing.md#sanitizer-run)).

### Bumping quiche or the toolchain

1. Update `native/enso_quiche/pins.env` (`QUICHE_COMMIT` from `git ls-remote https://github.com/cloudflare/quiche 'refs/tags/<version>^{}'`) and `Quiche.QUICHE_VERSION`.
2. Check that every patch in `native/enso_quiche/patches/` still applies, and drop the ones upstream has merged.
3. Regenerate the lockfile in a checkout of that commit (`cargo generate-lockfile`) and copy it to `native/enso_quiche/quiche-Cargo.lock`.
4. Regenerate the attributions with `python3 native/enso_quiche/third_party_notices.py quiche-src > THIRD-PARTY-NOTICES`, and update the BoringSSL section of `NOTICE` if boring-sys vendors a different BoringSSL (its commit is the `boring-sys/deps/boringssl` submodule of the matching cloudflare/boring tag). The `shim` CI job fails while THIRD-PARTY-NOTICES is out of date.
5. Check the lockfile against the RustSec database (`cargo audit --file native/enso_quiche/quiche-Cargo.lock`, also run nightly). A bump made for a security advisory follows [SECURITY.md](../SECURITY.md#native-dependency-advisories).

## Benchmark servers

The Netty and Jetty HTTP/3 servers used for comparison live under
`bench/java`:

```
clojure -T:build javac-bench
```

## Release CI

`.github/workflows/release.yml` runs on `workflow_dispatch` (builds
everything, publishes nothing) and on tags matching `v*`.

It runs the full test workflow, builds and checks the five shims (macOS
arm64, Linux glibc amd64 and arm64, Linux musl amd64 and arm64), runs the
HTTP/3 end-to-end namespaces on macOS against the darwin shim being
shipped, assembles the core, classifier and all-platform jars, and uploads
them as run artifacts. On a tag push it publishes the core and classifier
jars to Clojars.

`clojure -T:build release` (clean tree only) fast-forwards to the
upstream branch, tags that commit with the version derived from it, and
pushes the branch and tag together.

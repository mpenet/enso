#!/usr/bin/env bash
# ABOUTME: Runs the perf harness inside a Linux container (Temurin 25, Ubuntu 24.04 like the CI runners,
# ABOUTME: static shim, h2load) and copies the results out, to record a Linux allocation baseline.
#
# Usage (from the repository root, needs Docker; amd64 runs emulated on Apple Silicon):
#   bench/perf/linux-baseline.sh                       # linux/amd64, defaults below
#   bench/perf/linux-baseline.sh arm64                 # linux/arm64
#   bench/perf/linux-baseline.sh amd64 '{:duration-s 20 :warmup-s 15}'
#   clojure -M:perf-gate update target/perf-linux-amd64/latest.edn
#   SHIM=/tmp/libenso_quiche.so bench/perf/linux-baseline.sh   # prebuilt shim
#
# SHIM: a Linux shim for that architecture built elsewhere, e.g. the
# test-libenso_quiche-linux-amd64 artifact of a test.yml run
# (`gh run download <run-id> -n test-libenso_quiche-linux-amd64`), used
# instead of building libquiche in the container: emulated (QEMU)
# BoringSSL builds can crash the assembler.
#
# The working tree is copied into the container (read-only bind mount), so
# the host's target/ is never written while the run is in progress; only
# target/perf-linux-<arch>/ receives the results. The libquiche build,
# the Rust toolchain and the Maven cache live in named volumes
# (enso-perf-<arch>-*), so later runs skip the BoringSSL build. The default options warm up longer than the
# nightly job: an emulated JVM takes longer to reach compiled code, and
# allocation per request is only representative once it has.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ARCH="${1:-amd64}"
DEFAULT_OPTS='{:duration-s 20 :warmup-s 15}'
PERF_OPTS="${2:-$DEFAULT_OPTS}"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "usage: $0 [amd64|arm64] [PERF-OPTS-EDN]" >&2; exit 1 ;;
esac

OUT="target/perf-linux-$ARCH"
mkdir -p "$OUT"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
SHIM_MOUNT=()
if [ -n "${SHIM:-}" ]; then
  SHIM_MOUNT=(-v "$(cd "$(dirname "$SHIM")" && pwd -P)/$(basename "$SHIM")":/shim/libenso_quiche.so:ro)
fi

docker run --rm --platform "linux/$ARCH" \
  -v "$ROOT":/src:ro \
  -v "$ROOT/$OUT":/out \
  -v "enso-perf-$ARCH-quiche":/cache \
  -v "enso-perf-$ARCH-cargo":/root/.cargo \
  -v "enso-perf-$ARCH-rustup":/root/.rustup \
  -v "enso-perf-$ARCH-m2":/root/.m2 \
  ${SHIM_MOUNT[@]+"${SHIM_MOUNT[@]}"} \
  -e PERF_OPTS="$PERF_OPTS" \
  -e GIT_SHA="$GIT_SHA" \
  'eclipse-temurin:25-jdk-noble' \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential cmake clang libclang-dev llvm-dev \
      pkg-config git curl rsync nghttp2-client >/dev/null
    curl -sSfLO https://github.com/clojure/brew-install/releases/download/1.12.5.1654/posix-install.sh
    bash posix-install.sh >/dev/null
    . /src/native/enso_quiche/pins.env
    rsync -a --exclude target --exclude quiche-src --exclude .cpcache /src/ /work/
    cd /work
    if [ -f /shim/libenso_quiche.so ]; then
      case "$(uname -m)" in x86_64) arch=amd64 ;; *) arch=arm64 ;; esac
      mkdir -p "target/native/linux-$arch"
      cp /shim/libenso_quiche.so "target/native/linux-$arch/"
    else
      if [ ! -x /root/.cargo/bin/cargo ]; then
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
          | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" --profile minimal --no-modify-path
      fi
      export PATH="/root/.cargo/bin:$PATH"
      rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal >/dev/null
      if [ -d /cache/quiche-src ]; then cp -a /cache/quiche-src .; fi
      native/enso_quiche/build-libquiche.sh /tmp/quiche
      rsync -a --delete quiche-src /cache/
      make -C native/enso_quiche QUICHE_STATIC=1 QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
    fi
    clojure -T:build javac
    clojure -M:perf "$PERF_OPTS"
    sed "s/:git nil/:git \"$GIT_SHA\"/" target/perf/latest.edn > /out/latest.edn
    cp target/perf/latest.md target/perf/server.log /out/
  '

echo "results in $OUT/latest.edn; record them with: clojure -M:perf-gate update $OUT/latest.edn"

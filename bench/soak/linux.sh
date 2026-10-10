#!/usr/bin/env bash
# ABOUTME: Runs the soak/chaos driver (s-exp.enso-soak) inside a Linux container with 2 CPUs, optionally with
# ABOUTME: netem packet loss, delay and reordering on loopback UDP (QUIC only), and copies the results out.
#
# Usage (from the repository root, needs Docker):
#   bench/soak/linux.sh                                  # 120 min, netem on
#   bench/soak/linux.sh '{:duration-m 10 :warmup-m 1}'   # driver options (EDN)
#   NETEM=off bench/soak/linux.sh                        # no packet impairment
#   NETEM='loss 1% delay 2ms' bench/soak/linux.sh        # other netem parameters
#
# The container runs linux/<host arch> with --cpus 2 and NET_ADMIN (for
# tc). The working tree is copied in (read-only bind mount); the shim is
# built there with the cached libquiche of bench/perf/linux-baseline.sh
# (volumes enso-perf-<arch>-*). Results go to target/soak-linux/.
#
# netem applies to UDP on lo only (a prio qdisc with a u32 filter on IP
# protocol 17), so HTTP/1.1, HTTP/2 and WebSocket run unimpaired while
# QUIC sees loss, delay and reordering.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
SOAK_OPTS="${1:-{:duration-m 120\}}"
NETEM="${NETEM:-loss 2% delay 5ms 3ms reorder 10% 50%}"
OUT="target/soak-linux"
mkdir -p "$OUT"

docker run --rm --platform "linux/$ARCH" --cpus 2 --cap-add NET_ADMIN \
  -v "$ROOT":/src:ro \
  -v "$ROOT/$OUT":/out \
  -v "enso-perf-$ARCH-quiche":/cache \
  -v "enso-perf-$ARCH-cargo":/root/.cargo \
  -v "enso-perf-$ARCH-rustup":/root/.rustup \
  -v "enso-perf-$ARCH-m2":/root/.m2 \
  -e SOAK_OPTS="$SOAK_OPTS" \
  -e NETEM="$NETEM" \
  'eclipse-temurin:25-jdk-noble' \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential cmake clang libclang-dev llvm-dev \
      pkg-config git curl rsync iproute2 procps openssl >/dev/null
    curl -sSfLO https://github.com/clojure/brew-install/releases/download/1.12.5.1654/posix-install.sh
    bash posix-install.sh >/dev/null
    . /src/native/enso_quiche/pins.env
    rsync -a --exclude target --exclude quiche-src --exclude .cpcache /src/ /work/
    cd /work
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
    clojure -T:build javac
    if [ "$NETEM" != off ]; then
      tc qdisc add dev lo root handle 1: prio
      tc qdisc add dev lo parent 1:3 handle 30: netem $NETEM
      tc filter add dev lo parent 1:0 protocol ip prio 1 u32 match ip protocol 17 0xff flowid 1:3
      tc qdisc show dev lo
    fi
    clojure -J-Xmx512m -M:soak "$(echo "$SOAK_OPTS" | sed "s|}$| :out-dir \"/out\"}|")"
  '

echo "results in $OUT/"

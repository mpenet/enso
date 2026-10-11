#!/usr/bin/env bash
# ABOUTME: Runs the soak/chaos driver (s-exp.enso-soak) inside a Linux container, optionally with netem
# ABOUTME: packet loss, delay and reordering on loopback UDP (QUIC only), and copies the results out.
#
# Usage (from the repository root, needs Docker):
#   bench/soak/linux.sh                                  # 120 min, netem on
#   bench/soak/linux.sh '{:duration-m 10 :warmup-m 1}'   # driver options (EDN)
#   NETEM=off bench/soak/linux.sh                        # no packet impairment
#   NETEM='loss 1% delay 2ms' bench/soak/linux.sh        # other netem parameters
#   CPUS=3 MEMORY=5g bench/soak/linux.sh                 # container size
#   PCAP=1 bench/soak/linux.sh '{:duration-m 15}'        # also capture UDP headers (h3.pcap)
#
# The container runs linux/<host arch> with $CPUS CPUs (default 2), $MEMORY
# of memory (default 5g) and NET_ADMIN (for tc). The two JVMs (server with
# a pre-touched 512 MiB heap, driver with 1 GiB) plus native memory need
# about 2.5 GB, so the Docker VM needs more than that: colima's default
# 2 GiB VM is too small, e.g. use a dedicated one
# (`colima start enso-soak --cpu 4 --memory 6` and DOCKER_CONTEXT=colima-enso-soak).
#
# The working tree is copied in (read-only bind mount). The patched
# libquiche is built there by build-libquiche.sh, cached in the volumes of
# bench/perf/linux-baseline.sh (enso-perf-<arch>-*), and the shim must pass
# check-shim.sh, receive-window control included. Results go to
# target/soak-linux/<timestamp>/, with container.txt (versions, netem
# settings) and netem.log (qdisc, UDP and cgroup memory counters every
# minute) next to the driver's output.
#
# netem applies to UDP on lo only (a prio qdisc whose priomap sends
# everything to band 1:2, and a u32 filter sending IP protocol 17 to the
# netem band 1:3), so HTTP/1.1, HTTP/2 and WebSocket run unimpaired while
# QUIC sees loss, delay and reordering. Loss recovery of TCP is the
# kernel's, and loss on TCP would only stretch the timing of the chaos
# clients (slowloris, trickled bodies, slow readers). Every datagram the
# client sends is impaired on its own. The server sends with UDP GSO, and
# netem acts on a whole GSO send (up to 64 datagrams): server-to-client
# loss comes in bursts of up to a GSO batch.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
SOAK_OPTS="${1:-{:duration-m 120\}}"
NETEM="${NETEM:-delay 15ms 5ms reorder 5% 50% loss 2% limit 10000}"
CPUS="${CPUS:-2}"
MEMORY="${MEMORY:-5g}"
OUT="target/soak-linux"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then GIT_SHA="$GIT_SHA (uncommitted changes)"; fi
mkdir -p "$OUT"

docker run --rm --name "enso-soak-linux-$$" --platform "linux/$ARCH" --cpus "$CPUS" --memory "$MEMORY" \
  --cap-add NET_ADMIN \
  -v "$ROOT":/src:ro \
  -v "$ROOT/$OUT":/out \
  -v "enso-perf-$ARCH-quiche":/cache \
  -v "enso-perf-$ARCH-cargo":/root/.cargo \
  -v "enso-perf-$ARCH-rustup":/root/.rustup \
  -v "enso-perf-$ARCH-m2":/root/.m2 \
  -e SOAK_OPTS="$SOAK_OPTS" \
  -e NETEM="$NETEM" \
  -e GIT_SHA="$GIT_SHA" \
  -e CPUS="$CPUS" \
  -e MEMORY="$MEMORY" \
  -e PCAP="${PCAP:-}" \
  'eclipse-temurin:25-jdk-noble' \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential cmake clang libclang-dev llvm-dev \
      pkg-config git curl rsync iproute2 procps openssl file tcpdump >/dev/null
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
    case "$(uname -m)" in x86_64) arch=amd64 ;; *) arch=arm64 ;; esac
    ENSO_H3_REQUIRE_RECV_WINDOW_CONTROL=1 native/enso_quiche/check-shim.sh \
      "target/native/linux-$arch/libenso_quiche.so" "linux-$arch"
    clojure -T:build javac
    if [ "$NETEM" != off ]; then
      tc qdisc add dev lo root handle 1: prio priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
      tc qdisc add dev lo parent 1:3 handle 30: netem $NETEM
      tc filter add dev lo parent 1:0 protocol ip prio 1 u32 match ip protocol 17 0xff flowid 1:3
      tc qdisc show dev lo
    fi
    stats=/tmp/netem.log
    ( while true; do
        echo "== $(date -u +%FT%TZ)"
        tc -s qdisc show dev lo
        grep "^Udp:" /proc/net/snmp
        echo "memory.current $(cat /sys/fs/cgroup/memory.current)"
        grep -E "^(oom|oom_kill) " /sys/fs/cgroup/memory.events
        sleep 60
      done ) > "$stats" 2>&1 &
    stats_pid=$!
    if [ -n "$PCAP" ]; then
      tcpdump -i lo -s 128 -w /tmp/h3.pcap udp 2>/tmp/tcpdump.log &
      pcap_pid=$!
    fi
    status=0
    clojure -J-Xmx1g -M:soak "$(echo "$SOAK_OPTS" | sed "s|}$| :out-dir \"/out\"}|")" || status=$?
    kill "$stats_pid"
    run="$(ls -td /out/*/ 2>/dev/null | head -1 || true)"
    if [ -z "$run" ]; then run=/out/; fi
    cp "$stats" "$run/netem.log"
    if [ -n "$PCAP" ]; then
      kill "$pcap_pid"
      wait "$pcap_pid" || true
      cp /tmp/h3.pcap /tmp/tcpdump.log "$run/"
    fi
    { echo "git $GIT_SHA"
      echo "container: $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(uname -m), cpus $CPUS, memory $MEMORY"
      echo "java: $(java -version 2>&1 | head -1)"
      echo "libquiche: $QUICHE_VERSION ($QUICHE_COMMIT), patches: $(cd native/enso_quiche/patches && echo *.patch)"
      echo "netem: $NETEM"
      echo "driver exit status: $status"
    } > "$run/container.txt"
    exit "$status"
  '

echo "results in $OUT/"

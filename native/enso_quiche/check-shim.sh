#!/usr/bin/env bash
# ABOUTME: Verifies a built libenso_quiche before it ships: static libquiche, exported symbols equal
# ABOUTME: Quiche.java's natives, link hardening, glibc / macOS ceilings, a JVM load via the jar layout.
#
# Usage: native/enso_quiche/check-shim.sh LIB CLASSIFIER
#   LIB         path to libenso_quiche.so / .dylib
#   CLASSIFIER  META-INF/native/<classifier> it ships under (e.g. linux-musl-arm64)
#
# Environment:
#   GLIBC_MAX                 fail when the shim needs a newer GLIBC_x.y symbol (glibc builds)
#   MACOSX_DEPLOYMENT_TARGET  fail when the dylib's minimum macOS is newer (default 11.0)
#   JAVA                      java launcher for the load test (default: java on PATH)

set -euo pipefail

LIB="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CLASSIFIER="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JAVA="${JAVA:-java}"
OS="$(uname -s)"

fail() { echo "check-shim: $*" >&2; exit 1; }

echo "== $LIB ($CLASSIFIER)"
file "$LIB" || true

# libquiche must be linked in, not a runtime dependency.
if [ "$OS" = Darwin ]; then deps="$(otool -L "$LIB")"; else deps="$(ldd "$LIB" 2>&1 || true)"; fi
if grep -q libquiche <<< "$deps"; then
  fail "dynamic libquiche dependency: $deps"
fi

# The exported symbols are exactly the JNI entry points Quiche.java declares.
expected="$(grep -oE 'static native [^ (]+ [A-Za-z0-9_]+\(' "$ROOT/src/java/com/s_exp/enso/quiche/Quiche.java" \
  | sed -E 's/.* ([A-Za-z0-9_]+)\($/Java_com_s_1exp_enso_quiche_Quiche_\1/' | LC_ALL=C sort -u)"
if [ "$OS" = Darwin ]; then
  exported="$(nm -gU "$LIB" | awk '{print $3}' | sed 's/^_//' | LC_ALL=C sort -u)"
else
  exported="$(nm -D --defined-only "$LIB" | awk '{print $3}' | sed 's/@.*//' | LC_ALL=C sort -u)"
fi
if [ "$expected" != "$exported" ]; then
  diff <(echo "$expected") <(echo "$exported") >&2 || true
  fail "exported symbols differ from Quiche.java natives (< missing, > unexpected)"
fi
echo "exports: $(wc -l <<< "$exported" | tr -d ' ') JNI entry points, nothing else"

if [ "$OS" = Linux ]; then
  # Full RELRO, non-executable stack: the Makefile's link hardening held.
  # Captured first: grep -q exiting early would fail the pipe under pipefail.
  phdrs="$(readelf -lW "$LIB")"
  dynamic="$(readelf -dW "$LIB")"
  grep -q GNU_RELRO <<< "$phdrs" || fail "no GNU_RELRO segment"
  grep -qE 'BIND_NOW|FLAGS_1.*NOW' <<< "$dynamic" || fail "not linked with -z now"
  if grep GNU_STACK <<< "$phdrs" | grep -q RWE; then fail "executable stack"; fi
  echo "hardening: full RELRO, BIND_NOW, non-executable stack"
fi

if [ -n "${GLIBC_MAX:-}" ]; then
  needed="$(objdump -T "$LIB" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/GLIBC_//' | sort -uV | tail -1)"
  if [ -n "$needed" ] && [ "$(printf '%s\n%s\n' "$needed" "$GLIBC_MAX" | sort -V | tail -1)" != "$GLIBC_MAX" ]; then
    objdump -T "$LIB" | grep -E "GLIBC_$needed" >&2 || true
    fail "needs GLIBC_$needed, above the GLIBC_$GLIBC_MAX baseline"
  fi
  echo "glibc: needs GLIBC_${needed:-none} (baseline $GLIBC_MAX)"
fi

if [ "$OS" = Darwin ]; then
  target="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
  minos="$(otool -l "$LIB" | awk '/LC_BUILD_VERSION/ { f = 1 } f && /minos/ { print $2; exit }')"
  if [ -z "$minos" ] || [ "$(printf '%s\n%s\n' "$minos" "$target" | sort -V | tail -1)" != "$target" ]; then
    fail "minimum macOS ${minos:-unknown}, above the $target deployment target"
  fi
  echo "macOS: minos $minos (target $target)"
fi

# Load it the way a classifier jar does, from a directory with no
# target/native/ to fall back on.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
javac --release 21 -nowarn -d "$work/classes" -sourcepath "$ROOT/src/java" \
  "$ROOT/src/java/com/s_exp/enso/quiche/Quiche.java" "$ROOT/src/java/com/s_exp/enso/quiche/QuicheConfig.java"
mkdir -p "$work/res/META-INF/native/$CLASSIFIER" "$work/cwd"
cp "$LIB" "$work/res/META-INF/native/$CLASSIFIER/"
(cd "$work/cwd" && "$JAVA" --enable-native-access=ALL-UNNAMED -cp "$work/classes:$work/res" \
  "$ROOT/native/enso_quiche/ShimCheck.java")

#!/usr/bin/env bash
# ABOUTME: Runs the HTTP/3 test namespaces against an ASan+UBSan build of the JNI shim, loading the
# ABOUTME: sanitizer runtime into the JVMs only; fails on any sanitizer report or test failure.
#
# Usage:
#   make -C native/enso_quiche QUICHE_STATIC=1 SANITIZE=1 QUICHE_INCLUDE_DIR=... QUICHE_LIB_DIR=...
#   script/sanitizer-test.sh                   # the HTTP/3 namespaces
#   script/sanitizer-test.sh s-exp.enso-h3-e2e-test
#
# The JVM itself is not instrumented, so the runtime is preloaded
# (LD_PRELOAD on Linux, DYLD_INSERT_LIBRARIES on macOS) through a java
# wrapper handed to the Clojure CLI as JAVA_CMD. ASan must leave SIGSEGV
# and SIGBUS to the JVM (implicit null checks, safepoint polls), and leak
# detection is off: the JVM never frees much of what it maps. Reports
# land in target/sanitizer/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$#" -gt 0 ]; then
  NSES=("$@")
else
  NSES=(s-exp.quiche-h3-foundation-test s-exp.enso-http3-test s-exp.enso-h3-e2e-test s-exp.enso-h3-util-test)
fi

case "$(uname -s)" in
  Linux)
    OS=linux
    RUNTIME="$("${CC:-cc}" -print-file-name=libasan.so)"
    PRELOAD_VAR=LD_PRELOAD
    ;;
  Darwin)
    OS=darwin
    RUNTIME="$(clang -print-file-name=libclang_rt.asan_osx_dynamic.dylib)"
    PRELOAD_VAR=DYLD_INSERT_LIBRARIES
    ;;
  *) echo "unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

if [ ! -f "$RUNTIME" ]; then
  echo "ASan runtime not found (got '$RUNTIME')" >&2
  exit 1
fi
SHIM=
for f in "target/native/$OS-$ARCH"/libenso_quiche.so "target/native/$OS-$ARCH"/libenso_quiche.dylib; do
  if [ -f "$f" ]; then SHIM="$f"; fi
done
if [ -z "$SHIM" ]; then
  echo "no shim under target/native/$OS-$ARCH; build it with SANITIZE=1" >&2
  exit 1
fi
if [ "$OS" = darwin ]; then deps="$(otool -L "$SHIM")"; else deps="$(ldd "$SHIM")"; fi
if ! grep -q asan <<< "$deps"; then
  echo "$SHIM is not a sanitizer build (no ASan runtime dependency)" >&2
  exit 1
fi

REPORTS="$ROOT/target/sanitizer"
rm -rf "$REPORTS"
mkdir -p "$REPORTS"
# The JDK's own launcher: macOS's /usr/bin/java stub is SIP-protected and
# drops DYLD_* variables.
if [ -n "${JAVA_HOME:-}" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
elif [ "$OS" = darwin ]; then
  JAVA_BIN="$(/usr/libexec/java_home)/bin/java"
else
  JAVA_BIN="$(command -v java)"
fi
cat > "$REPORTS/java" <<EOF
#!/bin/sh
export $PRELOAD_VAR="$RUNTIME"
exec "$JAVA_BIN" "\$@"
EOF
chmod +x "$REPORTS/java"

export JAVA_CMD="$REPORTS/java"
export ASAN_OPTIONS="handle_segv=0:handle_sigbus=0:handle_sigfpe=0:allow_user_segv_handler=1:detect_leaks=0:detect_stack_use_after_return=0:halt_on_error=1:abort_on_error=1:log_path=$REPORTS/asan"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:log_path=$REPORTS/ubsan"

status=0
ENSO_TEST_LOG_DIR="$REPORTS/test-logs" script/test.sh "${NSES[@]}" || status=$?

reports="$(find "$REPORTS" -maxdepth 1 -name 'asan.*' -o -maxdepth 1 -name 'ubsan.*')"
if [ -n "$reports" ]; then
  echo "sanitizer reports:" >&2
  for r in $reports; do
    echo "== $r" >&2
    cat "$r" >&2
  done
  status=1
fi
exit "$status"

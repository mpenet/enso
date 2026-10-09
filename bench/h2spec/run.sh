#!/usr/bin/env bash
# ABOUTME: Runs the h2spec HTTP/2 conformance suite (pinned release) against enso over TLS or
# ABOUTME: cleartext (h2c) and fails on a crash, a truncated run or drift from expected-failures.txt.
#
# Usage:
#   bench/h2spec/run.sh            # HTTP/2 over TLS: boot the test server, run h2spec, diff vs expectations
#   bench/h2spec/run.sh h2c        # cleartext HTTP/2 with prior knowledge on a plain :http2c listener
#
# Environment:
#   H2SPEC_BIN   use this h2spec binary instead of downloading the pinned one
#   H2SPEC_PORT  port for the test server (default 18443 for TLS, 18080 for h2c)
#   ENSO_SERVER_OPTS EDN map of extra run-server options
#
# Outputs land in target/conformance/h2spec/ (TLS) or target/conformance/h2spec-h2c/
# (raw output + JUnit report). Expectations: expected-failures.txt (TLS),
# expected-failures-h2c.txt (h2c).
# Exit codes: 0 ok, 1 setup/run error (crash, missing report, case count
# other than the expected total), 2 results differ from the expectations.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../conformance-lib.sh
. "$HERE/../conformance-lib.sh"

H2SPEC_VERSION=2.6.0
TRANSPORT="${1:-tls}"
case "$TRANSPORT" in
  tls) PORT="${H2SPEC_PORT:-18443}"; LISTENER=h2; TLS_FLAGS=(-t -k); SUFFIX=""
       TITLE="HTTP/2 over TLS" ;;
  h2c) PORT="${H2SPEC_PORT:-18080}"; LISTENER=h2c; TLS_FLAGS=(); SUFFIX="-h2c"
       TITLE="cleartext HTTP/2, prior knowledge" ;;
  *) echo "usage: $0 [tls|h2c]" >&2; exit 1 ;;
esac
WORK_DIR="$ROOT/target/conformance/h2spec$SUFFIX"
mkdir -p "$WORK_DIR"

if [ -z "${H2SPEC_BIN:-}" ] && [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ]; then
  # Upstream ships no arm64 macOS build; use Homebrew's (brew install h2spec).
  H2SPEC_BIN="$(command -v h2spec)" || {
    echo "no arm64 h2spec release; brew install h2spec or set H2SPEC_BIN" >&2
    exit 1
  }
  "$H2SPEC_BIN" --version | grep -q "$H2SPEC_VERSION" ||
    echo "warning: $H2SPEC_BIN is not h2spec $H2SPEC_VERSION" >&2
fi

if [ -z "${H2SPEC_BIN:-}" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) asset=h2spec_linux_amd64.tar.gz
                  sha=157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318 ;;
    Darwin-x86_64) asset=h2spec_darwin_amd64.tar.gz
                   sha=981cb9f90a6f5e36300063022bd4eb7438d3dcf66d63a146a8541359697d1601 ;;
    *) echo "no pinned h2spec for $(uname -s)-$(uname -m); set H2SPEC_BIN" >&2; exit 1 ;;
  esac
  tarball="$TOOLS_DIR/h2spec-$H2SPEC_VERSION-$asset"
  fetch_pinned "https://github.com/summerwind/h2spec/releases/download/v$H2SPEC_VERSION/$asset" \
    "$sha" "$tarball" || exit 1
  H2SPEC_BIN="$TOOLS_DIR/h2spec-$H2SPEC_VERSION"
  if [ ! -x "$H2SPEC_BIN" ]; then
    tar -xzf "$tarball" -C "$TOOLS_DIR" h2spec && mv "$TOOLS_DIR/h2spec" "$H2SPEC_BIN" || exit 1
  fi
fi

start_test_server "$LISTENER" "$PORT" ${ENSO_SERVER_OPTS:+opts "$ENSO_SERVER_OPTS"} || exit 1

# -t TLS, -k accept the self-signed cert, -o per-case timeout in seconds.
"$H2SPEC_BIN" ${TLS_FLAGS[@]+"${TLS_FLAGS[@]}"} -h 127.0.0.1 -p "$PORT" -o 5 -j "$WORK_DIR/junit.xml" \
  > "$WORK_DIR/output.txt" 2>&1
status=$?
tail -3 "$WORK_DIR/output.txt"
stop_test_server

if [ ! -s "$WORK_DIR/junit.xml" ]; then
  echo "h2spec produced no report (exit $status); output:" >&2
  cat "$WORK_DIR/output.txt" >&2
  exit 1
fi

python3 "$HERE/junit_results.py" "$WORK_DIR/junit.xml" \
  "$WORK_DIR/failures.txt" "$WORK_DIR/passes.txt" || exit 1
check_tool_exit h2spec "$status" "$WORK_DIR/failures.txt" || { tail -20 "$WORK_DIR/output.txt" >&2; exit 1; }
compare_expectations "h2spec $H2SPEC_VERSION ($TITLE)" \
  "$WORK_DIR/failures.txt" "$WORK_DIR/passes.txt" "$HERE/expected-failures$SUFFIX.txt"

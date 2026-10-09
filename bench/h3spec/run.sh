#!/usr/bin/env bash
# ABOUTME: Runs the h3spec HTTP/3 + QUIC conformance suite (pinned release, downloaded and
# ABOUTME: checksum-verified) against enso; fails on a crash, a truncated run or expectation drift.
#
# Usage:
#   bench/h3spec/run.sh                 # boot the test server, run h3spec, diff vs expectations
#   bench/h3spec/run.sh --match=REGEX   # forward -m to h3spec (subset run: no case-count
#                                       # check, expected failures that pass still fail it)
#
# Needs the JNI shim (clojure -T:build shim) and compiled classes.
#
# Environment:
#   H3SPEC_BIN   use this h3spec binary instead of downloading the pinned one
#   H3SPEC_PORT  UDP port for the test server (default 18443)
#   ENSO_SERVER_OPTS EDN map of extra run-server options
#
# Outputs land in target/conformance/h3spec/.
# Exit codes: 0 ok, 1 setup/run error (crash, case count other than the
# expected total on a full run), 2 results differ from the expectations.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../conformance-lib.sh
. "$HERE/../conformance-lib.sh"

H3SPEC_VERSION=0.1.13
PORT="${H3SPEC_PORT:-18443}"
WORK_DIR="$ROOT/target/conformance/h3spec"
mkdir -p "$WORK_DIR"

MATCH=()
for arg in "$@"; do
  case "$arg" in
    --match=*) MATCH=(-m "${arg#*=}") ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [ -z "${H3SPEC_BIN:-}" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) asset=h3spec-linux-x86_64
                  sha=b5f8eddd968cb195d1e3e7698d33fa141d6b2ad56153089d89928ac0fdee28bf ;;
    Darwin-arm64) asset=h3spec-mac-arm64
                  sha=850ee3317b767db1e5e41cf3b9f034a74feabf52672744920ba41f330b710253 ;;
    *) echo "no pinned h3spec for $(uname -s)-$(uname -m); set H3SPEC_BIN" >&2; exit 1 ;;
  esac
  H3SPEC_BIN="$TOOLS_DIR/h3spec-$H3SPEC_VERSION"
  fetch_pinned "https://github.com/kazu-yamamoto/h3spec/releases/download/v$H3SPEC_VERSION/$asset" \
    "$sha" "$H3SPEC_BIN" || exit 1
  chmod +x "$H3SPEC_BIN"
fi

start_test_server h3 "$PORT" ${ENSO_SERVER_OPTS:+opts "$ENSO_SERVER_OPTS"} || exit 1

# -n: the test server's certificate is self-signed.
OUT="$WORK_DIR/output.txt"
"$H3SPEC_BIN" -n ${MATCH[@]+"${MATCH[@]}"} 127.0.0.1 "$PORT" > "$OUT" 2>&1
status=$?
# hspec colours its marks and summary when it thinks it has a terminal
# (CI does); strip the escapes so the parsing below sees plain text.
esc=$'\033'
sed "s/${esc}\[[0-9;]*m//g" "$OUT" > "$OUT.plain" && mv "$OUT.plain" "$OUT"
tail -3 "$OUT"
stop_test_server

grep -aE '\[✘\]$' "$OUT" | sed -E 's/^[[:space:]]+//; s/[[:space:]]*\[✘\]$//' > "$WORK_DIR/failures.txt"
grep -aE '\[✔\]$' "$OUT" | sed -E 's/^[[:space:]]+//; s/[[:space:]]*\[✔\]$//' > "$WORK_DIR/passes.txt"
check_tool_exit h3spec "$status" "$WORK_DIR/failures.txt" || { tail -20 "$OUT" >&2; exit 1; }

# hspec's own "N examples, M failures" line must agree with the marks
# parsed above, so a format change cannot silently drop cases.
reported="$(sed -n 's/^\([0-9][0-9]*\) examples*, [0-9][0-9]* failures*.*/\1/p' "$OUT" | tail -1)"
parsed=$(( $(wc -l < "$WORK_DIR/failures.txt") + $(wc -l < "$WORK_DIR/passes.txt") ))
if [ -z "$reported" ] || [ "$reported" -ne "$parsed" ]; then
  echo "h3spec reported ${reported:-no} examples but $parsed results were parsed; output:" >&2
  cat "$OUT" >&2
  exit 1
fi

compare_expectations "h3spec $H3SPEC_VERSION (QUIC + HTTP/3)" \
  "$WORK_DIR/failures.txt" "$WORK_DIR/passes.txt" "$HERE/expected-failures.txt" \
  ${MATCH[@]+subset}

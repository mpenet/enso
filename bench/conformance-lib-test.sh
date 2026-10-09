#!/usr/bin/env bash
# ABOUTME: Self-test of the conformance verdict logic in bench/conformance-lib.sh: truncated
# ABOUTME: runs, stale expectations, unexpected failures, tool crashes and subset runs.
#
# Usage: bench/conformance-lib-test.sh   (exits non-zero on the first wrong verdict)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=conformance-lib.sh
. "$HERE/conformance-lib.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fails=0

# expect WANT_STATUS DESCRIPTION CMD...
expect() {
  local want="$1" desc="$2"
  shift 2
  "$@" > "$T/out" 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then
    echo "ok   $desc"
  else
    echo "FAIL $desc: status $got, wanted $want" >&2
    sed 's/^/     /' "$T/out" >&2
    fails=$((fails + 1))
  fi
}

lines() { printf '%s\n' "$@" | sed '/^$/d'; }

lines '# header' 'total-cases: 4' 'case b' > "$T/expected"

lines 'case b' > "$T/f"; lines 'case a' 'case c' 'case d' > "$T/p"
expect 0 "full run matching the expectations" compare_expectations s "$T/f" "$T/p" "$T/expected"

lines 'case b' > "$T/f"; lines 'case a' 'case c' > "$T/p"
expect 1 "truncated run (3 of 4 cases)" compare_expectations s "$T/f" "$T/p" "$T/expected"

lines 'case b' > "$T/f"; lines 'case a' 'case c' 'case d' 'case e' > "$T/p"
expect 1 "suite grew (5 of 4 cases)" compare_expectations s "$T/f" "$T/p" "$T/expected"

: > "$T/f"; lines 'case a' 'case b' 'case c' 'case d' > "$T/p"
expect 2 "expected failure now passes" compare_expectations s "$T/f" "$T/p" "$T/expected"

lines 'case b' 'case c' > "$T/f"; lines 'case a' 'case d' > "$T/p"
expect 2 "unexpected failure" compare_expectations s "$T/f" "$T/p" "$T/expected"

lines 'case a' > "$T/f"; lines 'case c' > "$T/p"
expect 2 "subset run: unexpected failure" compare_expectations s "$T/f" "$T/p" "$T/expected" subset

: > "$T/f"; lines 'case c' > "$T/p"
expect 0 "subset run: listed case not run" compare_expectations s "$T/f" "$T/p" "$T/expected" subset

: > "$T/f"; lines 'case b' > "$T/p"
expect 2 "subset run: listed case passes" compare_expectations s "$T/f" "$T/p" "$T/expected" subset

lines 'total-cases: 2' '1.1.1 FAILED/OK' > "$T/ab"
: > "$T/f"; lines '1.1.1' > "$T/p"
expect 2 "subset run: entry matched by first field" compare_expectations s "$T/f" "$T/p" "$T/ab" subset

lines 'case b' > "$T/noTotal"
lines 'case b' > "$T/f"; lines 'case a' > "$T/p"
expect 1 "expectations without total-cases" compare_expectations s "$T/f" "$T/p" "$T/noTotal"

: > "$T/f"
expect 1 "tool exit 1 with no failing case (crash)" check_tool_exit s 1 "$T/f"
expect 0 "tool exit 0" check_tool_exit s 0 "$T/f"
lines 'case b' > "$T/f"
expect 0 "tool exit 1 with failing cases" check_tool_exit s 1 "$T/f"
expect 1 "tool killed by a signal" check_tool_exit s 139 "$T/f"

if [ "$fails" -gt 0 ]; then
  echo "$fails verdict(s) wrong" >&2
  exit 1
fi

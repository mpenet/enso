#!/usr/bin/env bash
# ABOUTME: Runs every test namespace (or the ones given as args) in its own JVM.
# ABOUTME: Prints a per-namespace summary and exits non-zero if any namespace failed.
#
# Usage:
#   script/test.sh                          # all namespaces under test/ except excluded ones
#   script/test.sh s-exp.enso-hpack-test    # selected namespaces
#
# Environment:
#   ENSO_TEST_EXCLUDE   space-separated namespaces to skip in the default run
#                       (default: the soak namespace, which has its own CI job)
#   ENSO_TEST_LOG_DIR   where per-namespace logs go (default: target/test-logs)
#   GITHUB_STEP_SUMMARY when set (GitHub Actions), a markdown table is appended

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

EXCLUDE="${ENSO_TEST_EXCLUDE-s-exp.enso-soak-test}"
LOG_DIR="${ENSO_TEST_LOG_DIR:-target/test-logs}"
mkdir -p "$LOG_DIR"

if [ "$#" -gt 0 ]; then
  NSES=("$@")
else
  NSES=()
  while IFS= read -r f; do
    ns=$(sed -n 's/^(ns \([^ )]*\).*/\1/p' "$f" | head -1)
    [ -z "$ns" ] && continue
    skip=0
    for e in $EXCLUDE; do [ "$e" = "$ns" ] && skip=1; done
    [ "$skip" -eq 0 ] && NSES+=("$ns")
  done < <(find test -name '*_test.clj' | sort)
fi

failed=()
rows=()
for ns in "${NSES[@]}"; do
  log="$LOG_DIR/$ns.log"
  start=$(date +%s)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::group::$ns"; fi
  clojure -X:test :nses "[$ns]" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; fi
  secs=$(( $(date +%s) - start ))
  ran=$(grep -aE '^Ran [0-9]+ tests' "$log" | tail -1)
  res=$(grep -aE '^[0-9]+ failures, [0-9]+ errors' "$log" | tail -1)
  if [ "$status" -eq 0 ]; then
    verdict=PASS
  else
    verdict=FAIL
    failed+=("$ns")
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error title=$ns failed::${res:-no summary line, see log}"
    fi
  fi
  printf '%-4s %-40s %4ss  %s %s\n' "$verdict" "$ns" "$secs" "$ran" "$res"
  rows+=("| $verdict | \`$ns\` | ${secs}s | $ran $res |")
done

echo
echo "== summary =="
for r in "${rows[@]}"; do echo "$r"; done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Test namespaces"
    echo
    echo "| | namespace | time | result |"
    echo "|---|---|---|---|"
    for r in "${rows[@]}"; do echo "$r"; done
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi

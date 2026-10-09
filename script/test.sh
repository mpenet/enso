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
#
# Quarantine: tests tagged ^:flaky (only on evidence of an intermittent
# failure, see doc/testing.md) run apart from the rest of their namespace,
# in a second JVM. A quarantined test that fails is rerun once; passing on
# the rerun is reported as FLAKY (a warning and its own summary section,
# not a pass), failing twice fails the run like any other test.

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

# Runs the tests of namespace $1 selected by the test-runner options in
# the remaining args, logging to $LOG_DIR/<log name $2>.log; sets status,
# secs, ran and res.
run_tests() {
  local ns="$1" name="$2"
  shift 2
  local log="$LOG_DIR/$name.log"
  local start
  start=$(date +%s)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::group::$name"; fi
  clojure -X:test :nses "[$ns]" "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; fi
  secs=$(( $(date +%s) - start ))
  ran=$(grep -aE '^Ran [0-9]+ tests' "$log" | tail -1)
  res=$(grep -aE '^[0-9]+ failures, [0-9]+ errors' "$log" | tail -1)
}

# Records the verdict of one run (namespace or quarantined tests).
report() {
  local verdict="$1" name="$2"
  if [ "$verdict" = FAIL ]; then
    failed+=("$name")
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error title=$name failed::${res:-no summary line, see log}"
    fi
  fi
  printf '%-5s %-40s %4ss  %s %s\n' "$verdict" "$name" "$secs" "$ran" "$res"
  rows+=("| $verdict | \`$name\` | ${secs}s | $ran $res |")
}

failed=()
rows=()
flaky=()
for ns in "${NSES[@]}"; do
  file="test/$(tr .- /_ <<< "$ns").clj"
  if [ -f "$file" ] && grep -q '\^:flaky' "$file"; then
    run_tests "$ns" "$ns" :excludes '[:flaky]'
    if [ "$status" -eq 0 ]; then report PASS "$ns"; else report FAIL "$ns"; fi
    run_tests "$ns" "$ns.flaky" :includes '[:flaky]'
    if [ "$status" -eq 0 ]; then
      report PASS "$ns (quarantined)"
    else
      first_res="$res"
      run_tests "$ns" "$ns.flaky-rerun" :includes '[:flaky]'
      if [ "$status" -eq 0 ]; then
        report FLAKY "$ns (quarantined)"
        flaky+=("| \`$ns\` | $first_res | see \`$LOG_DIR/$ns.flaky.log\` |")
        if [ -n "${GITHUB_ACTIONS:-}" ]; then
          echo "::warning title=$ns quarantined test failed, passed on rerun::$first_res"
        fi
      else
        report FAIL "$ns (quarantined)"
      fi
    fi
  else
    run_tests "$ns" "$ns"
    if [ "$status" -eq 0 ]; then report PASS "$ns"; else report FAIL "$ns"; fi
  fi
done

echo
echo "== summary =="
for r in "${rows[@]}"; do echo "$r"; done
if [ "${#flaky[@]}" -gt 0 ]; then
  echo
  echo "== quarantined tests that failed, then passed on rerun =="
  for r in "${flaky[@]}"; do echo "$r"; done
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Test namespaces"
    echo
    echo "| | namespace | time | result |"
    echo "|---|---|---|---|"
    for r in "${rows[@]}"; do echo "$r"; done
    if [ "${#flaky[@]}" -gt 0 ]; then
      echo
      echo "### Flaky: quarantined tests that failed, then passed on rerun"
      echo
      echo "| namespace | first run | log |"
      echo "|---|---|---|"
      for r in "${flaky[@]}"; do echo "$r"; done
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi

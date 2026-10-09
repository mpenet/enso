# ABOUTME: Shared shell helpers for the conformance runners (h2spec, Autobahn, h3spec):
# ABOUTME: pinned tool download with checksum, test-server lifecycle, exit-status and expectations checks.
# shellcheck shell=bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Used by the runners that source this file.
# shellcheck disable=SC2034
TOOLS_DIR="$ROOT/target/tools"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# fetch_pinned URL SHA256 DEST
# Downloads URL to DEST unless DEST already has the expected checksum.
# Fails (and removes the download) on checksum mismatch.
fetch_pinned() {
  local url="$1" sha="$2" dest="$3"
  if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$sha" ]; then
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  echo "downloading $url"
  curl --proto '=https' --tlsv1.2 -sSfL -o "$dest.part" "$url" || return 1
  local got
  got="$(sha256_of "$dest.part")"
  if [ "$got" != "$sha" ]; then
    echo "checksum mismatch for $url: expected $sha, got $got" >&2
    rm -f "$dest.part"
    return 1
  fi
  mv "$dest.part" "$dest"
}

# start_test_server ARGS...
# Boots `clojure -M:test-server ARGS...` in the background, waits for its
# READY line and stops it when the calling script exits. Sets SRV_PID and
# SRV_LOG.
start_test_server() {
  SRV_LOG="${WORK_DIR:-/tmp}/enso-test-server.log"
  (cd "$ROOT" && exec clojure -M:test-server "$@") >"$SRV_LOG" 2>&1 &
  SRV_PID=$!
  trap stop_test_server EXIT
  local _
  for _ in $(seq 1 360); do
    if grep -aq '^READY' "$SRV_LOG"; then
      return 0
    fi
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
  echo "test server did not become ready; log tail:" >&2
  tail -40 "$SRV_LOG" >&2
  return 1
}

stop_test_server() {
  if [ -n "${SRV_PID:-}" ] && kill -0 "$SRV_PID" 2>/dev/null; then
    kill "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
  fi
  SRV_PID=
}

# summary LINE...
# Prints to stdout and, under GitHub Actions, appends to the job summary.
summary() {
  printf '%s\n' "$@"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# expected_total EXPECTATIONS_FILE
# Prints the case count declared by the "total-cases: N" line.
expected_total() {
  sed -n 's/^total-cases:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$1" | head -1
}

# check_tool_exit SUITE STATUS FAILURES_FILE
# The suites exit 1 when a case fails, so a non-zero status is only a
# crash when it is not 1 or when no case was recorded as failing.
# Returns 1 on a crash.
check_tool_exit() {
  local suite="$1" status="$2" failures="$3"
  if [ "$status" -ne 0 ] && { [ "$status" -ne 1 ] || [ ! -s "$failures" ]; }; then
    echo "$suite exited with status $status without recording a failing case" >&2
    return 1
  fi
}

# compare_expectations SUITE FAILURES_FILE PASSES_FILE EXPECTATIONS_FILE [subset]
# FAILURES_FILE and PASSES_FILE hold one case id per line. The
# expectations file lists the case ids allowed to fail ('#' comments and
# blank lines ignored) and declares the suite size with a
# "total-cases: N" line.
#
# Full run (no 5th argument): returns 1 when the number of cases run is
# not N (a truncated or reshaped run), 2 when a case outside the
# expectations fails or an expected failure did not fail (fixed, renamed
# or removed: the entry must go). With "subset" (a filtered run) the
# count is not checked and only expected failures that passed are stale
# (matched by whole id or by first field).
compare_expectations() {
  local suite="$1" failures="$2" passes="$3" expected="$4" mode="${5:-full}"
  local a e p unexpected stale n_fail n_run want rel status=0
  rel="${expected#"$ROOT"/}"
  a="$(mktemp)"
  e="$(mktemp)"
  p="$(mktemp)"
  LC_ALL=C sort -u "$failures" | sed '/^$/d' > "$a"
  LC_ALL=C sort -u "$passes" | sed '/^$/d' > "$p"
  LC_ALL=C grep -av -e '^#' -e '^total-cases:' "$expected" \
    | sed 's/[[:space:]]*$//; /^$/d' | LC_ALL=C sort -u > "$e"
  n_fail="$(sed '/^$/d' "$failures" | wc -l | tr -d ' ')"
  n_run=$(( n_fail + $(sed '/^$/d' "$passes" | wc -l | tr -d ' ') ))
  want="$(expected_total "$expected")"
  unexpected="$(LC_ALL=C comm -23 "$a" "$e")"
  if [ "$mode" = subset ]; then
    # An entry matches a passing case by its whole id or by its first
    # field (Autobahn entries carry the outcome after the case number).
    stale="$(awk 'NR == FNR { pass[$0] = 1; next } ($0 in pass) || ($1 in pass)' "$p" "$e")"
  else
    stale="$(LC_ALL=C comm -13 "$a" "$e")"
  fi
  rm -f "$a" "$e" "$p"
  summary "### $suite" "" "$n_run cases run (${want:-?} expected, $mode run), $n_fail failing" ""
  if [ "$mode" != subset ]; then
    if [ -z "$want" ]; then
      summary "**\`$rel\` has no \`total-cases: N\` line.**" ""
      return 1
    fi
    if [ "$n_run" -ne "$want" ]; then
      summary "**Ran $n_run cases, expected $want: the run is incomplete or the suite changed" \
        "(update \`total-cases\` in \`$rel\` only after checking which).**" ""
      if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error title=$suite incomplete::ran $n_run of $want cases"
      fi
      return 1
    fi
  fi
  if [ -n "$stale" ]; then
    summary "**Expected failures that did not fail (remove them from \`$rel\`):**" ""
    while IFS= read -r l; do
      summary "- \`$l\`"
      if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error title=$suite stale expectation::$l"
      fi
    done <<< "$stale"
    summary ""
    status=2
  fi
  if [ -n "$unexpected" ]; then
    summary "**Unexpected failures:**" ""
    while IFS= read -r l; do
      summary "- \`$l\`"
      if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error title=$suite regression::$l"
      fi
    done <<< "$unexpected"
    status=2
  fi
  if [ "$status" -eq 0 ]; then
    summary "Results match the expectations."
  fi
  return "$status"
}

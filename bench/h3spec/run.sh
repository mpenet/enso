#!/usr/bin/env bash
# h3spec runner for the Enso h3 layer.
#
# Boots the h3 repro server (dev/h3_repro.clj) on 127.0.0.1:18443, runs the
# h3spec binary (bench/h3spec/h3spec — pinned v0.1.13 from
# https://github.com/kazu-yamamoto/h3spec/releases), and compares the raw
# output against bench/h3spec/baseline.txt to detect regressions.
#
# Usage:
#   bench/h3spec/run.sh                 # full run, diff vs baseline
#   bench/h3spec/run.sh --update        # rewrite baseline (use after a fix)
#   bench/h3spec/run.sh --match=REGEX   # forward -m flag to h3spec
#
# Exit codes:
#   0 = matches baseline (or --update)
#   1 = server failed to boot / h3spec crashed
#   2 = pass/fail count regressed vs baseline (new failures)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BASELINE="$HERE/baseline.txt"
BIN="$HERE/h3spec"
PORT=18443

UPDATE=0
MATCH=""
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    --match=*) MATCH="-m ${arg#*=}" ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [ ! -x "$BIN" ]; then
  echo "h3spec binary missing at $BIN" >&2
  echo "download: curl -sL -o $BIN https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.13/h3spec-mac-arm64 && chmod +x $BIN" >&2
  exit 1
fi

# Clean up any prior server on our port.
lsof -ti :$PORT 2>/dev/null | xargs -r kill -9 || true
pgrep -f "h3-repro" | xargs -r kill -9 || true
sleep 1

# Boot the h3 repro server in the background.
cd "$ROOT"
nohup clj -Sdeps '{:paths ["src/clj" "target/classes" "dev"]}' \
  -M -m h3-repro >/tmp/h3spec-server.out 2>/tmp/h3spec-server.err &
SRV_PID=$!
disown

# Wait for the server to bind. Give it ~15s to warm up + JIT.
for i in $(seq 1 30); do
  if lsof -i :$PORT >/dev/null 2>&1; then break; fi
  sleep 0.5
done

if ! lsof -i :$PORT >/dev/null 2>&1; then
  echo "server never bound port $PORT — stderr tail:" >&2
  tail -20 /tmp/h3spec-server.err >&2
  kill -9 $SRV_PID 2>/dev/null || true
  exit 1
fi

# Give quiche a moment past bind to fully warm up.
sleep 2

OUT="/tmp/h3spec-run-$$.txt"
# shellcheck disable=SC2086
$BIN -n $MATCH 127.0.0.1 $PORT 2>&1 > "$OUT" || true

kill -9 $SRV_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ "$UPDATE" -eq 1 ]; then
  cp "$OUT" "$BASELINE"
  echo "baseline updated: $BASELINE"
  tail -3 "$OUT"
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  echo "no baseline found at $BASELINE — run with --update to create" >&2
  cat "$OUT"
  exit 1
fi

# Compare just the pass/fail counts — the raw output includes randomised
# seeds + timings that would produce diff noise.
BASE_SUMMARY=$(grep -E "^[0-9]+ examples, [0-9]+ failures" "$BASELINE" | tail -1)
CUR_SUMMARY=$(grep -E "^[0-9]+ examples, [0-9]+ failures" "$OUT" | tail -1)

echo "baseline: $BASE_SUMMARY"
echo "current:  $CUR_SUMMARY"

BASE_FAILS=$(echo "$BASE_SUMMARY" | grep -oE "[0-9]+ failures" | grep -oE "[0-9]+")
CUR_FAILS=$(echo "$CUR_SUMMARY"  | grep -oE "[0-9]+ failures" | grep -oE "[0-9]+")

if [ -z "$CUR_FAILS" ]; then
  echo "h3spec run did not produce a summary line — check $OUT" >&2
  exit 1
fi

if [ "$CUR_FAILS" -gt "$BASE_FAILS" ]; then
  echo "REGRESSION: $CUR_FAILS failures vs baseline $BASE_FAILS" >&2
  diff -u "$BASELINE" "$OUT" | head -80 >&2 || true
  exit 2
fi

if [ "$CUR_FAILS" -lt "$BASE_FAILS" ]; then
  echo "IMPROVEMENT: $CUR_FAILS failures vs baseline $BASE_FAILS — rerun with --update to lock in"
fi

echo "OK"

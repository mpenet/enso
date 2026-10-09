#!/usr/bin/env bash
# ABOUTME: Runs the Autobahn TestSuite fuzzingclient (pinned Docker image) against enso's
# ABOUTME: WebSocket echo endpoint; fails on a crash, a truncated run or expectation drift.
#
# Usage:
#   bench/autobahn/run.sh               # every case
#   AUTOBAHN_CASES='["1.*","2.*"]' bench/autobahn/run.sh   # subset run: no case-count check
#
# Environment:
#   AUTOBAHN_PORT   plain HTTP/1.1 port for the echo server (default 18080)
#   AUTOBAHN_CASES  JSON array of case patterns (default ["*"])
#   ENSO_SERVER_OPTS EDN map of run-server options, replacing the default
#                   {:ws-compression true :ws-max-message-bytes 16777216}:
#                   permessage-deflate on for 12.* / 13.*, and a message cap
#                   that fits the suite's largest message (16 MiB, 9.1.6).
#
# The HTML/JSON report lands in target/conformance/autobahn/reports/.
# Exit codes: 0 ok, 1 setup/run error (crash, case count other than the
# expected total on a full run), 2 results differ from the expectations.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../conformance-lib.sh
. "$HERE/../conformance-lib.sh"

IMAGE="crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
PORT="${AUTOBAHN_PORT:-18080}"
CASES="${AUTOBAHN_CASES:-[\"*\"]}"
WORK_DIR="$ROOT/target/conformance/autobahn"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/config" "$WORK_DIR/reports"

# Linux: the container shares the host network. Docker Desktop (macOS)
# has no host networking; host.docker.internal reaches the host loopback.
if [ "$(uname -s)" = "Linux" ]; then
  NET_ARGS=(--network host)
  WS_HOST=127.0.0.1
else
  NET_ARGS=()
  WS_HOST=host.docker.internal
fi

DEFAULT_OPTS='{:ws-compression true :ws-max-message-bytes 16777216}'
OPTS="${ENSO_SERVER_OPTS:-$DEFAULT_OPTS}"

cat > "$WORK_DIR/config/fuzzingclient.json" <<EOF
{
  "outdir": "/reports",
  "servers": [{"agent": "enso", "url": "ws://$WS_HOST:$PORT/"}],
  "cases": $CASES,
  "exclude-cases": [],
  "exclude-agent-cases": {}
}
EOF

start_test_server h1 "$PORT" opts "$OPTS" || exit 1

docker run --rm ${NET_ARGS[@]+"${NET_ARGS[@]}"} \
  -v "$WORK_DIR/config:/config" -v "$WORK_DIR/reports:/reports" \
  "$IMAGE" wstest -m fuzzingclient -s /config/fuzzingclient.json \
  > "$WORK_DIR/output.txt" 2>&1
status=$?
tail -3 "$WORK_DIR/output.txt"
stop_test_server

INDEX="$WORK_DIR/reports/index.json"
if [ "$status" -ne 0 ] || [ ! -s "$INDEX" ]; then
  echo "autobahn run failed (exit $status); output tail:" >&2
  tail -40 "$WORK_DIR/output.txt" >&2
  exit 1
fi

python3 "$HERE/report_results.py" "$INDEX" \
  "$WORK_DIR/failures.txt" "$WORK_DIR/passes.txt" || exit 1
total=$(( $(wc -l < "$WORK_DIR/failures.txt") + $(wc -l < "$WORK_DIR/passes.txt") ))

# wstest stops at the first case it can't connect for, still exiting 0
# with a report of the cases run so far.
planned="$(sed -n 's/.*will run \([0-9]*\) test cases.*/\1/p' "$WORK_DIR/output.txt" | head -1)"
if [ -z "$planned" ] || [ "$planned" != "$total" ]; then
  echo "autobahn run incomplete: $total of ${planned:-?} cases; output tail:" >&2
  tail -5 "$WORK_DIR/output.txt" >&2
  exit 1
fi
compare_expectations "Autobahn TestSuite (WebSocket, fuzzingclient)" \
  "$WORK_DIR/failures.txt" "$WORK_DIR/passes.txt" "$HERE/expected-failures.txt" \
  ${AUTOBAHN_CASES:+subset}

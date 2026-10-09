#!/usr/bin/env bash
# ABOUTME: Runs the official quic-interop-runner (pinned commit) with enso as the HTTP/3 server against
# ABOUTME: a set of client implementations and checks the results against expected-results.txt.
#
# Usage (from the repository root):
#   bench/quic-interop-runner/run.sh                      # default clients, http3
#   bench/quic-interop-runner/run.sh quic-go,ngtcp2       # selected clients
#
# Environment:
#   INTEROP_TESTS   runner test cases (default http3: the only case whose
#                   clients negotiate ALPN h3; the others use hq-interop,
#                   which enso does not speak, and are answered 127 =
#                   unsupported by run_endpoint.sh)
#   INTEROP_IMAGE   use this enso endpoint image instead of building
#                   enso-interop:latest from bench/quic-interop-runner/Dockerfile
#   PYTHON          interpreter for the runner's venv (default python3; >= 3.10)
#
# Needs Docker (with Compose), Python >= 3.10 (venv) and tshark >= 4.5 (the runner
# dissects the captured QUIC traffic); on Linux also the ip6table_filter
# module (`sudo modprobe ip6table_filter`). The runner is fetched into
# target/tools/; logs, pcaps and results.json land in
# target/conformance/quic-interop/. Exit status: 0 when every result
# matches expected-results.txt, 1 when the run produced no results, 2 on a
# mismatch (see check_results.py).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

RUNNER_COMMIT=740c05a10b61d65e8abd3ad38d60898004d335d9
CLIENTS="${1:-quiche,ngtcp2,quic-go,neqo,quinn}"
TESTS="${INTEROP_TESTS:-http3}"
IMAGE="${INTEROP_IMAGE:-enso-interop:latest}"
PYTHON="${PYTHON:-python3}"
RUNNER="$ROOT/target/tools/quic-interop-runner-$RUNNER_COMMIT"
OUT="$ROOT/target/conformance/quic-interop"
VENV="$RUNNER/.venv-$(uname -s)-$(uname -m)"

tshark_version="$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)"
if [ -z "$tshark_version" ]; then
  echo "tshark not found (the runner needs Wireshark >= 4.5)" >&2
  exit 1
fi
if [ "$(printf '%s\n4.5\n' "$tshark_version" | sort -V | head -1)" != 4.5 ]; then
  echo "tshark $tshark_version is too old (the runner needs >= 4.5)" >&2
  exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "$PYTHON is older than 3.10 (the runner needs >= 3.10); set PYTHON" >&2
  exit 1
fi

if [ -z "${INTEROP_IMAGE:-}" ]; then
  docker build -t "$IMAGE" -f bench/quic-interop-runner/Dockerfile .
fi

if [ ! -f "$RUNNER/run.py" ]; then
  rm -rf "$RUNNER"
  git init -q "$RUNNER"
  git -C "$RUNNER" fetch -q --depth 1 https://github.com/quic-interop/quic-interop-runner.git "$RUNNER_COMMIT"
  git -C "$RUNNER" checkout -q FETCH_HEAD
fi
if [ ! -x "$VENV/bin/python" ]; then
  "$PYTHON" -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$RUNNER/requirements.txt"
fi

# Register enso as a server-only implementation.
"$VENV/bin/python" - "$RUNNER/implementations_quic.json" "$IMAGE" <<'EOF'
import json, sys
path, image = sys.argv[1], sys.argv[2]
with open(path) as f:
    impls = json.load(f)
impls["enso"] = {"image": image, "url": "https://github.com/mpenet/enso", "role": "server"}
with open(path, "w") as f:
    json.dump(impls, f, indent=2)
EOF

rm -rf "$OUT"
mkdir -p "$OUT"
# -n enso: a test enso fails against every client stays a failure instead
# of being re-labelled "unsupported". The runner's exit status counts
# failed tests; the verdict comes from the expectations file instead.
(cd "$RUNNER" && "$VENV/bin/python" run.py -p quic -s enso -c "$CLIENTS" -t "$TESTS" -n enso \
  -l "$OUT/logs" -j "$OUT/results.json" -m) | tee "$OUT/output.txt" || true

"$VENV/bin/python" bench/quic-interop-runner/check_results.py \
  "$OUT/results.json" bench/quic-interop-runner/expected-results.txt

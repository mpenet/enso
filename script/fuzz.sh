#!/usr/bin/env bash
# ABOUTME: Runs one coverage-guided Jazzer fuzz target (fuzz/java) against the compiled sources for
# ABOUTME: a bounded time, growing target/fuzz/corpus/<target>; exits non-zero on a finding.
#
# Usage:
#   script/fuzz.sh TARGET [SECONDS] [JAZZER_ARGS...]
#   script/fuzz.sh HpackDecoderFuzz 60
#   script/fuzz.sh QpackDecoderFuzz 0 target/fuzz/findings/QpackDecoderFuzz/crash-<sha>   # replay
#
# Targets: HpackDecoderFuzz QpackDecoderFuzz Http1RequestFuzz WebSocketFrameFuzz
# SECONDS defaults to 60; 0 with an input file argument replays that input.
# Needs compiled Java sources (clojure -T:build javac).
#
# Outputs: target/fuzz/corpus/TARGET (inputs that reached new coverage,
# reused by the next run), target/fuzz/findings/TARGET (crashing input
# plus a Java reproducer). Seed inputs live in fuzz/corpus/TARGET, an
# optional libFuzzer dictionary in fuzz/dict/TARGET.dict.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:?usage: script/fuzz.sh TARGET [SECONDS] [JAZZER_ARGS...]}"
SECONDS_BUDGET="${2:-60}"
shift $(( $# >= 2 ? 2 : 1 ))

if [ ! -f "fuzz/java/com/s_exp/enso/fuzz/$TARGET.java" ]; then
  echo "unknown target $TARGET; see fuzz/java/com/s_exp/enso/fuzz/" >&2
  exit 1
fi
if [ ! -d target/classes/com/s_exp/enso ]; then
  echo "no compiled sources; run clojure -T:build javac first" >&2
  exit 1
fi

CP="$(clojure -Spath -A:fuzz)"
mkdir -p target/fuzz-classes
javac --release 21 -nowarn -cp "$CP" -d target/fuzz-classes fuzz/java/com/s_exp/enso/fuzz/*.java

CORPUS="target/fuzz/corpus/$TARGET"
FINDINGS="target/fuzz/findings/$TARGET"
mkdir -p "$CORPUS" "$FINDINGS"

INPUTS=()
if [ "$#" -gt 0 ] && [ -f "$1" ]; then
  INPUTS=("$@")
  shift "$#"
else
  INPUTS=("$CORPUS")
  if [ -d "fuzz/corpus/$TARGET" ]; then INPUTS+=("fuzz/corpus/$TARGET"); fi
fi

EXTRA_ARGS=()
if [ "$SECONDS_BUDGET" -gt 0 ]; then EXTRA_ARGS+=("-max_total_time=$SECONDS_BUDGET"); fi
if [ -f "fuzz/dict/$TARGET.dict" ]; then EXTRA_ARGS+=("-dict=fuzz/dict/$TARGET.dict"); fi

# Jazzer attaches its instrumentation agent at startup and loads its own
# native driver: allow both explicitly (JDK 21+ warns otherwise, later
# releases refuse).
exec java -XX:+EnableDynamicAgentLoading --enable-native-access=ALL-UNNAMED \
  -cp "target/fuzz-classes:$CP" com.code_intelligence.jazzer.Jazzer \
  --target_class="com.s_exp.enso.fuzz.$TARGET" \
  --instrumentation_includes='com.s_exp.enso.**' \
  --instrumentation_excludes='com.s_exp.enso.fuzz.**' \
  --reproducer_path="$FINDINGS" \
  -artifact_prefix="$FINDINGS/" \
  -timeout=10 \
  -rss_limit_mb=4096 \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
  "$@" \
  "${INPUTS[@]}"

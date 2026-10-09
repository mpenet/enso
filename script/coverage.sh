#!/usr/bin/env bash
# ABOUTME: Runs the test namespaces through script/test.sh with the JaCoCo agent in every JVM, then
# ABOUTME: writes HTML/XML/CSV Java coverage reports under target/coverage and a per-package table.
#
# Usage:
#   script/coverage.sh                          # same namespaces as script/test.sh's default run
#   script/coverage.sh s-exp.enso-hpack-test    # selected namespaces
#   ENSO_COVERAGE_APPEND=1 script/coverage.sh s-exp.enso-http2-test   # add to the previous run
#
# Needs compiled Java sources (clojure -T:build javac). Only the Java core
# (com.s_exp.enso.* from src/java, minus fuzz harnesses) is measured; the
# Clojure namespaces under src/clj are not.
#
# Environment:
#   ENSO_COVERAGE_APPEND  when set to 1, keep target/coverage/jacoco.exec and
#                         accumulate into it instead of starting fresh
#   GITHUB_STEP_SUMMARY   when set (GitHub Actions), the coverage table is appended
#   (script/test.sh's ENSO_TEST_EXCLUDE / ENSO_TEST_LOG_DIR apply as well)
#
# Outputs: target/coverage/jacoco.exec (raw execution data),
# target/coverage/html/index.html, target/coverage/jacoco.xml,
# target/coverage/jacoco.csv. Exits with script/test.sh's status; the
# report is produced even when tests fail.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="$ROOT/target/coverage"
EXEC="$OUT/jacoco.exec"

if [ ! -d target/classes/com/s_exp/enso ]; then
  echo "no compiled sources; run clojure -T:build javac first" >&2
  exit 1
fi

JARS="$(clojure -Spath -A:coverage | tr ':' '\n')"
AGENT="$(grep -E 'org\.jacoco\.agent-[^/]*-runtime\.jar$' <<<"$JARS")"
CLI="$(grep -E 'org\.jacoco\.cli-[^/]*-nodeps\.jar$' <<<"$JARS")"
case "$AGENT$OUT" in
  *[[:space:]]*) echo "coverage paths must not contain whitespace (JDK_JAVA_OPTIONS splits on it)" >&2; exit 1 ;;
esac

mkdir -p "$OUT"
if [ "${ENSO_COVERAGE_APPEND:-0}" != 1 ]; then
  rm -f "$EXEC"
fi

# JDK_JAVA_OPTIONS reaches every `java` launcher started below, including
# the server subprocesses some tests spawn; append=true lets all of them
# (and every namespace's JVM) accumulate into one file.
status=0
JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:+$JDK_JAVA_OPTIONS }-javaagent:$AGENT=destfile=$EXEC,append=true,includes=com.s_exp.enso.*,excludes=com.s_exp.enso.fuzz.*" \
  script/test.sh "$@" || status=$?

if [ ! -s "$EXEC" ]; then
  echo "no coverage data at $EXEC" >&2
  exit 1
fi

# Report only the classes compiled from src/java.
rm -rf "$OUT/classes" "$OUT/html"
mkdir -p "$OUT/classes"
(cd target/classes && tar cf - --exclude 'com/s_exp/enso/fuzz' com/s_exp/enso) | (cd "$OUT/classes" && tar xf -)

java -jar "$CLI" report "$EXEC" \
  --classfiles "$OUT/classes" \
  --sourcefiles src/java \
  --name enso \
  --html "$OUT/html" \
  --xml "$OUT/jacoco.xml" \
  --csv "$OUT/jacoco.csv"

table="$(awk -F, '
  function pct(c, m) { return (c + m) == 0 ? "n/a" : sprintf("%.1f%%", 100 * c / (c + m)) }
  function row(name, lc, lm, bc, bm) {
    return sprintf("| %s | %d/%d | %s | %d/%d | %s |", name, lc, lc + lm, pct(lc, lm), bc, bc + bm, pct(bc, bm))
  }
  NR > 1 {
    bm[$2] += $6; bc[$2] += $7; lm[$2] += $8; lc[$2] += $9
    tbm += $6; tbc += $7; tlm += $8; tlc += $9
  }
  END {
    print "| package | lines | line % | branches | branch % |"
    print "|---|---|---|---|---|"
    sorted = "LC_ALL=C sort | cut -f2-"
    for (p in lc) print p "\t" row("`" p "`", lc[p], lm[p], bc[p], bm[p]) | sorted
    close(sorted)
    print row("**total**", tlc, tlm, tbc, tbm)
  }' "$OUT/jacoco.csv")"

echo
echo "== Java coverage =="
echo "$table"
echo "HTML report: $OUT/html/index.html"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Java coverage"
    echo
    echo "$table"
  } >> "$GITHUB_STEP_SUMMARY"
fi

exit "$status"

#!/usr/bin/env bash
# ABOUTME: Builds the GraalVM native-image example: compiles enso and Main.java, then links a
# ABOUTME: standalone binary with the graal-build-time feature. Run from anywhere; needs GraalVM.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/target"
GRAAL_BUILD_TIME_VERSION="1.0.5"

native_image="$(command -v native-image || true)"
if [ -z "$native_image" ]; then
  if [ -n "${GRAALVM_HOME:-}" ] && [ -x "$GRAALVM_HOME/bin/native-image" ]; then
    native_image="$GRAALVM_HOME/bin/native-image"
  else
    echo "native-image not found. Install GraalVM and put native-image on PATH, or set GRAALVM_HOME." >&2
    exit 1
  fi
fi

mkdir -p "$OUT"

# 1. Compile the enso Java sources into target/classes.
(cd "$ROOT" && clojure -T:build javac)

# 2. Classpath: enso plus the graal-build-time feature. Resolved from $ROOT so
#    the relative target/classes entry points at the compiled sources.
cd "$ROOT"
feature_cp="$(clojure -Sdeps "{:deps {com.github.clj-easy/graal-build-time {:mvn/version \"$GRAAL_BUILD_TIME_VERSION\"}}}" -Spath)"
classpath="$feature_cp:$OUT"

# 3. Compile the example entrypoint.
javac -cp "$classpath" -d "$OUT" "$HERE/Main.java"

# 4. Link the native image. The feature initialises Clojure's classes at build
#    time in the right order (enso's request map is a Clojure data structure).
"$native_image" \
  -cp "$classpath" \
  --no-fallback \
  --features=clj_easy.graal_build_time.InitClojureClasses \
  -o "$OUT/enso-native" \
  example.Main

echo
echo "built $OUT/enso-native"
echo "run it: $OUT/enso-native [port]"

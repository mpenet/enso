#!/usr/bin/env bash
# ABOUTME: Builds the Clojure GraalVM native-image example: AOT-compiles example.server (which pulls
# ABOUTME: s-exp.enso), then links a standalone binary. Run from anywhere; needs GraalVM.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLASSES="$HERE/target/classes"
OUT="$HERE/target"

native_image="$(command -v native-image || true)"
if [ -z "$native_image" ]; then
  if [ -n "${GRAALVM_HOME:-}" ] && [ -x "$GRAALVM_HOME/bin/native-image" ]; then
    native_image="$GRAALVM_HOME/bin/native-image"
  else
    echo "native-image not found. Install GraalVM and put native-image on PATH, or set GRAALVM_HOME." >&2
    exit 1
  fi
fi

mkdir -p "$CLASSES"

# 1. Compile the enso Java sources into target/classes.
(cd "$ROOT" && clojure -T:build javac)

# 2. Classpath: enso and Clojure plus the graal-build-time feature, resolved
#    from $ROOT so the relative target/classes entry points at the sources.
cd "$ROOT"
classpath="$(clojure -Spath -Sdeps "{:deps {com.github.clj-easy/graal-build-time {:mvn/version \"1.0.5\"}}}")"
classpath="$classpath:$HERE/src:$CLASSES"

# 3. AOT-compile the entrypoint; requiring it compiles s-exp.enso too.
java -cp "$classpath" -Dclojure.compile.path="$CLASSES" \
  clojure.main -e "(compile 'example.server)"

# 4. Link the native image. graal-build-time initialises Clojure's classes at
#    build time; enso's namespace builds a few Java objects as it loads, so its
#    Java packages initialise at build time as well.
"$native_image" \
  -cp "$classpath" \
  --no-fallback \
  --features=clj_easy.graal_build_time.InitClojureClasses \
  --initialize-at-build-time=example.server,com.s_exp.enso \
  -o "$OUT/enso-native" \
  example.server

echo
echo "built $OUT/enso-native"
echo "run it: $OUT/enso-native [port]"

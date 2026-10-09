#!/bin/sh
# ABOUTME: Builds the static libquiche + libenso_quiche for Linux inside a baseline container
# ABOUTME: (AlmaLinux 8 for glibc 2.28, Alpine for musl) and runs check-shim.sh on the result.
#
# Usage (from the repository root, inside the container):
#   native/enso_quiche/build-linux.sh gnu|musl
#
# Pins (quiche commit, Rust toolchain) come from native/enso_quiche/pins.env;
# libquiche is built by build-libquiche.sh in quiche-src/ (reused when a
# cached copy matches). The shim lands in target/native/linux-<arch>/ (gnu)
# or target/native/linux-musl-<arch>/ (musl).

set -eu

LIBC="$1"
# shellcheck source=pins.env
. ./native/enso_quiche/pins.env

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

case "$LIBC" in
  gnu)
    dnf install -y -q gcc gcc-c++ make cmake clang clang-devel llvm-devel perl python3 git \
      java-21-openjdk-devel binutils file which findutils diffutils gcc-toolset-12-gcc
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
    # GCC 12 for the shim's hardening flags (-mbranch-protection needs 9+);
    # it still links against the system glibc 2.28.
    SHIM_CC=/opt/rh/gcc-toolset-12/root/usr/bin/gcc
    CLASSIFIER="linux-$ARCH"
    # The oldest glibc the shim may require: this container's.
    GLIBC_MAX="$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')"
    export GLIBC_MAX
    ;;
  musl)
    # openjdk21: jni.h for the build and a JVM for the load test (the
    # shim's JNI ABI is stable across JDK versions).
    apk add --no-cache bash build-base cmake clang clang-dev llvm-dev perl python3 pkgconf \
      openjdk21 curl git linux-headers binutils file diffutils
    export JAVA_HOME=/usr/lib/jvm/default-jvm
    CLASSIFIER="linux-musl-$ARCH"
    SHIM_CC=cc
    # bindgen (used by boring-sys) dlopens libclang, which a static musl
    # build script cannot do: link build scripts and the final artifact
    # dynamically against musl libc.so instead.
    export RUSTFLAGS="-C target-feature=-crt-static"
    LIBCLANG_PATH="$(dirname "$(find /usr/lib -name 'libclang.so*' | head -1)")"
    export LIBCLANG_PATH
    ;;
  *) echo "usage: $0 gnu|musl" >&2; exit 1 ;;
esac
export PATH="$JAVA_HOME/bin:$PATH"

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" --profile minimal --no-modify-path
export PATH="$HOME/.cargo/bin:$PATH"

sh native/enso_quiche/build-libquiche.sh /tmp/quiche

make -C native/enso_quiche CC="$SHIM_CC" QUICHE_STATIC=1 \
  QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib
if [ "$CLASSIFIER" != "linux-$ARCH" ]; then
  rm -rf "target/native/$CLASSIFIER"
  mv "target/native/linux-$ARCH" "target/native/$CLASSIFIER"
fi

bash native/enso_quiche/check-shim.sh "target/native/$CLASSIFIER/libenso_quiche.so" "$CLASSIFIER"

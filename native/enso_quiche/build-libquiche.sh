#!/bin/sh
# ABOUTME: Fetches cloudflare/quiche at the pinned commit, applies native/enso_quiche/patches/ and builds
# ABOUTME: the static libquiche.a with the checked-in lockfile and pinned toolchain; stages archive and header.
#
# Usage (from the repository root): native/enso_quiche/build-libquiche.sh [STAGE_DIR]
#
# Pins come from native/enso_quiche/pins.env. The patches in
# native/enso_quiche/patches/ (applied in name order) add what the shim
# uses beyond stock quiche; the shim also runs on a stock libquiche
# without those features (see doc/build.md). The build lives in quiche-src/
# and is reused while quiche-src/.enso-build-key matches the commit,
# lockfile, patches, toolchain, platform, distribution and RUSTFLAGS (so a
# cached quiche-src/ is safe to restore). STAGE_DIR (default /tmp/quiche) receives lib/libquiche.a
# and include/quiche.h, as the Makefile's QUICHE_LIB_DIR / QUICHE_INCLUDE_DIR.

set -eu

STAGE="${1:-/tmp/quiche}"
PINS=native/enso_quiche/pins.env
LOCK=native/enso_quiche/quiche-Cargo.lock
PATCHES=native/enso_quiche/patches
# shellcheck source=pins.env
. "./$PINS"

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$@" | cut -d' ' -f1; }
else
  sha() { shasum -a 256 "$@" | cut -d' ' -f1; }
fi
lock_sha="$(sha "$LOCK")"
patches_sha="$(cat "$PATCHES"/*.patch | sha)"
# shellcheck disable=SC1091
distro="$( (. /etc/os-release 2>/dev/null && echo "$ID-$VERSION_ID") || true)"
KEY="$QUICHE_COMMIT $lock_sha $patches_sha $RUST_TOOLCHAIN $(uname -s)-$(uname -m) $distro ${RUSTFLAGS:-}"

if [ ! -f quiche-src/target/release/libquiche.a ] || [ "$(cat quiche-src/.enso-build-key 2>/dev/null)" != "$KEY" ]; then
  rm -rf quiche-src
  git init -q quiche-src
  git -C quiche-src fetch -q --depth 1 https://github.com/cloudflare/quiche.git "$QUICHE_COMMIT"
  git -C quiche-src checkout -q FETCH_HEAD
  if ! grep -qx "version = \"$QUICHE_VERSION\"" quiche-src/quiche/Cargo.toml; then
    echo "commit $QUICHE_COMMIT is not quiche $QUICHE_VERSION" >&2
    exit 1
  fi
  for p in "$PATCHES"/*.patch; do
    git -C quiche-src apply "$PWD/$p"
  done
  cp "$LOCK" quiche-src/Cargo.lock
  # -p quiche --lib: libquiche.a only. The workspace's datagram-socket
  # crate is not part of it and does not build on musl.
  (cd quiche-src && MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
    cargo "+$RUST_TOOLCHAIN" build --release --locked -p quiche --lib --features ffi,pkg-config-meta)
  echo "$KEY" > quiche-src/.enso-build-key
fi

mkdir -p "$STAGE/lib" "$STAGE/include"
cp quiche-src/target/release/libquiche.a "$STAGE/lib/"
cp quiche-src/quiche/include/quiche.h "$STAGE/include/"
echo "libquiche $QUICHE_VERSION ($QUICHE_COMMIT, patched) staged in $STAGE"

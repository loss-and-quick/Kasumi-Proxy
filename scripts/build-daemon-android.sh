#!/usr/bin/env bash
# Cross-build the Rust daemon (kasumi-proxy) for the Android module via cargo-ndk,
# placing the per-ABI binaries where the module bundle expects them.
#
# Requires: cargo-ndk, a Rust toolchain WITH the android std targets
# (aarch64-linux-android, x86_64-linux-android), and NDK_ROOT pointing at an NDK.
# The flake's `build-daemon-android` app wires these; see flake.nix.
set -euo pipefail

ROOT="${PROJECT_ROOT:-$PWD}"
BIN="$ROOT/module/bin"
: "${NDK_ROOT:?set NDK_ROOT to an Android NDK}"
export ANDROID_NDK_HOME="$NDK_ROOT"

mkdir -p "$BIN/arm64-v8a" "$BIN/x86_64"

# cargo-ndk selects the right clang linker per target from the NDK.
cargo ndk -t arm64-v8a -t x86_64 build --release -p kasumi-daemon --bin kasumi-proxy

cp -f target/aarch64-linux-android/release/kasumi-proxy "$BIN/arm64-v8a/kasumi-proxy"
cp -f target/x86_64-linux-android/release/kasumi-proxy "$BIN/x86_64/kasumi-proxy"
chmod 755 "$BIN/arm64-v8a/kasumi-proxy" "$BIN/x86_64/kasumi-proxy"

echo "✓ kasumi-proxy → module/bin/{arm64-v8a,x86_64}/"

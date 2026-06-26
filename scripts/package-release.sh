#!/usr/bin/env bash
# ============================================================
# scripts/package-release.sh
# Produce an installable Magisk module zip:
#   1. fetch cores + build geodat2srs into bin/ (not in git)
#   2. cross-build the Rust daemon (kasumi-proxy) per arch
#   3. build the React UI into webroot/
#   4. zip the module payload
#
# Needs Go (geodat2srs) + the android Rust toolchain/cargo-ndk + NDK_ROOT; the
# flake's `package-release` app wires all of these. Does not require nix.
#
# Usage: scripts/package-release.sh [output.zip]
# ============================================================
set -euo pipefail

# Honour PROJECT_ROOT (else the repo root) so the script can run from anywhere.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

OUT="${1:-$ROOT/build/$("$ROOT/scripts/artifact-name.sh" module)}"

echo "→ [1/4] Fetching cores + geodat2srs…"
if [ ! -f "$ROOT/module/bin/arm64-v8a/xray" ] || [ ! -f "$ROOT/module/bin/arm64-v8a/geodat2srs" ] || [ "${FORCE_FETCH:-0}" = "1" ]; then
	bash "$ROOT/scripts/fetch-binaries.sh" android
else
	echo "  bin/ already populated (set FORCE_FETCH=1 to re-download)"
fi

echo "→ [2/4] Cross-building the Rust daemon…"
# Always rebundled: it is our own code and must match the working tree. Needs a
# Rust toolchain carrying the android std targets + cargo-ndk + NDK_ROOT; the
# flake's `build-daemon-android` app wires these (nix run .#build-daemon-android,
# or nix run .#package-release which exports NDK_ROOT).
bash "$ROOT/scripts/build-daemon-android.sh"

echo "→ [3/4] Building the web UI → webroot/…"
bash "$ROOT/scripts/build-webroot.sh"

echo "→ [4/4] Packaging module zip…"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# Zip from inside module/ so its contents land at the archive root (where
# Magisk expects module.prop, customize.sh, META-INF/…). The webroot React
# build and bin/* binaries are produced by the steps above.
#
# Pack by directory/glob plus an explicit allowlist of named top-level files:
# whole bin/ (cores + kasumi-proxy + licenses), whole webroot/, every top-level
# *.sh, module.prop, logo.png (the action/webui icon referenced by module.prop)
# and META-INF. A new *.sh ships automatically; any other new top-level file
# (like logo.png) must be added here. AGENTS.md (dev doc) is intentionally left
# out by not matching.
(cd "$ROOT/module" && zip -r -q "$OUT" \
	META-INF bin webroot \
	module.prop logo.png ./*.sh \
	-x '*.DS_Store')

echo "✅ Release zip: $OUT"
echo "   $(du -h "$OUT" | cut -f1)"

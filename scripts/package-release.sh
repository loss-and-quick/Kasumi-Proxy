#!/usr/bin/env bash
# ============================================================
# scripts/package-release.sh
# Produce an installable Magisk module zip:
#   1. build geodat2srs for Android
#   2. fetch core binaries into bin/ (not in git)
#   3. cross-build the Rust daemon (kasumi-proxy) per arch
#   4. build the React UI into webroot/
#   5. zip the module payload
#
# Usage: scripts/package-release.sh [output.zip]
# ============================================================
set -euo pipefail

# Honour PROJECT_ROOT (else the repo root) so the script can run from anywhere.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

OUT="${1:-$ROOT/build/$("$ROOT/scripts/artifact-name.sh" module)}"

echo "→ [1/5] Building geodat2srs…"
if [ ! -f "$ROOT/module/bin/arm64-v8a/geodat2srs" ] || [ "${FORCE_FETCH:-0}" = "1" ]; then
	GEODAT2SRS_SRC="${GEODAT2SRS_SRC:-$ROOT/.cache/geodat2srs}"
	if [ ! -d "$GEODAT2SRS_SRC" ]; then
		git clone https://github.com/loss-and-quick/geodat2srs.git "$GEODAT2SRS_SRC"
	fi
	(
		cd "$GEODAT2SRS_SRC"
		NDK_HOST=$(uname -m | sed 's/x86_64/linux-x86_64/;s/aarch64/linux-aarch64/')
		if [ -n "${NDK_ROOT:-}" ] && [ -d "${NDK_ROOT:-}" ]; then
			CC_ARM64="$NDK_ROOT/toolchains/llvm/prebuilt/$NDK_HOST/bin/aarch64-linux-android35-clang"
			CC_AMD64="$NDK_ROOT/toolchains/llvm/prebuilt/$NDK_HOST/bin/x86_64-linux-android35-clang"
			CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC_ARM64" go build -o "$ROOT/module/bin/arm64-v8a/geodat2srs" .
			CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$CC_AMD64" go build -o "$ROOT/module/bin/x86_64/geodat2srs" .
		else
			echo "  NDK_ROOT not set, falling back to CGO_ENABLED=0"
			CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o "$ROOT/module/bin/arm64-v8a/geodat2srs" .
			CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$ROOT/module/bin/x86_64/geodat2srs" .
		fi
	)
	chmod 755 "$ROOT/module/bin/arm64-v8a/geodat2srs" "$ROOT/module/bin/x86_64/geodat2srs"
else
	echo "  geodat2srs already built (set FORCE_FETCH=1 to rebuild)"
fi

echo "→ [2/5] Fetching core binaries…"
if [ ! -f "$ROOT/module/bin/arm64-v8a/xray" ] || [ ! -f "$ROOT/module/bin/arm64-v8a/sing-box" ] || [ "${FORCE_FETCH:-0}" = "1" ]; then
	bash "$ROOT/scripts/fetch-cores-android.sh"
else
	echo "  bin/ already populated (set FORCE_FETCH=1 to re-download)"
fi

echo "→ [3/5] Cross-building the Rust daemon…"
# Always rebundled: it is our own code and must match the working tree. Needs a
# Rust toolchain carrying the android std targets + cargo-ndk + NDK_ROOT; the
# flake's `build-daemon-android` app wires these (nix run .#build-daemon-android,
# or nix run .#package-release which exports NDK_ROOT).
bash "$ROOT/scripts/build-daemon-android.sh"

echo "→ [4/5] Building the web UI → webroot/…"
bash "$ROOT/scripts/build-webroot.sh"

echo "→ [5/5] Packaging module zip…"
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

#!/usr/bin/env bash
# ============================================================
# scripts/package-release.sh
# Produce an installable Magisk module zip:
#   1. build geodat2srs for Android
#   2. fetch core binaries into bin/ (not in git)
#   3. build the React control center into webroot/
#   4. zip the module payload
#
# Usage: scripts/package-release.sh [output.zip]
# ============================================================
set -euo pipefail

# Honour PROJECT_ROOT so the flake `nix run` wrapper can point us at the user's
# working tree — $0 there resolves into the read-only /nix/store copy.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

OUT="${1:-$ROOT/build/kasumi-proxy-$(grep -m1 '^version=' module/module.prop | cut -d= -f2).zip}"

echo "→ [1/4] Building geodat2srs…"
if [ ! -f "$ROOT/module/bin/arm64-v8a/geodat2srs" ] || [ "${FORCE_FETCH:-0}" = "1" ]; then
	GEODAT2SRS_SRC="${GEODAT2SRS_SRC:-$HOME/geodat2srs}"
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

echo "→ [2/4] Fetching core binaries…"
if [ ! -f "$ROOT/module/bin/arm64-v8a/xray" ] || [ ! -f "$ROOT/module/bin/arm64-v8a/sing-box" ] || [ "${FORCE_FETCH:-0}" = "1" ]; then
	bash "$ROOT/scripts/fetch-bin.sh"
else
	echo "  bin/ already populated (set FORCE_FETCH=1 to re-download)"
fi

echo "→ [3/4] Building control center → webroot/…"
bash "$ROOT/scripts/build-webroot.sh"

echo "→ [4/4] Packaging module zip…"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# Zip from inside module/ so its contents land at the archive root (where
# Magisk expects module.prop, customize.sh, META-INF/…). The webroot React
# build and bin/* cores are produced by the steps above.
#
# Pack by directory/glob, not a per-file allowlist: whole bin/ (cores +
# kasumi-proxyctl + utils.sh + licenses), whole webroot/, every top-level
# *.sh, module.prop and META-INF. Adding a payload file ships it automatically;
# only AGENTS.md (dev doc) is intentionally left out by not matching the globs.
(cd "$ROOT/module" && zip -r -q "$OUT" \
	META-INF bin webroot \
	module.prop ./*.sh \
	-x '*.DS_Store')

echo "✅ Release zip: $OUT"
echo "   $(du -h "$OUT" | cut -f1)"

#!/usr/bin/env bash
# ============================================================
# scripts/fetch-cores-android.sh
# Download the core binaries (xray, tun2socks).
#
# These binaries are intentionally NOT committed to git (see
# .gitignore). Run this once before building a release zip.
#
# Usage:
#   scripts/fetch-cores-android.sh            # fetch pinned versions
#   XRAY_VERSION=v25.5.16 scripts/fetch-cores-android.sh
# ============================================================
set -euo pipefail

# ---- pinned versions (single source of truth; override via env) ----
# shellcheck source=scripts/core-versions.sh
. "$(dirname "$0")/core-versions.sh"

# Honour PROJECT_ROOT so the flake `nix run` wrapper can point us at the user's
# working tree — $0 there resolves into the read-only /nix/store copy.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
BIN="$ROOT/module/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || {
	echo "❌ missing dependency: $1" >&2
	exit 1
}; }
need curl
need unzip
need tar

dl() { # dl <url> <out>
	echo "  ↓ $1"
	curl -fL --retry 3 -o "$2" "$1"
}

mkdir -p "$BIN/arm64-v8a" "$BIN/x86_64"

# ---- Xray-core (binary bundled in the Android zips) ----
XRAY_BASE="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION"

echo "→ Xray-core $XRAY_VERSION (arm64-v8a)"
dl "$XRAY_BASE/Xray-android-arm64-v8a.zip" "$TMP/xray-arm64.zip"
unzip -o -j "$TMP/xray-arm64.zip" xray -d "$BIN/arm64-v8a" >/dev/null

echo "→ Xray-core $XRAY_VERSION (x86_64)"
dl "$XRAY_BASE/Xray-android-amd64.zip" "$TMP/xray-amd64.zip"
unzip -o -j "$TMP/xray-amd64.zip" xray -d "$BIN/x86_64" >/dev/null

# ---- tun2socks (xjasonlyu/tun2socks; flags match service.sh) ----
# No dedicated "android" build: tun2socks ships static Go binaries, so Android
# uses the linux-<arch> artifacts (linux-arm64 on devices, linux-amd64 on x86).
T2S_BASE="https://github.com/xjasonlyu/tun2socks/releases/download/$TUN2SOCKS_VERSION"

# Copy the single tun2socks binary out of an extracted archive. Take the first
# match only — `find -exec cp` would silently clobber on multiple hits.
copy_one() { # <search-dir> <name-glob> <dest>
	src=$(find "$1" -type f -name "$2" | head -n1)
	[ -n "$src" ] || {
		echo "❌ no match for '$2' under $1" >&2
		exit 1
	}
	cp "$src" "$3"
}

echo "→ tun2socks $TUN2SOCKS_VERSION (linux-arm64 → arm64-v8a)"
dl "$T2S_BASE/tun2socks-linux-arm64.zip" "$TMP/t2s-arm64.zip"
unzip -o -j "$TMP/t2s-arm64.zip" -d "$TMP/t2s-arm64" >/dev/null
copy_one "$TMP/t2s-arm64" 'tun2socks*' "$BIN/arm64-v8a/tun2socks"

echo "→ tun2socks $TUN2SOCKS_VERSION (linux-amd64 → x86_64)"
dl "$T2S_BASE/tun2socks-linux-amd64.zip" "$TMP/t2s-amd64.zip"
unzip -o -j "$TMP/t2s-amd64.zip" -d "$TMP/t2s-amd64" >/dev/null
copy_one "$TMP/t2s-amd64" 'tun2socks*' "$BIN/x86_64/tun2socks"

# ---- sing-box (SagerNet/sing-box; second core for Hysteria2/TUIC) ----
# Assets are .tar.gz; version in the filename has no leading 'v'.
SINGBOX_BASE="https://github.com/SagerNet/sing-box/releases/download/$SINGBOX_VERSION"
SB_VER="${SINGBOX_VERSION#v}"

echo "→ sing-box $SINGBOX_VERSION (android-arm64)"
dl "$SINGBOX_BASE/sing-box-$SB_VER-android-arm64.tar.gz" "$TMP/sb-arm64.tgz"
mkdir -p "$TMP/sb-arm64"
tar -xzf "$TMP/sb-arm64.tgz" -C "$TMP/sb-arm64"
copy_one "$TMP/sb-arm64" 'sing-box' "$BIN/arm64-v8a/sing-box"

echo "→ sing-box $SINGBOX_VERSION (android-amd64)"
dl "$SINGBOX_BASE/sing-box-$SB_VER-android-amd64.tar.gz" "$TMP/sb-amd64.tgz"
mkdir -p "$TMP/sb-amd64"
tar -xzf "$TMP/sb-amd64.tgz" -C "$TMP/sb-amd64"
copy_one "$TMP/sb-amd64" 'sing-box' "$BIN/x86_64/sing-box"

chmod 755 "$BIN/arm64-v8a/xray" "$BIN/arm64-v8a/tun2socks" "$BIN/arm64-v8a/sing-box" \
	"$BIN/x86_64/xray" "$BIN/x86_64/tun2socks" "$BIN/x86_64/sing-box"

echo "✅ Done. bin/ populated:"
for f in arm64-v8a/xray arm64-v8a/tun2socks arm64-v8a/sing-box x86_64/xray x86_64/tun2socks x86_64/sing-box; do
	if [ -f "$BIN/$f" ]; then
		printf '   %-24s %s\n' "$f" "$(du -h "$BIN/$f" | cut -f1)"
	else
		echo "   ⚠️  missing: $f"
	fi
done

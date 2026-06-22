#!/usr/bin/env bash
# ============================================================
# scripts/fetch-cores-desktop.sh
# Download the desktop core binaries (xray, sing-box, tun2socks) for one Tauri
# target and stage them under src-tauri/binaries/ with the target-triple suffix
# that `bundle.externalBin` expects, e.g.
#   src-tauri/binaries/xray-x86_64-unknown-linux-gnu
#   src-tauri/binaries/xray-x86_64-pc-windows-msvc.exe
# Tauri strips the suffix when bundling, so each lands next to the app exe where
# the desktop Platform finds it (`dir_of(exe)`).
#
# These binaries are intentionally NOT committed to git (see .gitignore). Run
# this before `cargo tauri build` (the CI desktop job calls it per runner).
#
# Usage:
#   scripts/fetch-cores-desktop.sh [target-triple]   # default: host triple
#   scripts/fetch-cores-desktop.sh x86_64-pc-windows-msvc
# ============================================================
set -euo pipefail

# ---- pinned versions (single source of truth; override via env) ----
# shellcheck source=scripts/core-versions.sh
. "$(dirname "$0")/core-versions.sh"

ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT="$ROOT/src-tauri/binaries"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ missing dependency: $1" >&2; exit 1; }; }
need curl
need unzip
need tar

# Resolve the target triple (default to the host's, as rustc reports it).
TARGET="${1:-$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')}"
[ -n "$TARGET" ] || { echo "❌ no target triple given and rustc not on PATH" >&2; exit 1; }

# Map the triple → the per-core release asset slugs + the bundle file extension.
case "$TARGET" in
	x86_64-unknown-linux-gnu)
		XRAY_ASSET="Xray-linux-64.zip"
		T2S_ASSET="tun2socks-linux-amd64.zip"
		SB_ASSET="sing-box-%s-linux-amd64.tar.gz"; SB_KIND="tgz"
		CRONET_LIB="libcronet.so"
		EXT="" ;;
	x86_64-pc-windows-msvc)
		XRAY_ASSET="Xray-windows-64.zip"
		T2S_ASSET="tun2socks-windows-amd64.zip"
		SB_ASSET="sing-box-%s-windows-amd64.zip"; SB_KIND="zip"
		CRONET_LIB="libcronet.dll"
		EXT=".exe" ;;
	*)
		echo "❌ unsupported desktop target: $TARGET" >&2
		echo "   supported: x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc" >&2
		exit 1 ;;
esac

mkdir -p "$OUT"

dl() { echo "  ↓ $1"; curl -fL --retry 3 -o "$2" "$1"; }

# Take the first match only — `find -exec cp` would silently clobber on multiple hits.
copy_one() { # <search-dir> <name-glob> <dest>
	local src
	src=$(find "$1" -type f -name "$2" | head -n1)
	[ -n "$src" ] || { echo "❌ no match for '$2' under $1" >&2; exit 1; }
	cp "$src" "$3"
}

echo "→ desktop cores for $TARGET"

# ---- Xray-core ----
dl "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$XRAY_ASSET" "$TMP/xray.zip"
unzip -o -j "$TMP/xray.zip" "xray$EXT" -d "$TMP/xray" >/dev/null
cp "$TMP/xray/xray$EXT" "$OUT/xray-$TARGET$EXT"

# ---- tun2socks ----
dl "https://github.com/xjasonlyu/tun2socks/releases/download/$TUN2SOCKS_VERSION/$T2S_ASSET" "$TMP/t2s.zip"
unzip -o -j "$TMP/t2s.zip" -d "$TMP/t2s" >/dev/null
copy_one "$TMP/t2s" "tun2socks*" "$OUT/tun2socks-$TARGET$EXT"

# ---- sing-box ----
SB_VER="${SINGBOX_VERSION#v}"
# shellcheck disable=SC2059
SB_FILE="$(printf "$SB_ASSET" "$SB_VER")"
dl "https://github.com/SagerNet/sing-box/releases/download/$SINGBOX_VERSION/$SB_FILE" "$TMP/sb.$SB_KIND"
mkdir -p "$TMP/sb"
if [ "$SB_KIND" = "tgz" ]; then
	tar -xzf "$TMP/sb.$SB_KIND" -C "$TMP/sb"
else
	unzip -o "$TMP/sb.$SB_KIND" -d "$TMP/sb" >/dev/null
fi
copy_one "$TMP/sb" "sing-box$EXT" "$OUT/sing-box-$TARGET$EXT"

# ---- libcronet (sing-box naive outbound) ----
# sing-box is a purego build that dlopen()s libcronet from the sing-box binary's
# own directory at runtime; without it every naive profile fails to initialise
# (`cronet: library not found`). It ships inside the sing-box release archive, so
# stage it next to sing-box — no target suffix (it's loaded by name, like wintun).
copy_one "$TMP/sb" "$CRONET_LIB" "$OUT/$CRONET_LIB"

# ---- wintun (Windows only) ----
# tun2socks loads wintun.dll from its own directory (the xray data-path needs it).
# sing-box embeds its own copy, so this is only for the tun2socks path. Staged
# WITHOUT a target suffix: it ships as a Tauri bundle *resource* placed next to the
# app exe, not as an externalBin sidecar (those only handle executables + add .exe).
if [ -n "$EXT" ]; then
	dl "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" "$TMP/wintun.zip"
	mkdir -p "$TMP/wintun"
	unzip -o "$TMP/wintun.zip" -d "$TMP/wintun" >/dev/null
	# Release zip lays out wintun/bin/<arch>/wintun.dll for amd64/arm64/x86/arm —
	# scope the search to amd64 so we don't pick another arch's DLL.
	copy_one "$TMP/wintun/wintun/bin/amd64" "wintun.dll" "$OUT/wintun.dll"
fi

[ -n "$EXT" ] || chmod 755 "$OUT/xray-$TARGET" "$OUT/tun2socks-$TARGET" "$OUT/sing-box-$TARGET"

echo "✅ staged → src-tauri/binaries/ (suffix $TARGET$EXT):"
for c in xray sing-box tun2socks; do
	f="$OUT/$c-$TARGET$EXT"
	[ -f "$f" ] && printf '   %-12s %s\n' "$c" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: $c"
done
{ f="$OUT/$CRONET_LIB"; [ -f "$f" ] && printf '   %-12s %s\n' "$CRONET_LIB" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: $CRONET_LIB"; }
[ -z "$EXT" ] || { f="$OUT/wintun.dll"; [ -f "$f" ] && printf '   %-12s %s\n' "wintun.dll" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: wintun.dll"; }

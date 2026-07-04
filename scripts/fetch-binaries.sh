#!/usr/bin/env bash
# ============================================================
# scripts/fetch-binaries.sh
# Download the proxy core binaries (xray, sing-box, tun2socks, hev-socks5-tunnel)
# for one platform
# and stage them where the build expects, plus the build's other binaries. Two modes:
#
#   fetch-binaries.sh android
#     → module/bin/{arm64-v8a,x86_64}/<binary>        (Magisk module payload)
#
#   fetch-binaries.sh desktop [target-triple]         (default: host triple)
#     → src-tauri/binaries/<binary>-<triple>[.exe]    (Tauri externalBin sidecars)
#       plus the desktop-only extras next to the cores: libcronet (sing-box naive
#       outbound), wintun.dll (Windows tun2socks), msys-2.0.dll (Windows hev), and
#       geodat2srs (built from source at the pinned GEODAT2SRS_REV — it ships no
#       release artifacts).
#
# The prebuilt cores' release-asset layout is read from scripts/binaries.json (the
# single source of truth, shared with nix/binaries.nix and update-binary-hashes.sh);
# versions come from scripts/binary-versions.sh. These binaries are NOT committed
# (.gitignore).
#
# Honours PROJECT_ROOT so the flake `nix run` wrapper can point at the caller's
# working tree (the in-store $0 copy is read-only).
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/binary-versions.sh
. "$HERE/binary-versions.sh"
CATALOG="$HERE/binaries.json"
ROOT="${PROJECT_ROOT:-$(cd "$HERE/.." && pwd)}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || {
	echo "❌ missing dependency: $1" >&2
	exit 1
}; }
need curl
need jq
need unzip
need tar
need go # geodat2srs is built from source (both modes)

dl() {
	echo "  ↓ $1" >&2
	curl -fL --retry 3 -o "$2" "$1"
}

extract() { # <archive> <kind:zip|tgz> <destdir>
	mkdir -p "$3"
	case "$2" in
	zip) unzip -o -q "$1" -d "$3" ;;
	tgz) tar -xzf "$1" -C "$3" ;;
	*)
		echo "❌ unknown archive kind: $2" >&2
		exit 1
		;;
	esac
}

# First file matching the member glob (or member+.exe on Windows). head -1 because
# a blind `find -exec cp` would silently clobber on multiple hits.
locate() { # <dir> <member-glob> <ext>
	local src
	src=$(find "$1" -type f \( -name "$2" -o -name "$2$3" \) | head -n1)
	[ -n "$src" ] || {
		echo "❌ no match for '$2' under $1" >&2
		exit 1
	}
	printf '%s' "$src"
}

# Download + extract the core's archive for <arch> into $TMP/<core>-<arch>/, then
# copy the located binary to <dest>. A 'raw' asset IS the binary — downloaded
# straight to <dest>, nothing to extract. Echoes the extract dir (sing-box's holds
# libcronet and hev's win64 zip holds msys-2.0.dll, which the desktop path stages
# too).
stage_core() { # <core> <arch> <dest> <ext>
	local core="$1" arch="$2" dest="$3" ext="$4"
	local repo vvar member file archive tag ver url dir
	repo=$(jq -r --arg c "$core" '.[$c].repo' "$CATALOG")
	vvar=$(jq -r --arg c "$core" '.[$c].version_var' "$CATALOG")
	member=$(jq -r --arg c "$core" '.[$c].member' "$CATALOG")
	file=$(jq -r --arg c "$core" --arg a "$arch" '.[$c].assets[$a].file' "$CATALOG")
	archive=$(jq -r --arg c "$core" --arg a "$arch" '.[$c].assets[$a].archive' "$CATALOG")
	tag="${!vvar}"
	ver="${tag#v}"
	file="${file//\{ver\}/$ver}"
	url="https://github.com/$repo/releases/download/$tag/$file"
	dir="$TMP/$core-$arch"
	if [ "$archive" = "raw" ]; then
		dl "$url" "$dest"
	else
		dl "$url" "$dir.ar"
		extract "$dir.ar" "$archive" "$dir"
		cp "$(locate "$dir" "$member" "$ext")" "$dest"
	fi
	printf '%s' "$dir"
}

# geodat2srs ships no release artifacts → build from source at the pinned rev.
# CGO_ENABLED=0 keeps it static and lets the host Go cross-compile any GOARCH
# with no NDK. The source tarball is fetched + extracted once, then reused.
G2S_SRC=""
build_geodat2srs() { # <goos> <goarch> <dest>
	if [ -z "$G2S_SRC" ]; then
		echo "• building geodat2srs (rev ${GEODAT2SRS_REV})" >&2
		dl "https://github.com/loss-and-quick/geodat2srs/archive/${GEODAT2SRS_REV}.tar.gz" "$TMP/g2s.tar.gz"
		extract "$TMP/g2s.tar.gz" tgz "$TMP/g2s"
		G2S_SRC=$(find "$TMP/g2s" -mindepth 1 -maxdepth 1 -type d | head -1)
		[ -n "$G2S_SRC" ] || {
			echo "❌ geodat2srs source not found" >&2
			exit 1
		}
	fi
	(cd "$G2S_SRC" && CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -o "$3" .)
}

CORES="xray tun2socks sing-box hev-socks5-tunnel"

fetch_android() {
	local out="$ROOT/module/bin"
	echo "→ android binaries → module/bin/"
	# abi (module dir) : catalog arch : Go GOARCH (geodat2srs is a static linux
	# cross — runs root-invoked on the rooted device).
	for triple in "arm64-v8a:android-arm64:arm64" "x86_64:android-amd64:amd64"; do
		local abi="${triple%%:*}" rest="${triple#*:}"
		local arch="${rest%%:*}" goarch="${rest##*:}"
		mkdir -p "$out/$abi"
		for core in $CORES; do
			stage_core "$core" "$arch" "$out/$abi/$core" "" >/dev/null
		done
		build_geodat2srs linux "$goarch" "$out/$abi/geodat2srs"
		chmod 755 "$out/$abi"/xray "$out/$abi"/tun2socks "$out/$abi"/sing-box \
			"$out/$abi"/hev-socks5-tunnel "$out/$abi"/geodat2srs
	done
	echo "✅ module/bin/ populated:"
	for abi in arm64-v8a x86_64; do
		for core in $CORES geodat2srs; do
			local f="$out/$abi/$core"
			[ -f "$f" ] && printf '   %-22s %s\n' "$abi/$core" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: $abi/$core"
		done
	done
}

fetch_desktop() {
	local target="${1:-$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')}"
	[ -n "$target" ] || {
		echo "❌ no target triple given and rustc not on PATH" >&2
		exit 1
	}
	local arch ext cronet wintun g2s_goos g2s_goarch
	case "$target" in
	x86_64-unknown-linux-gnu)
		arch="linux-amd64" ext="" cronet="libcronet.so" wintun=0 g2s_goos="linux" g2s_goarch="amd64" ;;
	x86_64-pc-windows-msvc)
		arch="windows-amd64" ext=".exe" cronet="libcronet.dll" wintun=1 g2s_goos="windows" g2s_goarch="amd64" ;;
	*)
		echo "❌ unsupported desktop target: $target" >&2
		echo "   supported: x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc" >&2
		exit 1
		;;
	esac

	local out="$ROOT/src-tauri/binaries"
	mkdir -p "$out"
	echo "→ desktop binaries for $target"
	local sbdir="" hevdir=""
	for core in $CORES; do
		local d
		d=$(stage_core "$core" "$arch" "$out/$core-$target$ext" "$ext")
		[ "$core" = "sing-box" ] && sbdir="$d"
		[ "$core" = "hev-socks5-tunnel" ] && hevdir="$d"
	done

	# libcronet — sing-box dlopen()s it from its own dir for the naive outbound;
	# it ships inside the sing-box archive. No target suffix (loaded by name).
	cp "$(locate "$sbdir" "$cronet" "")" "$out/$cronet"

	# geodat2srs (no release artifacts — built from the pinned source).
	build_geodat2srs "$g2s_goos" "$g2s_goarch" "$out/geodat2srs-$target$ext"

	# wintun.dll (Windows only) — tun2socks dlopen()s it from its dir. Staged
	# WITHOUT a target suffix: it's a Tauri bundle resource, not an externalBin.
	if [ "$wintun" = 1 ]; then
		dl "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" "$TMP/wintun.zip"
		extract "$TMP/wintun.zip" zip "$TMP/wintun"
		cp "$(locate "$TMP/wintun/wintun/bin/amd64" "wintun.dll" "")" "$out/wintun.dll"
		# msys-2.0.dll (Windows only) — the hev win64 build is msys2 and loads it
		# from its own directory. Staged from hev's zip WITHOUT a target suffix:
		# a Tauri bundle resource like wintun.dll. (hev's zip also carries its own
		# wintun.dll; the official one above wins.)
		cp "$(locate "$hevdir" "msys-2.0.dll" "")" "$out/msys-2.0.dll"
	fi

	[ -n "$ext" ] || chmod 755 "$out"/xray-"$target" "$out"/tun2socks-"$target" "$out"/sing-box-"$target" "$out"/hev-socks5-tunnel-"$target" "$out"/geodat2srs-"$target"

	echo "✅ staged → src-tauri/binaries/ (suffix $target$ext):"
	for c in xray sing-box tun2socks hev-socks5-tunnel geodat2srs; do
		local f="$out/$c-$target$ext"
		[ -f "$f" ] && printf '   %-12s %s\n' "$c" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: $c"
	done
	local f="$out/$cronet"
	[ -f "$f" ] && printf '   %-12s %s\n' "$cronet" "$(du -h "$f" | cut -f1)" || echo "   ⚠️  missing: $cronet"
	if [ "$wintun" = 1 ]; then
		for f in wintun.dll msys-2.0.dll; do
			[ -f "$out/$f" ] && printf '   %-12s %s\n' "$f" "$(du -h "$out/$f" | cut -f1)" || echo "   ⚠️  missing: $f"
		done
	fi
}

case "${1:-}" in
android) fetch_android ;;
desktop) shift; fetch_desktop "${1:-}" ;;
*)
	echo "usage: fetch-binaries.sh android | desktop [target-triple]" >&2
	exit 2
	;;
esac

#!/usr/bin/env bash
# ============================================================
# scripts/build-webroot.sh
# Build the control-center app and copy it into webroot/
# for Magisk module packaging / WebView serving.
# ============================================================
set -euo pipefail

# Honour PROJECT_ROOT so the flake `nix run` wrapper can point us at the user's
# working tree — $0 there resolves into the read-only /nix/store copy.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONTROL_CENTER="$ROOT/control-center"
WEBROOT="$ROOT/module/webroot"
DIST="$CONTROL_CENTER/dist"

echo "→ Building control-center..."
cd "$CONTROL_CENTER"

# Use whichever package manager is available
if command -v bun &>/dev/null; then
	bun run build
elif command -v pnpm &>/dev/null; then
	pnpm build
elif command -v npm &>/dev/null; then
	npm run build
else
	echo "❌ No package manager found (bun/pnpm/npm)"
	exit 1
fi

if [ ! -d "$DIST" ]; then
	echo "❌ Build did not produce dist/ directory"
	exit 1
fi

TMP_CGI="$(mktemp -d)"
trap 'rm -rf "$TMP_CGI"' EXIT

if [ -d "$WEBROOT/cgi-bin" ]; then
	echo "→ Preserving webroot/cgi-bin/..."
	cp -a "$WEBROOT/cgi-bin" "$TMP_CGI/"
fi

echo "→ Clearing old webroot/..."
find "$WEBROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

echo "→ Copying new build to webroot/..."
cp -a "$DIST"/* "$WEBROOT/"

if [ -d "$TMP_CGI/cgi-bin" ]; then
	echo "→ Restoring webroot/cgi-bin/..."
	mkdir -p "$WEBROOT"
	cp -a "$TMP_CGI/cgi-bin" "$WEBROOT/"
fi

# Ensure index.html is at the root
if [ -f "$WEBROOT/index.html" ]; then
	echo "✅ webroot/index.html ready"
else
	echo "⚠️  webroot/index.html not found — check dist output"
fi

echo "→ Done. webroot/ populated with $(find "$WEBROOT" -type f | wc -l) files."

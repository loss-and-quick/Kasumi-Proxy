#!/usr/bin/env bash
# ============================================================
# scripts/build-webroot.sh
# Build the frontend app and copy it into webroot/
# for Magisk module packaging / WebView serving.
# ============================================================
set -euo pipefail

# Honour PROJECT_ROOT (else the repo root) so the script can run from anywhere.
ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONTROL_CENTER="$ROOT/frontend"
WEBROOT="$ROOT/module/webroot"
DIST="$CONTROL_CENTER/dist"

echo "→ Building frontend..."
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

echo "→ Clearing old webroot/..."
mkdir -p "$WEBROOT"
find "$WEBROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

echo "→ Copying new build to webroot/..."
cp -a "$DIST"/* "$WEBROOT/"

# Ensure index.html is at the root
if [ -f "$WEBROOT/index.html" ]; then
	echo "✅ webroot/index.html ready"
else
	echo "⚠️  webroot/index.html not found — check dist output"
fi

echo "→ Done. webroot/ populated with $(find "$WEBROOT" -type f | wc -l) files."

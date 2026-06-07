#!/usr/bin/env bash
# ============================================================
# scripts/gen-update-json.sh
# Generate update.json from module/module.prop. Magisk / KernelSU
# poll the module's `updateJson` URL and offer an in-app update
# when the published versionCode is higher than the installed one.
#
# The zipUrl follows GitHub's deterministic release-asset path, so
# this can run before the release is actually published.
#
# Usage:
#   scripts/gen-update-json.sh                 # repo from $GITHUB_REPOSITORY
#   scripts/gen-update-json.sh owner/name      # explicit repo slug
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROP="$ROOT/module/module.prop"
OUT="$ROOT/update.json"

repo="${1:-${GITHUB_REPOSITORY:?repo slug required (owner/name or $GITHUB_REPOSITORY)}}"
server="${GITHUB_SERVER_URL:-https://github.com}"

ver="$(grep -m1 '^version=' "$PROP" | cut -d= -f2)"
code="$(grep -m1 '^versionCode=' "$PROP" | cut -d= -f2)"
# JSON forbids leading zeros — emit versionCode as a bare base-10 integer.
code="$((10#$code))"

cat >"$OUT" <<EOF
{
  "version": "${ver}",
  "versionCode": ${code},
  "zipUrl": "${server}/${repo}/releases/download/${ver}/kasumi-proxy-${ver}.zip"
}
EOF

echo "→ wrote $OUT (version=${ver} versionCode=${code})"

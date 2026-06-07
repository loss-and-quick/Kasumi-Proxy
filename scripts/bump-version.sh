#!/usr/bin/env bash
# ============================================================
# scripts/bump-version.sh
# Bump the patch version + versionCode in module/module.prop.
# Prints the new version tag (e.g. v0.0.2) to stdout so callers
# (CI, release scripts) can pick it up.
#
# Usage: scripts/bump-version.sh
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROP="$ROOT/module/module.prop"

cur_ver="$(grep -m1 '^version=' "$PROP" | cut -d= -f2)"      # e.g. v0.2.0
cur_code="$(grep -m1 '^versionCode=' "$PROP" | cut -d= -f2)" # e.g. 002

bump_type="${1:-minor}" # patch | minor

semver="${cur_ver#v}"
IFS='.' read -r major minor patch <<<"$semver"
case "$bump_type" in
patch) new_ver="v${major}.${minor}.$((patch + 1))" ;;
minor) new_ver="v${major}.$((minor + 1)).0" ;;
esac

new_code="$(printf '%03d' "$((10#$cur_code + 1))")"

sed -i.bak \
	-e "s/^version=.*/version=${new_ver}/" \
	-e "s/^versionCode=.*/versionCode=${new_code}/" \
	"$PROP"
rm -f "$PROP.bak"

echo "$new_ver"

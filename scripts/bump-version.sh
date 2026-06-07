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

cur_ver="$(grep -m1 '^version=' "$PROP" | cut -d= -f2)"        # e.g. v0.0.1
cur_code="$(grep -m1 '^versionCode=' "$PROP" | cut -d= -f2)"   # e.g. 001

# Split semver (strip leading v) and bump the patch component.
semver="${cur_ver#v}"
IFS='.' read -r major minor patch <<<"$semver"
new_ver="v${major}.${minor}.$((patch + 1))"

# versionCode: integer increment, keep the 3-digit zero padding.
# 10# forces base-10 so a leading zero (001) is not read as octal.
new_code="$(printf '%03d' "$((10#$cur_code + 1))")"

sed -i.bak \
	-e "s/^version=.*/version=${new_ver}/" \
	-e "s/^versionCode=.*/versionCode=${new_code}/" \
	"$PROP"
rm -f "$PROP.bak"

echo "$new_ver"

#!/usr/bin/env bash
# ============================================================
# scripts/artifact-name.sh
# Single source of truth for our release-artifact zip filenames. Given a
# variant, print "kasumi-proxy-<variant>-<version>.zip" with the version read
# verbatim from module/module.prop (its 'vX.Y.Z' form — no strip, so the Magisk
# updateJson URL resolves without massaging).
#
# Used by package-release.sh (the Android module zip's default name),
# gen-update-json.sh (the updateJson zipUrl, which MUST match the published
# asset or in-app updates 404), and the portable-zip steps in release.yml /
# nightly.yml — so the naming scheme lives in exactly one place.
#
# Variants: module | windows-portable | linux-portable
#
# Usage: scripts/artifact-name.sh <variant>
# ============================================================
set -euo pipefail

ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
variant="${1:?usage: artifact-name.sh <variant> (module|windows-portable|linux-portable)}"
ver="$(grep -m1 '^version=' "$ROOT/module/module.prop" | cut -d= -f2)"
echo "kasumi-proxy-${variant}-${ver}.zip"

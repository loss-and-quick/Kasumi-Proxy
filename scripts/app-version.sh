#!/usr/bin/env bash
# ============================================================
# scripts/app-version.sh
# Print the product version as a bare semver (no leading 'v'), read from the
# single source of truth: module/module.prop. The Android zip uses the prop's
# 'vX.Y.Z' form directly; cargo/tauri/npm need bare 'X.Y.Z', so this strips the
# 'v'. The desktop bundle steps feed this into `tauri build --config` so the
# .deb/.AppImage/.msi carry the real release version (the static versions in
# Cargo.toml/tauri.conf.json/flake.nix are 0.0.0 placeholders).
# ============================================================
set -euo pipefail

ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(grep -m1 '^version=' "$ROOT/module/module.prop" | cut -d= -f2)"
echo "${ver#v}"

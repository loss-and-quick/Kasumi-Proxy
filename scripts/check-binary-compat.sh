#!/usr/bin/env bash
# ============================================================
# scripts/check-binary-compat.sh
# Stage the desktop cores and run the config-validation harness against them, so a
# core version whose config schema drifted from our generators (a config the core
# now rejects) fails loudly. Used two ways:
#   - release.yml gates the auto-bump on it: a core bump that needs generator
#     changes blocks the release instead of shipping a broken build.
#   - core-compat.yml runs it on a schedule against the LATEST upstream cores for
#     early warning (opens a tracking issue) before the bump ever happens.
#
# Versions come from scripts/binary-versions.sh; override the ones under test with
# the usual env vars, e.g.
#   XRAY_VERSION=v26.4.0 SINGBOX_VERSION=v1.14.0 scripts/check-binary-compat.sh
#
# Usage:
#   scripts/check-binary-compat.sh [target-triple]   # default: host triple
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Stage xray / sing-box / tun2socks / libcronet for the target (honours the
# XRAY_VERSION / SINGBOX_VERSION / TUN2SOCKS_VERSION overrides via binary-versions.sh).
"$ROOT/scripts/fetch-binaries.sh" desktop "${1:-}"

# Run the harness with the staged cores present (it auto-detects them under
# src-tauri/binaries and validates every generated config against the real cores).
# A rejected config fails the test — and therefore this script.
cargo test --manifest-path "$ROOT/Cargo.toml" \
	-p kasumi-core --test core_validation -- --nocapture

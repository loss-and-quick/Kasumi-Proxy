# shellcheck shell=bash
# Single source of truth for the pinned binary versions, sourced by fetch-binaries.sh
# (and update-binary-hashes.sh / nix). Each value is overridable via the environment
# (the release workflow passes the upstream latest when bumping). release.yml/
# nightly.yml grep these defaults to detect upstream updates — keep the
# `NAME="${NAME:-vX}"` shape.
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
TUN2SOCKS_VERSION="${TUN2SOCKS_VERSION:-v2.7.0}"
# Alternative TUN engine (heiher/hev-socks5-tunnel). Selectable per core in
# Settings; pairs with a socks-only core. Tags have no leading 'v'.
HEV_VERSION="${HEV_VERSION:-2.15.0}"
# sing-box runs Hysteria2/TUIC profiles (second core). Pin a 1.13.x line whose
# config schema matches singbox_config.rs (mixed inbound, tls/utls, hysteria2/tuic).
SINGBOX_VERSION="${SINGBOX_VERSION:-v1.13.15}"
# geodat2srs converts geoip/geosite .dat → sing-box .srs rule-sets. Unlike the
# cores above it ships NO release artifacts — it is built from source at this rev
# (CGO off, static): scripts/fetch-binaries.sh builds it for both the Android module
# and the desktop Tauri/CI bundles, and the desktop `nix build` uses the matching
# buildGoModule derivation in nix/binaries.nix. It has no tags, so pin the commit on
# main directly. Its go.mod pins sing-box to the same line as SINGBOX_VERSION —
# bump them together.
GEODAT2SRS_REV="${GEODAT2SRS_REV:-abe704106a1ebafa5e9fedfaa3417a9d73702491}"

# Windows only: the wintun driver DLL that sing-box (tun inbound) and tun2socks
# both dlopen from the app directory. Bundled next to the cores on the Windows
# target; unused on Linux. Pinned to the last upstream wintun.net build.
WINTUN_VERSION="${WINTUN_VERSION:-0.14.1}"

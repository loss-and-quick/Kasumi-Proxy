# shellcheck shell=bash
# Single source of truth for the pinned core versions, sourced by both
# fetch-cores-android.sh and fetch-cores-desktop.sh. Each value is
# overridable via the environment (the release workflow passes the upstream
# latest when bumping). release.yml/nightly.yml grep these defaults to detect
# upstream updates — keep the `NAME="${NAME:-vX}"` shape.
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
TUN2SOCKS_VERSION="${TUN2SOCKS_VERSION:-v2.6.0}"
# sing-box runs Hysteria2/TUIC profiles (second core). Pin a 1.13.x line whose
# config schema matches singbox_config.rs (mixed inbound, tls/utls, hysteria2/tuic).
SINGBOX_VERSION="${SINGBOX_VERSION:-v1.13.13}"

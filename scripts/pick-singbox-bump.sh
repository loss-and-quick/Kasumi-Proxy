#!/usr/bin/env bash
# Decide which sing-box version the release may pin, given the current pin and the
# newest upstream release.
#
# The pin is not "whatever is newest": singbox_config.rs is written against one
# sing-box line, and geodat2srs builds its .srs writer from the same line, so a
# release on another line needs a hand bump of both (see
# scripts/check-geodat2srs-line.sh). A plain "pinned != latest" test would let the
# scheduled release replace a 1.15 pin with a 1.14 stable, or downgrade to an older
# release that happens to be newer-ordered by tag, and publish a core the config
# schema no longer matches.
#
# Usage: scripts/pick-singbox-bump.sh <pinned> <latest>
#   Prints the version to pin, and a GitHub warning annotation when it keeps the
#   current pin because upstream moved to another line.
set -euo pipefail

pinned="${1:?usage: $0 <pinned> <latest>}"
latest="${2:?usage: $0 <pinned> <latest>}"

line() { sed -E 's/^v?([0-9]+\.[0-9]+).*/\1/' <<<"$1"; }

if [ "$(line "$pinned")" != "$(line "$latest")" ]; then
	echo "::warning::sing-box ${latest} is on another line than the pinned ${pinned}; keeping ${pinned}. Bump geodat2srs to the same line first (scripts/check-geodat2srs-line.sh), then set SINGBOX_VERSION by hand." >&2
	echo "$pinned"
	exit 0
fi

# Same line: take the newer of the two, never a release older than the pin.
# `sort -V` ranks a prerelease above its own final release (1.15.0-alpha.13 >
# 1.15.0) — the opposite of semver — so a pin on an alpha line would ignore the
# stable release it was waiting for, and a stable pin would step back onto a
# prerelease. Settle those two cases first, then let `sort -V` order the rest.
core() { sed -E 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/' <<<"$1"; }
pre() {
	local v="${1#v}"
	case "$v" in
	*-*) printf '%s' "${v#*-}" ;;
	*) printf '' ;;
	esac
}

if [ "$(core "$pinned")" = "$(core "$latest")" ]; then
	if [ -n "$(pre "$pinned")" ] && [ -z "$(pre "$latest")" ]; then
		echo "$latest"
		exit 0
	fi
	if [ -z "$(pre "$pinned")" ] && [ -n "$(pre "$latest")" ]; then
		echo "$pinned"
		exit 0
	fi
fi

if [ "$(printf '%s\n%s\n' "$pinned" "$latest" | sort -V | tail -1)" = "$pinned" ]; then
	echo "$pinned"
else
	echo "$latest"
fi

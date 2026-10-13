#!/usr/bin/env bash
# Fail when the pinned geodat2srs rev was built against a different sing-box
# minor line than the one about to be pinned. The .srs rule-set format version
# follows the core, and a set written by a newer writer is rejected by an older
# core ("unsupported version"), so the two pins must move together. geodat2srs
# has no tags and its nix hashes can't be computed without nix, so the bump
# cannot be automated — this turns a silent skew into a loud release failure.
#
# Usage: scripts/check-geodat2srs-line.sh <singbox-version>   e.g. v1.15.0
set -euo pipefail

ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
# shellcheck source=scripts/binary-versions.sh
. "$ROOT/scripts/binary-versions.sh"

new="${1:?usage: $0 <singbox-version>}"
line() { sed -E 's/^v?([0-9]+\.[0-9]+).*/\1/' <<<"$1"; }

gomod_url="https://raw.githubusercontent.com/loss-and-quick/geodat2srs/${GEODAT2SRS_REV}/go.mod"
pinned=$(curl -fsSL --retry 3 "$gomod_url" | awk '$1 == "github.com/sagernet/sing-box" { print $2; exit }')
if [ -z "$pinned" ]; then
	echo "❌ no sagernet/sing-box requirement in $gomod_url" >&2
	exit 1
fi

if [ "$(line "$pinned")" != "$(line "$new")" ]; then
	cat >&2 <<MSG
❌ sing-box would move to ${new}, but geodat2srs @ ${GEODAT2SRS_REV:0:12} is built against sing-box ${pinned}.
   Its .srs output would be rejected by the new core. Bump geodat2srs first:
   1. update the loss-and-quick/geodat2srs fork to sing-box ${new} and note the commit;
   2. set GEODAT2SRS_REV in scripts/binary-versions.sh;
   3. refresh geodat2srs-src / geodat2srs-vendor in scripts/binary-hashes.json
      (nix build .#kasumi-desktop, paste the expected hash — CI has no nix here);
   4. re-run the release.
MSG
	exit 1
fi
echo "✅ geodat2srs sing-box ${pinned} matches the ${new} line"

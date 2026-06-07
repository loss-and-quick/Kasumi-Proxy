#!/usr/bin/env bash
# shellcheck shell=bash
# Generate CHANGELOG.md entry for the current release.
# Usage: scripts/gen-changelog.sh <version> [xray_old] [xray_new] [t2s_old] [t2s_new] [sb_old] [sb_new]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/CHANGELOG.md"

VERSION="${1:?version required}"
XRAY_OLD="${2:-}" XRAY_NEW="${3:-}"
T2S_OLD="${4:-}" T2S_NEW="${5:-}"
SB_OLD="${6:-}" SB_NEW="${7:-}"

# Idempotent: if this version already has an entry (hand-written ahead of a
# skip_bump release, or a re-run of this job), leave it untouched instead of
# prepending a duplicate. Match the `## <version> …` heading at line start,
# escaping regex metacharacters in the version string.
if [ -f "$OUT" ]; then
	ver_re=$(printf '%s' "$VERSION" | sed 's/[][\\.*^$/]/\\&/g')
	if grep -qE "^## ${ver_re}([[:space:]]|\$)" "$OUT"; then
		echo "→ $OUT already has a $VERSION entry — leaving it untouched"
		exit 0
	fi
fi

last_tag=$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null || echo "")

{
	echo "## $VERSION — $(date -u '+%Y-%m-%d')"
	echo ""

	# Binary updates
	bin_section=""
	[ -n "$XRAY_NEW" ] && [ "$XRAY_OLD" != "$XRAY_NEW" ] && bin_section+="- xray-core: \`$XRAY_OLD\` → \`$XRAY_NEW\`"$'\n'
	[ -n "$T2S_NEW" ] && [ "$T2S_OLD" != "$T2S_NEW" ] && bin_section+="- tun2socks: \`$T2S_OLD\` → \`$T2S_NEW\`"$'\n'
	[ -n "$SB_NEW" ] && [ "$SB_OLD" != "$SB_NEW" ] && bin_section+="- sing-box: \`$SB_OLD\` → \`$SB_NEW\`"$'\n'

	if [ -n "$bin_section" ]; then
		echo "### Core updates"
		echo ""
		printf '%s' "$bin_section"
		echo ""
	fi

	# Git commits since last tag
	if [ -n "$last_tag" ]; then
		commits=$(git -C "$ROOT" log "$last_tag"..HEAD --oneline \
			--no-merges \
			-- . ':(exclude)module/module.prop' ':(exclude)update.json' ':(exclude)CHANGELOG.md' \
			2>/dev/null || true)
		if [ -n "$commits" ]; then
			echo "### Changes"
			echo ""
			printf '%s\n' "$commits" | while IFS= read -r line; do
				echo "- ${line}"
			done
			echo ""
		fi
	fi
} >/tmp/new_entry.md

# Prepend to existing CHANGELOG.md
if [ -f "$OUT" ]; then
	cat /tmp/new_entry.md "$OUT" >/tmp/changelog_merged.md
	mv /tmp/changelog_merged.md "$OUT"
else
	mv /tmp/new_entry.md "$OUT"
fi

echo "→ updated $OUT"

#!/system/bin/sh
# Shared logging for the module's own scripts, sourced (not executed) by
# service.sh, action.sh and customize.sh. The daemon writes daemon.log; what
# happens *around* it — a boot that found no daemon, a WebUI button with no
# ws.json, an install step that failed — had nowhere to go at all, and the first
# of those is exactly what a user asks about later.
#
# Never log a token, a subscription URL or anything else copied out of ws.json:
# these files live in the same world as the daemon log, which redacts them.

# The data dir is fixed across the module's scripts (the binary uses the same
# path); set it here so a caller that already knows it does not repeat it.
KASUMI_DATADIR="/data/adb/kasumi-proxy"
KASUMI_LOG_FILE="$KASUMI_DATADIR/module.log"
# Nothing else rotates this file, so the writer bounds it itself. Same cap the
# daemon applies to its own logs.
KASUMI_LOG_MAX_BYTES=524288

# klog LEVEL MESSAGE... — append one timestamped line. Best effort: a script that
# cannot log must still do its job, so every failure here is swallowed.
klog() {
	_level=$1
	shift
	[ -d "$KASUMI_DATADIR" ] || mkdir -p "$KASUMI_DATADIR" 2>/dev/null || return 0
	_lockdir="$KASUMI_DATADIR/.module.log.lock"
	_tries=0
	_locked=0
	while [ "$_tries" -lt 5 ]; do
		if mkdir "$_lockdir" 2>/dev/null; then
			_locked=1
			break
		fi
		_tries=$((_tries + 1))
		sleep 1 2>/dev/null || break
	done
	if [ "$_locked" -ne 1 ]; then
		# Try breaking a stale lock left by a dead process once
		rmdir "$_lockdir" 2>/dev/null
		if mkdir "$_lockdir" 2>/dev/null; then
			_locked=1
		fi
	fi
	printf '%s %-5s %s: %s\n' \
		"$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)" \
		"$_level" \
		"${KASUMI_SCRIPT:-module}" \
		"$*" >>"$KASUMI_LOG_FILE" 2>/dev/null

	_size=$(wc -c <"$KASUMI_LOG_FILE" 2>/dev/null || echo 0)
	if [ "$_size" -gt "$KASUMI_LOG_MAX_BYTES" ] 2>/dev/null; then
		# `tail -n +2` drops the partial first line a byte cut leaves behind, so
		# every kept line is still a whole record — the same cut the daemon's own
		# in-place trim makes.
		tail -c "$((KASUMI_LOG_MAX_BYTES / 2))" "$KASUMI_LOG_FILE" 2>/dev/null | tail -n +2 >"$KASUMI_LOG_FILE.trim" &&
			mv "$KASUMI_LOG_FILE.trim" "$KASUMI_LOG_FILE" 2>/dev/null
	fi
	[ "$_locked" -eq 1 ] && rmdir "$_lockdir" 2>/dev/null
	unset _level _size _lockdir _tries _locked
	return 0
}
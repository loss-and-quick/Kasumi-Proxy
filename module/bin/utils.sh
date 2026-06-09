#!/system/bin/sh
# shellcheck disable=SC3043  # 'local' is supported by Android's /system/bin/sh (mksh)
# ============================================================
# bin/utils.sh — primitives shared by service.sh and kasumi-proxyctl.
#
# This file holds ONLY helpers that BOTH consumers genuinely need. Anything
# used by a single script lives in that script. Keep it that way: do not let
# this file accumulate service-daemon (logging, tun iface, state) or
# UI-facade (json/job writers) specific logic — that is the mixing this split
# exists to avoid.
# ============================================================

# read_socks_port <socks_port_file>
read_socks_port() {
	local p
	p=$(cat "$1" 2>/dev/null)
	case "$p" in '' | *[!0-9]*) echo 10808 ;; *) echo "$p" ;; esac
}

# read_engine <engine_file>
read_engine() {
	local e
	e=$(cat "$1" 2>/dev/null)
	case "$e" in sing-box) echo "sing-box" ;; *) echo "xray" ;; esac
}

# pipe_send <pipe> <cmd> — write cmd to a FIFO in background; no-op if pipe absent
pipe_send() {
	[ -p "$1" ] && (printf '%s\n' "$2" >"$1") &
	true
}

# pid_matches_bin <pid> <bin> — true if pid is alive and its exe inode is bin
pid_matches_bin() {
	local pid="$1" bin="$2" se sb
	case "$pid" in '' | *[!0-9]*) return 1 ;; esac
	[ -x "$bin" ] || return 1
	kill -0 "$pid" 2>/dev/null || return 1
	se=$(stat -L -c "%D:%i" "/proc/$pid/exe" 2>/dev/null)
	sb=$(stat -L -c "%D:%i" "$bin" 2>/dev/null)
	[ -n "$se" ] && [ "$se" = "$sb" ]
}

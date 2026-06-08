#!/system/bin/sh
# shellcheck disable=SC3043  # 'local' is supported by Android's /system/bin/sh (mksh)
MODDIR=${0%/*}
BINDIR="$MODDIR/bin"
DATADIR="/data/adb/kasumi-proxy"
SOCKS_PORT_FILE="$DATADIR/local-socks-port"
ENGINE_FILE="$DATADIR/engine"
STATE_FILE="$DATADIR/app-state.json"
TUN_IFACE_FILE="$DATADIR/tun-iface"
TUN2_IFACE_FILE="$DATADIR/tun2-iface"
# Lifecycle channel: this script is the single owner of the proxy lifecycle, so
# it publishes the authoritative state here for kasumi-proxyctl status to read.
# One of: connecting | running | stopped | failed:<reason>.
SERVICE_STATE_FILE="$DATADIR/service-state"
# Subscription auto-update cache: the daemon below downloads bodies on schedule;
# the UI parses & applies them on launch (kasumi-proxyctl {list,read,clear}SubCache).
SUBCACHE_DIR="$DATADIR/sub-cache"
mkdir -p "$DATADIR"
"$BINDIR/kasumi-proxyctl" rotateLogs
exec >>"$DATADIR/service.log" 2>&1
echo "service.sh started (pid=$$, moddir=$MODDIR)"

# Logging helpers — respect logLevel from app-state.json
_log_level_num() {
	case "$1" in debug) echo 0 ;; info) echo 1 ;; warning) echo 2 ;; error) echo 3 ;; none) echo 4 ;; *) echo 2 ;; esac
}
read_log_level() {
	[ -f "$STATE_FILE" ] || {
		echo "warning"
		return
	}
	compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
	lvl=$(printf '%s' "$compact" | sed -n 's/.*"logLevel":"\([^"]*\)".*/\1/p' | head -n 1)
	case "$lvl" in debug | info | warning | error | none) echo "$lvl" ;; *) echo "warning" ;; esac
}
log_debug() {
	[ "$(_log_level_num "$(read_log_level)")" -le 0 ] && echo "[DEBUG] $*"
	return 0
}
log_info() {
	[ "$(_log_level_num "$(read_log_level)")" -le 1 ] && echo "[INFO]  $*"
	return 0
}
log_warn() {
	[ "$(_log_level_num "$(read_log_level)")" -le 2 ] && echo "[WARN]  $*"
	return 0
}
log_error() { echo "[ERROR] $*"; }

PIDFILE="$MODDIR/run/core.pid"
TUN2SOCKS_PIDFILE="$MODDIR/run/tun2socks.pid"
TUN2SOCKS2_PIDFILE="$MODDIR/run/tun2socks2.pid"

# Control pipe for receiving commands from the UI or other components
PIPE_FILE="$MODDIR/run/control.pipe"
STUB_DIR=/dev/sysctl_stubs

rm -rf "$STUB_DIR"
mkdir -p "$STUB_DIR"
mount -t tmpfs -o "size=64k,mode=0755,context=u:object_r:proc_net:s0" proc "$STUB_DIR"

rm -rf "$MODDIR/run"
mkdir -p "$MODDIR/run"
mkfifo "$PIPE_FILE"
log_debug "control pipe ready: $PIPE_FILE"
# Fresh boot: no core runs yet. Seed the lifecycle channel so a stale value from
# the previous session can't make status lie before the first command lands.
printf '%s' "stopped" >"$SERVICE_STATE_FILE"
CORE_PID=0
TUN2SOCKS_PID=0
TUN2SOCKS2_PID=0

ip="/system/bin/ip"
iptables="/system/bin/iptables"
ip6tables="/system/bin/ip6tables"

RULE_PRIORITY=1000
FWMARK=255
MARK_CHAIN="KASUMI_PROXY_MARK"
LOCKED=0

read_socks_port() {
	if [ -f "$SOCKS_PORT_FILE" ]; then
		p=$(cat "$SOCKS_PORT_FILE" 2>/dev/null)
		case "$p" in '' | *[!0-9]*) echo 10808 ;; *) echo "$p" ;; esac
	else
		echo 10808
	fi
}

# HTTP inbound port (xray http-in). Read from app-state.json; default 10809.
read_http_port() {
	if [ -f "$STATE_FILE" ]; then
		compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
		p=$(printf '%s' "$compact" | sed -n 's/.*"localHttpPort":\([0-9]*\).*/\1/p' | head -n 1)
		case "$p" in '' | *[!0-9]*) echo 10809 ;; *) echo "$p" ;; esac
	else
		echo 10809
	fi
}

# Hide the local proxy inbounds from bypass-mode apps only.
# Apps going direct (bypass) must not be able to detect a running proxy by
# probing loopback ports. All other apps may reach them normally.
# Pass "add" or "del"; must be called after read_app_filter so APP_FILTER_JSON is set.
protect_local_ports() { # add|del
	local action="$1"
	local sp hp port uid mode
	sp=$(read_socks_port)
	hp=$(read_http_port)
	# First, always remove any per-uid rules to avoid stacking on repeated starts.
	[ -z "$APP_FILTER_JSON" ] && return
	printf '%s\n' "$APP_FILTER_JSON" | tr ',' '\n' | while IFS= read -r pair; do
		key=$(printf '%s' "$pair" | sed -n 's/"\([^"]*\)":"[^"]*".*/\1/p')
		mode=$(printf '%s' "$pair" | sed -n 's/"[^"]*":"\([^"]*\)".*/\1/p')
		[ "$mode" = "bypass" ] || continue
		uid=${key##*:}
		for port in "$sp" "$hp"; do
			case "$port" in '' | *[!0-9]*) continue ;; esac
			$iptables -D OUTPUT -o lo -p tcp --dport "$port" -m owner --uid-owner "$uid" -j REJECT --reject-with tcp-reset 2>/dev/null
			$ip6tables -D OUTPUT -o lo -p tcp --dport "$port" -m owner --uid-owner "$uid" -j REJECT --reject-with tcp-reset 2>/dev/null
			if [ "$action" = "add" ]; then
				$iptables -A OUTPUT -o lo -p tcp --dport "$port" -m owner --uid-owner "$uid" -j REJECT --reject-with tcp-reset
				$ip6tables -A OUTPUT -o lo -p tcp --dport "$port" -m owner --uid-owner "$uid" -j REJECT --reject-with tcp-reset
			fi
		done
	done
}

# Which core the active profile selected (xray default). The UI writes this
# marker via kasumi-proxyctl start; both cores launch as `<bin> run -c <cfg>`.
read_engine() {
	if [ -f "$ENGINE_FILE" ]; then
		e=$(cat "$ENGINE_FILE" 2>/dev/null)
		case "$e" in sing-box) echo "sing-box" ;; *) echo "xray" ;; esac
	else
		echo "xray"
	fi
}

# Read app filter config from app-state.json.
# Sets APP_CAPTURE_MODE (all|none) and APP_FILTER_JSON (raw object string).
read_app_filter() {
	APP_CAPTURE_MODE="all"
	APP_FILTER_JSON=""
	[ -f "$STATE_FILE" ] || return
	compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
	mode=$(printf '%s' "$compact" | sed -n 's/.*"appCaptureMode":"\([^"]*\)".*/\1/p' | head -n 1)
	case "$mode" in none) APP_CAPTURE_MODE="none" ;; *) APP_CAPTURE_MODE="all" ;; esac
	APP_FILTER_JSON=$(printf '%s' "$compact" | sed -n 's/.*"appFilter":{\([^}]*\)}.*/\1/p' | head -n 1)
}

# Resolve a package name -> every UID that owns it, one per Android profile.
# An app installed in both the personal profile (user 0) and a work profile
# (user 10, 11, …) has a DISTINCT uid per profile (≈ user*100000 + appId), and
# each needs its own iptables --uid-owner rule — otherwise the app filter would
# only ever cover the personal profile. We glob /data/user/<id>/<pkg>: /data/data
# is just a bind to /data/user/0, so this also picks up the personal profile.
# (No `pm` needed at runtime.) Output: newline-separated uids, possibly empty.
pkg_to_uids() { # <pkg> -> uids
	for d in /data/user/*/"$1"; do
		[ -d "$d" ] || continue
		stat -c '%u' "$d" 2>/dev/null
	done | sort -u
}

# Append uid-owner mark rules for app filter.
# Must be called after local exclusions, before the catch-all mark rules.
append_app_uid_rules() { # <ipt> <chain>
	local ipt="$1" chain="$2"
	[ -z "$APP_FILTER_JSON" ] && return
	# Parse "pkg:uid":"mode" pairs. Key format is "pkg:uid" — uid extracted directly.
	printf '%s\n' "$APP_FILTER_JSON" | tr ',' '\n' | while IFS= read -r pair; do
		key=$(printf '%s' "$pair" | sed -n 's/"\([^"]*\)":"[^"]*".*/\1/p')
		mode=$(printf '%s' "$pair" | sed -n 's/"[^"]*":"\([^"]*\)".*/\1/p')
		[ -z "$key" ] || [ -z "$mode" ] && continue
		uid=${key##*:}
		case "$mode" in
		bypass)
			"$ipt" -t mangle -A "$chain" -m owner --uid-owner "$uid" -j RETURN
			;;
		force-proxy)
			"$ipt" -t mangle -A "$chain" -m owner --uid-owner "$uid" -j MARK --set-xmark 2
			"$ipt" -t mangle -A "$chain" -m owner --uid-owner "$uid" -j RETURN
			;;
		esac
	done
}

# True when the active profile pins at least one app to force-proxy mode. The
# second tun (xray: tun2socks2 + fwmark 2/table 101; sing-box: tun-force inbound)
# only carries traffic then — without it nothing ever marks fwmark 2, so starting
# it just leaves an idle tun device, process and routes behind.
has_force_proxy_app() {
	[ -f "$STATE_FILE" ] || return 1
	compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
	filter=$(printf '%s' "$compact" | sed -n 's/.*"appFilter":{\([^}]*\)}.*/\1/p' | head -n 1)
	case "$filter" in
	*'"force-proxy"'*) return 0 ;;
	*) return 1 ;;
	esac
}

read_routing_mode() {
	if [ -f "$STATE_FILE" ]; then
		compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
		mode=$(printf '%s' "$compact" | sed -n 's/.*"routingMode":"\([^"]*\)".*/\1/p' | head -n 1)
		case "$mode" in
		custom | rules) echo "$mode" ;;
		*) echo "global" ;;
		esac
	else
		echo "global"
	fi
}

# Read the autoStart flag from app-state.json. Defaults to "true" so a device
# that has never written the setting keeps the prior boot behaviour. Returns
# "true" or "false".
read_auto_start() {
	[ -f "$STATE_FILE" ] || {
		echo "true"
		return
	}
	compact=$(tr -d '\r\n\t ' <"$STATE_FILE" 2>/dev/null)
	val=$(printf '%s' "$compact" | sed -n 's/.*"autoStart":\(true\|false\).*/\1/p' | head -n 1)
	case "$val" in false) echo "false" ;; *) echo "true" ;; esac
}

append_local_ipv4_exclusions() { # <chain>
	chain="$1"
	$iptables -t mangle -A "$chain" -d 127.0.0.0/8 -j RETURN
	$iptables -t mangle -A "$chain" -d 10.0.0.0/8 -j RETURN
	$iptables -t mangle -A "$chain" -d 172.16.0.0/12 -j RETURN
	$iptables -t mangle -A "$chain" -d 192.168.0.0/16 -j RETURN
	$iptables -t mangle -A "$chain" -d 169.254.0.0/16 -j RETURN
	$iptables -t mangle -A "$chain" -d 224.0.0.0/4 -j RETURN
	$iptables -t mangle -A "$chain" -d 255.255.255.255/32 -j RETURN
}

append_local_ipv6_exclusions() { # <chain>
	chain="$1"
	$ip6tables -t mangle -A "$chain" -d ::1/128 -j RETURN
	$ip6tables -t mangle -A "$chain" -d fc00::/7 -j RETURN
	$ip6tables -t mangle -A "$chain" -d fe80::/10 -j RETURN
	$ip6tables -t mangle -A "$chain" -d ff00::/8 -j RETURN
}

# Absolute path of the selected core binary (may not exist — caller checks).
core_bin() {
	case "$(read_engine)" in
	sing-box) echo "$BINDIR/sing-box" ;;
	*) echo "$BINDIR/xray" ;;
	esac
}

# Fingerprint a .dat asset so we can tell whether its .srs outputs are current.
# Prefer a content hash; fall back to size+mtime where no hash tool exists.
dat_fingerprint() { # <file> -> string ("" if missing)
	f="$1"
	[ -f "$f" ] || return 0
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$f" 2>/dev/null | cut -d' ' -f1
	elif command -v md5sum >/dev/null 2>&1; then
		md5sum "$f" 2>/dev/null | cut -d' ' -f1
	else
		stat -c '%s-%Y' "$f" 2>/dev/null
	fi
}

# Keep one geo asset kind (geoip|geosite) consistent between its .dat source and
# the .srs files sing-box loads. After this returns we are never in a half state:
#   * .dat present, changed or its .srs missing -> regenerate from a clean slate
#   * .dat absent                               -> drop orphaned .srs + stamp
# The stamp records the .dat fingerprint the current .srs set was built from, so
# we reconvert when the .dat is replaced and self-heal if the outputs vanish.
sync_geo_asset() { # <kind: geoip|geosite>
	kind="$1"
	dat="$DATADIR/$kind.dat"
	prefix="$kind-"
	stamp="$DATADIR/.$kind.srs.stamp"

	# Drop the legacy timestamp marker so the new stamp scheme owns the state.
	rm -f "$DATADIR/.$kind.converted"

	# Are any outputs for this kind currently on disk?
	srs_present=0
	for f in "$DATADIR/$prefix"*.srs; do
		[ -e "$f" ] && {
			srs_present=1
			break
		}
	done

	if [ ! -f "$dat" ]; then
		# No source: a .srs without its .dat must not survive — purge it.
		if [ "$srs_present" = 1 ] || [ -f "$stamp" ]; then
			log_warn "$kind.dat missing — removing orphaned ${prefix}*.srs"
			rm -f "$DATADIR/$prefix"*.srs "$stamp"
		fi
		return 0
	fi

	if [ ! -x "$BINDIR/geodat2srs" ]; then
		log_debug "geodat2srs not found, cannot convert $kind.dat"
		return 0
	fi

	want=$(dat_fingerprint "$dat")
	have=""
	[ -f "$stamp" ] && have=$(cat "$stamp" 2>/dev/null)
	# Up to date only when the stamp matches AND the outputs actually exist.
	if [ -n "$want" ] && [ "$want" = "$have" ] && [ "$srs_present" = 1 ]; then
		log_debug "$kind .srs already match $kind.dat"
		return 0
	fi

	log_info "converting $kind.dat -> .srs (source changed or outputs missing)"
	# Build into a temp dir so a mid-run failure can't leave a half-written set
	# mixed with the old one. Only swap in + stamp once we know it made files.
	tmp="$DATADIR/.$kind.srs.tmp"
	rm -rf "$tmp"
	mkdir -p "$tmp"
	if "$BINDIR/geodat2srs" "$kind" -i "$dat" -o "$tmp" --prefix "$prefix"; then
		moved=0
		rm -f "$DATADIR/$prefix"*.srs
		for f in "$tmp/$prefix"*.srs; do
			[ -e "$f" ] || continue
			mv -f "$f" "$DATADIR/" && moved=$((moved + 1))
		done
		rm -rf "$tmp"
		if [ "$moved" -gt 0 ]; then
			printf '%s' "$want" >"$stamp"
			log_info "$kind: generated $moved .srs file(s) from $kind.dat"
		else
			rm -f "$stamp"
			log_warn "$kind: conversion produced no .srs files"
		fi
	else
		# Keep the previous .srs (better than none) but drop the stamp so the
		# next start retries against the new .dat.
		rm -rf "$tmp"
		rm -f "$stamp"
		log_warn "$kind.dat conversion failed — leaving previous .srs untouched"
	fi
}

pid_matches_bin() { # <pid> <bin>
	pid="$1"
	bin="$2"
	case "$pid" in '' | *[!0-9]*) return 1 ;; esac
	[ -x "$bin" ] || return 1
	kill -0 "$pid" 2>/dev/null || return 1
	STAT_CORE_EXE=$(stat -L -c "%D:%i" "/proc/$pid/exe" 2>/dev/null)
	STAT_CORE_BIN=$(stat -L -c "%D:%i" "$bin" 2>/dev/null)
	[ -n "$STAT_CORE_EXE" ] && [ "$STAT_CORE_EXE" = "$STAT_CORE_BIN" ]
}

pid_matches_any_core() { # <pid>
	pid="$1"
	pid_matches_bin "$pid" "$BINDIR/xray" || pid_matches_bin "$pid" "$BINDIR/sing-box"
}

get_status() {
	if [ -f "$PIDFILE" ]; then
		PID=$(cat "$PIDFILE" 2>/dev/null)
		if pid_matches_any_core "$PID"; then
			return 0
		fi
	fi
	return 1
}

read_pidfile() { # <pidfile>
	file="$1"
	if [ -f "$file" ]; then
		pid=$(cat "$file" 2>/dev/null)
		case "$pid" in '' | *[!0-9]*) echo 0 ;; *) echo "$pid" ;; esac
	else
		echo 0
	fi
}

refresh_runtime_pids() {
	CORE_PID=$(read_pidfile "$PIDFILE")
	TUN2SOCKS_PID=$(read_pidfile "$TUN2SOCKS_PIDFILE")
	TUN2SOCKS2_PID=$(read_pidfile "$TUN2SOCKS2_PIDFILE")
}

lock_sysctl() {
	local value="$1"
	local target_path="$2"
	# Key the stub by the full path so distinct sysctls never collide on a
	# shared basename (e.g. conf/all/rp_filter vs conf/default/rp_filter vs
	# conf/<tun>/rp_filter would otherwise all map to one "rp_filter" stub).
	local key
	key=$(printf '%s' "$target_path" | tr '/' '_')
	local stub_file="$STUB_DIR/$key"

	# Drop any prior bind-mount on this path first. A bind-mount over a
	# /proc/sys file only shadows the *readback*: reads/writes hit the stub,
	# while the kernel keeps using whatever was last written to the real
	# inode. So we must unmount before the real write below can land.
	local guard=8
	while [ "$guard" -gt 0 ] && umount "$target_path" 2>/dev/null; do
		guard=$((guard - 1))
	done

	# STEP 1: actually apply the value to the kernel variable.
	echo "$value" >"$target_path" 2>/dev/null
	local real
	real=$(cat "$target_path" 2>/dev/null)
	if [ "$real" != "$value" ]; then
		log_warn "lock_sysctl: $target_path kernel=$real wanted=$value"
	fi

	# STEP 2: lock it. Bind-mount a stub holding the same value so later
	# writes by netd land on the stub instead of reverting the kernel.
	echo "$value" >"$stub_file"
	chown "$(stat -c '%u:%g' "$target_path")" "$stub_file" 2>/dev/null
	chcon "$(stat -Z -c '%C' "$target_path")" "$stub_file" 2>/dev/null # Just in case

	mount -o bind "$stub_file" "$target_path"
}

random_tun_iface() {
	if [ -r /proc/sys/kernel/random/uuid ]; then
		raw=$(cat /proc/sys/kernel/random/uuid 2>/dev/null)
	else
		raw=""
	fi
	[ -n "$raw" ] || raw="$(date +%s 2>/dev/null)$$"
	hex=$(printf '%s%s' "$raw" "$(date +%s 2>/dev/null)$$abcdef12" | tr 'A-F' 'a-f' | tr -cd 'a-f0-9' | cut -c1-9)
	first=$(printf '%s' "$hex" | cut -c1)
	case "$first" in
	0) lead=q ;;
	1) lead=w ;;
	2) lead=e ;;
	3) lead=r ;;
	4) lead=t ;;
	5) lead=y ;;
	6) lead=u ;;
	7) lead=i ;;
	8) lead=o ;;
	9) lead=p ;;
	a) lead=s ;;
	b) lead=d ;;
	c) lead=f ;;
	d) lead=g ;;
	e) lead=h ;;
	*) lead=j ;;
	esac
	tail=$(printf '%s' "$hex" | cut -c2-9)
	printf '%s%s\n' "$lead" "$tail"
}

current_tun_iface() {
	if [ -f "$TUN_IFACE_FILE" ]; then
		cat "$TUN_IFACE_FILE" 2>/dev/null
	fi
}

current_tun2_iface() {
	if [ -f "$TUN2_IFACE_FILE" ]; then
		cat "$TUN2_IFACE_FILE" 2>/dev/null
	fi
}

lock_tun_iface() { # <iface>
	iface="$1"
	[ $LOCKED = 1 ] && return
	[ -n "$iface" ] || return
	if [ -e "/proc/sys/net/ipv4/conf/$iface/rp_filter" ]; then
		LOCKED=1
		lock_sysctl "0" "/proc/sys/net/ipv4/conf/$iface/rp_filter"
	fi
}

remove_mark_rule() {
	$ip rule del fwmark $FWMARK priority $RULE_PRIORITY 2>/dev/null
	$ip -6 rule del fwmark $FWMARK priority $RULE_PRIORITY 2>/dev/null
}

clear_routing_rules() {
	TUN_IFACE=$(current_tun_iface)

	remove_mark_rule
	read_app_filter
	protect_local_ports del

	# IPv4
	$iptables -t mangle -D OUTPUT -j "$MARK_CHAIN" 2>/dev/null
	$iptables -t mangle -F "$MARK_CHAIN" 2>/dev/null
	$iptables -t mangle -X "$MARK_CHAIN" 2>/dev/null
	$ip rule del fwmark 1 table 100 priority 1010 2>/dev/null
	$ip rule del fwmark 2 table 101 priority 1011 2>/dev/null
	$ip -6 rule del fwmark 2 table 101 priority 1011 2>/dev/null
	# IPv4 local-origin uplink pin + hotspot
	$ip rule del pref 5020 2>/dev/null
	$ip rule del pref 5021 2>/dev/null
	$ip rule del pref 5022 2>/dev/null
	$ip rule del pref 5030 2>/dev/null
	$ip rule del pref 5040 2>/dev/null
	$ip rule del pref 5050 2>/dev/null
	if [ -n "$TUN_IFACE" ]; then
		$iptables -D FORWARD -o "$TUN_IFACE" -j ACCEPT 2>/dev/null
		$iptables -D FORWARD -i "$TUN_IFACE" -j ACCEPT 2>/dev/null
		$iptables -t mangle -D FORWARD -o "$TUN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null
	fi
	TUN2_IFACE=$(current_tun2_iface)
	if [ -n "$TUN2_IFACE" ]; then
		$iptables -D FORWARD -o "$TUN2_IFACE" -j ACCEPT 2>/dev/null
		$iptables -D FORWARD -i "$TUN2_IFACE" -j ACCEPT 2>/dev/null
		$ip link set dev "$TUN2_IFACE" down 2>/dev/null
	fi
	rm -f "$TUN2_IFACE_FILE"
	# IPv6
	$ip6tables -t mangle -D OUTPUT -j "$MARK_CHAIN" 2>/dev/null
	$ip6tables -t mangle -F "$MARK_CHAIN" 2>/dev/null
	$ip6tables -t mangle -X "$MARK_CHAIN" 2>/dev/null
	$ip -6 rule del fwmark 1 table 100 priority 1010 2>/dev/null
	# IPv6 hotspot
	$ip6tables -D FORWARD -j REJECT --reject-with icmp6-no-route 2>/dev/null

	# Down the tun device
	if [ -n "$TUN_IFACE" ]; then
		$ip link set dev "$TUN_IFACE" down 2>/dev/null
	fi
	rm -f "$TUN_IFACE_FILE"
}

# Publish the authoritative lifecycle state for the status channel.
set_service_state() { # <connecting|running|stopped|failed:reason>
	printf '%s' "$1" >"$SERVICE_STATE_FILE"
}

# Tear down the running cores + routing without touching the lifecycle channel.
# Shared by the user-facing stop (which then marks "stopped") and the internal
# restart (which keeps "connecting" so the UI never blips to disconnected while a
# new config is applied).
teardown_runtime() {
	clear_routing_rules
	if [ "$CORE_PID" -gt 0 ]; then
		pid_matches_any_core "$CORE_PID" && kill -9 "$CORE_PID" 2>/dev/null
		rm -f "$PIDFILE"
		CORE_PID=0
	fi
	if [ "$TUN2SOCKS_PID" -gt 0 ]; then
		pid_matches_bin "$TUN2SOCKS_PID" "$BINDIR/tun2socks" && kill -9 "$TUN2SOCKS_PID" 2>/dev/null
		rm -f "$TUN2SOCKS_PIDFILE"
		TUN2SOCKS_PID=0
	fi
	if [ "$TUN2SOCKS2_PID" -gt 0 ]; then
		pid_matches_bin "$TUN2SOCKS2_PID" "$BINDIR/tun2socks" && kill -9 "$TUN2SOCKS2_PID" 2>/dev/null
		rm -f "$TUN2SOCKS2_PIDFILE"
		TUN2SOCKS2_PID=0
	fi
}

do_job() {
	local content="$1"
	log_info "command: $content"
	refresh_runtime_pids
	# A restart is an atomic teardown+start that stays "connecting" throughout, so
	# the status channel never flashes "stopped" between applying a new config.
	if [ "$content" = "restart" ]; then
		set_service_state connecting
		teardown_runtime
		content="start"
	fi
	if [ "$content" = "wait" ]; then
		: # Do nothing
	fi
	if [ "$content" = "start_httpd" ]; then
		httpd -p 127.17.1.3:80 -h "$MODDIR/webroot"
	fi
	if [ "$content" = "stop_httpd" ]; then
		pkill -f "httpd -p 127.17.1.3:80"
	fi
	if [ "$content" = "start" ]; then
		log_info "preparing proxy start"
		set_service_state connecting
		if [ ! -e /dev/net/tun ]; then
			mkdir -p /dev/net
			mknod /dev/net/tun c 10 200
			chmod 666 /dev/net/tun
		fi
		# Select core by engine marker. xray -> config.json, sing-box -> singbox.json.
		ENGINE=$(read_engine)
		ROUTING_MODE=$(read_routing_mode)
		case "$ENGINE" in
		sing-box)
			CORE_BIN="$BINDIR/sing-box"
			CORE_CFG="$DATADIR/singbox.json"
			CORE_LOG="$DATADIR/singbox.log"
			# Keep .srs in lock-step with their .dat sources: regenerate when a
			# .dat changed or its outputs are missing, and purge orphaned .srs
			# whose .dat is gone. Guarantees we never start with a mismatch.
			sync_geo_asset geoip
			sync_geo_asset geosite
			;;
		*)
			CORE_BIN="$BINDIR/xray"
			CORE_CFG="$DATADIR/config.json"
			CORE_LOG="$DATADIR/xray.log"
			;;
		esac
		log_info "engine=$ENGINE config=$CORE_CFG"
		log_info "routing_mode=$ROUTING_MODE"
		if [ ! -x "$CORE_BIN" ]; then
			log_error "core binary missing: $CORE_BIN"
			set_service_state "failed:core binary missing"
			return 0
		fi
		if [ ! -f "$CORE_CFG" ]; then
			log_error "config missing: $CORE_CFG"
			set_service_state "failed:config missing"
			return 0
		fi
		if [ "$ENGINE" = "sing-box" ] && grep -q '"rule_set"' "$CORE_CFG"; then
			# Verify every local rule_set the config references actually has its
			# .srs on disk. A generic "any .srs present" check would still let
			# sing-box fail on a specific missing geoip-xx/geosite-xx set.
			missing=$(sed -n 's/.*"path":[[:space:]]*"\([^"]*.srs\)".*/\1/p' "$CORE_CFG" | while IFS= read -r srs; do
				[ -f "$srs" ] || printf '%s\n' "$srs"
			done | tr '\n' ' ')
			if [ -n "$missing" ]; then
				log_error "sing-box config references missing rule_set files:$missing — download/refresh geoip/geosite assets"
				set_service_state "failed:missing rule_set assets"
				return 0
			fi
		fi
		if [ "$ENGINE" = "sing-box" ]; then
			TUN_IFACE=$(current_tun_iface)
			[ -n "$TUN_IFACE" ] || TUN_IFACE=$(random_tun_iface)
			printf '%s' "$TUN_IFACE" >"$TUN_IFACE_FILE"
			# Inject interface_name into the tun inbounds. Strip any names a prior
			# start injected in a DEDICATED pass first: re-running start on the
			# same config (auto-start, watchdog, network-change restart) must never
			# accumulate duplicate "interface_name" keys — sing-box silently honours
			# the LAST duplicate, which would be a stale iface that disagrees with
			# the tun-iface tracking file used for teardown.
			sed -i 's/, "interface_name": "[^"]*"//g' "$CORE_CFG"
			sed -i "s/\"tag\": \"tun-in\"/\"tag\": \"tun-in\", \"interface_name\": \"$TUN_IFACE\"/" "$CORE_CFG"
			# The force-proxy tun inbound only exists when the active profile has
			# force-proxy apps (the UI omits it otherwise). Only allocate/track/
			# inject the second iface when the config actually contains it, so the
			# tun2-iface file never points at a device that was never created.
			if grep -q '"tag": "tun-force"' "$CORE_CFG"; then
				TUN2_IFACE=$(current_tun2_iface)
				[ -n "$TUN2_IFACE" ] || TUN2_IFACE=$(random_tun_iface)
				printf '%s' "$TUN2_IFACE" >"$TUN2_IFACE_FILE"
				sed -i "s/\"tag\": \"tun-force\"/\"tag\": \"tun-force\", \"interface_name\": \"$TUN2_IFACE\"/" "$CORE_CFG"
				log_info "sing-box tun ifaces: main=$TUN_IFACE force=$TUN2_IFACE"
			else
				rm -f "$TUN2_IFACE_FILE"
				log_info "sing-box tun iface: main=$TUN_IFACE (no force-proxy inbound)"
			fi
		fi
		if [ "$CORE_PID" -gt 0 ] && pid_matches_bin "$CORE_PID" "$CORE_BIN"; then
			log_info "$ENGINE already running pid=$CORE_PID"
		else
			# Start the selected core (both accept: <bin> run -c <cfg>)
			XRAY_LOCATION_ASSET="$BINDIR" "$CORE_BIN" run -c "$CORE_CFG" </dev/null >"$CORE_LOG" 2>&1 &
			CORE_PID=$!
			echo "$CORE_PID" >"$PIDFILE"
			log_info "started $ENGINE pid=$CORE_PID log=$CORE_LOG"
		fi

		SOCKS_PORT=$(read_socks_port)
		# sing-box manages its own tun interfaces natively via auto_route
		if [ "$ENGINE" = "xray" ]; then
			TUN_IFACE=$(current_tun_iface)
			[ -n "$TUN_IFACE" ] || TUN_IFACE=$(random_tun_iface)
			if [ "$TUN2SOCKS_PID" -gt 0 ] && pid_matches_bin "$TUN2SOCKS_PID" "$BINDIR/tun2socks"; then
				log_info "tun2socks already running pid=$TUN2SOCKS_PID"
			else
				printf '%s' "$TUN_IFACE" >"$TUN_IFACE_FILE"
				"$BINDIR/tun2socks" -device "tun://$TUN_IFACE" -proxy "socks5://127.0.0.1:$SOCKS_PORT" -fwmark 255 </dev/null >"$DATADIR/tun2socks.log" 2>&1 &
				TUN2SOCKS_PID=$!
				echo "$TUN2SOCKS_PID" >"$TUN2SOCKS_PIDFILE"
				log_info "started tun2socks pid=$TUN2SOCKS_PID iface=$TUN_IFACE socks=127.0.0.1:$SOCKS_PORT"
				local retry=0
				while [ $retry -lt 10 ]; do
					$ip link show "$TUN_IFACE" >/dev/null 2>&1 && break
					sleep 0.5
					retry=$((retry + 1))
				done
				if $ip link show "$TUN_IFACE" >/dev/null 2>&1; then
					log_debug "tun iface $TUN_IFACE up after ${retry} retries"
				else
					log_error "tun iface $TUN_IFACE did not appear — tun2socks may have failed (check $DATADIR/tun2socks.log)"
				fi
			fi
			# The force-proxy lane (second tun) is only worth standing up when the
			# profile actually pins apps to force-proxy. Otherwise skip it: no
			# packet ever carries fwmark 2, so the device/process/table 101 would
			# sit idle. Mirrors sing-box only emitting tun-force in that case.
			if has_force_proxy_app; then
				FORCE_PORT=$((SOCKS_PORT + 2))
				TUN2_IFACE=$(current_tun2_iface)
				[ -n "$TUN2_IFACE" ] || TUN2_IFACE=$(random_tun_iface)
				if [ "$TUN2SOCKS2_PID" -gt 0 ] && pid_matches_bin "$TUN2SOCKS2_PID" "$BINDIR/tun2socks"; then
					log_info "tun2socks2 already running pid=$TUN2SOCKS2_PID"
				else
					printf '%s' "$TUN2_IFACE" >"$TUN2_IFACE_FILE"
					"$BINDIR/tun2socks" -device "tun://$TUN2_IFACE" -proxy "socks5://127.0.0.1:$FORCE_PORT" -fwmark 255 </dev/null >"$DATADIR/tun2socks2.log" 2>&1 &
					TUN2SOCKS2_PID=$!
					echo "$TUN2SOCKS2_PID" >"$TUN2SOCKS2_PIDFILE"
					log_info "started tun2socks2 (force-proxy) pid=$TUN2SOCKS2_PID iface=$TUN2_IFACE port=$FORCE_PORT"
					local retry2=0
					while [ $retry2 -lt 10 ]; do
						$ip link show "$TUN2_IFACE" >/dev/null 2>&1 && break
						sleep 0.5
						retry2=$((retry2 + 1))
					done
					if $ip link show "$TUN2_IFACE" >/dev/null 2>&1; then
						log_debug "tun2 iface $TUN2_IFACE up after ${retry2} retries"
					else
						log_error "tun2 iface $TUN2_IFACE did not appear — tun2socks2 may have failed (check $DATADIR/tun2socks2.log)"
					fi
				fi
			else
				# No force-proxy apps: ensure no stale second lane lingers.
				if [ "$TUN2SOCKS2_PID" -gt 0 ]; then
					pid_matches_bin "$TUN2SOCKS2_PID" "$BINDIR/tun2socks" && kill -9 "$TUN2SOCKS2_PID" 2>/dev/null
					rm -f "$TUN2SOCKS2_PIDFILE"
					TUN2SOCKS2_PID=0
				fi
				TUN2_IFACE=""
				rm -f "$TUN2_IFACE_FILE"
				log_info "xray: no force-proxy apps, skipping second tun"
			fi
			lock_tun_iface "$TUN_IFACE"
			$ip addr add 198.18.0.1/15 dev "$TUN_IFACE" 2>/dev/null
			$ip link set dev "$TUN_IFACE" up
			$ip route replace default dev "$TUN_IFACE" table 100
			$ip rule del fwmark 1 table 100 priority 1010 2>/dev/null
			$ip rule add fwmark 1 table 100 priority 1010
			if [ -n "$TUN2_IFACE" ]; then
				$ip addr add 198.19.0.1/16 dev "$TUN2_IFACE" 2>/dev/null
				$ip link set dev "$TUN2_IFACE" up
				$ip route replace default dev "$TUN2_IFACE" table 101
				$ip rule del fwmark 2 table 101 priority 1011 2>/dev/null
				$ip rule add fwmark 2 table 101 priority 1011
			fi
		fi
		# xray only: iptables marking and manual routing (sing-box uses auto_route)
		if [ "$ENGINE" = "xray" ]; then
			# STEP 3: Add iptables rules to mark packets from tun2socks and route them through the tun device
			$iptables -t mangle -F "$MARK_CHAIN" 2>/dev/null
			$iptables -t mangle -D OUTPUT -j "$MARK_CHAIN" 2>/dev/null
			$iptables -t mangle -X "$MARK_CHAIN" 2>/dev/null
			$iptables -t mangle -N "$MARK_CHAIN"
			$iptables -t mangle -A "$MARK_CHAIN" -m mark --mark 255 -j RETURN
			$iptables -t mangle -A "$MARK_CHAIN" -m conntrack --ctdir REPLY -j RETURN
			log_debug "applying IPv4 local exclusions"
			append_local_ipv4_exclusions "$MARK_CHAIN"
			read_app_filter
			log_info "app filter: mode=$APP_CAPTURE_MODE"
			append_app_uid_rules "$iptables" "$MARK_CHAIN"
			if [ "$APP_CAPTURE_MODE" = "all" ]; then
				$iptables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 1000 -j MARK --set-xmark 1
				$iptables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 9999-2147483647 -j MARK --set-xmark 1
			fi
			$iptables -t mangle -A OUTPUT -j "$MARK_CHAIN"
			$iptables -I FORWARD -o "$TUN_IFACE" -j ACCEPT 2>/dev/null
			$iptables -I FORWARD -i "$TUN_IFACE" -j ACCEPT 2>/dev/null
			UPLINK=$($ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\) .*/\1/p' | head -n 1)
			if [ -n "$UPLINK" ]; then
				$ip rule del from 10.0.0.0/8 iif lo lookup "$UPLINK" pref 5020 2>/dev/null
				$ip rule add from 10.0.0.0/8 iif lo lookup "$UPLINK" pref 5020
				$ip rule del from 172.16.0.0/12 iif lo lookup "$UPLINK" pref 5021 2>/dev/null
				$ip rule add from 172.16.0.0/12 iif lo lookup "$UPLINK" pref 5021
				$ip rule del from 192.168.0.0/16 iif lo lookup "$UPLINK" pref 5022 2>/dev/null
				$ip rule add from 192.168.0.0/16 iif lo lookup "$UPLINK" pref 5022
				log_info "pinned local-origin traffic to uplink=$UPLINK"
			else
				log_warn "no uplink default route found; skipping local-origin pin"
			fi
			$ip rule del from 10.0.0.0/8 lookup 100 pref 5030 2>/dev/null
			$ip rule add from 10.0.0.0/8 lookup 100 pref 5030
			$ip rule del from 172.16.0.0/12 lookup 100 pref 5040 2>/dev/null
			$ip rule add from 172.16.0.0/12 lookup 100 pref 5040
			$ip rule del from 192.168.0.0/16 lookup 100 pref 5050 2>/dev/null
			$ip rule add from 192.168.0.0/16 lookup 100 pref 5050
			$iptables -t mangle -I FORWARD -o "$TUN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null
			$ip -6 addr add fdfe:dcba:9876::1/64 dev "$TUN_IFACE" 2>/dev/null
			$ip -6 link set dev "$TUN_IFACE" up 2>/dev/null
			$ip -6 route replace default dev "$TUN_IFACE" table 100
			$ip -6 rule del fwmark 1 table 100 priority 1010 2>/dev/null
			$ip -6 rule add fwmark 1 table 100 priority 1010
			if [ -n "$TUN2_IFACE" ]; then
				$ip -6 addr add fdfe:dcba:9877::1/64 dev "$TUN2_IFACE" 2>/dev/null
				$ip -6 link set dev "$TUN2_IFACE" up 2>/dev/null
				$ip -6 route replace default dev "$TUN2_IFACE" table 101
				$ip -6 rule del fwmark 2 table 101 priority 1011 2>/dev/null
				$ip -6 rule add fwmark 2 table 101 priority 1011
			fi
			$ip6tables -t mangle -F "$MARK_CHAIN" 2>/dev/null
			$ip6tables -t mangle -D OUTPUT -j "$MARK_CHAIN" 2>/dev/null
			$ip6tables -t mangle -X "$MARK_CHAIN" 2>/dev/null
			$ip6tables -t mangle -N "$MARK_CHAIN"
			$ip6tables -t mangle -A "$MARK_CHAIN" -m mark --mark 255 -j RETURN
			$ip6tables -t mangle -A "$MARK_CHAIN" -m conntrack --ctdir REPLY -j RETURN
			log_debug "applying IPv6 local exclusions"
			append_local_ipv6_exclusions "$MARK_CHAIN"
			append_app_uid_rules "$ip6tables" "$MARK_CHAIN"
			if [ "$APP_CAPTURE_MODE" = "all" ]; then
				$ip6tables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 1000 -j MARK --set-xmark 1
				$ip6tables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 9999-2147483647 -j MARK --set-xmark 1
			fi
			$ip6tables -t mangle -A OUTPUT -j "$MARK_CHAIN"
			$ip6tables -I FORWARD -j REJECT --reject-with icmp6-no-route 2>/dev/null
		fi # end xray-only block

		# Protect local proxy ports from bypass-mode apps
		read_app_filter
		protect_local_ports add

		# Publish the terminal lifecycle state. A bad config makes the core exit
		# within ~1s, so confirm it actually stayed up before reporting running.
		verify=0
		core_ok=0
		while [ "$verify" -lt 6 ]; do
			if pid_matches_bin "$CORE_PID" "$CORE_BIN"; then
				core_ok=1
			else
				core_ok=0
				break
			fi
			sleep 0.25
			verify=$((verify + 1))
		done
		if [ "$core_ok" = 1 ]; then
			set_service_state running
			log_info "$ENGINE running pid=$CORE_PID"
		else
			set_service_state "failed:core exited on startup — see $CORE_LOG"
			log_error "$ENGINE exited on startup — see $CORE_LOG"
		fi
	fi
	if [ "$content" = "stop" ]; then
		log_info "stopping proxy service"
		teardown_runtime
		set_service_state stopped
		log_info "proxy service stopped"
	fi
	if [ "$content" = "reload-app-filter" ]; then
		if get_status; then
			ENGINE=$(read_engine)
			if [ "$ENGINE" = "xray" ]; then
				log_info "reloading app filter rules (no core restart)"
				$iptables -t mangle -F "$MARK_CHAIN" 2>/dev/null
				$ip6tables -t mangle -F "$MARK_CHAIN" 2>/dev/null
				read_app_filter
				log_info "app filter reload: mode=$APP_CAPTURE_MODE"
				append_app_uid_rules "$iptables" "$MARK_CHAIN"
				append_app_uid_rules "$ip6tables" "$MARK_CHAIN"
				if [ "$APP_CAPTURE_MODE" = "all" ]; then
					$iptables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 1000 -j MARK --set-xmark 1
					$iptables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 9999-2147483647 -j MARK --set-xmark 1
					$ip6tables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 1000 -j MARK --set-xmark 1
					$ip6tables -t mangle -A "$MARK_CHAIN" -m owner --uid-owner 9999-2147483647 -j MARK --set-xmark 1
				fi
				log_info "app filter rules reloaded"
			else
				# sing-box: app filter is baked into config, requires full restart
				log_info "reload-app-filter: sing-box requires restart"
				echo "restart" >"$PIPE_FILE"
			fi
		else
			log_warn "reload-app-filter: service not running, skipping"
		fi
	fi
}

{
	# Keep the FIFO open and drain it line-by-line. A single writer session may
	# deliver several commands at once (e.g. stop\nwait\nstart); reading the whole
	# blob with `cat` would hand do_job a multi-line string that matches no branch.
	# Holding the read fd open across do_job also lets do_job re-queue commands
	# into the pipe (sing-box reload-app-filter) without deadlocking on open().
	while true; do
		while IFS= read -r line; do
			[ -n "$line" ] && do_job "$line"
		done <"$PIPE_FILE"
		sleep 0.1
	done
} &

# ===

get_active_interface() {
	for iface in /sys/class/net/*; do
		iface=$(basename "$iface")

		case "$iface" in
		wlan0 | eth0 | bt-pan | rmnet_data* | r_rmnet_data* | ccmni*)
			if $ip route show table "$iface" 2>/dev/null | grep -q '^default '; then
				echo "$iface"
				return 0
			fi
			;;
		esac
	done
}

apply_mark_rule() {
	local iface="$1"

	[ -z "$iface" ] && return 1

	remove_mark_rule

	$ip rule add fwmark $FWMARK table "$iface" priority $RULE_PRIORITY
	$ip -6 rule add fwmark 255 table "$iface" priority $RULE_PRIORITY
	log_info "applied: fwmark $FWMARK -> table $iface"
}

{
	on_boot_triggered=0
	last=""

	start_on_boot() {
		[ $on_boot_triggered = 1 ] && return
		on_boot_triggered=1
		# Respect the user's auto-start setting (default on).
		if [ "$(read_auto_start)" = "false" ]; then
			return
		fi
		# Either core's config present means a profile is active.
		if [ -e "$DATADIR/config.json" ] || [ -e "$DATADIR/singbox.json" ]; then
			log_info "auto-start: launching proxy on boot"
			echo "start" >"$PIPE_FILE"
			echo "wait" >"$PIPE_FILE"
		fi
	}

	while [ ! -f /data/misc/net/rt_tables ]; do
		sleep 1
	done
	lock_sysctl "1" "/proc/sys/net/ipv4/ip_forward"
	lock_sysctl "1" "/proc/sys/net/ipv6/conf/all/forwarding"
	lock_sysctl "1" "/proc/sys/net/ipv6/conf/default/forwarding"

	lock_sysctl "0" "/proc/sys/net/ipv4/conf/all/rp_filter"
	lock_sysctl "0" "/proc/sys/net/ipv4/conf/default/rp_filter"

	cur=$(get_active_interface)
	last="$cur"
	if [ -n "$cur" ]; then
		log_info "initial active interface: $cur"
		# apply iptables rules for the first time
		start_on_boot
		apply_mark_rule "$cur"
	else
		log_warn "no active interface detected at startup"
	fi

	inotifyd - /data/misc/net::w | while read -r _; do
		until [ -n "$(get_active_interface)" ]; do
			sleep 1
		done
		cur=$(get_active_interface)

		if [ "$cur" != "$last" ]; then
			log_info "network changed: $last -> $cur"
			last="$cur"
			if get_status; then
				log_info "network change: restarting proxy"
				echo "restart" >"$PIPE_FILE"
				echo "wait" >"$PIPE_FILE"
			fi
			start_on_boot

			# Remove the old rule
			# then add the new rule
			apply_mark_rule "$cur"
		fi
	done
} &

# Watchdog: if xray/sing-box or tun2socks crashes, flush iptables and stop cleanly.
{
	while true; do
		sleep 5
		refresh_runtime_pids
		[ "$CORE_PID" -le 0 ] && [ "$TUN2SOCKS_PID" -le 0 ] && continue
		core_dead=0
		tun_dead=0
		[ "$CORE_PID" -gt 0 ] && ! pid_matches_any_core "$CORE_PID" && core_dead=1
		[ "$TUN2SOCKS_PID" -gt 0 ] && ! pid_matches_bin "$TUN2SOCKS_PID" "$BINDIR/tun2socks" && tun_dead=1
		if [ "$core_dead" -eq 1 ] || [ "$tun_dead" -eq 1 ]; then
			log_error "watchdog: process died core_dead=$core_dead tun_dead=$tun_dead — flushing rules and stopping"
			echo "stop" >"$PIPE_FILE"
		fi
	done
} &

# ---- Subscription auto-update daemon --------------------------------------
# Backend half of the hybrid auto-update: for each enabled subscription with
# autoUpdate, once its interval (minutes) elapses since the last fetch, download
# the raw body into SUBCACHE_DIR. The UI parses & applies it on next launch.
# app-state.json is written compact by the UI; fields are pulled with sed (no jq),
# mirroring read_app_filter. Reuses kasumi-proxyctl fetchSubscription for the curl.
sub_autoupdate_tick() {
	[ -f "$STATE_FILE" ] || return
	mkdir -p "$SUBCACHE_DIR"
	now=$(date +%s)
	compact=$(tr -d '\r\n' <"$STATE_FILE" 2>/dev/null)
	subs=$(printf '%s' "$compact" | sed -n 's/.*"subscriptions":\[\(.*\)\],"routingRules".*/\1/p')
	[ -n "$subs" ] || return
	# One subscription object per line.
	printf '%s' "$subs" | sed 's/},{/}\
{/g' | while IFS= read -r obj; do
		case "$obj" in *'"autoUpdate":true'*) ;; *) continue ;; esac
		case "$obj" in *'"enabled":true'*) ;; *) continue ;; esac
		s_id=$(printf '%s' "$obj" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
		s_url=$(printf '%s' "$obj" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
		s_int=$(printf '%s' "$obj" | sed -n 's/.*"interval":\([0-9]*\).*/\1/p')
		s_ua=$(printf '%s' "$obj" | sed -n 's/.*"userAgent":"\([^"]*\)".*/\1/p')
		s_ai=0
		case "$obj" in *'"allowInsecure":true'*) s_ai=1 ;; esac
		[ -n "$s_id" ] && [ -n "$s_url" ] || continue
		case "$s_int" in (''|*[!0-9]*) s_int=0 ;; esac
		[ "$s_int" -gt 0 ] || continue
		case "$s_id" in (*/*|*..*) continue ;; esac
		fetched=$(cat "$SUBCACHE_DIR/$s_id.fetched" 2>/dev/null)
		case "$fetched" in (''|*[!0-9]*) fetched=0 ;; esac
		[ "$(( now - fetched ))" -ge "$(( s_int * 60 ))" ] || continue
		tmp="$SUBCACHE_DIR/$s_id.raw.tmp"
		if printf '%s' "$s_url" | "$BINDIR/kasumi-proxyctl" fetchSubscription "$s_ai" 0 "$s_ua" >"$tmp" 2>/dev/null && [ -s "$tmp" ]; then
			mv "$tmp" "$SUBCACHE_DIR/$s_id.raw"
			printf '%s' "$now" >"$SUBCACHE_DIR/$s_id.fetched"
			log_info "sub auto-update: fetched $s_id"
		else
			rm -f "$tmp"
			log_warn "sub auto-update: fetch failed for $s_id"
		fi
	done
}

# Poll the subscription schedule once a minute.
{
	while true; do
		sleep 60
		sub_autoupdate_tick
	done
} &

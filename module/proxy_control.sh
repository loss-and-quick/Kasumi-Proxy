#!/system/bin/sh
MODDIR=${0%/*}
PIDFILE="$MODDIR/run/core.pid"

PIPE_FILE="$MODDIR/run/control.pipe"
DATADIR="/data/adb/kasumi-proxy"
ENGINE_FILE="$DATADIR/engine"
mkdir -p "$DATADIR"
"$MODDIR/bin/kasumi-proxyctl" rotateLogs
exec >>"$DATADIR/proxy_control.log" 2>&1
echo "proxy_control.sh invoked (pid=$$, action=${1:-none})"

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
	pid_matches_bin "$pid" "$MODDIR/bin/xray" || pid_matches_bin "$pid" "$MODDIR/bin/sing-box"
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

wait_for_status() { # <running|stopped>
	want="$1"
	attempts=40
	while [ "$attempts" -gt 0 ]; do
		if get_status; then
			[ "$want" = "running" ] && return 0
		else
			[ "$want" = "stopped" ] && return 0
		fi
		sleep 0.25
		attempts=$((attempts - 1))
	done
	return 1
}

send_cmd() { # <command>
	cmd="$1"
	if [ ! -p "$PIPE_FILE" ]; then
		echo "Control pipe unavailable: $PIPE_FILE"
		return 1
	fi
	echo "Sending command to service: $cmd"
	(
		printf '%s\n' "$cmd" >"$PIPE_FILE"
	) &
	writer_pid=$!
	attempts=20
	while kill -0 "$writer_pid" 2>/dev/null && [ "$attempts" -gt 0 ]; do
		sleep 0.1
		attempts=$((attempts - 1))
	done
	if kill -0 "$writer_pid" 2>/dev/null; then
		echo "Timed out while writing '$cmd' to $PIPE_FILE"
		kill "$writer_pid" 2>/dev/null
		wait "$writer_pid" 2>/dev/null
		return 1
	fi
	wait "$writer_pid"
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "Command writer for '$cmd' exited with status $status"
		return "$status"
	fi
	echo "Command delivered: $cmd"
}

start_proxy() {
	echo "start_proxy requested"
	if get_status; then
		echo "Proxy core is already running with PID $(cat "$PIDFILE")"
		return 0
	fi

	# Start xray core / singbox and tun2socks in the background
	if ! send_cmd start; then
		echo "Failed to send start command to service"
		return 1
	fi
	if ! wait_for_status running; then
		echo "Proxy core failed to reach running state -- sending stop to flush rules"
		send_cmd stop
		return 1
	fi

	echo "Proxy core successfully running!"
}

stop_proxy() {
	echo "stop_proxy requested"
	# Stop xray core / singbox and tun2socks in the background
	if ! send_cmd stop; then
		echo "Failed to send stop command to service"
		return 1
	fi
	if ! wait_for_status stopped; then
		echo "Proxy core failed to stop"
		return 1
	fi

	echo "Proxy core successfully stopped!"
}

case "$1" in
start) start_proxy ;;
stop)
	stop_proxy
	rm -f "$DATADIR/config.json" "$DATADIR/singbox.json" "$ENGINE_FILE"
	echo "Cleared active config files after stop"
	;;
restart)
	echo "restart requested"
	stop_proxy
	sleep 1
	start_proxy
	;;
status)
	if get_status; then
		echo "running"
	else
		echo "stopped"
	fi
	;;
esac

#!/system/bin/sh
# Launch the kasumi-proxy daemon (single binary). The daemon does its own boot
# wait (rt_tables), sysctl locks, control socket, WS server, lifecycle, watchdog
# and subscription auto-update.
MODDIR=${0%/*}
DATADIR="/data/adb/kasumi-proxy"
mkdir -p "$DATADIR"
KASUMI_SCRIPT="service.sh"
. "$MODDIR/log.sh"

# Trimming before the daemon starts is what keeps yesterday's log from still
# being the first thing a support request shows.
if ! "$MODDIR/bin/kasumi-proxy" rotateLogs >/dev/null 2>&1; then
	klog WARN "rotateLogs failed; the log keeps growing until the next boot"
fi

# stderr goes to daemon.log, which is also where panics and anything printed
# outside the facade end up — that is why the daemon logs to stderr.
"$MODDIR/bin/kasumi-proxy" daemon >>"$DATADIR/daemon.log" 2>&1 &
klog INFO "daemon started (pid $!)"
#!/system/bin/sh
# Launch the kasumi-proxy daemon (single binary). The daemon does its own boot
# wait (rt_tables), sysctl locks, control socket, WS server, lifecycle, watchdog
# and subscription auto-update.
MODDIR=${0%/*}
DATADIR="/data/adb/kasumi-proxy"
mkdir -p "$DATADIR"
"$MODDIR/bin/kasumi-proxy" rotateLogs >/dev/null 2>&1
"$MODDIR/bin/kasumi-proxy" daemon >>"$DATADIR/daemon.log" 2>&1 &

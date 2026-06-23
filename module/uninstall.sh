#!/system/bin/sh
# Stop the daemon and tear down its routing/TUN/iptables before dropping state.
# `kasumi-proxy stop` kills the running daemon (so its watchdog can't restart the
# proxy) and runs the idempotent data-path teardown; then we remove the data dir.
DIR=${0%/*}
[ -x "$DIR/bin/kasumi-proxy" ] && "$DIR/bin/kasumi-proxy" stop >/dev/null 2>&1
rm -rf /data/adb/kasumi-proxy

#!/system/bin/sh

MODDIR=${0%/*}
PIPE_FILE="$MODDIR/run/control.pipe"
MAGISK_TOKEN="__SECRET_TOKEN__"

echo start_httpd >"$PIPE_FILE"
am start -a android.intent.action.VIEW -d "http://127.17.1.3:80/?token=$MAGISK_TOKEN" >/dev/null 2>&1

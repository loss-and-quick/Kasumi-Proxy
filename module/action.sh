#!/system/bin/sh
# Open the WebUI in the browser. The daemon serves webroot/ over loopback HTTP
# next to its WS endpoint; the {port, token} bootstrap is the ws.json it writes
# on startup. (`am start ksu://…` is not a thing — manager WebUIs can only be
# entered by hand, so the action button goes through the browser instead.)
WS_INFO="/data/adb/kasumi-proxy/run/ws.json"

if [ ! -f "$WS_INFO" ]; then
	echo "! kasumi-proxy daemon is not running (no $WS_INFO)"
	echo "  Reboot to start it."
	exit 1
fi

PORT=$(sed -n 's/.*"port":\([0-9][0-9]*\).*/\1/p' "$WS_INFO")
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$WS_INFO")
if [ -z "$PORT" ] || [ -z "$TOKEN" ]; then
	echo "! malformed $WS_INFO"
	exit 1
fi

am start -a android.intent.action.VIEW -d "http://127.0.0.1:$PORT/?token=$TOKEN" >/dev/null 2>&1
echo "- WebUI: http://127.0.0.1:$PORT/"

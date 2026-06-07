#!/system/bin/sh
# shellcheck disable=SC2034 # Magisk installer reads this flag from the script environment.
SKIPUNZIP=1

mkdir -p "$MODPATH/bin"
mkdir -p "$MODPATH/webroot"

ui_print "- Detected Architecture: $ARCH"

# 2. Extract only the matching binary directly into the module's private directory
case "$ARCH" in
arm64)
	ui_print "- Extracting Xray-core for arm64-v8a..."
	unzip -j -o "$ZIPFILE" "bin/arm64-v8a/*" -d "$MODPATH/bin"
	;;
x64)
	ui_print "- Extracting Xray-core for Android-x86_64..."
	unzip -j -o "$ZIPFILE" "bin/x86_64/*" -d "$MODPATH/bin"
	;;
*)
	ui_print "❌ Unsupported CPU architecture: $ARCH"
	abort "Unsupported device target!"
	;;
esac

# 3. Extract core scripts, webroot UI files and structural assets
ui_print "- Extracting management scripts and Webroot components..."
unzip -o "$ZIPFILE" "webroot/*" -d "$MODPATH/"
unzip -j -o "$ZIPFILE" "proxy_control.sh" -d "$MODPATH"
unzip -j -o "$ZIPFILE" "service.sh" -d "$MODPATH"
unzip -j -o "$ZIPFILE" "action.sh" -d "$MODPATH"
unzip -j -o "$ZIPFILE" "bin/kasumi-proxyctl" -d "$MODPATH/bin"
unzip -j -o "$ZIPFILE" "module.prop" -d "$MODPATH"

# 4. Enforce strict executable permissions natively
ui_print "- Setting executable permissions..."
chmod 755 "$MODPATH/bin/"*
chmod 755 "$MODPATH/bin/kasumi-proxyctl"

ui_print "- Setup /data/adb/kasumi-proxy directory"
# Keep any existing state across re-installs/upgrades; only create when absent.
mkdir -p "/data/adb/kasumi-proxy"

ui_print "- Setup secret token for files"
RANDOM_TOKEN=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 150 | head -n 1)
FILE_ACTION="$MODPATH/action.sh"
FILE_CGI="$MODPATH/webroot/cgi-bin/exec"
[ -f "$FILE_ACTION" ] && sed -i "s/__SECRET_TOKEN__/$RANDOM_TOKEN/g" "$FILE_ACTION"
[ -f "$FILE_CGI" ] && sed -i "s/__SECRET_TOKEN__/$RANDOM_TOKEN/g" "$FILE_CGI"
chmod 755 "$FILE_CGI"

ui_print "Kasumi Proxy configuration deployment complete!"

# Grant camera permission to root manager apps so QR scanner works
ui_print "- Granting camera permission to root manager..."
for pkg in \
	com.topjohnwu.magisk \
	me.weishu.kernelsu \
	me.bmax.superuser \
	com.rifsxd.kasuinext \
	io.github.huskydg.magisk \
	com.apatch.apm; do
	if pm list packages 2>/dev/null | grep -qF "$pkg"; then
		pm grant "$pkg" android.permission.CAMERA 2>/dev/null
		ui_print "  granted CAMERA -> $pkg"
	fi
done

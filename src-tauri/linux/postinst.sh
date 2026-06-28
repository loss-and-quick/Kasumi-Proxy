#!/bin/sh
# Grant the data-path helper its Linux file capabilities at install time, so the GUI
# can launch it directly — no pkexec prompt — on a packaged install (deb/rpm). The cap
# set mirrors the helper's in-code keep-set (see src/desktop/capabilities.rs) and the
# NixOS `security.wrappers` string. Other installs do the same once at first run via a
# `pkexec setcap` (see privhelper::spawn); NixOS uses the wrapper.
#
# Best-effort: a setcap failure (no libcap, a filesystem without xattrs) leaves the
# GUI to fall back to per-launch root elevation, so never fail the install.
set -e

caps="cap_net_admin,cap_net_raw,cap_chown,cap_dac_override+ep"

if command -v setcap >/dev/null 2>&1; then
    # The helper ships as a tauri sidecar beside the GUI; cover both layouts tauri
    # may use (next to the binary, or under the product libdir).
    for helper in /usr/bin/kasumi-helper "/usr/lib/Kasumi Proxy/kasumi-helper"; do
        if [ -f "$helper" ]; then
            setcap "$caps" "$helper" || true
        fi
    done
fi

exit 0

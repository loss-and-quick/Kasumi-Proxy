//! OS system-proxy integration for the `system` proxy mode: point the OS proxy at
//! the core's local inbound and clear it again.
//!
//! Linux has no single system-proxy store, so the apply/clear pipeline is *layered*
//! and the layers are NOT mutually exclusive — each reaches a disjoint set of apps:
//!   1. **gsettings `org.gnome.system.proxy`** (guarded by schema presence) — covers
//!      GNOME, MATE, Cinnamon, Budgie, and every GLib/GIO + Chromium-family app on
//!      any desktop where the schema is installed (most XFCE/LXQt/LXDE too).
//!   2. **kwriteconfig `kioslaverc`** on KDE/Plasma, followed by a
//!      `reparseSlaveConfiguration` D-Bus signal so KIO apps reload.
//!   3. **environment variables** (`~/.config/environment.d` for persistence + a live
//!      `systemctl --user`/`dbus-update-activation-environment` push) — the only layer
//!      that reaches CLI tools and non-GLib apps, and the only programmatic mechanism
//!      for XFCE/LXQt/LXDE.
//!
//! Windows uses the WinINET registry keys plus an `InternetSetOption` refresh so the
//! change takes effect without a sign-out. macOS has no port yet (no-op).
//!
//! This module runs in the GUI process — the logged-in user — never in the
//! privileged data-path helper: the OS proxy lives in that user's session
//! (gsettings/D-Bus/HKCU), which root's session isn't.

#[cfg(target_os = "linux")]
pub use linux::{clear_system_proxy, set_system_proxy};
#[cfg(target_os = "windows")]
pub use windows::{clear_system_proxy, set_system_proxy};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use other::{clear_system_proxy, set_system_proxy};

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use crate::desktop::{run_out, silent};

    const HOST: &str = "127.0.0.1";
    const IGNORE_GNOME: &str = "['localhost', '127.0.0.0/8', '::1']";
    const IGNORE_KDE: &str = "localhost,127.0.0.1,::1";
    const NO_PROXY: &str = "localhost,127.0.0.1,::1";

    /// Proxy env vars, lower- and upper-case (programs disagree on which they read).
    const ENV_KEYS: &[&str] = &[
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];
    /// Persistent per-user env file (systemd user generator reads `environment.d`).
    const ENV_FILE_REL: &str = ".config/environment.d/50-kasumi-proxy.conf";

    // ── apply / clear: run EVERY applicable layer, not just the first match ──

    /// Point the OS at the local socks/http inbound. `http_port` carries http + https,
    /// `socks_port` the socks proxy (a sing-box mixed inbound passes the same for both).
    pub async fn set_system_proxy(socks_port: u16, http_port: u16) {
        gsettings_manual(socks_port, http_port).await;
        kde_manual(socks_port, http_port).await;
        env_apply(socks_port, http_port).await;
    }

    /// Disable every layer. Idempotent — safe whatever was (or wasn't) set.
    pub async fn clear_system_proxy() {
        gsettings_none().await;
        kde_none().await;
        env_clear().await;
    }

    // ── layer 1: gsettings (GNOME schema), guarded by schema presence ──

    /// Only call gsettings when the proxy schema is installed, so minimal systems
    /// (no `gsettings-desktop-schemas`) don't spew errors.
    async fn gnome_schema_present() -> bool {
        let (code, out) = run_out(&["gsettings", "list-schemas"]).await;
        code == 0 && out.lines().any(|l| l.trim() == "org.gnome.system.proxy")
    }

    async fn gsettings(args: &[&str]) {
        let mut argv = vec!["gsettings", "set"];
        argv.extend_from_slice(args);
        silent(&argv).await;
    }

    async fn gsettings_manual(socks_port: u16, http_port: u16) {
        if !gnome_schema_present().await {
            return;
        }
        let http = http_port.to_string();
        let socks = socks_port.to_string();
        gsettings(&["org.gnome.system.proxy", "mode", "manual"]).await;
        for schema in [
            "org.gnome.system.proxy.http",
            "org.gnome.system.proxy.https",
        ] {
            gsettings(&[schema, "host", HOST]).await;
            gsettings(&[schema, "port", &http]).await;
        }
        gsettings(&["org.gnome.system.proxy.socks", "host", HOST]).await;
        gsettings(&["org.gnome.system.proxy.socks", "port", &socks]).await;
        gsettings(&["org.gnome.system.proxy", "ignore-hosts", IGNORE_GNOME]).await;
    }

    async fn gsettings_none() {
        if !gnome_schema_present().await {
            return;
        }
        gsettings(&["org.gnome.system.proxy", "mode", "none"]).await;
    }

    // ── layer 2: KDE kioslaverc (+ reparse so KIO apps reload) ──

    /// True on a KDE/Plasma session.
    fn is_kde() -> bool {
        std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("kde")
    }

    /// The KDE config writer present on this host (Plasma 6 → `kwriteconfig6`, 5 → 5).
    fn kde_writer() -> Option<&'static str> {
        ["kwriteconfig6", "kwriteconfig5"]
            .into_iter()
            .find(|bin| which(bin))
    }

    fn which(bin: &str) -> bool {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .any(|dir| std::path::Path::new(dir).join(bin).exists())
    }

    async fn kde_manual(socks_port: u16, http_port: u16) {
        let Some(w) = (is_kde().then(kde_writer)).flatten() else {
            return;
        };
        kde(w, "ProxyType", "1").await;
        kde(w, "httpProxy", &format!("http://{HOST} {http_port}")).await;
        kde(w, "httpsProxy", &format!("http://{HOST} {http_port}")).await;
        kde(w, "socksProxy", &format!("socks://{HOST} {socks_port}")).await;
        kde(w, "NoProxyFor", IGNORE_KDE).await;
        kde_reparse().await;
    }

    async fn kde_none() {
        let Some(w) = (is_kde().then(kde_writer)).flatten() else {
            return;
        };
        kde(w, "ProxyType", "0").await;
        kde_reparse().await;
    }

    async fn kde(writer: &str, key: &str, value: &str) {
        silent(&[
            writer,
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
            value,
        ])
        .await;
    }

    /// Without this signal KIO apps keep the old proxy until restart.
    async fn kde_reparse() {
        silent(&[
            "dbus-send",
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:",
        ])
        .await;
    }

    // ── layer 3: environment variables (CLI + non-GLib apps; the only XFCE/LXQt path) ──

    fn env_file() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(ENV_FILE_REL))
    }

    /// Persist the proxy env vars (`environment.d`, survives re-login) and push them
    /// live into the running session (systemd user manager + D-Bus activation env).
    async fn env_apply(socks_port: u16, http_port: u16) {
        let http_url = format!("http://{HOST}:{http_port}");
        let socks_url = format!("socks5://{HOST}:{socks_port}");
        let assigns = [
            format!("http_proxy={http_url}"),
            format!("https_proxy={http_url}"),
            format!("all_proxy={socks_url}"),
            format!("no_proxy={NO_PROXY}"),
            format!("HTTP_PROXY={http_url}"),
            format!("HTTPS_PROXY={http_url}"),
            format!("ALL_PROXY={socks_url}"),
            format!("NO_PROXY={NO_PROXY}"),
        ];

        if let Some(path) = env_file() {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&path, format!("{}\n", assigns.join("\n")));
        }

        let refs: Vec<&str> = assigns.iter().map(String::as_str).collect();
        run_with(&["systemctl", "--user", "set-environment"], &refs).await;
        run_with(&["dbus-update-activation-environment", "--systemd"], &refs).await;
    }

    /// Remove the persistent file and unset the vars in the live session. D-Bus can't
    /// truly unset, so it gets the vars emptied; systemd does the real unset.
    async fn env_clear() {
        if let Some(path) = env_file() {
            let _ = std::fs::remove_file(path);
        }
        run_with(&["systemctl", "--user", "unset-environment"], ENV_KEYS).await;
        let empties: Vec<String> = ENV_KEYS.iter().map(|k| format!("{k}=")).collect();
        let refs: Vec<&str> = empties.iter().map(String::as_str).collect();
        run_with(&["dbus-update-activation-environment", "--systemd"], &refs).await;
    }

    /// Run `base` with `extra` args appended (one process, args owned by the caller).
    async fn run_with(base: &[&str], extra: &[&str]) {
        let mut argv = base.to_vec();
        argv.extend_from_slice(extra);
        silent(&argv).await;
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::c_void;

    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, REG_DWORD, REG_SZ, RegSetKeyValueW,
    };

    const HOST: &str = "127.0.0.1";
    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const OVERRIDE: &str = "localhost;127.*;<local>";

    /// `s` as a NUL-terminated UTF-16 buffer for the Win32 `*W` APIs.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Write a `REG_SZ` value under the Internet Settings key.
    fn set_sz(name: &str, value: &str) {
        let sub = wide(SUBKEY);
        let n = wide(name);
        let v = wide(value);
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                REG_SZ,
                v.as_ptr() as *const c_void,
                (v.len() * 2) as u32,
            );
        }
    }

    /// Write a `REG_DWORD` value under the Internet Settings key.
    fn set_dword(name: &str, value: u32) {
        let sub = wide(SUBKEY);
        let n = wide(name);
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                REG_DWORD,
                &value as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );
        }
    }

    /// Tell WinINET to re-read the settings so the change is live immediately.
    fn refresh() {
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
    }

    pub async fn set_system_proxy(socks_port: u16, http_port: u16) {
        let server =
            format!("http={HOST}:{http_port};https={HOST}:{http_port};socks={HOST}:{socks_port}");
        set_sz("AutoConfigURL", "");
        set_sz("ProxyServer", &server);
        set_sz("ProxyOverride", OVERRIDE);
        set_dword("ProxyEnable", 1);
        refresh();
    }

    pub async fn clear_system_proxy() {
        set_dword("ProxyEnable", 0);
        set_sz("AutoConfigURL", "");
        refresh();
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod other {
    pub async fn set_system_proxy(_socks_port: u16, _http_port: u16) {}
    pub async fn clear_system_proxy() {}
}

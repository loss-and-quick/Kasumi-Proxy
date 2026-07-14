//! OS system-proxy integration for the `system` and `pac` proxy modes: point the
//! OS proxy (or PAC auto-config URL) at the core's local inbound and clear it
//! again.
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
//! **Ownership record.** Applying our proxy over a proxy the user configured by hand
//! would silently wipe theirs. To avoid that, the first apply snapshots the current
//! OS proxy state per layer into an ownership record (`os-proxy-backup.json` in the
//! datadir); its presence marks the current OS proxy as ours. Clearing restores every
//! layer from that snapshot and deletes the record; with no record we touch nothing.
//! The record lives in the datadir (not the run dir) so it survives a reboot, letting
//! the next start recover a proxy left behind by a hard crash.
//!
//! This module runs in the GUI process — the logged-in user — never in the
//! privileged data-path helper: the OS proxy lives in that user's session
//! (gsettings/D-Bus/HKCU), which root's session isn't.

#[cfg(target_os = "linux")]
pub use linux::{clear_system_proxy, set_pac, set_system_proxy};
#[cfg(target_os = "windows")]
pub use windows::{clear_system_proxy, set_pac, set_system_proxy};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use other::{clear_system_proxy, set_pac, set_system_proxy};

// ── ownership record: the versioned per-layer snapshot that marks the OS proxy ours ──

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod backup {
    use std::path::{Path, PathBuf};

    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};

    use crate::desktop::paths::DesktopPaths;

    /// Bumped whenever a layer snapshot's shape changes; an older/newer record then
    /// reads as corrupt and the clear falls back to a blanket disable.
    const VERSION: u32 = 1;

    /// The ownership record file, in the datadir so it outlives a reboot.
    const FILE_NAME: &str = "os-proxy-backup.json";

    /// The on-disk record: a version tag plus the platform's per-layer snapshot,
    /// taken just before the app first applied its own proxy.
    #[derive(Serialize, Deserialize)]
    struct ProxyBackup<S> {
        version: u32,
        layers: S,
    }

    /// What an apply should do given whether a record already exists.
    pub enum ApplyDecision {
        /// No record yet — snapshot the live OS state, then apply ours.
        Snapshot,
        /// A record already marks the OS proxy ours — apply ours without
        /// re-snapshotting (re-snapshotting would capture our own settings).
        ApplyOnly,
    }

    /// What a clear should do given the record's content.
    pub enum ClearDecision<S> {
        /// A parseable record — restore each layer from `S`, then delete it.
        Restore(S),
        /// A record exists but can't be parsed — blanket-disable, then delete it.
        BlankClear,
        /// No record — the current OS proxy isn't ours; leave it untouched.
        Noop,
    }

    pub fn decide_apply(record_present: bool) -> ApplyDecision {
        if record_present {
            ApplyDecision::ApplyOnly
        } else {
            ApplyDecision::Snapshot
        }
    }

    pub fn decide_clear<S: DeserializeOwned>(raw: Option<&str>) -> ClearDecision<S> {
        match raw {
            None => ClearDecision::Noop,
            Some(s) => match serde_json::from_str::<ProxyBackup<S>>(s) {
                Ok(b) if b.version == VERSION => ClearDecision::Restore(b.layers),
                _ => ClearDecision::BlankClear,
            },
        }
    }

    /// The record path, or `None` when the datadir can't be resolved — the caller
    /// then degrades to a blanket clear rather than consulting a record.
    pub fn record_path() -> Option<PathBuf> {
        DesktopPaths::resolve()
            .ok()
            .map(|p| PathBuf::from(p.datadir).join(FILE_NAME))
    }

    pub fn read_raw(path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    pub fn write<S: Serialize>(path: &Path, layers: &S) {
        let record = ProxyBackup {
            version: VERSION,
            layers,
        };
        if let Ok(json) = serde_json::to_string_pretty(&record) {
            let _ = std::fs::write(path, json);
        }
    }

    pub fn delete(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Default)]
        struct FakeLayers {
            enabled: bool,
            server: String,
        }

        fn record_json(version: u32, server: &str) -> String {
            format!(
                "{{\"version\":{version},\"layers\":{{\"enabled\":true,\"server\":\"{server}\"}}}}"
            )
        }

        #[test]
        fn round_trips_through_the_record() {
            let layers = FakeLayers {
                enabled: true,
                server: "127.0.0.1:8080".into(),
            };
            let json = serde_json::to_string(&ProxyBackup {
                version: VERSION,
                layers: &layers,
            })
            .unwrap();
            assert!(json.contains("\"version\":1"));
            match decide_clear::<FakeLayers>(Some(&json)) {
                ClearDecision::Restore(got) => assert_eq!(got, layers),
                _ => panic!("a well-formed current-version record should restore"),
            }
        }

        #[test]
        fn absent_record_is_a_noop() {
            assert!(matches!(
                decide_clear::<FakeLayers>(None),
                ClearDecision::Noop
            ));
        }

        #[test]
        fn corrupt_record_falls_back_to_blank_clear() {
            assert!(matches!(
                decide_clear::<FakeLayers>(Some("{ this is not json")),
                ClearDecision::BlankClear
            ));
        }

        #[test]
        fn wrong_version_reads_as_corrupt() {
            let json = record_json(VERSION + 1, "1.2.3.4:9");
            assert!(matches!(
                decide_clear::<FakeLayers>(Some(&json)),
                ClearDecision::BlankClear
            ));
        }

        #[test]
        fn apply_snapshots_only_when_no_record_exists() {
            assert!(matches!(decide_apply(false), ApplyDecision::Snapshot));
            assert!(matches!(decide_apply(true), ApplyDecision::ApplyOnly));
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    use super::backup::{self, ApplyDecision, ClearDecision};
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

    /// The gsettings proxy keys captured in a snapshot: mode + auto-config + ignore
    /// list on the parent schema, host + port on each protocol child.
    const GSETTINGS_KEYS: &[(&str, &str)] = &[
        ("org.gnome.system.proxy", "mode"),
        ("org.gnome.system.proxy", "autoconfig-url"),
        ("org.gnome.system.proxy", "ignore-hosts"),
        ("org.gnome.system.proxy.http", "host"),
        ("org.gnome.system.proxy.http", "port"),
        ("org.gnome.system.proxy.https", "host"),
        ("org.gnome.system.proxy.https", "port"),
        ("org.gnome.system.proxy.socks", "host"),
        ("org.gnome.system.proxy.socks", "port"),
    ];

    /// The KDE `kioslaverc` proxy keys captured in a snapshot.
    const KDE_KEYS: &[&str] = &[
        "ProxyType",
        "httpProxy",
        "httpsProxy",
        "socksProxy",
        "NoProxyFor",
        "Proxy Config Script",
    ];

    /// One captured `schema key value` triple for the gsettings layer.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    struct GEntry {
        schema: String,
        key: String,
        value: String,
    }

    /// One captured `key value` pair for the KDE and env layers.
    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    struct Kv {
        key: String,
        value: String,
    }

    /// The per-layer OS proxy state captured just before the app applies its own.
    /// `None` for a layer means it doesn't apply on this host (no schema / not KDE)
    /// and is skipped on restore.
    #[derive(Serialize, Deserialize, Default)]
    struct Snapshot {
        gsettings: Option<Vec<GEntry>>,
        kde: Option<Vec<Kv>>,
        env: Vec<Kv>,
    }

    // ── apply / clear: run EVERY applicable layer, not just the first match ──

    /// Point the OS at the local socks/http inbound. `http_port` carries http + https,
    /// `socks_port` the socks proxy (a sing-box mixed inbound passes the same for both).
    pub async fn set_system_proxy(socks_port: u16, http_port: u16) {
        ensure_backup().await;
        gsettings_manual(socks_port, http_port).await;
        kde_manual(socks_port, http_port).await;
        env_apply(socks_port, http_port).await;
    }

    /// Point the OS at a PAC auto-config URL (`pac` mode). Env vars can't express a
    /// PAC, so the env layer is cleared rather than set.
    pub async fn set_pac(pac_url: &str) {
        ensure_backup().await;
        gsettings_auto(pac_url).await;
        kde_pac(pac_url).await;
        env_clear().await;
    }

    /// Restore the pre-app OS proxy from the ownership record and drop it; with no
    /// record the current proxy isn't ours, so leave it be. A record that can't be
    /// read falls back to a blanket disable.
    pub async fn clear_system_proxy() {
        let Some(path) = backup::record_path() else {
            blank_clear().await;
            return;
        };
        match backup::decide_clear::<Snapshot>(backup::read_raw(&path).as_deref()) {
            ClearDecision::Restore(snap) => {
                restore(&snap).await;
                backup::delete(&path);
            }
            ClearDecision::BlankClear => {
                blank_clear().await;
                backup::delete(&path);
            }
            ClearDecision::Noop => {}
        }
    }

    /// Snapshot the current OS proxy on the first apply (no record yet). A later apply
    /// (restart / profile switch) finds the record present and skips this, so the
    /// snapshot always captures the user's state rather than ours.
    async fn ensure_backup() {
        let Some(path) = backup::record_path() else {
            return;
        };
        if let ApplyDecision::Snapshot = backup::decide_apply(path.exists()) {
            let snap = snapshot().await;
            backup::write(&path, &snap);
        }
    }

    async fn snapshot() -> Snapshot {
        Snapshot {
            gsettings: gsettings_snapshot().await,
            kde: kde_snapshot().await,
            env: env_snapshot().await,
        }
    }

    async fn restore(snap: &Snapshot) {
        restore_gsettings(snap.gsettings.as_deref()).await;
        restore_kde(snap.kde.as_deref()).await;
        restore_env(&snap.env).await;
    }

    /// Disable every layer. Idempotent — safe whatever was (or wasn't) set.
    async fn blank_clear() {
        gsettings_none().await;
        kde_none().await;
        env_clear().await;
    }

    // ── layer 1: gsettings (GNOME schema), guarded by schema presence ──

    /// Only touch gsettings when the proxy schema is installed, so minimal systems
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

    async fn gsettings_auto(pac_url: &str) {
        if !gnome_schema_present().await {
            return;
        }
        gsettings(&["org.gnome.system.proxy", "mode", "auto"]).await;
        gsettings(&["org.gnome.system.proxy", "autoconfig-url", pac_url]).await;
    }

    async fn gsettings_none() {
        if !gnome_schema_present().await {
            return;
        }
        gsettings(&["org.gnome.system.proxy", "mode", "none"]).await;
    }

    /// Capture the gsettings proxy keys, or `None` when the schema is absent.
    /// `gsettings get` serializes string scalars single-quoted; those quotes are
    /// stripped so restore can pass the raw value back to `gsettings set`.
    async fn gsettings_snapshot() -> Option<Vec<GEntry>> {
        if !gnome_schema_present().await {
            return None;
        }
        let mut out = Vec::new();
        for (schema, key) in GSETTINGS_KEYS {
            let (code, raw) = run_out(&["gsettings", "get", schema, key]).await;
            if code == 0 {
                out.push(GEntry {
                    schema: (*schema).to_string(),
                    key: (*key).to_string(),
                    value: unquote(&raw),
                });
            }
        }
        Some(out)
    }

    /// Write each captured gsettings value back; if any write fails, disable the
    /// layer rather than leave it half-restored.
    async fn restore_gsettings(entries: Option<&[GEntry]>) {
        let Some(entries) = entries else {
            return;
        };
        let mut ok = true;
        for e in entries {
            if silent(&["gsettings", "set", &e.schema, &e.key, &e.value]).await != 0 {
                ok = false;
            }
        }
        if !ok {
            gsettings_none().await;
        }
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

    /// The KDE config reader matching the writer generation.
    fn kde_reader() -> Option<&'static str> {
        ["kreadconfig6", "kreadconfig5"]
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

    async fn kde_pac(pac_url: &str) {
        let Some(w) = (is_kde().then(kde_writer)).flatten() else {
            return;
        };
        kde(w, "ProxyType", "2").await;
        kde(w, "Proxy Config Script", pac_url).await;
        kde_reparse().await;
    }

    async fn kde_none() {
        let Some(w) = (is_kde().then(kde_writer)).flatten() else {
            return;
        };
        kde(w, "ProxyType", "0").await;
        kde_reparse().await;
    }

    async fn kde(writer: &str, key: &str, value: &str) -> i32 {
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
        .await
    }

    /// Capture the KDE proxy keys, or `None` off KDE / with no writer present. Keys
    /// absent from `kioslaverc` read as empty, which restore writes back verbatim.
    async fn kde_snapshot() -> Option<Vec<Kv>> {
        if !is_kde() || kde_writer().is_none() {
            return None;
        }
        let reader = kde_reader()?;
        let mut out = Vec::new();
        for key in KDE_KEYS {
            let (_, raw) = run_out(&[
                reader,
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                key,
            ])
            .await;
            out.push(Kv {
                key: (*key).to_string(),
                value: raw.trim_end_matches('\n').to_string(),
            });
        }
        Some(out)
    }

    /// Write each captured KDE value back and reparse; a failed write disables the
    /// layer rather than leave it half-restored.
    async fn restore_kde(entries: Option<&[Kv]>) {
        let Some(entries) = entries else {
            return;
        };
        let Some(w) = kde_writer() else {
            return;
        };
        let mut ok = true;
        for kv in entries {
            if kde(w, &kv.key, &kv.value).await != 0 {
                ok = false;
            }
        }
        if !ok {
            let _ = kde(w, "ProxyType", "0").await;
        }
        kde_reparse().await;
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

    /// Capture the live-session values of the proxy env vars we clobber. The
    /// persistent `environment.d` file is ours by name and never snapshotted (it is
    /// simply removed on restore).
    async fn env_snapshot() -> Vec<Kv> {
        let (code, out) = run_out(&["systemctl", "--user", "show-environment"]).await;
        if code != 0 {
            return Vec::new();
        }
        filter_env(&out)
    }

    /// Restore the live-session proxy env vars: set the ones that existed, unset the
    /// rest, drop our persistent file, then push the result to the D-Bus activation
    /// environment (which can only empty, not unset).
    async fn restore_env(snap: &[Kv]) {
        if let Some(path) = env_file() {
            let _ = std::fs::remove_file(path);
        }

        let present: Vec<&str> = snap.iter().map(|kv| kv.key.as_str()).collect();
        let sets: Vec<String> = snap
            .iter()
            .map(|kv| format!("{}={}", kv.key, kv.value))
            .collect();
        if !sets.is_empty() {
            let refs: Vec<&str> = sets.iter().map(String::as_str).collect();
            run_with(&["systemctl", "--user", "set-environment"], &refs).await;
        }

        let absent: Vec<&str> = ENV_KEYS
            .iter()
            .copied()
            .filter(|k| !present.contains(k))
            .collect();
        if !absent.is_empty() {
            run_with(&["systemctl", "--user", "unset-environment"], &absent).await;
        }

        let mut pushes = sets;
        pushes.extend(absent.iter().map(|k| format!("{k}=")));
        let refs: Vec<&str> = pushes.iter().map(String::as_str).collect();
        run_with(&["dbus-update-activation-environment", "--systemd"], &refs).await;
    }

    /// Run `base` with `extra` args appended (one process, args owned by the caller).
    async fn run_with(base: &[&str], extra: &[&str]) {
        let mut argv = base.to_vec();
        argv.extend_from_slice(extra);
        silent(&argv).await;
    }

    // ── pure helpers ──

    /// Strip the single quotes `gsettings get` wraps string scalars in. Non-quoted
    /// values (ints, array literals) pass through unchanged.
    fn unquote(s: &str) -> String {
        let t = s.trim();
        if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
            t[1..t.len() - 1].to_string()
        } else {
            t.to_string()
        }
    }

    /// Keep only the proxy env vars from `systemctl --user show-environment` output
    /// (`KEY=value` per line), preserving their captured values.
    fn filter_env(show_output: &str) -> Vec<Kv> {
        show_output
            .lines()
            .filter_map(|line| {
                let (k, v) = line.split_once('=')?;
                ENV_KEYS.contains(&k).then(|| Kv {
                    key: k.to_string(),
                    value: v.to_string(),
                })
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unquote_strips_gsettings_string_scalars() {
            assert_eq!(unquote("'manual'"), "manual");
            assert_eq!(unquote("  '127.0.0.1'\n"), "127.0.0.1");
            assert_eq!(unquote("''"), "");
        }

        #[test]
        fn unquote_leaves_ints_and_arrays_intact() {
            assert_eq!(unquote("8080"), "8080");
            assert_eq!(
                unquote("['localhost', '127.0.0.0/8', '::1']"),
                "['localhost', '127.0.0.0/8', '::1']"
            );
        }

        #[test]
        fn filter_env_keeps_only_proxy_keys() {
            let out = "LANG=en_US.UTF-8\n\
                       http_proxy=http://127.0.0.1:10809\n\
                       PATH=/usr/bin\n\
                       NO_PROXY=localhost,127.0.0.1\n";
            let got = filter_env(out);
            assert_eq!(
                got,
                vec![
                    Kv {
                        key: "http_proxy".into(),
                        value: "http://127.0.0.1:10809".into()
                    },
                    Kv {
                        key: "NO_PROXY".into(),
                        value: "localhost,127.0.0.1".into()
                    },
                ]
            );
        }

        #[test]
        fn filter_env_handles_values_with_equals_signs() {
            let out = "all_proxy=socks5://127.0.0.1:10808?k=v\n";
            let got = filter_env(out);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].value, "socks5://127.0.0.1:10808?k=v");
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::c_void;

    use serde::{Deserialize, Serialize};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
        RegSetKeyValueW,
    };

    use super::backup::{self, ApplyDecision, ClearDecision};

    const HOST: &str = "127.0.0.1";
    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const OVERRIDE: &str = "localhost;127.*;<local>";

    /// The WinINET proxy keys captured just before the app applies its own.
    #[derive(Serialize, Deserialize, Default)]
    struct Snapshot {
        proxy_enable: Option<u32>,
        proxy_server: Option<String>,
        proxy_override: Option<String>,
        auto_config_url: Option<String>,
    }

    /// `s` as a NUL-terminated UTF-16 buffer for the Win32 `*W` APIs.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Write a `REG_SZ` value under the Internet Settings key. Returns whether it
    /// succeeded.
    fn set_sz(name: &str, value: &str) -> bool {
        let sub = wide(SUBKEY);
        let n = wide(name);
        let v = wide(value);
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                REG_SZ,
                v.as_ptr() as *const c_void,
                (v.len() * 2) as u32,
            )
        };
        status == ERROR_SUCCESS
    }

    /// Write a `REG_DWORD` value under the Internet Settings key. Returns whether it
    /// succeeded.
    fn set_dword(name: &str, value: u32) -> bool {
        let sub = wide(SUBKEY);
        let n = wide(name);
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                REG_DWORD,
                &value as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        status == ERROR_SUCCESS
    }

    /// Read a `REG_DWORD` under the Internet Settings key, or `None` if absent.
    fn get_dword(name: &str) -> Option<u32> {
        let sub = wide(SUBKEY);
        let n = wide(name);
        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut data as *mut u32 as *mut c_void,
                &mut size,
            )
        };
        (status == ERROR_SUCCESS).then_some(data)
    }

    /// Read a `REG_SZ` under the Internet Settings key, or `None` if absent. An empty
    /// string value is distinguished from an absent one (`Some("")` vs `None`).
    fn get_sz(name: &str) -> Option<String> {
        let sub = wide(SUBKEY);
        let n = wide(name);

        // First call with a null buffer reports the required size, in bytes.
        let mut size: u32 = 0;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        if size == 0 {
            return Some(String::new());
        }

        // `size` is bytes including the terminating NUL; the buffer is UTF-16 units.
        let count = (size as usize).div_ceil(2);
        let mut buf = vec![0u16; count];
        let mut size2 = size;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                &mut size2,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        // `size2` is bytes written including the NUL; trim it off the UTF-16 length.
        let len = (size2 as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..len.min(buf.len())]))
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
        ensure_backup();
        let server =
            format!("http={HOST}:{http_port};https={HOST}:{http_port};socks={HOST}:{socks_port}");
        set_sz("AutoConfigURL", "");
        set_sz("ProxyServer", &server);
        set_sz("ProxyOverride", OVERRIDE);
        set_dword("ProxyEnable", 1);
        refresh();
    }

    pub async fn set_pac(pac_url: &str) {
        ensure_backup();
        set_dword("ProxyEnable", 0);
        set_sz("AutoConfigURL", pac_url);
        refresh();
    }

    /// Restore the pre-app WinINET proxy from the ownership record and drop it; with
    /// no record the current proxy isn't ours, so leave it be. A record that can't be
    /// read falls back to a blanket disable.
    pub async fn clear_system_proxy() {
        let Some(path) = backup::record_path() else {
            blank_clear();
            return;
        };
        match backup::decide_clear::<Snapshot>(backup::read_raw(&path).as_deref()) {
            ClearDecision::Restore(snap) => {
                restore(&snap);
                backup::delete(&path);
            }
            ClearDecision::BlankClear => {
                blank_clear();
                backup::delete(&path);
            }
            ClearDecision::Noop => {}
        }
    }

    /// Snapshot the current WinINET proxy on the first apply (no record yet).
    fn ensure_backup() {
        let Some(path) = backup::record_path() else {
            return;
        };
        if let ApplyDecision::Snapshot = backup::decide_apply(path.exists()) {
            backup::write(&path, &snapshot());
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            proxy_enable: get_dword("ProxyEnable"),
            proxy_server: get_sz("ProxyServer"),
            proxy_override: get_sz("ProxyOverride"),
            auto_config_url: get_sz("AutoConfigURL"),
        }
    }

    /// Write the captured values back. A value absent at snapshot time restores to the
    /// neutral default (disabled / empty), which is equivalent to its absence. A failed
    /// write forces the proxy off rather than leaving it half-restored.
    fn restore(snap: &Snapshot) {
        let mut ok = true;
        ok &= set_sz("ProxyServer", snap.proxy_server.as_deref().unwrap_or(""));
        ok &= set_sz(
            "ProxyOverride",
            snap.proxy_override.as_deref().unwrap_or(""),
        );
        ok &= set_sz(
            "AutoConfigURL",
            snap.auto_config_url.as_deref().unwrap_or(""),
        );
        ok &= set_dword("ProxyEnable", snap.proxy_enable.unwrap_or(0));
        if !ok {
            set_dword("ProxyEnable", 0);
            set_sz("AutoConfigURL", "");
        }
        refresh();
    }

    fn blank_clear() {
        set_dword("ProxyEnable", 0);
        set_sz("AutoConfigURL", "");
        refresh();
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod other {
    pub async fn set_system_proxy(_socks_port: u16, _http_port: u16) {}
    pub async fn set_pac(_pac_url: &str) {}
    pub async fn clear_system_proxy() {}
}

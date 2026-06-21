//! Headless geosite/geoip auto-update. On its own interval the daemon re-fetches
//! every asset file, writes it to the dat dir and rebuilds the matching `.srs`.
//! Because both cores load geo data at startup (xray reads the `.dat`, sing-box
//! loads local rule-sets) and cache it in memory, fresh data only takes effect on
//! a restart — so the active core is restarted, but only when a download actually
//! changed the file content (mirrors the `sub_update` restart-only-on-change rule).

use std::collections::HashMap;

use tokio::sync::Mutex;

use kasumi_core::contract::FetchMode;
use kasumi_core::state::AssetFile;

use crate::commands::safe_filename;
use crate::fsjson::write_bytes_atomic;
use crate::net::{fetch_url, FetchUrlOptions};
use crate::platform::Platform;
use crate::state::{read_app_state, write_app_state};
use crate::updater::{self, now_ms, LifecycleControl};

/// Download one asset into the dat dir and convert it, returning whether the file
/// content actually changed (so a caller can decide whether a core restart is
/// warranted). Shared by the `DownloadAsset` command and the headless tick.
pub async fn download_asset(
    platform: &dyn Platform,
    filename: &str,
    url: &str,
    mode: FetchMode,
) -> Result<bool, String> {
    if !safe_filename(filename) {
        return Err("invalid filename".into());
    }
    let url = url.trim();
    if url.is_empty() {
        return Err("empty asset URL".into());
    }
    let proxy = platform.proxy_status().await.map_err(|e| e.to_string())?;
    let body = fetch_url(
        url,
        FetchUrlOptions {
            mode,
            proxy: Some(proxy),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    if body.is_empty() {
        return Err("download failed".into());
    }
    let path = platform.paths().dat_dir.join(filename);
    let changed = tokio::fs::read(&path).await.ok().as_deref() != Some(body.as_slice());
    write_bytes_atomic(&path, &body)
        .await
        .map_err(|e| e.to_string())?;
    platform
        .convert_asset(filename)
        .await
        .map_err(|e| e.to_string())?;
    Ok(changed)
}

fn is_due(asset: &AssetFile, last_attempt: Option<i64>, now: i64, interval_ms: i64) -> bool {
    updater::is_due(
        asset.last_updated.unwrap_or(0),
        last_attempt,
        now,
        interval_ms,
    )
}

/// One pass: re-fetch every due asset on the global interval. `last_attempt` is the
/// caller's persistent backoff map; `serialize` is the lifecycle lock shared with the
/// command path so a restart never interleaves with a start/stop. When any download
/// changed the on-disk data and a core is running, the active core is restarted so the
/// new geo data takes effect.
pub async fn tick(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    serialize: &Mutex<()>,
    last_attempt: &mut HashMap<String, i64>,
) {
    let Some(state) = read_app_state(platform).await else {
        return;
    };
    if !state.settings.asset_auto_update {
        return;
    }
    let interval_ms = state
        .settings
        .asset_update_interval
        .saturating_mul(60_000)
        .max(60_000);
    let mode = state.settings.asset_update_mode;
    let now = now_ms();
    let due: Vec<AssetFile> = state
        .asset_files
        .iter()
        .filter(|a| !a.url.trim().is_empty())
        .filter(|a| is_due(a, last_attempt.get(&a.id).copied(), now, interval_ms))
        .cloned()
        .collect();
    if due.is_empty() {
        return;
    }

    let mut any_changed = false;
    for asset in &due {
        last_attempt.insert(asset.id.clone(), now);
        log::info!("asset-update {}: fetching", asset.remarks);
        // The frontend names the on-disk file after the asset's remarks.
        match download_asset(platform, &asset.remarks, &asset.url, mode).await {
            Ok(changed) => {
                any_changed |= changed;
                let _g = serialize.lock().await;
                mark_updated(platform, &asset.id, now).await;
            }
            Err(message) => log::warn!("asset-update {}: failed: {message}", asset.remarks),
        }
    }

    if any_changed {
        let _g = serialize.lock().await;
        let running = platform
            .service_state()
            .await
            .map(|s| s.engine.is_some())
            .unwrap_or(false);
        if running {
            if let Some(active) = read_app_state(platform).await.and_then(|s| s.active_id) {
                log::info!("asset-update: geo data changed, restarting active core");
                let _ = lifecycle.restart(Some(active)).await;
            }
        }
    }
}

/// Stamp the asset's `last_updated` (epoch-ms) in the persisted state.
async fn mark_updated(platform: &dyn Platform, asset_id: &str, now: i64) {
    let Some(mut state) = read_app_state(platform).await else {
        return;
    };
    let mut found = false;
    for a in state.asset_files.iter_mut() {
        if a.id == asset_id {
            a.last_updated = Some(now);
            found = true;
        }
    }
    if found {
        let _ = write_app_state(platform, &state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::write_app_state;
    use crate::testutil::TestPlatform;
    use kasumi_core::state::{default_app_state, AssetFile};
    use std::sync::Mutex as StdMutex;

    fn asset(id: &str, url: &str, last_updated: Option<i64>) -> AssetFile {
        AssetFile {
            id: id.into(),
            remarks: format!("{id}.dat"),
            url: url.into(),
            last_updated,
            locked: false,
        }
    }

    struct RecordingLifecycle {
        calls: StdMutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl LifecycleControl for RecordingLifecycle {
        async fn start(&self, id: Option<String>) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("start:{id:?}"));
            Ok(())
        }
        async fn stop(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("stop".into());
            Ok(())
        }
        async fn restart(&self, id: Option<String>) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("restart:{id:?}"));
            Ok(())
        }
        async fn reload_app_filter(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("reload".into());
            Ok(())
        }
    }

    #[test]
    fn due_only_after_interval_and_backoff() {
        let interval = 60 * 60_000; // 60 minutes
        let now = 100 * 60_000;
        let mut a = asset("geoip", "u", None);
        // Never updated, never attempted → due.
        assert!(is_due(&a, None, now, interval));
        // Just updated → not due.
        a.last_updated = Some(now);
        assert!(!is_due(&a, None, now, interval));
        // Old update but attempted just now → backoff holds it.
        a.last_updated = Some(0);
        assert!(!is_due(&a, Some(now), now, interval));
    }

    #[tokio::test]
    async fn disabled_setting_is_a_noop() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.asset_files = vec![asset("geoip", "http://127.0.0.1:1/", None)];
        state.settings.asset_auto_update = false;
        write_app_state(&p, &state).await.unwrap();

        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let mut last = HashMap::new();
        tick(&p, &lc, &serialize, &mut last).await;
        assert!(lc.calls.lock().unwrap().is_empty());
        assert!(last.is_empty());
    }

    #[tokio::test]
    async fn fetch_failure_does_not_restart_or_stamp() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        // Port 1 refuses instantly → fetch fails.
        state.asset_files = vec![asset("geoip", "http://127.0.0.1:1/", None)];
        state.settings.asset_auto_update = true;
        state.settings.asset_update_interval = 60;
        write_app_state(&p, &state).await.unwrap();

        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let mut last = HashMap::new();
        tick(&p, &lc, &serialize, &mut last).await;

        let after = read_app_state(&p).await.unwrap();
        assert!(after.asset_files[0].last_updated.is_none());
        assert!(lc.calls.lock().unwrap().is_empty());
        // The attempt is still recorded for backoff.
        assert!(last.contains_key("geoip"));
    }
}

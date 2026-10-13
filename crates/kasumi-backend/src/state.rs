//! App-state persistence over the split file layout: `app-state.json` (everything
//! but profiles) + `profiles.json`. The two are merged into one in-memory
//! [`AppState`] so the daemon and the UI see the same shape.

use std::path::Path;

use kasumi_core::state::AppState;
use serde_json::Value;

use crate::fsjson::{read_json, write_json_atomic};
use crate::platform::Platform;

/// Read the split app-state + profiles pair as one [`AppState`], or `None` when no
/// app-state file exists. Old on-disk data is upgraded by [`kasumi_core::migrate`]
/// before it is deserialized.
pub async fn read_app_state(platform: &dyn Platform) -> Option<AppState> {
    let paths = platform.paths();
    let mut doc: Value = read_json(&paths.app_state).await?;
    // Profiles live in their own file; fold them into the one document the
    // migration ladder operates on. The legacy layout kept them inline in
    // app-state.json, so only override when profiles.json actually has some.
    if let Some(profiles) = read_json::<Value>(&paths.profiles).await
        && profiles.as_array().is_some_and(|a| !a.is_empty())
        && let Some(obj) = doc.as_object_mut()
    {
        obj.insert("profiles".into(), profiles);
    }
    let mut state = migrated(doc)?;
    // Typed read-side normalization (g-main, legacy assets, dangling active_id) — the
    // load-time counterpart to the write-side chain, so callers get canonical state.
    kasumi_core::normalize::normalize_app_state(&mut state);
    Some(state)
}

/// `app-state.json` alone, upgraded the same way, for readers that want the
/// settings or the active id without loading every profile. Not normalized: that
/// needs the profiles (a dangling `active_id` is judged against them).
pub async fn read_state_shell(app_state: &Path) -> Option<AppState> {
    migrated(read_json(app_state).await?)
}

/// Run the migration ladder over a stored document, then type it.
fn migrated(mut doc: Value) -> Option<AppState> {
    kasumi_core::migrate::migrate_app_state(&mut doc);
    serde_json::from_value(doc).ok()
}

/// Persist an [`AppState`] back to the split files (both writes atomic).
pub async fn write_app_state(platform: &dyn Platform, state: &AppState) -> std::io::Result<()> {
    let paths = platform.paths();
    write_json_atomic(&paths.profiles, &state.profiles).await?;
    let mut shell = state.clone();
    shell.profiles = Vec::new();
    // A typed state has the current shape whatever version it was handed over
    // with (the UI's wholesale replace carries none), and a lower stamp would
    // run the migrations over it again on the next read.
    shell.schema_version = kasumi_core::migrate::SCHEMA_VERSION;
    write_json_atomic(&paths.app_state, &shell).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestPlatform, sample_vless};
    use kasumi_core::profile::Profile;
    use kasumi_core::state::default_app_state;

    #[tokio::test]
    async fn none_without_app_state_file() {
        let (p, _d) = TestPlatform::new();
        assert!(read_app_state(&p).await.is_none());
    }

    #[tokio::test]
    async fn write_splits_and_read_merges() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.profiles = vec![sample_vless()];
        state.active_id = Some(state.profiles[0].meta().id.clone());
        write_app_state(&p, &state).await.unwrap();

        // app-state.json holds no profiles; profiles.json holds them.
        let shell: AppState = read_json(&p.paths().app_state).await.unwrap();
        assert!(shell.profiles.is_empty());
        let profs: Vec<Profile> = read_json(&p.paths().profiles).await.unwrap();
        assert_eq!(profs.len(), 1);

        // Reading merges them back.
        let merged = read_app_state(&p).await.unwrap();
        assert_eq!(merged.profiles.len(), 1);
        assert_eq!(merged.active_id, state.active_id);
    }

    #[tokio::test]
    async fn write_stamps_the_current_schema_version() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.schema_version = 0;
        write_app_state(&p, &state).await.unwrap();
        let doc: Value = read_json(&p.paths().app_state).await.unwrap();
        assert_eq!(
            doc["schemaVersion"],
            kasumi_core::migrate::SCHEMA_VERSION,
            "{doc}"
        );
    }

    #[tokio::test]
    async fn shell_read_migrates_a_legacy_document() {
        let (p, _d) = TestPlatform::new();
        // Before the split layout and the nested profiles: one flat profile inline,
        // and settings from before the request identity.
        let mut doc = serde_json::to_value(default_app_state()).unwrap();
        let obj = doc.as_object_mut().unwrap();
        obj.remove("schemaVersion");
        obj["settings"]
            .as_object_mut()
            .unwrap()
            .remove("requestIdentity");
        obj.insert(
            "profiles".into(),
            serde_json::json!([{
                "protocol": "trojan", "id": "t1", "remarks": "Home", "groupId": "g-main",
                "address": "ex.com", "port": 443, "network": "tcp", "security": "tls",
                "sni": "ex.com", "password": "pw"
            }]),
        );
        obj.insert("activeId".into(), "t1".into());
        write_json_atomic(&p.paths().app_state, &doc).await.unwrap();

        // Typed as it is on disk, the flat profile fails the whole document.
        assert!(read_json::<AppState>(&p.paths().app_state).await.is_none());
        let state = read_state_shell(&p.paths().app_state).await.unwrap();
        assert_eq!(state.active_id.as_deref(), Some("t1"));
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.schema_version, kasumi_core::migrate::SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn read_adopts_legacy_inline_profiles() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.profiles = vec![sample_vless()];
        // Write app-state.json WITH inline profiles and no profiles.json.
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        let merged = read_app_state(&p).await.unwrap();
        assert_eq!(merged.profiles.len(), 1);
    }
}

//! App-state persistence over the split file layout: `app-state.json` (everything
//! but profiles) + `profiles.json`. The two are merged into one in-memory
//! [`AppState`] so the daemon and the UI see the same shape.

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
    if let Some(profiles) = read_json::<Value>(&paths.profiles).await {
        if profiles.as_array().is_some_and(|a| !a.is_empty()) {
            if let Some(obj) = doc.as_object_mut() {
                obj.insert("profiles".into(), profiles);
            }
        }
    }
    kasumi_core::migrate::migrate_app_state(&mut doc);
    serde_json::from_value(doc).ok()
}

/// Persist an [`AppState`] back to the split files (both writes atomic).
pub async fn write_app_state(platform: &dyn Platform, state: &AppState) -> std::io::Result<()> {
    let paths = platform.paths();
    write_json_atomic(&paths.profiles, &state.profiles).await?;
    let mut shell = state.clone();
    shell.profiles = Vec::new();
    write_json_atomic(&paths.app_state, &shell).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{sample_vless, TestPlatform};
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

//! Read-side normalization: bring a deserialized [`AppState`] to a canonical,
//! invariant-holding shape before the UI sees it.
//!
//! This is the read counterpart to the write-side middleware chain
//! (`kasumi-backend::state_mw`). The write chain canonicalizes on *save*; this
//! canonicalizes on *load*, so the frontend stops patching up stale persisted state
//! in TypeScript and just renders what the backend returns.
//!
//! Two distinct read layers exist and must not be conflated: schema migration
//! ([`crate::migrate::migrate_app_state`]) runs on the raw JSON `Value`
//! *before* deserialization (it reshapes things that wouldn't deserialize at all);
//! this module runs *after* deserialization on a typed [`AppState`] (valid-but-stale
//! fixes). Pure and idempotent — running it twice equals running it once.

use crate::chain::fixup_dangling_via;
use crate::route::normalize_routes;
use crate::state::{
    AppState, BASE_GROUP_ID, BASE_GROUP_NAME, Group, fixup_active_id, fixup_dangling_groups,
};

/// Legacy locked asset ids that used to ship as built-in defaults; dropped on read.
const LEGACY_DEFAULT_ASSET_IDS: [&str; 2] = ["asset-geoip", "asset-geosite"];

/// Normalize a freshly-read [`AppState`] in place: ensure the base group exists
/// and nothing names a missing group, drop legacy default assets, null a dangling
/// `active_id` and `via`s, and bring routes to shape (folding a legacy rule list).
pub fn normalize_app_state(state: &mut AppState) {
    ensure_base_group(state);
    fixup_dangling_groups(state);
    strip_legacy_default_assets(state);
    fixup_active_id(state);
    fixup_dangling_via(state);
    normalize_routes(state);
}

/// The `g-main` base group must always exist (the share-import / emptyProfile
/// default that can't be deleted); insert it at the front when missing.
fn ensure_base_group(state: &mut AppState) {
    if !state.groups.iter().any(|g| g.id == BASE_GROUP_ID) {
        state.groups.insert(
            0,
            Group {
                id: BASE_GROUP_ID.into(),
                name: BASE_GROUP_NAME.into(),
                sub_id: None,
            },
        );
    }
}

/// Drop the locked geoip/geosite entries that used to be seeded as defaults.
fn strip_legacy_default_assets(state: &mut AppState) {
    state
        .asset_files
        .retain(|a| !(a.locked && LEGACY_DEFAULT_ASSET_IDS.contains(&a.id.as_str())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AssetFile, Group, default_app_state};

    #[test]
    fn inserts_missing_base_group_at_front() {
        let mut s = default_app_state();
        s.groups = vec![Group {
            id: "g2".into(),
            name: "Two".into(),
            sub_id: None,
        }];
        normalize_app_state(&mut s);
        assert_eq!(s.groups[0].id, BASE_GROUP_ID);
        assert_eq!(s.groups[0].name, BASE_GROUP_NAME);
        assert_eq!(s.groups.len(), 2);
    }

    #[test]
    fn keeps_existing_base_group_in_place() {
        let mut s = default_app_state(); // already has g-main at 0
        s.groups.push(Group {
            id: "g2".into(),
            name: "Two".into(),
            sub_id: None,
        });
        normalize_app_state(&mut s);
        assert_eq!(s.groups.iter().filter(|g| g.id == BASE_GROUP_ID).count(), 1);
        assert_eq!(s.groups[0].id, BASE_GROUP_ID);
    }

    #[test]
    fn strips_only_locked_legacy_default_assets() {
        let mut s = default_app_state();
        s.asset_files = vec![
            AssetFile {
                id: "asset-geoip".into(),
                remarks: "GeoIP".into(),
                url: "u".into(),
                last_updated: None,
                locked: true,
            },
            // Same id but user-unlocked → kept.
            AssetFile {
                id: "asset-geosite".into(),
                remarks: "GeoSite".into(),
                url: "u".into(),
                last_updated: None,
                locked: false,
            },
            AssetFile {
                id: "custom".into(),
                remarks: "Custom".into(),
                url: "u".into(),
                last_updated: None,
                locked: true,
            },
        ];
        normalize_app_state(&mut s);
        let ids: Vec<&str> = s.asset_files.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["asset-geosite", "custom"]);
    }

    #[test]
    fn nulls_dangling_active_id() {
        let mut s = default_app_state();
        s.active_id = Some("ghost".into());
        normalize_app_state(&mut s);
        assert_eq!(s.active_id, None);
    }

    #[test]
    fn points_whatever_names_a_missing_group_at_main() {
        let mut s = default_app_state();
        let mut p = crate::share::parse_share_link("trojan://pw@a.com:443#A", None).unwrap();
        p.meta_mut().group_id = "gone".into();
        s.profiles = vec![p];
        s.subscriptions = vec![
            serde_json::from_value(serde_json::json!({
                "id": "s1", "remarks": "S", "url": "", "enabled": true, "groupId": "gone",
                "autoUpdate": false, "interval": 60, "allowInsecure": false,
                "userAgent": "", "filter": "", "lastUpdated": "", "count": 0
            }))
            .unwrap(),
        ];
        s.groups.push(Group {
            id: "g2".into(),
            name: "Two".into(),
            sub_id: Some("removed-sub".into()),
        });
        normalize_app_state(&mut s);
        assert_eq!(s.profiles[0].meta().group_id, BASE_GROUP_ID);
        assert_eq!(s.subscriptions[0].group_id.as_deref(), Some(BASE_GROUP_ID));
        assert_eq!(s.groups[1].sub_id, None);
    }

    #[test]
    fn is_idempotent() {
        let mut s = default_app_state();
        s.groups.clear();
        s.active_id = Some("ghost".into());
        normalize_app_state(&mut s);
        let once = s.clone();
        normalize_app_state(&mut s);
        assert_eq!(s, once);
    }
}

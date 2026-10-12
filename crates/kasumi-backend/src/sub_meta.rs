//! `sub-meta.json`: the provider meta each subscription carries between fetches,
//! keyed by subscription id. Kept out of `AppState` and backups; a lost entry only
//! makes the next fetch an import.

use std::collections::BTreeMap;

use kasumi_core::sub_ingest::StoredSubMeta;

use crate::fsjson::{read_json, write_json_atomic};
use crate::platform::Platform;

/// Every stored entry; a missing or corrupt file reads as empty.
pub async fn read_all(platform: &dyn Platform) -> BTreeMap<String, StoredSubMeta> {
    read_json(platform.paths().sub_meta())
        .await
        .unwrap_or_default()
}

/// Write one entry (`None` = remove) and drop entries whose sub id is no longer live.
pub async fn write_entry(
    platform: &dyn Platform,
    sub_id: &str,
    entry: Option<StoredSubMeta>,
    live_ids: &[&str],
) -> std::io::Result<()> {
    let mut all = read_all(platform).await;
    match entry {
        Some(e) => all.insert(sub_id.to_owned(), e),
        None => all.remove(sub_id),
    };
    all.retain(|id, _| live_ids.contains(&id.as_str()));
    write_json_atomic(platform.paths().sub_meta(), &all).await
}

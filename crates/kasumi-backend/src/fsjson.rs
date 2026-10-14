//! Atomic JSON read/write: write to a temp sibling then rename over the target so
//! a crash mid-write never leaves a half-written `app-state.json`/`profiles.json`.

use std::path::Path;

use kasumi_core::data_path_state::DataPathState;
use kasumi_log::{Area, ks_debug, ks_warn};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::fs;

/// Read the persisted [`DataPathState`], or `None` when it is missing, corrupt or of
/// another version — all of which mean "no data-path known". A file that exists and
/// is none of those is recorded: "no data path known" is what makes the service
/// start a second one.
pub async fn read_data_path_state(path: impl AsRef<Path>) -> Option<DataPathState> {
    let path = path.as_ref();
    let bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            ks_debug!(Area::State, "cannot read {}: {e}", path.display());
            return None;
        }
    };
    match DataPathState::from_json(&bytes) {
        Some(state) => Some(state),
        None => {
            ks_warn!(
                Area::State,
                "{} is not a data-path state this build recognises",
                path.display()
            );
            None
        }
    }
}

/// Write the [`DataPathState`] atomically. The document lives in the run dir and is
/// written by the privileged owner, so a rename-based write is fine (the ownership
/// sweep re-chowns it after every start/stop request).
pub async fn write_data_path_state(
    path: impl AsRef<Path>,
    state: &DataPathState,
) -> std::io::Result<()> {
    write_text_atomic(path, &state.to_json()).await
}

/// Parse `path` into `T`, or `None` if it's missing or not valid JSON for `T`. A
/// corrupt document is reported: every caller reads `None` as "nothing stored yet",
/// which for app-state means the app behaves like a fresh install.
pub async fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Option<T> {
    let path = path.as_ref();
    let bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            ks_debug!(Area::State, "cannot read {}: {e}", path.display());
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(e) => {
            ks_warn!(Area::State, "{} is not valid JSON: {e}", path.display());
            None
        }
    }
}

/// Serialize `value` and write it atomically.
pub async fn write_json_atomic(
    path: impl AsRef<Path>,
    value: &impl Serialize,
) -> std::io::Result<()> {
    let data = serde_json::to_string(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_text_atomic(path, &data).await
}

/// Write `data` atomically (temp file + rename). The temp name carries the pid so
/// concurrent writers to the same path don't clobber each other's temp file.
pub async fn write_text_atomic(path: impl AsRef<Path>, data: &str) -> std::io::Result<()> {
    write_bytes_atomic(path, data.as_bytes()).await
}

/// Atomic write of raw bytes (downloaded assets aren't text).
pub async fn write_bytes_atomic(path: impl AsRef<Path>, data: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, data).await?;
    fs::rename(&tmp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_missing_or_garbage_is_none() {
        assert!(
            read_json::<serde_json::Value>("/no/such/json")
                .await
                .is_none()
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.json");
        write_text_atomic(&p, "{ not json").await.unwrap();
        assert!(read_json::<serde_json::Value>(&p).await.is_none());
    }

    #[tokio::test]
    async fn write_json_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        let value = serde_json::json!({ "a": 1, "b": ["x", "y"] });
        write_json_atomic(&p, &value).await.unwrap();
        let back: serde_json::Value = read_json(&p).await.unwrap();
        assert_eq!(back, value);
        // No temp file is left behind after a successful rename.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}

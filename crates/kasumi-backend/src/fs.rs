//! Generic filesystem helpers. JSON-specific variants live in [`crate::fsjson`].
//!
//! Reads return `None` rather than erroring on a missing/unreadable file because
//! the backend treats absent state, pidfiles and logs as the empty case.

use std::io::ErrorKind;
use std::path::Path;

use kasumi_log::{Area, ks_debug};
use tokio::fs;

/// File contents as text, or `None` if it can't be read (missing, no permission).
/// A file that exists and cannot be read is not the empty case, so it is recorded:
/// everything downstream treats `None` as "nothing stored here".
pub async fn read_text(path: impl AsRef<Path>) -> Option<String> {
    let path = path.as_ref();
    match fs::read(path).await {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            ks_debug!(Area::State, "cannot read {}: {e}", path.display());
            None
        }
    }
}

/// Overwrite `path` with `data`.
pub async fn write_text(path: impl AsRef<Path>, data: &str) -> std::io::Result<()> {
    fs::write(path, data.as_bytes()).await
}

/// Whether anything exists at `path`.
pub async fn exists(path: impl AsRef<Path>) -> bool {
    fs::metadata(path).await.is_ok()
}

/// Remove `path`, ignoring a missing file.
pub async fn remove_file(path: impl AsRef<Path>) {
    let _ = fs::remove_file(path).await;
}

/// Names of the entries directly under `dir`; empty if it can't be read.
pub async fn list_names(dir: impl AsRef<Path>) -> Vec<String> {
    let Ok(mut rd) = fs::read_dir(dir).await else {
        return Vec::new();
    };
    let mut names = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_missing_is_none() {
        assert!(read_text("/no/such/path/here").await.is_none());
    }

    #[tokio::test]
    async fn write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        write_text(&p, "héllo").await.unwrap();
        assert!(exists(&p).await);
        assert_eq!(read_text(&p).await.as_deref(), Some("héllo"));
        remove_file(&p).await;
        assert!(!exists(&p).await);
        // Removing a gone file is a no-op.
        remove_file(&p).await;
    }
}

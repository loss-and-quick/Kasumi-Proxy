//! Generic filesystem helpers. JSON-specific variants live in [`crate::fsjson`].
//!
//! Reads return `None` rather than erroring on a missing/unreadable file because
//! the backend treats absent state, pidfiles and logs as the empty case.

use std::path::Path;

use tokio::fs;

/// File contents as text, or `None` if it can't be read (missing, no permission).
pub async fn read_text(path: impl AsRef<Path>) -> Option<String> {
    fs::read(path)
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
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

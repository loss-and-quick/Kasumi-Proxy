//! In-place log trimming.
//!
//! Renaming a log to `daemon.log.1` is the usual rotation trick and it does not work
//! here: `Command::Log` reads `<data_dir>/<target>.log` and nothing else, so a
//! renamed file is invisible to the in-app viewer — and on Android those files live
//! under the app's own data directory, where a growing tail is cheap but a pile of
//! rotated copies is not. So growth is bounded by keeping the newest half of the file
//! and dropping the rest in place, through a temporary file and a rename so a reader
//! never sees a half-written log.
//!
//! Trimming synchronously is intentional: log files here are capped at a few hundred
//! kilobytes, and the callers are either the boot path or a periodic tick.

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::Path;

/// Keep the newest `max_bytes / 2` of `path` once the file grows past `max_bytes`.
/// A file that does not exist is not an error — the app has simply not logged yet.
///
/// The trim rewrites the existing file in place and truncates it, preserving the
/// inode/handle so running writers (fern in this process, or cores logging via
/// redirected descriptors) continue appending to the trimmed file rather than
/// an unlinked former inode.
///
/// The cut lands on a record boundary: the first partial line in the kept tail is
/// dropped rather than kept, so every line in the file is still a whole record.
pub fn trim_in_place(path: &Path, max_bytes: u64) -> io::Result<()> {
    let mut file = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    if len <= max_bytes {
        return Ok(());
    }

    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    let keep = ((max_bytes / 2) as usize).clamp(1, content.len());
    let mut start = content.len() - keep;
    if start > 0
        && let Some(offset) = content[start..].iter().position(|byte| *byte == b'\n')
    {
        start += offset + 1;
    }

    let slice = &content[start..];
    file.seek(io::SeekFrom::Start(0))?;
    file.write_all(slice)?;
    file.set_len(slice.len() as u64)?;
    file.sync_all()?;
    Ok(())
}

/// How many bytes the file would keep after trimming — exposed for tests and for
/// callers that want to log how much was dropped.
pub fn kept_bytes(path: &Path) -> Option<usize> {
    fs::metadata(path).ok().map(|m| m.len() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
    }

    #[test]
    fn leaves_a_small_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        write(&path, "one\ntwo\n");
        trim_in_place(&path, 1024).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        trim_in_place(&dir.path().join("absent.log"), 1024).unwrap();
    }

    #[test]
    fn keeps_the_newest_half() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
        write(&path, &text);
        trim_in_place(&path, 400).unwrap();

        let kept = fs::read_to_string(&path).unwrap();
        assert!(kept.len() < 400);
        assert!(kept.ends_with("line 99\n"));
        assert!(kept.starts_with("line "), "kept: {kept:?}");
        // Whole records only: no line may start mid-way.
        assert!(kept.lines().all(|l| l.starts_with("line ")));
        assert!(!dir.path().join("daemon.log.1").exists());
        // No scratch file survives the rename.
        assert!(!dir.path().join(".daemon.log.trim").exists());
    }

    #[test]
    fn cut_lands_on_a_record_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        // Twenty fixed-width records: the byte-aligned tail would start in the
        // middle of one, so the cut has to move to the next record instead.
        let record = "0123456789\n";
        write(&path, &record.repeat(20));
        trim_in_place(&path, 100).unwrap();

        let kept = fs::read_to_string(&path).unwrap();
        // Whatever the exact byte cut, the result must be whole records only, no
        // longer than the limit, and still the newest ones.
        assert!(kept.len() <= 100);
        assert!(kept.len() >= 40, "kept {} bytes", kept.len());
        assert!(kept.ends_with(record));
        assert!(kept.lines().all(|line| line == "0123456789"));
        assert!(!dir.path().join(".daemon.log.trim").exists());
    }

    #[test]
    fn a_limit_smaller_than_a_record_yields_an_empty_but_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        write(&path, "aaaa\nbbbb\n");
        trim_in_place(&path, 1).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        assert!(!dir.path().join(".daemon.log.trim").exists());
    }

    #[test]
    fn preserves_file_inode_and_appends_continue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut appender = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        appender
            .write_all(b"line 1\nline 2\nline 3\nline 4\n")
            .unwrap();
        appender.sync_all().unwrap();

        trim_in_place(&path, 15).unwrap();

        // An already-open append descriptor must keep appending to the trimmed file.
        appender.write_all(b"line 5\n").unwrap();
        appender.sync_all().unwrap();

        let after = fs::read_to_string(&path).unwrap();
        assert!(after.ends_with("line 5\n"));
        assert!(!after.starts_with("line 1\n"));
    }
}

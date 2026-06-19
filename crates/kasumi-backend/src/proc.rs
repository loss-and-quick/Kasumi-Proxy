//! Spawning external binaries (`ip`/`iptables`/the cores) and POSIX process
//! identity. The pid primitives read `/proc` and `kill(2)`; they're reused by
//! every POSIX [`Platform`](crate::Platform) (Android, desktop Linux). A Windows
//! port would need its own process-identity path.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

use crate::fs::{read_text, remove_file};

#[derive(Debug, Clone)]
pub struct RunResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Default)]
pub struct RunOpts {
    pub env: Option<HashMap<String, String>>,
    pub cwd: Option<String>,
    pub stdin: Option<String>,
}

/// Run an external command to completion, capturing stdout/stderr as text.
pub async fn run(argv: &[String], opts: RunOpts) -> std::io::Result<RunResult> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if let Some(env) = &opts.env {
        cmd.env_clear();
        cmd.envs(env);
    }
    if let Some(cwd) = &opts.cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if opts.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let mut child = cmd.spawn()?;
    if let Some(input) = &opts.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await?;
        }
    }
    let out = child.wait_with_output().await?;
    Ok(RunResult {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run an external command, discarding output and returning only its exit code.
pub async fn silent(argv: &[String]) -> i32 {
    run(argv, RunOpts::default())
        .await
        .map(|r| r.code)
        .unwrap_or(-1)
}

/// `(dev, ino)` of a path (following symlinks), or `None`.
async fn dev_ino(path: impl AsRef<Path>) -> Option<(u64, u64)> {
    let m = tokio::fs::metadata(path).await.ok()?;
    Some((m.dev(), m.ino()))
}

/// True if `pid` is alive and its executable inode is `bin`.
pub async fn pid_matches_bin(pid: i32, bin: impl AsRef<Path>) -> bool {
    if pid <= 0 {
        return false;
    }
    let Some(exe) = dev_ino(format!("/proc/{pid}/exe")).await else {
        return false;
    };
    dev_ino(bin).await == Some(exe)
}

/// True if `pid` is alive and its executable is one of `bins`.
pub async fn pid_matches_any(pid: i32, bins: &[String]) -> bool {
    for bin in bins {
        if pid_matches_bin(pid, bin).await {
            return true;
        }
    }
    false
}

/// Read a pidfile, returning 0 for a missing/garbage file.
pub async fn read_pidfile(path: impl AsRef<Path>) -> i32 {
    match read_text(path).await {
        Some(raw) => {
            let raw = raw.trim();
            if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
                raw.parse().unwrap_or(0)
            } else {
                0
            }
        }
        None => 0,
    }
}

/// True while `/proc/<pid>` exists (the process isn't yet reaped).
async fn pid_exists(pid: i32) -> bool {
    tokio::fs::metadata(format!("/proc/{pid}")).await.is_ok()
}

fn send_signal(pid: i32, sig: i32) {
    // Errors (ESRCH on an already-reaped pid) are intentionally ignored.
    unsafe {
        libc::kill(pid, sig);
    }
}

/// Kill `pid` (when it still matches `bin`, or unconditionally if `bin` is `None`)
/// and drop its pidfile. With `graceful`, send SIGTERM and wait up to ~2s for the
/// process to exit before SIGKILL — this lets a tun-managing core (sing-box
/// auto_route) tear down its own ip rules + tun device, instead of stranding them
/// for the next engine to trip over.
pub async fn kill_if_running(
    pid: i32,
    bin: Option<&str>,
    pidfile: impl AsRef<Path>,
    graceful: bool,
) {
    let should_kill = pid > 0
        && match bin {
            None => true,
            Some(b) => pid_matches_bin(pid, b).await,
        };
    if should_kill {
        if graceful {
            send_signal(pid, libc::SIGTERM);
            let mut exited = false;
            for _ in 0..20 {
                if !pid_exists(pid).await {
                    exited = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !exited {
                send_signal(pid, libc::SIGKILL);
            }
        } else {
            send_signal(pid, libc::SIGKILL);
        }
    }
    remove_file(pidfile).await;
}

/// Spawn a long-running process (core/tun2socks) with `env`, its stdout+stderr
/// redirected (truncating) to `log_path`. Returns the live [`Child`] so the caller
/// can record its pid and supervise it.
/// `kill_on_drop` ties the OS process lifetime to the returned [`Child`] handle:
/// for ephemeral diagnostic cores (ping/speed) the handle may be dropped by a
/// cancelled future — e.g. the client's WS frame is dropped mid-test — and
/// without this the `sing-box` would leak and pile up. Long-running supervised
/// processes (the active core, tun2socks) pass `false`: their pid is persisted
/// and they must outlive the spawning scope.
pub async fn spawn_logged(
    argv: &[String],
    env: &HashMap<String, String>,
    log_path: impl AsRef<Path>,
    kill_on_drop: bool,
) -> std::io::Result<Child> {
    let log = std::fs::File::create(log_path)?;
    let err = log.try_clone()?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    cmd.envs(env);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(err));
    cmd.kill_on_drop(kill_on_drop);
    cmd.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_captures_output_and_code() {
        let r = run(
            &[
                "sh".into(),
                "-c".into(),
                "printf out; printf err 1>&2; exit 3".into(),
            ],
            RunOpts::default(),
        )
        .await
        .unwrap();
        assert_eq!(r.code, 3);
        assert_eq!(r.stdout, "out");
        assert_eq!(r.stderr, "err");
    }

    #[tokio::test]
    async fn run_feeds_stdin() {
        let r = run(
            &["cat".into()],
            RunOpts {
                stdin: Some("piped".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(r.stdout, "piped");
    }

    #[tokio::test]
    async fn silent_returns_exit_code() {
        assert_eq!(silent(&["true".into()]).await, 0);
        assert_eq!(silent(&["false".into()]).await, 1);
    }

    #[tokio::test]
    async fn read_pidfile_handles_missing_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_pidfile(dir.path().join("none")).await, 0);
        let p = dir.path().join("pid");
        crate::fs::write_text(&p, "  4321\n").await.unwrap();
        assert_eq!(read_pidfile(&p).await, 4321);
        crate::fs::write_text(&p, "notapid").await.unwrap();
        assert_eq!(read_pidfile(&p).await, 0);
    }

    #[tokio::test]
    async fn pid_matches_bin_against_self() {
        let me = std::process::id() as i32;
        // /proc/self/exe and our own pid's exe share an inode.
        let exe = std::fs::read_link(format!("/proc/{me}/exe")).unwrap();
        assert!(pid_matches_bin(me, &exe).await);
        assert!(!pid_matches_bin(me, "/bin/sh").await);
        assert!(!pid_matches_bin(-1, &exe).await);
    }

    #[tokio::test]
    async fn kill_if_running_drops_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("p.pid");
        crate::fs::write_text(&pidfile, "999999").await.unwrap();
        // No process matches (bin is our own shell, pid is bogus) → just unlink.
        kill_if_running(999_999, Some("/bin/sh"), &pidfile, false).await;
        assert!(!crate::fs::exists(&pidfile).await);
    }

    #[tokio::test]
    async fn spawn_logged_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("c.log");
        let mut child = spawn_logged(
            &[
                "sh".into(),
                "-c".into(),
                "printf hello; printf oops 1>&2".into(),
            ],
            &HashMap::new(),
            &log,
            false,
        )
        .await
        .unwrap();
        child.wait().await.unwrap();
        let body = crate::fs::read_text(&log).await.unwrap();
        assert!(body.contains("hello"));
        assert!(body.contains("oops"));
    }
}

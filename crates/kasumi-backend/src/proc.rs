//! Spawning external binaries (the cores, `ip`/`route`/`iptables`) and OS process
//! identity. `run`/`silent`/`spawn_logged`/`read_pidfile` are portable; the
//! pid-identity and kill primitives are OS-specific and live in the [`imp`] module
//! — POSIX reads `/proc` and `kill(2)`, Windows queries the process image path and
//! `TerminateProcess`. Both back the same liveness/teardown contract every
//! [`Platform`](crate::Platform) relies on.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;

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

/// Keep a spawned child from popping a console window. On Windows a GUI process
/// spawning a console subsystem child (our `ip`/`route`/`netsh`/`powershell` calls
/// and the cores) flashes a black console for each one unless `CREATE_NO_WINDOW` is
/// set — see tauri-apps/tauri#13230. A no-op everywhere else.
fn hide_console(cmd: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = cmd;
}

/// Set the child's env. POSIX starts from a clean slate (the Android/Linux
/// data-path wants no inherited surprises). Windows KEEPS the inherited
/// environment and only overlays `env` — clearing it drops `SystemRoot`/`windir`,
/// without which `ws2_32` can't load its Winsock provider catalog and the cores
/// fail to open any socket ("The requested service provider could not be loaded or
/// initialized").
fn set_env(cmd: &mut Command, env: &HashMap<String, String>) {
    #[cfg(unix)]
    cmd.env_clear();
    cmd.envs(env);
}

/// Run an external command to completion, capturing stdout/stderr as text.
pub async fn run(argv: &[String], opts: RunOpts) -> std::io::Result<RunResult> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    hide_console(&mut cmd);
    if let Some(env) = &opts.env {
        set_env(&mut cmd, env);
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
    if let Some(input) = &opts.stdin
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await?;
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

/// True if `pid` is alive and its executable is `bin`.
pub async fn pid_matches_bin(pid: i32, bin: impl AsRef<Path>) -> bool {
    if pid <= 0 {
        return false;
    }
    imp::pid_matches_bin(pid, bin.as_ref()).await
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

/// Kill `pid` (when it still matches `bin`, or unconditionally if `bin` is `None`)
/// and drop its pidfile. With `graceful`, give a tun-managing core (sing-box
/// auto_route) a window to tear down its own routing + tun device before a hard
/// kill — on POSIX that's SIGTERM-then-SIGKILL; on Windows there is no SIGTERM, so
/// it's a `TerminateProcess` and the wintun driver reclaims the adapter on exit.
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
        imp::kill(pid, graceful).await;
    }
    remove_file(pidfile).await;
}

/// Tie a spawned data-path process (the core / tun2socks) to the helper that is its
/// parent: `PR_SET_PDEATHSIG(SIGTERM)` makes the kernel SIGTERM the child the instant
/// the helper dies — including an *unclean* exit (crash / SIGKILL) where no teardown
/// code can run. SIGTERM (not KILL) lets sing-box remove its own tun + auto_route on
/// the way out, so an orphaned core can't strand a tun / routes and leave
/// `service-state` reporting "stopped" while traffic is still captured. The
/// `getppid() == 1` guard closes the fork→prctl race: if the helper already died
/// (child reparented to init), PDEATHSIG would never fire, so exit rather than exec
/// an unsupervised core.
///
/// # Async-signal-safety
///
/// Only `prctl` / `getppid` / `_exit` — no allocation, locks, or stdio — per the
/// `pre_exec` contract (it runs between `fork` and `exec`).
#[cfg(unix)]
fn die_with_parent() -> std::io::Result<()> {
    // SAFETY: async-signal-safe syscalls only, per the contract above.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGTERM as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getppid is async-signal-safe and never fails.
    if unsafe { libc::getppid() } == 1 {
        // SAFETY: _exit is async-signal-safe; the helper is already gone, so don't
        // bring up an unsupervised core that nothing would ever reap.
        unsafe { libc::_exit(0) };
    }
    Ok(())
}

/// Build the `tokio::process::Command` for a long-running core/tun2socks child:
/// argv + env, stdin null, stdout+stderr redirected (truncating) to `log_path`, and
/// the `kill_on_drop` flag. On Unix it stamps `PR_SET_PDEATHSIG` (see
/// [`die_with_parent`]) into the forked child, so every data-path child is reaped
/// when its parent helper dies — no per-call-site pre_exec plumbing.
fn build_logged_command(
    argv: &[String],
    env: &HashMap<String, String>,
    log_path: impl AsRef<Path>,
    kill_on_drop: bool,
) -> std::io::Result<Command> {
    // Truncate the file so a fresh spawn starts with a clean log, then open in
    // append mode so any in-place trim during this run keeps writes at EOF rather
    // than at a stale file offset.
    std::fs::File::create(&log_path)?;
    let log = std::fs::OpenOptions::new().append(true).open(&log_path)?;
    let err = log.try_clone()?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    set_env(&mut cmd, env);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(err));
    cmd.kill_on_drop(kill_on_drop);
    hide_console(&mut cmd);
    // SAFETY: die_with_parent is async-signal-safe per the pre_exec contract.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(die_with_parent);
    }
    Ok(cmd)
}

/// Spawn a long-running process (core/tun2socks) with `env`, its stdout+stderr
/// redirected (truncating) to `log_path`. The child dies with its parent: on Unix
/// via `PR_SET_PDEATHSIG` (see [`die_with_parent`]), on Windows via the parent's
/// kill-on-close job (see [`job`]). Returns the live [`Child`] so the caller can
/// record its pid and supervise it.
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
    let mut cmd = build_logged_command(argv, env, log_path, kill_on_drop)?;
    #[cfg(windows)]
    {
        job::spawn_in_job(&mut cmd)
    }
    #[cfg(not(windows))]
    {
        cmd.spawn()
    }
}

/// The Windows counterpart of [`die_with_parent`]. Windows never kills children
/// with their parent, so every `spawn_logged` child joins one job object flagged
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and this process holds the only handle to
/// it. When the process ends for any reason, a crash or `TerminateProcess`
/// included, the kernel closes that handle and terminates every process in the
/// job, grandchildren too. No graceful window is needed: the wintun driver
/// reclaims a dead core's adapter.
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information>
#[cfg(windows)]
mod job {
    use std::sync::OnceLock;

    use kasumi_log::{Area, ks_warn};

    use tokio::process::{Child, Command};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    struct Job(HANDLE);
    // SAFETY: a job handle names a kernel object and is usable from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    /// Never closed: the handle has to live exactly as long as this process.
    static PARENT_JOB: OnceLock<Option<Job>> = OnceLock::new();

    pub(super) fn parent_job() -> Option<HANDLE> {
        PARENT_JOB
            .get_or_init(|| match kill_on_close_job() {
                Ok(h) => Some(Job(h)),
                Err(e) => {
                    ks_warn!(
                        Area::Proc,
                        "no job object, children can outlive a crash: {e}"
                    );
                    None
                }
            })
            .as_ref()
            .map(|j| j.0)
    }

    /// A new unnamed job whose processes die when its last handle closes. Null
    /// security attributes make the handle non-inheritable, so no child can keep
    /// the job open after this process is gone.
    pub(super) fn kill_on_close_job() -> std::io::Result<HANDLE> {
        // SAFETY: Win32 calls on a handle we own; `info` outlives the call.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                CloseHandle(job);
                return Err(e);
            }
            Ok(job)
        }
    }

    /// Spawn `cmd` suspended, put it in the job, then let it run, so it can't
    /// start a process of its own before it is in the job (children of a job
    /// member join the job, <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>).
    /// A process that already belongs to a job, e.g. because this one was started
    /// inside a job, can join a second one since Windows 8
    /// (<https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs>).
    /// A failed assignment only loses the crash guarantee, so the child still runs.
    pub(super) fn spawn_in_job(cmd: &mut Command) -> std::io::Result<Child> {
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        let mut child = cmd.spawn()?;
        let (Some(process), Some(pid)) = (child.raw_handle(), child.id()) else {
            return Ok(child);
        };
        if let Some(job) = parent_job() {
            // SAFETY: both handles are open; `child` owns `process`.
            if unsafe { AssignProcessToJobObject(job, process as HANDLE) } == 0 {
                ks_warn!(
                    Area::Proc,
                    "pid {pid} is not in the parent job: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        if let Err(e) = resume_threads(pid) {
            let _ = child.start_kill();
            return Err(e);
        }
        Ok(child)
    }

    /// Resume a process created with `CREATE_SUSPENDED`. Only threads can be
    /// resumed, and `std` closes the main thread's handle right after
    /// `CreateProcessW`, so the thread is looked up again by owner pid.
    fn resume_threads(pid: u32) -> std::io::Result<()> {
        // SAFETY: the snapshot and every thread handle are closed on all paths.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            let mut resumed = 0;
            let mut more = Thread32First(snap, &mut entry) != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !thread.is_null() {
                        if ResumeThread(thread) != u32::MAX {
                            resumed += 1;
                        }
                        CloseHandle(thread);
                    }
                }
                more = Thread32Next(snap, &mut entry) != 0;
            }
            CloseHandle(snap);
            if resumed == 0 {
                return Err(std::io::Error::other(format!(
                    "could not resume suspended pid {pid}"
                )));
            }
            Ok(())
        }
    }
}

/// POSIX process identity: a pid's executable is matched by `(dev, ino)` of
/// `/proc/<pid>/exe`, and termination is `kill(2)` (graceful = SIGTERM, then
/// SIGKILL after a grace window).
#[cfg(unix)]
mod imp {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::Duration;

    /// `(dev, ino)` of a path (following symlinks), or `None`.
    async fn dev_ino(path: impl AsRef<Path>) -> Option<(u64, u64)> {
        let m = tokio::fs::metadata(path).await.ok()?;
        Some((m.dev(), m.ino()))
    }

    pub async fn pid_matches_bin(pid: i32, bin: &Path) -> bool {
        let Some(exe) = dev_ino(format!("/proc/{pid}/exe")).await else {
            return false;
        };
        dev_ino(bin).await == Some(exe)
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

    pub async fn kill(pid: i32, graceful: bool) {
        if graceful {
            send_signal(pid, libc::SIGTERM);
            for _ in 0..20 {
                if !pid_exists(pid).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        send_signal(pid, libc::SIGKILL);
        // Wait for the pid to actually vanish before returning: a sing-box auto_route
        // core still owns its tun + routing rules until it's reaped, and the caller
        // (stop_data_path) spawns the next core as soon as we return — overlapping tuns
        // wedge routing. Bounded so a stuck/unreapable pid can't hang the stop path.
        for _ in 0..20 {
            if !pid_exists(pid).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Windows process identity: there is no `/proc` inode, so a pid's executable is
/// matched by its full image path (`QueryFullProcessImageNameW`), and termination
/// is `TerminateProcess` (no SIGTERM — the wintun driver reclaims a core's adapter
/// when the process exits, so the hard kill is still clean).
#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess,
    };

    /// Full on-disk path of a running pid's executable image, or `None` if the
    /// process is gone / inaccessible.
    fn image_path(pid: u32) -> Option<PathBuf> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 32_768];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(handle);
            if ok == 0 {
                return None;
            }
            Some(PathBuf::from(OsString::from_wide(&buf[..size as usize])))
        }
    }

    /// Compare two image paths. Canonicalize both (resolves 8.3 / case / symlinks);
    /// fall back to a case-insensitive compare when the file is no longer openable.
    fn same_image(a: &Path, b: &Path) -> bool {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => a
                .to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy()),
        }
    }

    pub async fn pid_matches_bin(pid: i32, bin: &Path) -> bool {
        match image_path(pid as u32) {
            Some(image) => same_image(&image, bin),
            None => false,
        }
    }

    pub async fn kill(pid: i32, _graceful: bool) {
        // No POSIX SIGTERM on Windows; TerminateProcess ends the process and the
        // wintun driver tears the core's adapter down on exit.
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
            if !handle.is_null() {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[tokio::test]
    async fn pid_matches_bin_against_self() {
        let me = std::process::id() as i32;
        // /proc/self/exe and our own pid's exe share an inode.
        let exe = std::fs::read_link(format!("/proc/{me}/exe")).unwrap();
        assert!(pid_matches_bin(me, &exe).await);
        assert!(!pid_matches_bin(me, "/bin/sh").await);
        assert!(!pid_matches_bin(-1, &exe).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pid_matches_any_scans_the_candidate_list() {
        let me = std::process::id() as i32;
        let exe = std::fs::read_link(format!("/proc/{me}/exe"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // Matches as long as one candidate is our real exe.
        assert!(pid_matches_any(me, &["/bin/sh".into(), exe.clone()]).await);
        // None match → false; an empty list → false.
        assert!(!pid_matches_any(me, &["/bin/sh".into(), "/no/such/bin".into()]).await);
        assert!(!pid_matches_any(me, &[]).await);
    }

    #[tokio::test]
    async fn kill_if_running_drops_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("p.pid");
        crate::fs::write_text(&pidfile, "999999").await.unwrap();
        // No process matches (bin is a path nothing runs as, pid is bogus) → just
        // unlink the pidfile without signalling anything.
        kill_if_running(999_999, Some("/no/such/binary"), &pidfile, false).await;
        assert!(!crate::fs::exists(&pidfile).await);
    }

    #[cfg(unix)]
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

    // Every spawn_logged child is tied to its parent via PR_SET_PDEATHSIG (see
    // die_with_parent). Exercising the wiring end-to-end: a `sh -c 'printf ran'`
    // child still runs and writes to the log, proving the pre_exec hook didn't
    // abort the exec. (The SIGTERM-on-parent-death contract itself is verified at
    // runtime, not by a unit test.)
    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_logged_stamps_pdeathsig_and_runs() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("c.log");
        let mut child = spawn_logged(
            &["sh".into(), "-c".into(), "printf ran".into()],
            &HashMap::new(),
            &log,
            false,
        )
        .await
        .unwrap();
        child.wait().await.unwrap();
        let body = crate::fs::read_text(&log).await.unwrap();
        assert!(body.contains("ran"));
    }

    #[cfg(windows)]
    fn in_job(child: &Child, job: windows_sys::Win32::Foundation::HANDLE) -> bool {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let mut result = 0;
        let process = child.raw_handle().unwrap();
        // SAFETY: both handles are open for the duration of the call.
        let ok = unsafe { IsProcessInJob(process as _, job, &mut result) };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        result != 0
    }

    #[cfg(windows)]
    fn cmd(script: &str) -> Vec<String> {
        vec!["cmd".into(), "/C".into(), script.into()]
    }

    // A child spawned suspended must still run to completion once it is resumed.
    #[cfg(windows)]
    #[tokio::test]
    async fn spawn_logged_resumes_the_suspended_child() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("c.log");
        let mut child = spawn_logged(&cmd("echo ran"), &HashMap::new(), &log, false)
            .await
            .unwrap();
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .expect("child still suspended")
            .unwrap();
        assert!(status.success());
        let body = crate::fs::read_text(&log).await.unwrap();
        assert!(body.contains("ran"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn spawn_logged_puts_the_child_in_the_parent_job() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("c.log");
        let mut child = spawn_logged(&cmd("ping -n 30 127.0.0.1"), &HashMap::new(), &log, true)
            .await
            .unwrap();
        assert!(in_job(&child, job::parent_job().unwrap()));
        child.kill().await.unwrap();
    }

    // The crash guarantee itself: closing the last job handle, which is what the
    // kernel does when the parent dies, terminates the job's processes.
    #[cfg(windows)]
    #[tokio::test]
    async fn closing_the_job_kills_its_processes() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let job = job::kill_on_close_job().unwrap();
        // Blocks reading the stdin pipe, which stays open for the whole test.
        let mut child = Command::new("cmd")
            .args(["/C", "set /p line="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let process = child.raw_handle().unwrap();
        // SAFETY: both handles are open.
        unsafe {
            assert_ne!(AssignProcessToJobObject(job, process as _), 0);
            assert!(in_job(&child, job));
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited on its own"
        );
        // SAFETY: the job handle is open and closed exactly once.
        unsafe { CloseHandle(job) };
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .expect("job close did not kill the child")
            .unwrap();
    }

    #[cfg(windows)]
    const JOB_ROLE: &str = "KASUMI_TEST_JOB_ROLE";

    /// Re-runs this test binary as the parent or the grandchild of
    /// `children_die_with_a_killed_parent`; returns at once in a normal run.
    #[cfg(windows)]
    #[tokio::test]
    async fn job_role() {
        let exe = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        match std::env::var(JOB_ROLE).as_deref() {
            Ok("parent") => {
                let dir = tempfile::tempdir().unwrap();
                let argv = [exe, "--exact".into(), "proc::tests::job_role".into()];
                let env = HashMap::from([(JOB_ROLE.to_owned(), "child".to_owned())]);
                let child = spawn_logged(&argv, &env, dir.path().join("c.log"), false)
                    .await
                    .unwrap();
                println!("child-pid={}", child.id().unwrap());
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            }
            Ok("child") => tokio::time::sleep(std::time::Duration::from_secs(120)).await,
            _ => {}
        }
    }

    // The helper crash case: TerminateProcess on the parent runs none of its
    // code, yet the core it spawned has to go with it.
    #[cfg(windows)]
    #[tokio::test]
    async fn children_die_with_a_killed_parent() {
        use tokio::io::AsyncBufReadExt;

        let exe = std::env::current_exe().unwrap();
        let mut parent = Command::new(&exe)
            .args(["--exact", "proc::tests::job_role", "--nocapture"])
            .env(JOB_ROLE, "parent")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = tokio::io::BufReader::new(parent.stdout.take().unwrap()).lines();
        let pid = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(pid) = line.strip_prefix("child-pid=") {
                    return pid.trim().parse::<i32>().unwrap();
                }
            }
            panic!("parent exited without spawning");
        })
        .await
        .unwrap();
        assert!(pid_matches_bin(pid, &exe).await);

        parent.kill().await.unwrap();
        for _ in 0..50 {
            if !pid_matches_bin(pid, &exe).await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        imp::kill(pid, false).await;
        panic!("child {pid} outlived its killed parent");
    }
}

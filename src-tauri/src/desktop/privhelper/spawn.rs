//! GUI side: spawn the root helper through the elevator and connect to it.
//!
//! The GUI stays unprivileged and runs `pkexec`/`sudo` on the *small fixed helper*
//! (not the whole GUI). It hands the helper its already-resolved dirs + the cores
//! dir + the controlling pid as CLI args — pkexec scrubs the environment, so
//! re-deriving them root-side would drift; passing them keeps both halves in
//! lock-step. Nothing dangerous (no `LD_*`) crosses the boundary; the helper picks
//! its own trusted paths from these explicit, non-executable arguments.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::desktop::paths::{DesktopPaths, path_args};
use kasumi_log::{Area, ks_info};

use super::client::Client;
use super::proto::HelperOutdated;

/// Path of the bundled helper binary shipped beside the GUI executable. Under
/// the Nix GApps wrapper `current_exe` is the real ELF in the package's `bin/`,
/// so the helper is its sibling.
fn bundled_sibling_bin() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("locate current exe")?;
    let dir = exe.parent().context("current exe has no parent dir")?;
    Ok(dir.join("kasumi-helper"))
}

/// Path of the helper binary shipped beside the GUI (`KASUMI_HELPER_BIN` overrides
/// for dev).
fn helper_bin() -> anyhow::Result<PathBuf> {
    if let Some(p) = std::env::var_os("KASUMI_HELPER_BIN") {
        return Ok(PathBuf::from(p));
    }
    bundled_sibling_bin()
}

/// Locate the elevator to run the helper through. Prefer a graphical pkexec (a
/// polkit dialog suits a GUI), then sudo. On NixOS the setuid wrappers live under
/// /run/wrappers/bin (the store pkexec is NOT setuid).
fn find_elevator() -> Option<PathBuf> {
    for c in [
        "/run/wrappers/bin/pkexec",
        "/usr/bin/pkexec",
        "/run/wrappers/bin/sudo",
        "/usr/bin/sudo",
    ] {
        if std::path::Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

/// System paths where an administrator or distribution package may install a
/// capability-bearing helper binary. Checked in order: /usr/local/bin first
/// (local administrative installs), then /usr/bin (packaged installs).
const INSTALLED_HELPER_CANDIDATES: [&str; 2] =
    ["/usr/local/bin/kasumi-helper", "/usr/bin/kasumi-helper"];

/// Minimal metadata needed to evaluate trust and execution eligibility of a binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStat {
    is_file: bool,
    is_dir: bool,
    mode: u32,
    uid: u32,
}

impl From<&std::fs::Metadata> for FileStat {
    fn from(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            is_file: m.is_file(),
            is_dir: m.is_dir(),
            mode: m.mode(),
            uid: m.uid(),
        }
    }
}

/// Environment abstraction for helper candidate discovery and security validation.
/// Enables deterministic unit testing without requiring root privileges or host /usr state.
trait HelperEnv {
    fn get_override(&self) -> Option<PathBuf>;
    fn get_sibling(&self) -> anyhow::Result<PathBuf>;
    fn wrapper_exists(&self, path: &Path) -> bool;
    fn has_caps(&self, path: &Path) -> bool;
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf>;
    fn metadata(&self, path: &Path) -> std::io::Result<FileStat>;
}

/// Real operating system environment implementation.
struct RealSystem;

impl HelperEnv for RealSystem {
    fn get_override(&self) -> Option<PathBuf> {
        std::env::var_os("KASUMI_HELPER_BIN").map(PathBuf::from)
    }

    fn get_sibling(&self) -> anyhow::Result<PathBuf> {
        bundled_sibling_bin()
    }

    fn wrapper_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn has_caps(&self, path: &Path) -> bool {
        has_file_caps(path)
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        path.canonicalize()
    }

    fn metadata(&self, path: &Path) -> std::io::Result<FileStat> {
        std::fs::metadata(path).map(|m| FileStat::from(&m))
    }
}

/// Implicit fallbacks must be administrator-controlled. Resolve symlinks before
/// checking the executable and its ancestors, then execute that resolved path so
/// replacing the original symlink cannot redirect the launch.
fn validate_installed_candidate<E: HelperEnv>(candidate: &Path, env: &E) -> Option<PathBuf> {
    let canonical = env.canonicalize(candidate).ok()?;
    if !canonical.is_absolute() {
        return None;
    }

    let file_stat = env.metadata(&canonical).ok()?;
    if !file_stat.is_file {
        return None;
    }
    // File must have at least one executable bit set.
    if file_stat.mode & 0o111 == 0 {
        return None;
    }
    // File must be owned by root.
    if file_stat.uid != 0 {
        return None;
    }
    // File must not be writable by group or other (no 0o020 or 0o002).
    if file_stat.mode & 0o022 != 0 {
        return None;
    }

    // Every resolved ancestor directory must be owned by root and non-group/other-writable.
    for ancestor in canonical.ancestors().skip(1) {
        let dir_stat = env.metadata(ancestor).ok()?;
        if !dir_stat.is_dir {
            return None;
        }
        if dir_stat.uid != 0 {
            return None;
        }
        if dir_stat.mode & 0o022 != 0 {
            return None;
        }
    }

    // File capabilities identify provisioned candidates; presence alone does not
    // prove the complete keep-set will be effective when the helper starts.
    if !env.has_caps(&canonical) {
        return None;
    }

    Some(canonical)
}

/// Select a capability-bearing helper binary according to precedence:
/// 1. `KASUMI_HELPER_BIN` override (exclusive: uncapped override returns `None`
///    so subsequent elevation targets the override directly without shadowing).
/// 2. NixOS `/run/wrappers/bin/kasumi-helper` security wrapper.
/// 3. Bundled sibling helper beside GUI executable, if capped.
/// 4. Installed system fallbacks (`/usr/local/bin`, then `/usr/bin`), only if
///    trusted and capability-bearing.
fn find_capped_helper<E: HelperEnv>(env: &E, installed_candidates: &[&Path]) -> Option<PathBuf> {
    // A dev `KASUMI_HELPER_BIN` override pins a specific binary; the NixOS
    // `/run/wrappers/bin/kasumi-helper` wrapper points at the *installed* helper — a
    // different binary — so it must not shadow the override. With the override set,
    // only the override's own file caps qualify here; otherwise the caller falls back
    // to setcap/elevation, which run the override directly.
    if let Some(override_bin) = env.get_override() {
        return env.has_caps(&override_bin).then_some(override_bin);
    }

    // Preserve the administrator-provisioned NixOS security wrapper.
    let wrapper = Path::new("/run/wrappers/bin/kasumi-helper");
    if env.wrapper_exists(wrapper) {
        return Some(wrapper.to_path_buf());
    }

    // Bundled sibling helper wins next so a matching bundled version is preferred.
    if let Ok(sibling) = env.get_sibling()
        && env.has_caps(&sibling)
    {
        return Some(sibling);
    }

    // Fall back to pre-installed capability-bearing system binaries (e.g. for AppImage).
    for candidate in installed_candidates {
        if let Some(trusted) = validate_installed_candidate(candidate, env) {
            return Some(trusted);
        }
    }

    None
}

/// A `kasumi-helper` that already holds the data-path file caps, so the GUI execs
/// it directly with no elevation or prompt. Checks the NixOS `security.wrappers`
/// entry first, then the sibling helper's own file caps — set either by the deb
/// postinst or by a prior one-time self-`setcap` (see [`self_setcap_target`]).
/// When unprivileged or ephemeral (e.g. running from an AppImage), falls back to
/// checking pre-installed, trusted, capability-bearing system helpers in
/// `/usr/local/bin` and `/usr/bin`.
/// `None` → no capped helper yet; fall back to elevating via pkexec/sudo.
fn capped_helper() -> Option<PathBuf> {
    let candidates = INSTALLED_HELPER_CANDIDATES.map(Path::new);
    find_capped_helper(&RealSystem, &candidates)
}

/// Discover provisioned helpers without attempting elevation. This only checks
/// for a capability xattr; mounts, capability bits and process restrictions may
/// still prevent the helper from obtaining the complete data-path keep-set.
fn has_file_caps(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // getxattr(.., size=0) returns the value's length (>0 if present), or -1 (ENODATA)
    // when the attribute is absent.
    let ret = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    ret > 0
}

/// The on-disk helper a one-time `pkexec setcap` can grant file caps to, or `None`
/// when self-`setcap` can't or shouldn't run: a read-only `/nix/store` path (NixOS
/// uses the wrapper), inside an AppImage mount (FUSE + nosuid — caps wouldn't
/// persist), or a dev `KASUMI_HELPER_BIN` override.
fn self_setcap_target() -> Option<PathBuf> {
    if std::env::var_os("KASUMI_HELPER_BIN").is_some() || std::env::var_os("APPIMAGE").is_some() {
        return None;
    }
    let bin = helper_bin().ok()?;
    (!bin.starts_with("/nix/store")).then_some(bin)
}

/// Absolute `setcap` (libcap), searched where it actually ships — it's in `sbin`,
/// usually off the `$PATH` pkexec hands a child. `None` → libcap isn't installed.
fn find_setcap() -> Option<PathBuf> {
    for c in [
        "/usr/sbin/setcap",
        "/sbin/setcap",
        "/usr/bin/setcap",
        "/bin/setcap",
    ] {
        if Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

/// Grant the data-path file caps to `helper` via a single `pkexec setcap` (one
/// prompt). On success every later launch finds the capped helper and runs it
/// directly — no further prompts, mirroring the deb postinst for non-deb installs.
async fn grant_file_caps(elevator: &Path, setcap: &Path, helper: &Path) -> bool {
    let status = tokio::process::Command::new(elevator)
        .arg(setcap)
        .arg(crate::desktop::capabilities::file_caps_setcap_arg())
        .arg(helper)
        .status()
        .await;
    matches!(status, Ok(s) if s.success())
}

/// The unix socket the helper binds, inside the GUI-resolved run dir.
fn socket_path(paths: &DesktopPaths) -> String {
    format!("{}/helper.sock", paths.run_dir)
}

/// Spawn the helper elevated and return a connected [`Client`]. Resolves once the
/// helper answers a `Ping`. The helper keeps running after this returns (it owns
/// the data-path); it exits on its own when the GUI (pid `gui_pid`) goes away.
///
/// Launch paths, in preference order:
/// 1. a helper that already holds the data-path caps (NixOS wrapper, deb postinst,
///    or a prior self-`setcap`) → exec directly, no elevation, no prompt;
/// 2. first run without caps → one `pkexec setcap` to grant them, then exec the now-
///    capped helper directly (every later launch hits path 1);
/// 3. setcap unavailable / read-only path → elevate the helper as root per-launch.
pub async fn spawn_and_connect(paths: &DesktopPaths) -> anyhow::Result<Client> {
    let socket = socket_path(paths);
    let gui_pid = std::process::id();
    let uid = unsafe { libc::geteuid() };

    let mut cmd = if let Some(bin) = capped_helper() {
        ks_info!(
            Area::Helper,
            "launching capped helper directly (no elevation): {}",
            bin.display()
        );
        let mut c = tokio::process::Command::new(bin);
        c.arg("--socket").arg(&socket);
        c
    } else {
        let elevator = find_elevator().context("no pkexec/sudo found to elevate the helper")?;
        // First-run bootstrap: grant the helper its caps once so every later launch
        // runs capped + promptless. Best-effort — on failure (no setcap, read-only
        // FS) fall through to elevating the helper as root for this session.
        let target = self_setcap_target();
        let granted = match (&target, find_setcap()) {
            (Some(t), Some(setcap)) => {
                grant_file_caps(&elevator, &setcap, t).await && has_file_caps(t)
            }
            _ => false,
        };
        match (granted, target) {
            (true, Some(t)) => {
                ks_info!(
                    Area::Helper,
                    "granted file caps to {}; launching directly",
                    t.display()
                );
                let mut c = tokio::process::Command::new(&t);
                c.arg("--socket").arg(&socket);
                c
            }
            _ => {
                let helper = helper_bin()?;
                ks_info!(
                    Area::Helper,
                    "elevating helper {} via {} (socket {socket})",
                    helper.display(),
                    elevator.display()
                );
                let mut c = tokio::process::Command::new(&elevator);
                c.arg(&helper).arg("--socket").arg(&socket);
                c
            }
        }
    };
    for (flag, value) in path_args(paths) {
        cmd.arg(flag).arg(value);
    }
    cmd.arg("--owner-uid")
        .arg(uid.to_string())
        .arg("--gui-pid")
        .arg(gui_pid.to_string());
    // Detach from the GUI's stdio; the helper logs to stderr inherited by the GUI.
    cmd.stdin(std::process::Stdio::null());
    // A helper left from an earlier session may still answer on the old socket
    // until the new one replaces it, so only a socket created after this spawn
    // speaks for the helper just launched.
    let stale_socket = socket_inode(&socket);
    cmd.spawn().context("spawn the privilege helper")?;

    // The elevator may show a prompt; wait (bounded) for the helper to bind + chown
    // the socket, then confirm it with the handshake.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut outdated = None;
    loop {
        let fresh = socket_inode(&socket).is_some_and(|ino| Some(ino) != stale_socket);
        let err = match Client::connect(&socket).await {
            Ok(client) => match client.handshake().await {
                Ok(()) => return Ok(client),
                Err(e) if e.is::<HelperOutdated>() => {
                    if fresh {
                        return Err(e);
                    }
                    let msg = format!("{e:#}");
                    outdated = Some(e);
                    msg
                }
                Err(e) => format!("{e:#}"),
            },
            Err(e) => format!("{e:#}"),
        };
        if std::time::Instant::now() >= deadline {
            if let Some(e) = outdated {
                return Err(e);
            }
            anyhow::bail!("privilege helper did not become ready (elevation declined?): {err}");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Inode of the socket file, to tell a freshly bound socket from a stale one.
fn socket_inode(socket: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(socket).ok().map(|m| m.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    struct MockEnv {
        override_bin: Option<PathBuf>,
        wrapper_path: PathBuf,
        wrapper_present: bool,
        sibling_result: anyhow::Result<PathBuf>,
        caps: HashSet<PathBuf>,
        canonical_map: HashMap<PathBuf, PathBuf>,
        stats: HashMap<PathBuf, FileStat>,
    }

    impl MockEnv {
        fn new() -> Self {
            Self {
                override_bin: None,
                wrapper_path: PathBuf::from("/run/wrappers/bin/kasumi-helper"),
                wrapper_present: false,
                sibling_result: Err(anyhow::anyhow!("sibling missing")),
                caps: HashSet::new(),
                canonical_map: HashMap::new(),
                stats: HashMap::new(),
            }
        }

        /// Register a path with a fully trusted root-owned directory tree up to root.
        fn add_trusted_file(&mut self, path: &Path, mode: u32, uid: u32, capped: bool) {
            let canon = path.to_path_buf();
            self.canonical_map.insert(path.to_path_buf(), canon.clone());
            self.stats.insert(
                canon.clone(),
                FileStat {
                    is_file: true,
                    is_dir: false,
                    mode,
                    uid,
                },
            );
            if capped {
                self.caps.insert(canon.clone());
            }

            for ancestor in canon.ancestors().skip(1) {
                self.stats
                    .entry(ancestor.to_path_buf())
                    .or_insert(FileStat {
                        is_file: false,
                        is_dir: true,
                        mode: 0o755,
                        uid: 0,
                    });
            }
        }
    }

    impl HelperEnv for MockEnv {
        fn get_override(&self) -> Option<PathBuf> {
            self.override_bin.clone()
        }

        fn get_sibling(&self) -> anyhow::Result<PathBuf> {
            match &self.sibling_result {
                Ok(p) => Ok(p.clone()),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        }

        fn wrapper_exists(&self, path: &Path) -> bool {
            self.wrapper_present && path == self.wrapper_path
        }

        fn has_caps(&self, path: &Path) -> bool {
            self.caps.contains(path)
        }

        fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
            self.canonical_map
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
        }

        fn metadata(&self, path: &Path) -> std::io::Result<FileStat> {
            self.stats
                .get(path)
                .copied()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
        }
    }

    #[test]
    fn override_pins_specific_binary_and_does_not_shadow_other_candidates() {
        let mut env = MockEnv::new();
        let override_path = PathBuf::from("/dev/override/kasumi-helper");
        env.override_bin = Some(override_path.clone());
        env.caps.insert(override_path.clone());

        // Even with wrapper present, capped sibling, and capped installed fallbacks,
        // the explicit override must win.
        env.wrapper_present = true;
        let sibling_path = PathBuf::from("/bundled/kasumi-helper");
        env.sibling_result = Ok(sibling_path.clone());
        env.caps.insert(sibling_path);
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), Some(override_path));
    }

    #[test]
    fn override_without_caps_returns_none_without_falling_back() {
        let mut env = MockEnv::new();
        let override_path = PathBuf::from("/dev/override/kasumi-helper");
        env.override_bin = Some(override_path);
        // Override is intentionally NOT capped.

        // Other valid candidates are present, but override exclusivity must prevent shadowing.
        env.wrapper_present = true;
        let sibling_path = PathBuf::from("/bundled/kasumi-helper");
        env.sibling_result = Ok(sibling_path.clone());
        env.caps.insert(sibling_path);
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn nixos_wrapper_is_preferred_when_it_exists_without_checking_caps() {
        let mut env = MockEnv::new();
        env.wrapper_present = true;

        // Security wrappers need not expose capabilities directly on their own inode.
        let sibling_path = PathBuf::from("/bundled/kasumi-helper");
        env.sibling_result = Ok(sibling_path.clone());
        env.caps.insert(sibling_path);
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/run/wrappers/bin/kasumi-helper"))
        );
    }

    #[test]
    fn bundled_sibling_with_caps_is_preferred_over_installed_candidates() {
        let mut env = MockEnv::new();
        let sibling_path = PathBuf::from("/bundled/kasumi-helper");
        env.sibling_result = Ok(sibling_path.clone());
        env.caps.insert(sibling_path.clone());

        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);
        env.add_trusted_file(Path::new("/usr/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(find_capped_helper(&env, &candidates), Some(sibling_path));
    }

    #[test]
    fn installed_local_bin_is_preferred_over_system_bin() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);
        env.add_trusted_file(Path::new("/usr/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/usr/local/bin/kasumi-helper"))
        );
    }

    #[test]
    fn installed_candidate_is_selected_when_bundled_sibling_is_uncapped() {
        let mut env = MockEnv::new();
        let sibling_path = PathBuf::from("/bundled/kasumi-helper");
        env.sibling_result = Ok(sibling_path);
        // Sibling has no capabilities (e.g. running from AppImage mount).

        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/usr/local/bin/kasumi-helper"))
        );
    }

    #[test]
    fn installed_candidate_is_selected_when_bundled_sibling_resolution_fails() {
        let mut env = MockEnv::new();
        env.sibling_result = Err(anyhow::anyhow!("current exe resolution failed"));

        env.add_trusted_file(Path::new("/usr/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/usr/bin/kasumi-helper"))
        );
    }

    #[test]
    fn installed_local_candidate_skipped_when_uncapped_falling_back_to_system_bin() {
        let mut env = MockEnv::new();
        // /usr/local/bin is trusted but uncapped:
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, false);
        // /usr/bin is trusted and capped:
        env.add_trusted_file(Path::new("/usr/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/usr/bin/kasumi-helper"))
        );
    }

    #[test]
    fn installed_local_candidate_skipped_when_missing_falling_back_to_system_bin() {
        let mut env = MockEnv::new();
        // /usr/local/bin candidate not present at all.
        // /usr/bin is trusted and capped:
        env.add_trusted_file(Path::new("/usr/bin/kasumi-helper"), 0o755, 0, true);

        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(PathBuf::from("/usr/bin/kasumi-helper"))
        );
    }

    #[test]
    fn installed_candidate_rejected_when_not_root_owned() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 1000, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_group_writable() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o775, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_world_writable() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o777, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_not_executable() {
        let mut env = MockEnv::new();
        // Mode 0644 has no execute bits.
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o644, 0, true);

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_it_is_a_directory() {
        let mut env = MockEnv::new();
        let path = Path::new("/usr/local/bin/kasumi-helper");
        env.add_trusted_file(path, 0o755, 0, true);
        if let Some(stat) = env.stats.get_mut(path) {
            stat.is_file = false;
            stat.is_dir = true;
        }

        let candidates = [path];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_ancestor_is_not_root_owned() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);
        if let Some(stat) = env.stats.get_mut(Path::new("/usr/local")) {
            stat.uid = 1000;
        }

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_ancestor_is_group_writable() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);
        if let Some(stat) = env.stats.get_mut(Path::new("/usr/local")) {
            stat.mode = 0o775;
        }

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejected_when_ancestor_is_world_writable() {
        let mut env = MockEnv::new();
        env.add_trusted_file(Path::new("/usr/local/bin/kasumi-helper"), 0o755, 0, true);
        if let Some(stat) = env.stats.get_mut(Path::new("/usr/local/bin")) {
            stat.mode = 0o777;
        }

        let candidates = [Path::new("/usr/local/bin/kasumi-helper")];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn returns_none_when_no_candidate_qualifies() {
        let env = MockEnv::new();
        let candidates = [
            Path::new("/usr/local/bin/kasumi-helper"),
            Path::new("/usr/bin/kasumi-helper"),
        ];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_resolves_and_accepts_safe_symlink_target() {
        let mut env = MockEnv::new();
        let cand = Path::new("/usr/local/bin/kasumi-helper");
        let target = Path::new("/opt/kasumi/bin/kasumi-helper");

        env.canonical_map
            .insert(cand.to_path_buf(), target.to_path_buf());
        env.add_trusted_file(target, 0o755, 0, true);

        let candidates = [cand];
        assert_eq!(
            find_capped_helper(&env, &candidates),
            Some(target.to_path_buf())
        );
    }

    #[test]
    fn installed_candidate_rejects_symlink_pointing_to_writable_directory() {
        let mut env = MockEnv::new();
        let cand = Path::new("/usr/local/bin/kasumi-helper");
        let target = Path::new("/tmp/evil-helper");

        env.canonical_map
            .insert(cand.to_path_buf(), target.to_path_buf());
        env.add_trusted_file(target, 0o755, 0, true);
        // /tmp is world-writable (mode 01777):
        if let Some(stat) = env.stats.get_mut(Path::new("/tmp")) {
            stat.mode = 0o1777;
        }

        let candidates = [cand];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }

    #[test]
    fn installed_candidate_rejects_symlink_pointing_to_non_root_owned_directory() {
        let mut env = MockEnv::new();
        let cand = Path::new("/usr/local/bin/kasumi-helper");
        let target = Path::new("/home/alice/bin/kasumi-helper");

        env.canonical_map
            .insert(cand.to_path_buf(), target.to_path_buf());
        env.add_trusted_file(target, 0o755, 0, true);
        // /home/alice is owned by alice (uid 1001):
        if let Some(stat) = env.stats.get_mut(Path::new("/home/alice")) {
            stat.uid = 1001;
        }

        let candidates = [cand];
        assert_eq!(find_capped_helper(&env, &candidates), None);
    }
}

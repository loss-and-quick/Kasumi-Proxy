//! How the running desktop binary was installed, and whether it can self-update.
//!
//! The release updater manifest (`latest.json`) only ships self-updating bundles:
//! the Linux AppImage and the Windows NSIS installer. Distro packages (Fedora COPR
//! RPM, GitHub `.rpm`/`.deb`, NixOS flake) are managed by their package manager,
//! and portable zips carry a `portable.dat` marker next to the executable and are
//! updated manually. Trying to invoke `tauri-plugin-updater` on those either fails
//! with an invalid format or tries to overwrite `/usr/bin/kasumi-desktop` or a
//! read-only `/nix/store` binary.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;
use tauri::utils::config::BundleType;

/// Whether the running desktop installation can self-update through the bundled
/// updater plugin, or why in-app updates are disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum UpdatePolicy {
    /// Self-updating bundle (Linux AppImage or installed Windows build).
    SelfUpdate,
    /// Installed and updated by a system package manager (RPM, DEB, Nix, etc.).
    ExternallyManaged,
    /// Portable zip (`portable.dat` beside the executable); updated manually.
    Portable,
    /// Build without a matching self-update artifact (e.g. local dev build).
    Unsupported,
}

impl UpdatePolicy {
    pub fn can_self_update(self) -> bool {
        matches!(self, Self::SelfUpdate)
    }
}

/// Pure inputs for [`detect_update_policy`], separated from process/FS probes so
/// every packaging layout is unit-tested deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallFacts {
    externally_managed_feature: bool,
    portable: bool,
    bundle: Option<BundleType>,
    has_appimage_env: bool,
    /// `uninstall.exe` beside the executable (written by Tauri's NSIS installer
    /// in `$INSTDIR`). Preserves NSIS self-update even if bundle-type patching
    /// did not stamp the binary.
    has_nsis_uninstaller: bool,
    exe_path: Option<PathBuf>,
    os: &'static str,
}

/// System-owned prefixes where Linux package managers and distro builds install
/// executables. Used as a fallback when a distro package is built via `cargo build`
/// without `--features externally-managed`.
const LINUX_MANAGED_PREFIXES: [&str; 6] = ["/usr", "/bin", "/nix/store", "/opt", "/app", "/snap"];

fn is_linux_managed_path(path: &Path) -> bool {
    LINUX_MANAGED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn detect_update_policy(facts: &InstallFacts) -> UpdatePolicy {
    if facts.externally_managed_feature {
        return UpdatePolicy::ExternallyManaged;
    }
    if facts.portable {
        return UpdatePolicy::Portable;
    }

    match facts.bundle {
        Some(BundleType::Deb | BundleType::Rpm) => UpdatePolicy::ExternallyManaged,
        Some(BundleType::AppImage) => {
            if facts.has_appimage_env {
                UpdatePolicy::SelfUpdate
            } else {
                UpdatePolicy::Unsupported
            }
        }
        Some(BundleType::Nsis) => UpdatePolicy::SelfUpdate,
        Some(BundleType::Msi | BundleType::App | BundleType::Dmg) => UpdatePolicy::Unsupported,
        None => match facts.os {
            "linux" => {
                // Check managed prefixes before an inherited `$APPIMAGE` env var so a
                // system-installed binary launched from another AppImage cannot treat
                // that unrelated file as its own update target. Genuine AppImages run
                // from a mount point (e.g. `/tmp/.mount_…/usr/bin/kasumi-desktop`).
                if facts.exe_path.as_deref().is_some_and(is_linux_managed_path) {
                    UpdatePolicy::ExternallyManaged
                } else if facts.has_appimage_env {
                    UpdatePolicy::SelfUpdate
                } else {
                    UpdatePolicy::Unsupported
                }
            }
            "windows" => {
                if facts.has_nsis_uninstaller {
                    UpdatePolicy::SelfUpdate
                } else {
                    UpdatePolicy::Unsupported
                }
            }
            _ => UpdatePolicy::Unsupported,
        },
    }
}

/// Compute the running process's [`UpdatePolicy`] once and cache it for the
/// lifetime of the process so plugin registration and IPC queries always agree.
pub fn current_update_policy() -> UpdatePolicy {
    static POLICY: OnceLock<UpdatePolicy> = OnceLock::new();
    *POLICY.get_or_init(|| {
        let exe_path = std::env::current_exe().ok();
        let exe_dir = exe_path.as_deref().and_then(Path::parent);
        let portable = exe_dir.is_some_and(|dir| dir.join("portable.dat").exists());
        let has_nsis_uninstaller = cfg!(target_os = "windows")
            && exe_dir.is_some_and(|dir| dir.join("uninstall.exe").exists());
        let has_appimage_env = std::env::var_os("APPIMAGE").is_some_and(|v| !v.is_empty());

        detect_update_policy(&InstallFacts {
            externally_managed_feature: cfg!(feature = "externally-managed"),
            portable,
            bundle: tauri::utils::platform::bundle_type(),
            has_appimage_env,
            has_nsis_uninstaller,
            exe_path,
            os: std::env::consts::OS,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_facts() -> InstallFacts {
        InstallFacts {
            externally_managed_feature: false,
            portable: false,
            bundle: None,
            has_appimage_env: false,
            has_nsis_uninstaller: false,
            exe_path: Some(PathBuf::from(
                "/home/user/project/target/debug/kasumi-desktop",
            )),
            os: "linux",
        }
    }

    fn windows_facts() -> InstallFacts {
        InstallFacts {
            externally_managed_feature: false,
            portable: false,
            bundle: None,
            has_appimage_env: false,
            has_nsis_uninstaller: false,
            exe_path: Some(PathBuf::from(
                r"C:\Program Files\Kasumi Proxy\kasumi-desktop.exe",
            )),
            os: "windows",
        }
    }

    #[test]
    fn externally_managed_feature_overrides_every_runtime_signal() {
        let mut facts = linux_facts();
        facts.externally_managed_feature = true;
        facts.bundle = Some(BundleType::AppImage);
        facts.has_appimage_env = true;
        assert_eq!(
            detect_update_policy(&facts),
            UpdatePolicy::ExternallyManaged
        );

        let mut win = windows_facts();
        win.externally_managed_feature = true;
        win.bundle = Some(BundleType::Nsis);
        assert_eq!(detect_update_policy(&win), UpdatePolicy::ExternallyManaged);
    }

    #[test]
    fn portable_marker_disables_self_update_on_linux_and_windows() {
        let mut linux = linux_facts();
        linux.portable = true;
        assert_eq!(detect_update_policy(&linux), UpdatePolicy::Portable);

        let mut win = windows_facts();
        win.portable = true;
        win.bundle = Some(BundleType::Nsis);
        win.has_nsis_uninstaller = true;
        assert_eq!(detect_update_policy(&win), UpdatePolicy::Portable);
    }

    #[test]
    fn linux_rpm_and_deb_bundles_are_externally_managed() {
        for bundle in [BundleType::Rpm, BundleType::Deb] {
            let mut facts = linux_facts();
            facts.bundle = Some(bundle.clone());
            assert_eq!(
                detect_update_policy(&facts),
                UpdatePolicy::ExternallyManaged,
                "bundle {bundle:?}"
            );
        }
    }

    #[test]
    fn linux_system_and_nix_paths_stay_externally_managed_even_with_inherited_appimage() {
        for exe in [
            "/usr/bin/kasumi-desktop",
            "/usr/local/bin/kasumi-desktop",
            "/nix/store/abc123-kasumi-desktop/bin/.kasumi-desktop-wrapped",
            "/opt/kasumi-proxy/kasumi-desktop",
            "/app/bin/kasumi-desktop",
        ] {
            for has_appimage_env in [false, true] {
                let mut facts = linux_facts();
                facts.exe_path = Some(PathBuf::from(exe));
                facts.has_appimage_env = has_appimage_env;
                assert_eq!(
                    detect_update_policy(&facts),
                    UpdatePolicy::ExternallyManaged,
                    "exe {exe} (APPIMAGE={has_appimage_env})"
                );
            }
        }
    }

    #[test]
    fn linux_appimage_self_updates_only_when_appimage_env_is_set() {
        let mut mounted = linux_facts();
        mounted.bundle = Some(BundleType::AppImage);
        mounted.has_appimage_env = true;
        assert_eq!(detect_update_policy(&mounted), UpdatePolicy::SelfUpdate);

        // Untagged genuine AppImage mount point under /tmp/.mount_…
        let mut untagged_mounted = linux_facts();
        untagged_mounted.exe_path = Some(PathBuf::from(
            "/tmp/.mount_Kasumi1234/usr/bin/kasumi-desktop",
        ));
        untagged_mounted.has_appimage_env = true;
        assert_eq!(
            detect_update_policy(&untagged_mounted),
            UpdatePolicy::SelfUpdate
        );

        let mut extracted = linux_facts();
        extracted.bundle = Some(BundleType::AppImage);
        extracted.has_appimage_env = false;
        assert_eq!(detect_update_policy(&extracted), UpdatePolicy::Unsupported);
    }

    #[test]
    fn windows_nsis_self_updates_with_tag_or_uninstaller_while_msi_and_dev_do_not() {
        let mut nsis = windows_facts();
        nsis.bundle = Some(BundleType::Nsis);
        assert_eq!(detect_update_policy(&nsis), UpdatePolicy::SelfUpdate);

        // Untagged NSIS installation (e.g. if bundle-type patching was skipped)
        // still carries Tauri's `uninstall.exe` beside the app binary.
        let mut untagged_nsis = windows_facts();
        untagged_nsis.has_nsis_uninstaller = true;
        assert_eq!(
            detect_update_policy(&untagged_nsis),
            UpdatePolicy::SelfUpdate
        );

        let mut msi = windows_facts();
        msi.bundle = Some(BundleType::Msi);
        assert_eq!(detect_update_policy(&msi), UpdatePolicy::Unsupported);

        assert_eq!(
            detect_update_policy(&windows_facts()),
            UpdatePolicy::Unsupported
        );
        assert_eq!(
            detect_update_policy(&linux_facts()),
            UpdatePolicy::Unsupported
        );
    }
}

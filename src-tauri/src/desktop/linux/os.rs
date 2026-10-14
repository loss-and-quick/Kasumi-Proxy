//! The Linux [`DesktopOs`] seam: the parts of the desktop data-path that differ from
//! Windows — a native tun reachable via `ip`, `/proc/net/dev` byte counters, and the
//! gvisor sing-box stack for the root-binary tun path.

use std::time::Duration;

use async_trait::async_trait;

use kasumi_backend::fs::{exists, read_text};
use kasumi_core::request_identity::{DesktopHost, DeviceFacts};
use kasumi_core::state::SingboxStack;

use crate::desktop::paths::DesktopPaths;
use crate::desktop::platform::DesktopOs;
use crate::desktop::silent;

/// The userspace tun's address; `/15` covers the CGNAT-ish 198.18/15 test net.
/// Single-sourced from core so it can't drift from hev's self-assigned address.
pub(crate) const TUN_ADDR: &str = kasumi_core::tun::TUN_IPV4_CIDR;

/// The `ip` (iproute2) binary. Resolved via `PATH`: on distros it sits in the
/// system path (and pkexec's own minimal PATH includes it for the helper); the Nix
/// build puts iproute2 on the GUI's and helper's PATH via their wrappers, so this
/// stays a plain name with no environment plumbing.
pub(crate) const IP: &str = "ip";

pub(crate) struct LinuxOs;

/// RX/TX bytes for `iface` from /proc/net/dev, or (0, 0).
async fn iface_traffic(iface: Option<&str>) -> (u64, u64) {
    let Some(iface) = iface else {
        return (0, 0);
    };
    let Some(dev) = read_text("/proc/net/dev").await else {
        return (0, 0);
    };
    for line in dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        let rx = f.first().and_then(|x| x.parse().ok()).unwrap_or(0);
        let tx = f.get(8).and_then(|x| x.parse().ok()).unwrap_or(0);
        return (rx, tx);
    }
    (0, 0)
}

#[async_trait]
impl DesktopOs for LinuxOs {
    fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }

    async fn precheck_external_tun(&self, _p: &DesktopPaths) -> anyhow::Result<()> {
        Ok(())
    }

    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()> {
        // Best-effort: tun2socks creates the device asynchronously. If it never
        // shows we still proceed — addressing/routing will simply no-op, matching
        // the original `ip` flow (no hard failure here).
        for _ in 0..20 {
            if silent(&[IP, "link", "show", name]).await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    }

    async fn iface_traffic(&self, iface: Option<&str>) -> (u64, u64) {
        iface_traffic(iface).await
    }

    async fn tun_capable(&self) -> bool {
        exists("/dev/net/tun").await
    }

    fn singbox_stack(&self) -> SingboxStack {
        SingboxStack::Gvisor
    }

    async fn machine_id(&self) -> Option<String> {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Some(id) = read_text(path).await.map(|s| s.trim().to_owned())
                && !id.is_empty()
            {
                return Some(id);
            }
        }
        None
    }

    // The raw values; happ-sub formats them as each client does.
    async fn device_facts(&self) -> DeviceFacts {
        let os_release = match read_text("/etc/os-release").await {
            Some(text) => text,
            None => read_text("/usr/lib/os-release").await.unwrap_or_default(),
        };
        let kernel = |key: &'static str| async move {
            read_text(&format!("/proc/sys/kernel/{key}"))
                .await
                .map(|v| v.trim().to_owned())
                .unwrap_or_default()
        };
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        DeviceFacts::desktop(
            "Linux",
            DesktopHost {
                os_release_id: os_release_field(&os_release, "ID"),
                os_release_version: os_release_field(&os_release, "VERSION_ID"),
                kernel_release: kernel("osrelease").await,
                hostname: kernel("hostname").await,
                cpu_arch: std::env::consts::ARCH.into(),
                username: env("USER").or_else(|| env("LOGNAME")).unwrap_or_default(),
                posix_locale: posix_locale([env("LC_ALL"), env("LC_MESSAGES"), env("LANG")]),
            },
        )
    }
}

/// One field of an os-release file, unquoted; empty when missing.
fn os_release_field(os_release: &str, key: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches(['"', '\'']).to_owned())
        .unwrap_or_default()
}

/// The first set locale variable, as POSIX resolves them.
fn posix_locale(vars: [Option<String>; 3]) -> String {
    vars.into_iter()
        .flatten()
        .map(|v| v.trim().to_owned())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "C".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_fields_unquote() {
        let nixos = "NAME=NixOS\nID=nixos\nVERSION_ID=\"26.05\"\nPRETTY_NAME=\"NixOS 26.05\"\n";
        assert_eq!(os_release_field(nixos, "ID"), "nixos");
        assert_eq!(os_release_field(nixos, "VERSION_ID"), "26.05");
        // `ID_LIKE` is not `ID`.
        assert_eq!(
            os_release_field("ID_LIKE=debian\nID=ubuntu\n", "ID"),
            "ubuntu"
        );
        assert_eq!(
            os_release_field("ID=arch\nBUILD_ID=rolling\n", "VERSION_ID"),
            ""
        );
    }

    #[test]
    fn posix_locale_follows_precedence() {
        let s = |v: &str| Some(v.to_owned());
        assert_eq!(posix_locale([None, s(""), s("ru_RU.UTF-8")]), "ru_RU.UTF-8");
        assert_eq!(
            posix_locale([s("de_DE.UTF-8"), None, s("ru_RU.UTF-8")]),
            "de_DE.UTF-8"
        );
        assert_eq!(posix_locale([None, None, None]), "C");
    }

    #[tokio::test]
    async fn iface_traffic_handles_absent_iface() {
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
    }
}

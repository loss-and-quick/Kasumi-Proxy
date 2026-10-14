//! The Linux [`DesktopOs`] seam: the parts of the desktop data-path that differ from
//! Windows — a native tun reachable via `ip`, `/proc/net/dev` byte counters, and the
//! gvisor sing-box stack for the root-binary tun path.

use std::time::Duration;

use async_trait::async_trait;

use kasumi_backend::fs::{exists, read_text};
use kasumi_core::request_identity::DeviceFacts;
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

    // What Happ desktop reports through Qt's `QSysInfo` and `QLocale`.
    async fn device_facts(&self) -> DeviceFacts {
        let os_release = match read_text("/etc/os-release").await {
            Some(text) => text,
            None => read_text("/usr/lib/os-release").await.unwrap_or_default(),
        };
        let hostname = read_text("/proc/sys/kernel/hostname")
            .await
            .map(|h| h.trim().to_owned())
            .unwrap_or_default();
        let env = |k: &str| std::env::var(k).ok();
        DeviceFacts {
            os: "Linux".into(),
            os_version: qt_product(&os_release),
            model: format!("{hostname}_{}", qt_cpu_architecture(std::env::consts::ARCH)),
            locale: qt_locale_name(&posix_locale([
                env("LC_ALL"),
                env("LC_MESSAGES"),
                env("LANG"),
            ])),
            ..Default::default()
        }
    }
}

/// `QSysInfo::productType()` + `_` + `productVersion()`: the os-release `ID` and
/// `VERSION_ID`, each `unknown` when missing.
fn qt_product(os_release: &str) -> String {
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches(['"', '\'']).to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unknown".into())
    };
    format!("{}_{}", field("ID"), field("VERSION_ID"))
}

/// `QSysInfo::currentCpuArchitecture()` for a Rust target architecture.
fn qt_cpu_architecture(arch: &str) -> &str {
    match arch {
        "x86" => "i386",
        "aarch64" => "arm64",
        other => other,
    }
}

/// The first set locale variable, as POSIX resolves them.
fn posix_locale(vars: [Option<String>; 3]) -> String {
    vars.into_iter()
        .flatten()
        .map(|v| v.trim().to_owned())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "C".into())
}

/// `QLocale::name()` for a POSIX locale: `language_TERRITORY` without the codeset
/// or modifier, and `C` for the C and POSIX locales.
fn qt_locale_name(posix: &str) -> String {
    let name = posix.split(['.', '@']).next().unwrap_or_default();
    if name.is_empty() || name == "C" || name == "POSIX" {
        "C".into()
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qt_product_joins_id_and_version() {
        let nixos = "NAME=NixOS\nID=nixos\nVERSION_ID=\"26.05\"\nPRETTY_NAME=\"NixOS 26.05\"\n";
        assert_eq!(qt_product(nixos), "nixos_26.05");
        // `ID_LIKE` is not `ID`.
        assert_eq!(
            qt_product("ID_LIKE=debian\nID=ubuntu\nVERSION_ID=24.04\n"),
            "ubuntu_24.04"
        );
        assert_eq!(qt_product("ID=arch\nBUILD_ID=rolling\n"), "arch_unknown");
        assert_eq!(qt_product(""), "unknown_unknown");
    }

    #[test]
    fn qt_cpu_architecture_names() {
        assert_eq!(qt_cpu_architecture("x86_64"), "x86_64");
        assert_eq!(qt_cpu_architecture("aarch64"), "arm64");
        assert_eq!(qt_cpu_architecture("x86"), "i386");
    }

    #[test]
    fn locale_follows_posix_precedence_and_qt_naming() {
        let s = |v: &str| Some(v.to_owned());
        let name = |vars| qt_locale_name(&posix_locale(vars));
        assert_eq!(name([None, s(""), s("ru_RU.UTF-8")]), "ru_RU");
        assert_eq!(name([s("de_DE.UTF-8"), None, s("ru_RU.UTF-8")]), "de_DE");
        assert_eq!(name([None, None, s("sr_RS@latin")]), "sr_RS");
        assert_eq!(name([None, None, s("C.UTF-8")]), "C");
        assert_eq!(name([None, None, None]), "C");
    }

    #[tokio::test]
    async fn iface_traffic_handles_absent_iface() {
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
    }
}

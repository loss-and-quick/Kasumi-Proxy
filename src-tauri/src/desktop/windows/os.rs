//! The Windows [`DesktopOs`] seam: the parts of the desktop data-path that differ
//! from Linux — a wintun tun (needing the bundled `wintun.dll` for the external-tun path),
//! no per-interface byte counters, and the system sing-box stack.

use std::ffi::c_void;
use std::time::Duration;

use async_trait::async_trait;

use kasumi_backend::fs::exists;
use kasumi_core::request_identity::DeviceFacts;
use kasumi_core::state::SingboxStack;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW,
};

use crate::desktop::paths::DesktopPaths;
use crate::desktop::platform::DesktopOs;

use super::routing::{adapter_ifindex, iface_counters};

pub(crate) struct WindowsOs;

#[async_trait]
impl DesktopOs for WindowsOs {
    fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }

    async fn precheck_external_tun(&self, p: &DesktopPaths) -> anyhow::Result<()> {
        // tun2socks loads wintun.dll from its own directory (unlike sing-box, which
        // embeds it), so the external-tun path genuinely needs the bundled DLL on disk.
        if !exists(&p.wintun_dll).await {
            anyhow::bail!("wintun.dll missing — cannot create a tun");
        }
        Ok(())
    }

    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()> {
        // tun2socks creates the wintun adapter asynchronously; it must appear before
        // we address/route it, else routing would target a non-existent interface.
        for _ in 0..40 {
            if adapter_ifindex(name).is_some() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::bail!("tun adapter never came up — see tun2socks log")
    }

    async fn iface_traffic(&self, iface: Option<&str>) -> (u64, u64) {
        // The tun's own counters, straight from iphlpapi — no /proc/net/dev here.
        // An unnamed or absent device has nothing to report.
        let Some(index) = iface.and_then(adapter_ifindex) else {
            return (0, 0);
        };
        iface_counters(index).unwrap_or((0, 0))
    }

    async fn tun_capable(&self) -> bool {
        // sing-box embeds wintun, so a tun is always possible; the external-tun path
        // additionally needs the bundled wintun.dll (checked at start).
        true
    }

    fn singbox_stack(&self) -> SingboxStack {
        SingboxStack::System
    }

    async fn machine_id(&self) -> Option<String> {
        reg_sz(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            "MachineGuid",
        )
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    }

    async fn device_facts(&self) -> DeviceFacts {
        let build = reg_sz(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuildNumber",
        )
        .and_then(|b| b.trim().parse::<u32>().ok());
        let locale = reg_sz(
            HKEY_CURRENT_USER,
            r"Control Panel\International",
            "LocaleName",
        )
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| "en".into());
        DeviceFacts {
            os: "Windows".into(),
            os_version: build.map(windows_release).unwrap_or_default(),
            model: "PC".into(),
            locale,
            ..Default::default()
        }
    }
}

/// The marketing release for a build number; Windows 11 kept the 10.0 version.
fn windows_release(build: u32) -> String {
    if build >= 22_000 { "11" } else { "10" }.into()
}

/// A `REG_SZ` value, or `None` when absent.
fn reg_sz(root: HKEY, subkey: &str, name: &str) -> Option<String> {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (sub, n) = (wide(subkey), wide(name));
    let read = |buf: *mut c_void, size: &mut u32| unsafe {
        RegGetValueW(
            root,
            sub.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf,
            size,
        )
    };
    // The first call reports the size in bytes, terminating NUL included.
    let mut size = 0u32;
    if read(std::ptr::null_mut(), &mut size) != ERROR_SUCCESS {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    if read(buf.as_mut_ptr() as *mut c_void, &mut size) != ERROR_SUCCESS {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_numbers_map_to_releases() {
        assert_eq!(windows_release(19_045), "10");
        assert_eq!(windows_release(22_631), "11");
    }
}

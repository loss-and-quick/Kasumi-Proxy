//! Windows desktop routing for an external-tun data-path. The core exposes a local SOCKS;
//! tun2socks bridges a wintun device to it. To put all traffic through the tun
//! while keeping the core's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ the active DNS servers, for a core
//!     that resolves through them itself) via the real uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `0.0.0.0/0` without deleting it (classic VPN trick).
//!
//! Everything is driven through `route` / `netsh` / `Get-Net*`, mirroring the Linux
//! `ip` back-end. The exact set of installed routes is persisted so teardown is
//! idempotent.
//!
//! With an xray core the system's DNS is sent into the tun as well (see
//! [`point_dns_at_tun`]), and port 53 is closed everywhere else for as long as this
//! process holds the [`dns_guard`].

use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use kasumi_backend::fsjson::{read_json, write_text_atomic};

use crate::desktop::net::is_loopback;
use crate::desktop::{run_out, silent};

use super::dns_guard;

/// The userspace tun's address + mask; `/15` covers the 198.18/15 test net.
/// Address single-sourced from core so it can't drift from hev's / the routing's.
const TUN_ADDR: &str = kasumi_core::tun::TUN_IPV4;
const TUN_MASK: &str = "255.254.0.0";

/// The two halves of a split-default route, as (dest, mask) pairs. Each overrides
/// `0.0.0.0/0` for its half without touching the real default.
const SPLIT_DEFAULT: [(&str, &str); 2] = [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")];

/// Resolver the tun advertises; see [`kasumi_core::tun::TUN_DNS_IPV4`].
const TUN_DNS: &str = kasumi_core::tun::TUN_DNS_IPV4;

static DNS_GUARD: Mutex<Option<dns_guard::Guard>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteState {
    tun: String,
    tun_ifindex: u32,
    /// Bypass host-routes we added (CIDR strings), to delete on teardown.
    bypass: Vec<String>,
}

/// `netsh` fallback for [`set_adapter_dns`] on Windows before 10 2004.
fn netsh_dns_argv(tun: &str) -> Vec<String> {
    [
        "netsh",
        "interface",
        "ipv4",
        "set",
        "dnsservers",
        &format!("name={tun}"),
        "source=static",
        &format!("address={TUN_DNS}"),
        "register=none",
        "validate=no",
    ]
    .map(String::from)
    .to_vec()
}

/// The lowest interface metric, which makes the tun the adapter Windows lists
/// first and asks first.
/// <https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-interface-metric>
fn netsh_metric_argv(tun_ifindex: u32) -> Vec<String> {
    [
        "netsh",
        "interface",
        "ipv4",
        "set",
        "interface",
        &format!("interface={tun_ifindex}"),
        "metric=1",
    ]
    .map(String::from)
    .to_vec()
}

async fn run_argv(argv: &[String]) -> i32 {
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    silent(&argv).await
}

fn luid_of(ifindex: u32) -> std::io::Result<NET_LUID_LH> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
    // SAFETY: `luid` outlives the call.
    unsafe {
        let mut luid: NET_LUID_LH = std::mem::zeroed();
        match ConvertInterfaceIndexToLuid(ifindex, &mut luid) {
            ERROR_SUCCESS => Ok(luid),
            rc => Err(std::io::Error::from_raw_os_error(rc as i32)),
        }
    }
}

/// Point the tun's DNS at [`TUN_DNS`] through `SetInterfaceDnsSettings`
/// (Windows 10 2004+). It is looked up at run time: a static import of a missing
/// export would stop the whole app from loading on older builds.
/// <https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings>
fn set_adapter_dns(tun_ifindex: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToGuid, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_NAMESERVER,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::core::GUID;

    type SetDns = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;

    let dll: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
    // SAFETY: plain Win32 calls; every pointer outlives its call, and the
    // transmuted pointer has the documented signature of the export it names.
    unsafe {
        let module = LoadLibraryW(dll.as_ptr());
        if module.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let Some(proc) = GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) else {
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        };
        let set_dns: SetDns = std::mem::transmute(proc);

        let luid = luid_of(tun_ifindex)?;
        let mut guid: GUID = std::mem::zeroed();
        let mut rc = ConvertInterfaceLuidToGuid(&luid, &mut guid);
        if rc == ERROR_SUCCESS {
            let mut servers: Vec<u16> = TUN_DNS.encode_utf16().chain(std::iter::once(0)).collect();
            let mut settings: DNS_INTERFACE_SETTINGS = std::mem::zeroed();
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = u64::from(DNS_SETTING_NAMESERVER);
            settings.NameServer = servers.as_mut_ptr();
            rc = set_dns(guid, &settings);
        }
        match rc {
            ERROR_SUCCESS => Ok(()),
            rc => Err(std::io::Error::from_raw_os_error(rc as i32)),
        }
    }
}

/// Give the tun [`TUN_DNS`] as its resolver and the lowest metric, so Windows asks
/// it first. Both live on the adapter and go away with it. Best effort.
async fn point_dns_at_tun(tun: &str, tun_ifindex: u32) {
    if let Err(e) = set_adapter_dns(tun_ifindex) {
        log::info!("SetInterfaceDnsSettings unavailable ({e}); using netsh");
        run_argv(&netsh_dns_argv(tun)).await;
    }
    run_argv(&netsh_metric_argv(tun_ifindex)).await;
}

/// Close port 53 outside the tun until [`clear_external_tun_routing`] or the end of
/// this process. Best effort: without it, other adapters' resolvers stay reachable.
fn guard_dns(tun_ifindex: u32, core_bin: &str) {
    let installed = luid_of(tun_ifindex).and_then(|luid| {
        let tun_dns = TUN_DNS.parse().map_err(std::io::Error::other)?;
        // SAFETY: `Value` spans the whole LUID union.
        let luid = unsafe { luid.Value };
        let key = dns_guard::new_sublayer_key()?;
        dns_guard::install(&dns_guard::plan(key, luid, tun_dns, core_bin))
    });
    match installed {
        Ok(guard) => *DNS_GUARD.lock().unwrap_or_else(PoisonError::into_inner) = Some(guard),
        Err(e) => log::warn!("DNS guard not installed ({e}); other resolvers stay reachable"),
    }
}

/// Run a PowerShell one-liner, returning trimmed stdout (empty on failure).
pub(super) async fn powershell(script: &str) -> String {
    let (code, out) = run_out(&[
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ])
    .await;
    if code != 0 {
        return String::new();
    }
    out.trim().to_string()
}

/// The current default route's gateway + uplink interface index, or `None`.
pub async fn read_default_route() -> Option<(String, u32)> {
    let out = powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object RouteMetric \
         | Select-Object -First 1 -Property NextHop,InterfaceIndex \
         | ConvertTo-Json -Compress",
    )
    .await;
    parse_default_route(&out)
}

/// Pull `(gateway, ifindex)` from the `ConvertTo-Json` object of a default route.
fn parse_default_route(out: &str) -> Option<(String, u32)> {
    let v: Value = serde_json::from_str(out.trim()).ok()?;
    let gw = v.get("NextHop")?.as_str()?.to_string();
    let idx = v.get("InterfaceIndex")?.as_u64()? as u32;
    // A non-routable next hop ("on-link" default) has no gateway to bypass via.
    if gw.is_empty() || gw == "0.0.0.0" {
        return None;
    }
    Some((gw, idx))
}

/// The interface index of the named adapter (the wintun device tun2socks created),
/// or `None` if it isn't up yet.
pub async fn adapter_ifindex(name: &str) -> Option<u32> {
    let out = powershell(&format!(
        "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue).InterfaceIndex"
    ))
    .await;
    out.lines().next()?.trim().parse().ok()
}

/// The DNS server IPs of every active interface (so name resolution keeps working
/// while the tun is up). The Linux side reads /etc/resolv.conf; here it's WMI.
pub async fn read_resolvers() -> Vec<String> {
    let out = powershell(
        "Get-DnsClientServerAddress -AddressFamily IPv4 \
         | Select-Object -ExpandProperty ServerAddresses \
         | Sort-Object -Unique",
    )
    .await;
    out.lines()
        .map(|l| l.trim().to_string())
        .filter(|ip| !is_loopback(ip))
        .collect()
}

/// The tun bypass set for the resolved proxy servers and the user's TUN-exclude
/// CIDRs (e.g. docker networks). `keep_resolvers` also routes the system's DNS
/// servers (WMI) off the tun, for a core that resolves through them itself
/// (a socks-only sing-box); an xray core reaches its servers through pinned
/// `dns.hosts` instead, so its system DNS goes through the tun.
pub async fn bypass_cidrs(
    servers: &std::collections::BTreeMap<String, Vec<String>>,
    tun_exclude: &[String],
    keep_resolvers: bool,
) -> Vec<String> {
    let resolvers = if keep_resolvers {
        read_resolvers().await
    } else {
        Vec::new()
    };
    crate::desktop::net::bypass_cidrs(servers, &resolvers, tun_exclude)
}

/// `1.2.3.4/32` → `("1.2.3.4", true)`; `2001:db8::1/128` → `("2001:db8::1", false)`.
/// Returns the bare address and whether it's IPv4.
fn split_cidr(cidr: &str) -> (&str, bool) {
    let addr = cidr.split('/').next().unwrap_or(cidr);
    (addr, !addr.contains(':'))
}

/// Bring up external-tun routing: host-route the bypass CIDRs via the uplink, address the
/// tun and split-default into it. Persists the installed set. `core_bin` is the core
/// whose own DNS stays allowed out of the uplink while `capture_dns` guards the rest.
pub async fn apply_external_tun_routing(
    tun: &str,
    bypass: &[String],
    capture_dns: bool,
    core_bin: &str,
    route_state_file: &str,
) -> anyhow::Result<()> {
    let Some((gw, uplink)) = read_default_route().await else {
        anyhow::bail!("no default route — cannot set up tun bypass");
    };
    let Some(tun_ifindex) = adapter_ifindex(tun).await else {
        anyhow::bail!("tun adapter '{tun}' not found — tun2socks did not bring it up");
    };
    let uplink = uplink.to_string();
    let tun_idx = tun_ifindex.to_string();

    // Host-route each proxy server / DNS server out via the real uplink gateway.
    for c in bypass {
        let (addr, v4) = split_cidr(c);
        if v4 {
            silent(&[
                "route",
                "add",
                addr,
                "mask",
                "255.255.255.255",
                &gw,
                "metric",
                "1",
                "if",
                &uplink,
            ])
            .await;
        } else {
            silent(&[
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                c,
                &uplink,
                &gw,
            ])
            .await;
        }
    }

    // Address the tun and pull the split-default into it (gateway = the tun's own
    // on-link address, scoped to the tun interface).
    silent(&[
        "netsh",
        "interface",
        "ip",
        "set",
        "address",
        &format!("name={tun}"),
        "static",
        TUN_ADDR,
        TUN_MASK,
    ])
    .await;
    for (dest, mask) in SPLIT_DEFAULT {
        silent(&[
            "route", "add", dest, "mask", mask, TUN_ADDR, "metric", "1", "if", &tun_idx,
        ])
        .await;
    }

    let state = RouteState {
        tun: tun.to_string(),
        tun_ifindex,
        bypass: bypass.to_vec(),
    };
    write_text_atomic(route_state_file, &serde_json::to_string(&state)?).await?;
    if capture_dns {
        point_dns_at_tun(tun, tun_ifindex).await;
        guard_dns(tun_ifindex, core_bin);
    }
    Ok(())
}

/// Tear down everything `apply_external_tun_routing` installed. Idempotent.
pub async fn clear_external_tun_routing(route_state_file: &str) {
    // Dropping the guard removes its filters.
    let guard = DNS_GUARD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    drop(guard);
    let Some(state) = read_json::<RouteState>(route_state_file).await else {
        return;
    };
    for (dest, mask) in SPLIT_DEFAULT {
        silent(&["route", "delete", dest, "mask", mask]).await;
    }
    for c in &state.bypass {
        let (addr, v4) = split_cidr(c);
        if v4 {
            silent(&["route", "delete", addr, "mask", "255.255.255.255"]).await;
        } else {
            let ifidx = state.tun_ifindex.to_string();
            silent(&["netsh", "interface", "ipv6", "delete", "route", c, &ifidx]).await;
        }
    }
    kasumi_backend::fs::remove_file(route_state_file).await;
}

/// No-op on Windows: native sing-box rides its embedded wintun, whose driver
/// reclaims the adapter (and its routes) when the core process exits, so there are
/// no orphaned `auto_route` ip-rules/tables to flush like on Linux. (A hard kill
/// leaving a wedged adapter is a separate wintun job-object concern.) The signature
/// matches the Linux seam so `platform.rs` can call it unconditionally.
pub async fn clear_singbox_autoroute(_tun_iface_file: &str, _tun2_iface_file: &str) {}

/// No-op on Windows: fwmark is a Linux concept and `route.default_mark` is never
/// injected off-Linux — the core's escape here is route-based
/// (`route_exclude_address` + wintun's own binding). Linux-seam signature match.
pub async fn apply_singbox_escape_rule() {}

/// The physical uplink adapter name of the current default route — what a
/// helper-spawned test core binds its outbound to (`bind_interface` /
/// `sockopt.interface`) so it escapes an active tun. `None` when offline.
pub async fn uplink_device() -> Option<String> {
    let alias = powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object RouteMetric \
         | Select-Object -First 1 -ExpandProperty InterfaceAlias",
    )
    .await;
    let alias = alias.trim();
    (!alias.is_empty()).then(|| alias.to_string())
}

/// Bind `socket` to the uplink adapter with `IP_UNICAST_IF` / `IPV6_UNICAST_IF`,
/// the option sing-box `bind_interface` sets for test cores; it needs no
/// privilege. No uplink leaves it unbound.
pub async fn bind_uplink(
    socket: &tokio::net::TcpSocket,
    dest: std::net::IpAddr,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR, setsockopt,
    };

    let Some(alias) = uplink_device().await else {
        return Ok(());
    };
    let Some(index) = adapter_ifindex(&alias).await else {
        return Ok(());
    };
    // The IPv4 option takes the index in network byte order, the IPv6 one in host order.
    let (level, name, value) = if dest.is_ipv4() {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    };
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            (&raw const value).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Source-address pin for the uplink bind. Windows binds by interface index
/// (`IP_UNICAST_IF`), which doesn't suffer the multi-homed source-selection issue the
/// Linux `SO_BINDTODEVICE` path does, so no source override is emitted here, for
/// either family.
pub async fn uplink_source(_dev: &str) -> kasumi_core::outbound_bind::UplinkSource {
    kasumi_core::outbound_bind::UplinkSource::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route_json() {
        let out = r#"{"NextHop":"192.168.1.1","InterfaceIndex":12}"#;
        assert_eq!(
            parse_default_route(out),
            Some(("192.168.1.1".to_string(), 12))
        );
        // On-link default (no gateway) is not bypassable.
        assert_eq!(
            parse_default_route(r#"{"NextHop":"0.0.0.0","InterfaceIndex":12}"#),
            None
        );
        assert_eq!(parse_default_route("not json"), None);
    }

    // No adapter has this index: the call has to fail cleanly, either at the
    // run-time export lookup (before Windows 10 2004) or at the index.
    #[test]
    fn adapter_dns_fails_cleanly_for_a_missing_interface() {
        assert!(set_adapter_dns(u32::MAX).is_err());
    }

    #[test]
    fn netsh_targets_the_tun_only() {
        let dns = netsh_dns_argv("kasumi0");
        assert!(dns.contains(&"name=kasumi0".to_string()));
        assert!(dns.contains(&format!("address={TUN_DNS}")));
        assert!(dns.contains(&"validate=no".to_string()));
        let metric = netsh_metric_argv(42);
        assert!(metric.contains(&"interface=42".to_string()));
        assert!(metric.contains(&"metric=1".to_string()));
    }

    #[test]
    fn splits_cidr_family() {
        assert_eq!(split_cidr("1.2.3.4/32"), ("1.2.3.4", true));
        assert_eq!(split_cidr("2001:db8::1/128"), ("2001:db8::1", false));
    }
}

//! Windows desktop routing for an external-tun data-path. The core exposes a local SOCKS;
//! tun2socks bridges a wintun device to it. To put all traffic through the tun
//! while keeping the core's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ the active DNS servers, for a core
//!     that resolves through them itself) via the real uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `0.0.0.0/0` without deleting it (classic VPN trick).
//!
//! Everything is driven through `iphlpapi` (`GetBestRoute`, `CreateIpForwardEntry2`,
//! …) rather than `route` / `netsh` / `Get-Net*`, mirroring the Linux `ip`
//! back-end. The exact set of installed routes is persisted so teardown is
//! idempotent.
//!
//! With an xray core the system's DNS is sent into the tun as well (see
//! [`point_dns_at_tun`]), and port 53 is closed everywhere else for as long as this
//! process holds the [`dns_guard`].

use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;

use kasumi_backend::fsjson::{read_json, write_text_atomic};

use crate::desktop::net::is_loopback;
use crate::desktop::{run_out, silent};
use kasumi_log::{Area, ks_info, ks_warn};

use super::dns_guard;

/// The userspace tun's address; `/15` ([`TUN_PREFIX_LEN`]) covers the 198.18/15
/// test net. Address single-sourced from core so it can't drift from hev's / the
/// routing's.
const TUN_ADDR: &str = kasumi_core::tun::TUN_IPV4;

/// The two halves of a split-default route: each overrides `0.0.0.0/0` for its
/// half without touching the real default (classic VPN trick).
const SPLIT_DEFAULT: [(&str, u8); 2] = [("0.0.0.0", 1), ("128.0.0.0", 1)];

/// The tun's on-link prefix length (the `255.254.0.0` mask of [`TUN_ADDR`]).
const TUN_PREFIX_LEN: u8 = 15;

/// `route add`'s metric: as low as a route can be, so it wins over anything the
/// system installed.
const ROUTE_METRIC: u32 = 1;

/// A route's lifetime in a `MIB_IPFORWARD_ROW2`: no expiry, like `route add`.
const INFINITE_LIFETIME: u32 = u32::MAX;

/// Resolver the tun advertises; see [`kasumi_core::tun::TUN_DNS_IPV4`].
const TUN_DNS: &str = kasumi_core::tun::TUN_DNS_IPV4;

static DNS_GUARD: Mutex<Option<dns_guard::Guard>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteState {
    tun: String,
    tun_ifindex: u32,
    /// Every route this process installed, so teardown deletes exactly those.
    routes: Vec<RouteRow>,
}

/// One installed route, as `delete` has to identify it: a route is not addressable
/// by its destination alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RouteRow {
    /// Destination prefix as a CIDR string (`1.2.3.4/32`, `2001:db8::1/128`).
    dest: String,
    /// Next hop (`0.0.0.0` / `::` for an on-link prefix).
    next_hop: String,
    ifindex: u32,
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
/// first and asks first. The Linux side reaches the same end by moving the tun's
/// routes into their own table.
/// <https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-interface-metric>
const TUN_METRIC: u32 = 1;

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
        ks_info!(
            Area::Platform,
            "SetInterfaceDnsSettings unavailable ({e}); using netsh"
        );
        run_argv(&netsh_dns_argv(tun)).await;
    }
    if let Err(e) = set_interface_metric(tun_ifindex, TUN_METRIC) {
        ks_warn!(Area::Platform, "tun metric not set ({e})");
    }
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
        Err(e) => ks_warn!(
            Area::Platform,
            "DNS guard not installed ({e}); other resolvers stay reachable"
        ),
    }
}

/// Run a PowerShell one-liner, returning trimmed stdout (empty on failure).
///
/// The script runs with the console output encoding forced to UTF-8. PowerShell
/// encodes a redirected command's stdout through the console's OEM codepage
/// otherwise (CP936 on a Chinese Windows), so any non-ASCII text it prints — a
/// Start-menu name, an adapter alias — comes back as bytes no UTF-8 caller can
/// decode. Doing it here keeps every script from having to remember it.
pub(super) async fn powershell(script: &str) -> String {
    let script =
        format!("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); {script}");
    let (code, out) = run_out(&[
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script,
    ])
    .await;
    if code != 0 {
        return String::new();
    }
    out.trim().trim_start_matches('\u{feff}').trim().to_string()
}

#[derive(Clone, Copy)]
struct DefaultRoute {
    ifindex: u32,
    next_hop: u32,
}

/// The current default route's gateway + uplink interface index, or `None`.
pub async fn read_default_route() -> Option<(String, u32)> {
    let route = best_route()?;
    // A non-routable next hop ("on-link" default) has no gateway to bypass via.
    if route.next_hop == 0 {
        return None;
    }
    Some((ipv4_string(route.next_hop), route.ifindex))
}

/// The default route (`0.0.0.0/0`) with the lowest effective metric (route metric
/// plus interface metric), or `None` when offline.
///
/// Enumerates routes via `GetIpForwardTable2` and matches on prefix length 0
/// specifically: a destination-based lookup like `GetBestRoute(0.0.0.0)` matches
/// the `0.0.0.0/1` split-default route once the tun is up (longest prefix match),
/// which would return the tun instead of the physical uplink.
fn best_route() -> Option<DefaultRoute> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpInterfaceEntry,
        MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: table is a valid out-pointer; non-zero is an error.
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != 0 || table.is_null() {
        return None;
    }
    struct TableGuard(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
    let _guard = TableGuard(table);

    let num = unsafe { (*table).NumEntries as usize };
    let first = unsafe { std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>() };
    let rows = unsafe { std::slice::from_raw_parts(first, num) };

    let mut best: Option<(DefaultRoute, u32)> = None;
    for row in rows {
        // DestinationPrefix must be 0.0.0.0/0 specifically (excludes /1 split-default).
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let family = unsafe { row.DestinationPrefix.Prefix.si_family };
        if family != AF_INET {
            continue;
        }
        let next_hop = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr };
        if row.InterfaceIndex == 0 {
            continue;
        }

        // Effective metric is route metric + interface metric.
        let mut if_row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut if_row) };
        if_row.Family = AF_INET;
        if_row.InterfaceLuid = row.InterfaceLuid;
        if_row.InterfaceIndex = row.InterfaceIndex;
        let if_metric = if unsafe { GetIpInterfaceEntry(&mut if_row) } == 0 {
            if_row.Metric
        } else {
            continue;
        };
        let effective_metric = row.Metric.saturating_add(if_metric);

        if best.is_none_or(|(_, m)| effective_metric < m) {
            best = Some((
                DefaultRoute {
                    ifindex: row.InterfaceIndex,
                    next_hop,
                },
                effective_metric,
            ));
        }
    }

    best.map(|(r, _)| r)
}

/// `10.0.0.1` from a routing-table address (network byte order in a `u32`).
fn ipv4_string(addr: u32) -> String {
    std::net::Ipv4Addr::from(addr.to_ne_bytes()).to_string()
}

/// The host route that sends `dest` (a CIDR, or a bare address) out through `gw`
/// on the uplink adapter `uplink`.
fn host_route(dest: &str, gw: std::net::IpAddr, uplink: u32) -> std::io::Result<RouteRow> {
    let (addr, prefix_len) = parse_cidr(dest)?;
    Ok(RouteRow {
        dest: format!("{addr}/{prefix_len}"),
        next_hop: gw.to_string(),
        ifindex: uplink,
    })
}

/// Add `row`'s route to the routing table. Idempotent only in the sense that a
/// second call reports "already exists" rather than changing anything.
fn add_route(row: &RouteRow) -> std::io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::CreateIpForwardEntry2;

    let mut entry = forward_row(row)?;
    entry.Metric = ROUTE_METRIC;
    win32(unsafe { CreateIpForwardEntry2(&entry) })
}

/// Delete the route `add_route` installed. A route is identified by its
/// destination *and* its next hop and interface, so nothing else is matched.
fn delete_route(row: &RouteRow) -> std::io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::DeleteIpForwardEntry2;

    win32(unsafe { DeleteIpForwardEntry2(&forward_row(row)?) })
}

/// The routing-table row for `row`.
fn forward_row(row: &RouteRow) -> std::io::Result<MIB_IPFORWARD_ROW2> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IP_ADDRESS_PREFIX, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

    let (dest, prefix_len) = parse_cidr(&row.dest)?;
    let next_hop = parse_addr(&row.next_hop)?;
    let mut entry: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: `entry` is a valid out param; the API fills in its defaults.
    unsafe { InitializeIpForwardEntry(&mut entry) };
    entry.InterfaceIndex = row.ifindex;
    entry.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(dest),
        PrefixLength: prefix_len,
    };
    entry.NextHop = sockaddr(next_hop);
    entry.Protocol = MIB_IPPROTO_NETMGMT;
    entry.ValidLifetime = INFINITE_LIFETIME;
    entry.PreferredLifetime = INFINITE_LIFETIME;
    Ok(entry)
}

/// Give adapter `ifindex` the address `addr` with `prefix_len` on-link.
fn add_address(addr: std::net::IpAddr, prefix_len: u8, ifindex: u32) -> std::io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{
        IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
    };

    let mut entry: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: `entry` is a valid out param; the API fills in its defaults.
    unsafe { InitializeUnicastIpAddressEntry(&mut entry) };
    entry.InterfaceIndex = ifindex;
    entry.Address = sockaddr(addr);
    entry.OnLinkPrefixLength = prefix_len;
    entry.PrefixOrigin = IpPrefixOriginManual;
    entry.SuffixOrigin = IpSuffixOriginManual;
    // A configured address is usable at once; no duplicate-address detection for a
    // point-to-point device only this process routes into.
    entry.DadState = IpDadStatePreferred;
    entry.ValidLifetime = INFINITE_LIFETIME;
    entry.PreferredLifetime = INFINITE_LIFETIME;
    win32(unsafe { CreateUnicastIpAddressEntry(&entry) })
}

/// Pin adapter `ifindex`'s metric to `metric` and stop it tracking the link speed:
/// without a metric of its own, the tun can rank below another adapter and Windows
/// asks that one first.
fn set_interface_metric(ifindex: u32, metric: u32) -> std::io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: `row` is a valid out param; the API fills in its defaults.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid_of(ifindex)?;
    row.InterfaceIndex = ifindex;
    // SAFETY: `row` identifies the interface above.
    win32(unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.UseAutomaticMetric = 0; // FALSE
    row.Metric = metric;
    // SetIpInterfaceEntry rejects an IPv4 row whose SitePrefixLength is non-zero.
    row.SitePrefixLength = 0;
    win32(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// RX/TX bytes on interface `ifindex` since it came up, or `None` when it is gone.
pub fn iface_counters(ifindex: u32) -> Option<(u64, u64)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = luid_of(ifindex).ok()?;
    row.InterfaceIndex = ifindex;
    // SAFETY: `row` identifies the interface above.
    (unsafe { GetIfEntry2(&mut row) } == 0).then_some((row.InOctets, row.OutOctets))
}

/// The address and prefix length of a CIDR; a bare address is a host route.
fn parse_cidr(cidr: &str) -> std::io::Result<(std::net::IpAddr, u8)> {
    let (addr, len) = cidr.split_once('/').unwrap_or((cidr, ""));
    let addr = parse_addr(addr)?;
    let host = if addr.is_ipv4() { 32 } else { 128 };
    let len = match len {
        "" => host,
        _ => len
            .parse()
            .ok()
            .filter(|l| *l <= host)
            .ok_or_else(|| invalid(format!("{cidr}: no usable prefix length")))?,
    };
    Ok((addr, len))
}

/// An IP address, with the input quoted back on failure.
fn parse_addr(addr: &str) -> std::io::Result<std::net::IpAddr> {
    addr.parse()
        .map_err(|_| invalid(format!("{addr}: not an address")))
}

/// `addr` in the socket-address form a routing-table row holds.
fn sockaddr(addr: std::net::IpAddr) -> SOCKADDR_INET {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
    };

    match addr {
        std::net::IpAddr::V4(v4) => {
            let mut in_addr: IN_ADDR = unsafe { std::mem::zeroed() };
            in_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: in_addr,
                    sin_zero: [0; 8],
                },
            }
        }
        std::net::IpAddr::V6(v6) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

/// A `WIN32_ERROR` return as a `Result` (zero is success, as with `errno`).
fn win32(rc: u32) -> std::io::Result<()> {
    match rc {
        0 => Ok(()),
        code => Err(std::io::Error::from_raw_os_error(code as i32)),
    }
}

/// An `InvalidInput` carrying the offending value.
fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

/// The interface index of the named adapter — the wintun device tun2socks
/// created, or the physical uplink — or `None` when no such adapter is up.
pub fn adapter_ifindex(name: &str) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    if unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) } != 0 {
        return None;
    }
    let mut index = 0u32;
    // SAFETY: `luid` and `index` outlive the call.
    if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != 0 {
        return None;
    }
    (index != 0).then_some(index)
}

/// The DNS server IPs every adapter is configured with (so name resolution keeps
/// working while the tun is up). The Linux side reads /etc/resolv.conf; here it's
/// `GetAdaptersAddresses`, which hands back the same configured list
/// `Get-DnsClientServerAddress` printed — as `SOCKADDR`s, not as text to decode.
pub async fn read_resolvers() -> Vec<String> {
    let mut resolvers: Vec<String> = adapter_resolvers()
        .into_iter()
        .map(|ip| ip.to_string())
        .filter(|ip| !is_loopback(ip))
        .collect();
    resolvers.sort_unstable();
    resolvers.dedup();
    resolvers
}

/// Every IPv4 DNS server address across all adapters, down ones included (the
/// same set `Get-DnsClientServerAddress` lists).
fn adapter_resolvers() -> Vec<std::net::Ipv4Addr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let list = adapters();
    let mut resolvers = Vec::new();
    for adapter in list.iter() {
        let mut server = adapter.FirstDnsServerAddress;
        while !server.is_null() {
            // SAFETY: the API built this node list; the pointers stay valid until
            // the buffer is dropped, and `list` outlives this walk.
            let node = unsafe { &*server };
            let addr = node.Address.lpSockaddr;
            if !addr.is_null()
                && node.Address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>()
            {
                // SAFETY: a non-empty `SOCKET_ADDRESS` of at least `SOCKADDR_IN`
                // length holds a `SOCKADDR` whose family decides the shape.
                let sock = unsafe { &*addr };
                if sock.sa_family == AF_INET {
                    // SAFETY: the family above says this is a `SOCKADDR_IN`.
                    let v4 = unsafe { &*addr.cast::<SOCKADDR_IN>() };
                    // SAFETY: reading the plain-`u32` arm of the address union.
                    let raw = unsafe { v4.sin_addr.S_un.S_addr };
                    resolvers.push(std::net::Ipv4Addr::from(raw.to_ne_bytes()));
                }
            }
            server = node.Next;
        }
    }
    resolvers
}

/// Every adapter `GetAdaptersAddresses` reports, as the allocated node list it
/// fills in. The returned list owns the buffer, so a walk over `Next` stays valid.
fn adapters() -> AdapterList {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const FLAGS: u32 = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    // A caller-sized buffer: the first call reports the size it needs.
    let mut size = 0u32;
    // SAFETY: a NULL buffer with a size out-param is the documented sizing call.
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.into(),
            FLAGS,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_BUFFER_OVERFLOW || size == 0 {
        return AdapterList::default();
    }
    // `usize`-aligned storage: the node list is 8-byte aligned (it holds u64s and
    // pointers) and a `Vec<u8>` is not required to be.
    let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buf = vec![0usize; words];
    let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // SAFETY: `head` points at `size` bytes of writable, aligned storage.
    let rc =
        unsafe { GetAdaptersAddresses(AF_UNSPEC.into(), FLAGS, std::ptr::null(), head, &mut size) };
    if rc != 0 {
        return AdapterList::default();
    }
    AdapterList { _buf: buf, head }
}

/// The buffer `GetAdaptersAddresses` filled, walked through [`AdapterList::iter`].
#[derive(Default)]
struct AdapterList {
    /// Holds the allocation the node list points into; never read directly.
    _buf: Vec<usize>,
    head: *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
}

impl AdapterList {
    /// The adapters in the list, in the API's order.
    fn iter(
        &self,
    ) -> impl Iterator<Item = &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH>
    {
        let mut next = (!self.head.is_null()).then_some(self.head);
        std::iter::from_fn(move || {
            let node = next?;
            // SAFETY: every non-NULL `Next` in the list points into the buffer,
            // which `self` keeps alive for the iterator's lifetime.
            let node = unsafe { &*node };
            next = (!node.Next.is_null()).then_some(node.Next);
            Some(node)
        })
    }
}

/// The tun bypass set for the resolved proxy servers and the user's TUN-exclude
/// CIDRs (e.g. docker networks). `keep_resolvers` also routes the system's DNS
/// servers off the tun, for a core that resolves through them itself
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

/// An external tun's core escapes by binding the uplink (`IP_UNICAST_IF`): Windows has
/// no fwmark to route it past the tun by.
pub const CORE_ESCAPES_BY_MARK: bool = false;

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
    let Some(tun_ifindex) = adapter_ifindex(tun) else {
        anyhow::bail!("tun adapter '{tun}' not found — tun2socks did not bring it up");
    };
    let tun_addr = TUN_ADDR.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let gw: std::net::IpAddr = gw.parse().map_err(|e| anyhow::anyhow!("{e}"))?;

    // Host-route each proxy server / DNS server out via the real uplink gateway,
    // and record the row: teardown deletes exactly what was installed here.
    let mut routes = Vec::new();
    for c in bypass {
        match host_route(c, gw, uplink) {
            Ok(row) => {
                if let Err(e) = add_route(&row) {
                    ks_warn!(Area::Platform, "bypass route {c} not installed ({e})");
                    continue;
                }
                routes.push(row);
            }
            Err(e) => {
                ks_warn!(Area::Platform, "bypass route {c} unusable ({e})");
            }
        }
    }

    // Address the tun and pull the split-default into it (unspecified next hop
    // = on-link route, scoped to the tun interface).
    match add_address(tun_addr, TUN_PREFIX_LEN, tun_ifindex) {
        Ok(()) => {}
        // ERROR_OBJECT_ALREADY_EXISTS: the tun already has the address.
        Err(e) if e.raw_os_error() == Some(5010) => {}
        Err(e) => {
            for row in routes.iter().rev() {
                let _ = delete_route(row);
            }
            anyhow::bail!("cannot address the tun ({e})");
        }
    }
    let mut missing_split_default = Vec::new();
    for (dest, prefix_len) in SPLIT_DEFAULT {
        let row = RouteRow {
            dest: format!("{dest}/{prefix_len}"),
            next_hop: "0.0.0.0".to_string(),
            ifindex: tun_ifindex,
        };
        match add_route(&row) {
            Ok(()) => routes.push(row),
            Err(e) => missing_split_default.push(format!("{dest}/{prefix_len} ({e})")),
        }
    }
    if !missing_split_default.is_empty() {
        // Without the split-default, traffic does not enter the tun. Remove the
        // routes installed so far and fail before the state file is written.
        for row in routes.iter().rev() {
            let _ = delete_route(row);
        }
        anyhow::bail!(
            "split-default not installed: {}",
            missing_split_default.join(", ")
        );
    }

    let state = RouteState {
        tun: tun.to_string(),
        tun_ifindex,
        routes,
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
    // The recorded rows, not a prefix-+mask match: deleting by destination alone
    // can take a route this process never installed.
    for row in state.routes.iter().rev() {
        if let Err(e) = delete_route(row) {
            ks_warn!(Area::Platform, "route {} still installed ({e})", row.dest);
        }
    }
    // The tun's address and the tun itself go with the adapter the helper owns on
    // process exit; the routes above are the state that would otherwise outlive us.
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
pub async fn apply_escape_rules() {}

/// The physical uplink adapter name of the current default route — what a
/// helper-spawned test core binds its outbound to (`bind_interface` /
/// `sockopt.interface`) so it escapes an active tun. `None` when offline.
///
/// Read straight from the routing table (`GetBestRoute`) rather than through
/// PowerShell: the alias comes back as UTF-16 from `iphlpapi`, no console
/// codepage to mangle it. A `Get-NetRoute | Select InterfaceAlias` one-liner
/// encoded the alias through the OEM codepage (CP936 on a Chinese system), so
/// a non-ASCII adapter name (以太网) arrived as mojibake and the core's
/// `bind_interface` lookup failed. `GetBestRoute` is IPv4-only, so an
/// IPv6-only default route reads as offline (no bind) — the pre-fix behaviour.
pub async fn uplink_device() -> Option<String> {
    adapter_alias(best_route()?.ifindex)
}

/// The adapter alias of interface `ifindex`, or `None` if it is gone.
fn adapter_alias(ifindex: u32) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
    };

    let mut luid: windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH =
        unsafe { std::mem::zeroed() };
    // SAFETY: `luid` outlives the call.
    if unsafe { ConvertInterfaceIndexToLuid(ifindex, &mut luid) } != 0 {
        return None;
    }
    let mut buf = [0u16; 256];
    // The call writes a NUL-terminated alias and reports an error code, not a length.
    if unsafe { ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    let alias = String::from_utf16_lossy(&buf[..len]);
    (!alias.is_empty()).then_some(alias)
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

    // Take the interface index straight from the best route rather than resolving
    // the alias back through PowerShell.
    let Some(index) = best_route().map(|r| r.ifindex) else {
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
    }

    // DNS capture leaves nothing for a later start to undo: its adapter settings go
    // with the tun and its filters with this process, so only routes are recorded.
    #[test]
    fn route_state_records_only_routes() {
        let state = RouteState {
            tun: "kasumi0".into(),
            tun_ifindex: 42,
            routes: vec![RouteRow {
                dest: "1.2.3.4/32".into(),
                next_hop: "192.168.1.1".into(),
                ifindex: 12,
            }],
        };
        let json = serde_json::to_value(&state).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["routes", "tun", "tun_ifindex"]);
    }

    #[test]
    fn parses_cidr_and_length() {
        assert_eq!(
            parse_cidr("1.2.3.4/32").unwrap(),
            ("1.2.3.4".parse().unwrap(), 32)
        );
        assert_eq!(
            parse_cidr("1.2.3.4").unwrap(),
            ("1.2.3.4".parse().unwrap(), 32)
        );
        assert_eq!(
            parse_cidr("2001:db8::1/128").unwrap(),
            ("2001:db8::1".parse().unwrap(), 128)
        );
        assert_eq!(
            parse_cidr("2001:db8::1").unwrap(),
            ("2001:db8::1".parse().unwrap(), 128)
        );
        assert!(parse_cidr("1.2.3.4/33").is_err());
        assert!(parse_cidr("not-an-ip").is_err());
    }

    // The alias and the bypass routes must name the same adapter: both come from
    // the routing table's best route, so a host with two defaults on different
    // metrics cannot bind the core to one uplink and route its bypass to another.
    // Offline has nothing to compare.
    #[tokio::test]
    async fn uplink_and_default_route_agree() {
        let Some((gw, ifindex)) = read_default_route().await else {
            return;
        };
        assert!(gw.parse::<std::net::Ipv4Addr>().is_ok(), "gateway {gw}");
        let alias = uplink_device()
            .await
            .expect("a default route names a adapter");
        assert_eq!(adapter_ifindex(&alias), Some(ifindex));
    }
}

//! Closes port 53 outside the tun while an xray core captures the system's DNS.
//! Windows asks every adapter's resolvers in parallel, so giving the tun its own
//! resolver is not enough: the LAN resolver would still answer.
//!
//! The filters belong to a dynamic WFP session. The base filtering engine deletes
//! everything a dynamic session added when its engine handle closes, and the kernel
//! closes that handle when this process exits for any reason. A crashed or killed
//! helper therefore leaves no filter behind: DNS falls back to the normal resolvers.
//!
//! The filter set follows sing-tun's `strict_route` (`tun_windows.go`) and
//! wireguard-windows' `tunnel/firewall` (`blockDNS`, `permitTunInterface`).
//! <https://learn.microsoft.com/en-us/windows/win32/fwp/object-management>

use std::net::Ipv4Addr;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, UuidCreate};
use windows_sys::core::GUID;

const DNS_PORT: u16 = 53;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const NAME: &str = "Kasumi Proxy DNS guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layer {
    ConnectV4,
    ConnectV6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Condition {
    /// The executable the connection comes from.
    App(String),
    LocalInterface(u64),
    RemoteAddr(Ipv4Addr),
    RemotePort(u16),
    /// Conditions on the same field are OR-ed by WFP; different fields are AND-ed.
    Protocol(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Filter {
    pub name: &'static str,
    pub layer: Layer,
    /// Within one sublayer only the matching filter with the highest weight decides.
    pub weight: u8,
    pub permit: bool,
    pub conditions: Vec<Condition>,
}

pub(super) struct Plan {
    pub sublayer: GUID,
    pub filters: Vec<Filter>,
}

fn dns() -> Vec<Condition> {
    vec![
        Condition::RemotePort(DNS_PORT),
        Condition::Protocol(IPPROTO_UDP),
        Condition::Protocol(IPPROTO_TCP),
    ]
}

/// Block DNS everywhere except into the tun (`tun_luid`), to the tun's resolver,
/// and from the core (`core_bin`), which resolves its upstreams out of the uplink.
pub(super) fn plan(sublayer: GUID, tun_luid: u64, tun_dns: Ipv4Addr, core_bin: &str) -> Plan {
    let mut filters = Vec::new();
    for layer in [Layer::ConnectV4, Layer::ConnectV6] {
        filters.push(Filter {
            name: "Permit the core",
            layer,
            weight: 15,
            permit: true,
            conditions: vec![Condition::App(core_bin.to_owned())],
        });
        filters.push(Filter {
            name: "Permit the tun",
            layer,
            weight: 14,
            permit: true,
            conditions: vec![Condition::LocalInterface(tun_luid)],
        });
    }
    filters.push(Filter {
        name: "Permit DNS to the tun resolver",
        layer: Layer::ConnectV4,
        weight: 13,
        permit: true,
        conditions: [vec![Condition::RemoteAddr(tun_dns)], dns()].concat(),
    });
    for layer in [Layer::ConnectV4, Layer::ConnectV6] {
        filters.push(Filter {
            name: "Block DNS",
            layer,
            weight: 12,
            permit: false,
            conditions: dns(),
        });
    }
    Plan { sublayer, filters }
}

pub(super) fn new_sublayer_key() -> std::io::Result<GUID> {
    // SAFETY: `key` outlives the call.
    unsafe {
        let mut key: GUID = std::mem::zeroed();
        check(UuidCreate(&mut key) as u32)?;
        Ok(key)
    }
}

/// The installed filters; dropping it removes them.
pub(super) struct Guard(HANDLE);

// SAFETY: an engine handle is usable from any thread.
unsafe impl Send for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed only here.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// Add the sublayer and every filter of `plan` in one transaction.
pub(super) fn install(plan: &Plan) -> std::io::Result<Guard> {
    let mut name = wide(NAME);
    let session = session(&mut name);
    let mut engine: HANDLE = null_mut();
    // SAFETY: every pointer outlives the call.
    check(unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) })?;
    let guard = Guard(engine);
    // SAFETY: the engine stays open while `guard` lives.
    check(unsafe { FwpmTransactionBegin0(engine, 0) })?;
    let added = add_all(&guard, plan);
    // SAFETY: as above.
    match added.and_then(|()| check(unsafe { FwpmTransactionCommit0(engine) })) {
        Ok(()) => Ok(guard),
        Err(e) => {
            // SAFETY: as above.
            unsafe { FwpmTransactionAbort0(engine) };
            Err(e)
        }
    }
}

fn add_all(guard: &Guard, plan: &Plan) -> std::io::Result<()> {
    let engine = guard.0;
    let mut name = wide(NAME);
    let sublayer = sublayer(plan.sublayer, &mut name);
    // SAFETY: the engine is open; `sublayer` and `name` outlive the call.
    check(unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) })?;
    for f in &plan.filters {
        let apps = f
            .conditions
            .iter()
            .map(|c| match c {
                Condition::App(path) => AppId::of(path).map(Some),
                _ => Ok(None),
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = f
            .conditions
            .iter()
            .zip(&apps)
            .map(|(c, app)| raw_condition(c, app.as_ref().map_or(null_mut(), |a| a.0)))
            .collect();
        let mut name = wide(f.name);
        let raw = raw_filter(f, plan.sublayer, &mut name, &mut conditions);
        let mut id = 0u64;
        // SAFETY: `raw` points into `name`, `conditions`, `apps` and `plan`, all
        // alive until after the call.
        check(unsafe { FwpmFilterAdd0(engine, &raw, null_mut(), &mut id) })?;
    }
    Ok(())
}

/// A WFP-allocated application id, freed on drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn of(path: &str) -> std::io::Result<Self> {
        let path = wide(path);
        let mut blob = null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call.
        check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) })?;
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: the blob came from WFP and is freed once.
        unsafe { FwpmFreeMemory0((&raw mut self.0).cast()) };
    }
}

fn session(name: &mut [u16]) -> FWPM_SESSION0 {
    // SAFETY: an all-zero FWPM_SESSION0 is valid (null pointers, no flags).
    let mut s: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    s.displayData.name = name.as_mut_ptr();
    s.flags = FWPM_SESSION_FLAG_DYNAMIC;
    // INFINITE: wait for another session's transaction rather than fail.
    s.txnWaitTimeoutInMSec = u32::MAX;
    s
}

fn sublayer(key: GUID, name: &mut [u16]) -> FWPM_SUBLAYER0 {
    // SAFETY: an all-zero FWPM_SUBLAYER0 is valid (null pointers, no flags).
    let mut s: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    s.subLayerKey = key;
    s.displayData.name = name.as_mut_ptr();
    s.weight = u16::MAX;
    s
}

fn raw_filter(
    f: &Filter,
    sublayer: GUID,
    name: &mut [u16],
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> FWPM_FILTER0 {
    // SAFETY: an all-zero FWPM_FILTER0 is valid (null pointers, no flags).
    let mut raw: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    raw.displayData.name = name.as_mut_ptr();
    raw.layerKey = match f.layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    raw.subLayerKey = sublayer;
    raw.weight = FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: f.weight },
    };
    raw.numFilterConditions = conditions.len() as u32;
    raw.filterCondition = conditions.as_mut_ptr();
    // Soft verdicts: they settle this sublayer only, and a block from another
    // firewall still wins.
    raw.action.r#type = if f.permit {
        FWP_ACTION_PERMIT
    } else {
        FWP_ACTION_BLOCK
    };
    raw
}

/// `app_id` is the resolved blob for a [`Condition::App`]; a `LocalInterface`
/// condition points into `c` itself.
fn raw_condition(c: &Condition, app_id: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let (field, kind, value) = match c {
        Condition::App(_) => (
            FWPM_CONDITION_ALE_APP_ID,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
        ),
        Condition::LocalInterface(luid) => (
            FWPM_CONDITION_IP_LOCAL_INTERFACE,
            FWP_UINT64,
            FWP_CONDITION_VALUE0_0 {
                uint64: std::ptr::from_ref(luid).cast_mut(),
            },
        ),
        Condition::RemoteAddr(addr) => (
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: u32::from(*addr),
            },
        ),
        Condition::RemotePort(port) => (
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: *port },
        ),
        Condition::Protocol(proto) => (
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_UINT8,
            FWP_CONDITION_VALUE0_0 { uint8: *proto },
        ),
    };
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(rc: u32) -> std::io::Result<()> {
    match rc {
        ERROR_SUCCESS => Ok(()),
        rc => Err(std::io::Error::from_raw_os_error(rc as i32)),
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_PERSISTENT, FWPM_SUBLAYER_FLAG_PERSISTENT,
        FwpmSubLayerGetByKey0,
    };

    use super::*;

    const LUID: u64 = 0x0006_0000_0000_0007;
    const CORE: &str = r"C:\Kasumi\xray.exe";
    const TUN_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

    fn test_plan() -> Plan {
        plan(GUID::from_u128(1), LUID, TUN_DNS, CORE)
    }

    fn key_of(g: GUID) -> (u32, u16, u16, [u8; 8]) {
        (g.data1, g.data2, g.data3, g.data4)
    }

    fn only_dns() -> Vec<Condition> {
        vec![
            Condition::RemotePort(53),
            Condition::Protocol(17),
            Condition::Protocol(6),
        ]
    }

    #[test]
    fn plan_blocks_dns_outside_the_tun_only() {
        let p = test_plan();
        for layer in [Layer::ConnectV4, Layer::ConnectV6] {
            let on_layer: Vec<&Filter> = p.filters.iter().filter(|f| f.layer == layer).collect();
            let blocks: Vec<&&Filter> = on_layer.iter().filter(|f| !f.permit).collect();
            assert_eq!(blocks.len(), 1, "{layer:?}");
            // Only DNS is ever blocked.
            assert_eq!(blocks[0].conditions, only_dns());
            let permit = |c: Condition| {
                on_layer
                    .iter()
                    .find(|f| f.permit && f.conditions == [c.clone()])
                    .map(|f| f.weight)
                    .unwrap_or_else(|| panic!("no {c:?} permit on {layer:?}"))
            };
            assert!(permit(Condition::LocalInterface(LUID)) > blocks[0].weight);
            assert!(permit(Condition::App(CORE.into())) > blocks[0].weight);
        }
        let to_resolver: Vec<&Filter> = p
            .filters
            .iter()
            .filter(|f| f.conditions.contains(&Condition::RemoteAddr(TUN_DNS)))
            .collect();
        assert_eq!(to_resolver.len(), 1);
        assert!(to_resolver[0].permit);
        assert_eq!(to_resolver[0].layer, Layer::ConnectV4);
        assert!(to_resolver[0].weight > 12);
        assert!(p.filters.iter().all(|f| f.weight <= 15));
    }

    // Nothing may outlive the helper: the session is dynamic, and no object asks to
    // persist or to apply at boot.
    #[test]
    fn guard_is_dynamic_and_persists_nothing() {
        let mut name = wide(NAME);
        assert_eq!(session(&mut name).flags, FWPM_SESSION_FLAG_DYNAMIC);
        let sl = sublayer(GUID::from_u128(1), &mut name);
        assert_eq!(sl.flags & FWPM_SUBLAYER_FLAG_PERSISTENT, 0);
        assert_eq!(sl.weight, u16::MAX);
        let p = test_plan();
        for f in &p.filters {
            let mut conditions: Vec<_> = f
                .conditions
                .iter()
                .map(|c| raw_condition(c, null_mut()))
                .collect();
            let raw = raw_filter(f, p.sublayer, &mut name, &mut conditions);
            assert_eq!(
                raw.flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME),
                0
            );
            assert_eq!(raw.numFilterConditions as usize, f.conditions.len());
            assert_eq!(key_of(raw.subLayerKey), key_of(p.sublayer));
            // SAFETY: the weight was written as uint8.
            assert_eq!(unsafe { raw.weight.Anonymous.uint8 }, f.weight);
            let action = if f.permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            };
            assert_eq!(raw.action.r#type, action);
        }
    }

    #[test]
    fn raw_conditions_carry_their_values() {
        let mut blob = FWP_BYTE_BLOB {
            size: 0,
            data: null_mut(),
        };
        let blob: *mut FWP_BYTE_BLOB = &raw mut blob;
        let luid = Condition::LocalInterface(LUID);
        let cases = [
            (
                Condition::App(CORE.into()),
                FWPM_CONDITION_ALE_APP_ID,
                FWP_BYTE_BLOB_TYPE,
            ),
            (luid.clone(), FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_UINT64),
            (
                Condition::RemoteAddr(TUN_DNS),
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_UINT32,
            ),
            (
                Condition::RemotePort(53),
                FWPM_CONDITION_IP_REMOTE_PORT,
                FWP_UINT16,
            ),
            (
                Condition::Protocol(17),
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_UINT8,
            ),
        ];
        for (c, field, kind) in &cases {
            let raw = raw_condition(c, blob);
            assert_eq!(key_of(raw.fieldKey), key_of(*field), "{c:?}");
            assert_eq!(raw.conditionValue.r#type, *kind, "{c:?}");
            assert_eq!(raw.matchType, FWP_MATCH_EQUAL);
        }
        // SAFETY: each union member read is the one `raw_condition` wrote.
        unsafe {
            let v = |c: &Condition| raw_condition(c, blob).conditionValue.Anonymous;
            assert_eq!(v(&cases[0].0).byteBlob, blob);
            assert_eq!(*v(&luid).uint64, LUID);
            // WFP takes IPv4 addresses as host-order integers.
            assert_eq!(v(&cases[2].0).uint32, 0xC612_0002);
            assert_eq!(v(&cases[3].0).uint16, 53);
            assert_eq!(v(&cases[4].0).uint8, 17);
        }
    }

    fn sublayer_exists(key: GUID) -> bool {
        let mut engine: HANDLE = null_mut();
        // SAFETY: plain WFP calls on a handle this function owns.
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            check(FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_WINNT,
                null(),
                &session,
                &mut engine,
            ))
            .unwrap();
            let mut found = null_mut();
            let rc = FwpmSubLayerGetByKey0(engine, &key, &mut found);
            if rc == ERROR_SUCCESS {
                FwpmFreeMemory0((&raw mut found).cast());
            }
            FwpmEngineClose0(engine);
            rc == ERROR_SUCCESS
        }
    }

    // Against the real base filtering engine: every filter of a plan is accepted,
    // and closing the engine handle, which the kernel does when the process dies,
    // removes them. The blocks are turned into permits, so nothing is filtered.
    // Skipped without the rights to add filters, or without a filtering engine.
    #[test]
    fn closing_the_engine_removes_the_guard() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        use windows_sys::Win32::System::Rpc::RPC_S_CANNOT_SUPPORT;

        let exe = std::env::current_exe().unwrap();
        let key = new_sublayer_key().unwrap();
        let mut p = plan(key, LUID, TUN_DNS, &exe.to_string_lossy());
        for f in &mut p.filters {
            f.permit = true;
        }
        let guard = match install(&p) {
            Ok(guard) => guard,
            Err(e)
                if [ERROR_ACCESS_DENIED as i32, RPC_S_CANNOT_SUPPORT]
                    .contains(&e.raw_os_error().unwrap_or_default()) =>
            {
                eprintln!("skipped: {e}");
                return;
            }
            Err(e) => panic!("install: {e}"),
        };
        assert!(sublayer_exists(key));
        drop(guard);
        assert!(!sublayer_exists(key));
    }
}

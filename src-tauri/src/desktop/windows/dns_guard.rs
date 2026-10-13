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

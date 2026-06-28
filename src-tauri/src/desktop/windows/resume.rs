//! System resume monitor (Windows). A core left running across a sleep/hibernate can
//! hold stale routing/DNS state, and the uplink watcher doesn't fire if the default
//! route survived — so we register for power notifications and notify the `Service` on
//! resume, which restarts the data-path to re-pin it.
//!
//! The Linux side listens for logind's `PrepareForSleep(false)`; here we use
//! `PowerRegisterSuspendResumeNotification` with a callback (no message window needed).

use std::ffi::c_void;
use std::ptr;

use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Power::{
    PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
};

/// `recipient` is a pointer to a `DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS` callback block.
const DEVICE_NOTIFY_CALLBACK: u32 = 2;
/// Power-broadcast event types signalling a wake (resume after standby / automatic).
const PBT_APMRESUMESUSPEND: u32 = 7;
const PBT_APMRESUMEAUTOMATIC: u32 = 18;

/// The C callback the kernel invokes on power transitions, on its own thread. `context`
/// is the `mpsc::Sender<()>` we registered; on a resume edge we nudge it (non-blocking —
/// the channel coalesces, one restart per wake is enough).
unsafe extern "system" fn on_power_event(
    context: *const c_void,
    event_type: u32,
    _setting: *const c_void,
) -> u32 {
    if (event_type == PBT_APMRESUMEAUTOMATIC || event_type == PBT_APMRESUMESUSPEND)
        && !context.is_null()
    {
        let tx = &*(context as *const mpsc::Sender<()>);
        let _ = tx.try_send(());
    }
    0 // NO_ERROR
}

/// Register for resume notifications and send `()` on each wake. Returns immediately if
/// registration fails; otherwise parks so the callback's `Sender` stays alive for the
/// process lifetime.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    // Keep the Sender at a stable heap address — the kernel stores this pointer as the
    // callback Context and reads it on every power event, so it must outlive the loop.
    let tx = Box::new(tx);
    let params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(on_power_event),
        Context: &*tx as *const mpsc::Sender<()> as *mut c_void,
    };
    let mut handle: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            &params as *const _ as HANDLE,
            &mut handle,
        )
    };
    if rc != 0 {
        return; // couldn't subscribe — no resume restarts on this host
    }
    // Park forever: holding `tx` and `handle` here keeps the callback Context valid and
    // the subscription alive until the process exits.
    std::future::pending::<()>().await;
    drop((tx, handle));
}

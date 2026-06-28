//! System resume monitor. A core left running across a suspend/hibernate can hold stale
//! routing/DNS state, and the uplink watcher doesn't fire if the default route survived
//! the sleep — so we listen for logind's `PrepareForSleep(false)` signal and notify the
//! `Service`, which restarts the data-path to re-pin it.
//!
//! `org.freedesktop.login1.Manager.PrepareForSleep(b)` fires `true` right before
//! sleeping and `false` right after resuming; we forward only the resume edge.

use futures_util::StreamExt;
use tokio::sync::mpsc;
use zbus::Connection;

/// Typed proxy for the bits of logind's manager we use — just the sleep signal.
#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Logind {
    /// `true` before suspend/hibernate, `false` after resume.
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

/// Watch logind for resume and send `()` on each wake. Reconnects if the bus drops;
/// returns when the receiver is gone.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    loop {
        match watch_once(&tx).await {
            // Receiver dropped — nothing left to notify.
            Ok(()) => return,
            // No system bus / signal stream ended — back off and re-arm.
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
        }
    }
}

/// One connection's worth of watching; `Ok(())` means the receiver was dropped.
async fn watch_once(tx: &mpsc::Sender<()>) -> zbus::Result<()> {
    let conn = Connection::system().await?;
    let logind = LogindProxy::new(&conn).await?;
    let mut sleep = logind.receive_prepare_for_sleep().await?;
    while let Some(signal) = sleep.next().await {
        // `start == false` is the resume edge; ignore the pre-sleep `true`.
        if !signal.args()?.start && tx.send(()).await.is_err() {
            return Ok(());
        }
    }
    // Stream ended (bus closed) — surface as an error so the caller re-arms.
    Err(zbus::Error::InvalidReply)
}

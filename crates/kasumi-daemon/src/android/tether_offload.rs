//! Android's tethering fast paths, held off while tethered traffic is proxied.
//!
//! The Tethering module forwards established tethered flows outside the kernel's
//! routing and netfilter, so the steering rules in [`super::tethering`] never see
//! them:
//!
//! - **BPF offload** (`BpfCoordinator`): tc ingress programs
//!   `tether_upstream4/6` on each downstream send matching packets straight to the
//!   upstream. IPv4 entries are added only for conntrack flows masqueraded to the
//!   upstream address (`BpfConntrackEventConsumer.accept`), so flows steered into
//!   the tun never get one, but flows from before the steering keep theirs. IPv6
//!   entries cover every client address in the upstream prefix, which skips the
//!   IPv6 reject in `FORWARD` entirely.
//!   Whether BPF offload runs is fixed when Tethering starts
//!   (`BpfCoordinator.mIsBpfEnabled`, from `TetheringConfiguration
//!   .isBpfOffloadEnabled()`), so the only runtime lever is removing the programs
//!   from the downstream. Tethering attaches them again on an upstream change, so
//!   the watcher removes them on every poll. Conntrack is not flushed: once the
//!   programs are gone, the packets of an older flow take the kernel path, are
//!   steered into the tun mid-connection and die there, and the client reconnects
//!   through the proxy.
//! - **Hardware offload** (`OffloadController`, the offload HAL, Qualcomm IPA on
//!   the reference phone): disabled by `settings global tether_offload_disabled`.
//!   `OffloadController.start()` reads it only when tethering becomes active
//!   (`Tethering.TetherModeAliveState.enter()`); no observer reacts to a change, so
//!   a session that is already running keeps the HAL until tethering restarts.
//!
//! The setting's previous value is saved in the run dir before it is changed and
//! put back exactly on teardown, also after a crash (boot init restores it).

use std::time::Duration;

use kasumi_backend::fs::{read_text, remove_file};
use kasumi_backend::fsjson::write_text_atomic;

use super::paths::{CMD, TC, TETHER_OFFLOAD_SAVED};
use super::{run_out, silent};

const OFFLOAD_KEY: &str = "tether_offload_disabled";
/// What `settings get` prints for a key that is not set.
const UNSET: &str = "null";

/// `cmd settings <args>`, bounded: the settings service can be slow to come up
/// at boot. `None` when it did not answer in time or could not run.
async fn settings(args: &[&str]) -> Option<(i32, String)> {
    let mut argv = vec![CMD, "settings"];
    argv.extend_from_slice(args);
    let (code, out) = tokio::time::timeout(Duration::from_secs(10), run_out(&argv))
        .await
        .ok()?;
    (code >= 0).then_some((code, out))
}

/// Turn hardware offload off, saving the current value first. A no-op while a
/// saved value exists: the setting is already ours. Returns whether it changed
/// the setting now.
pub async fn suppress_hw_offload() -> bool {
    if read_text(TETHER_OFFLOAD_SAVED).await.is_some() {
        return false;
    }
    let reply = settings(&["get", "global", OFFLOAD_KEY]).await;
    let Some(prev) = reply.and_then(|(code, out)| saved_value(&out).filter(|_| code == 0)) else {
        log::warn!("tethering offload: cannot read {OFFLOAD_KEY}, leaving it alone");
        return false;
    };
    // Saved before the change, so a crash in between still restores it.
    if write_text_atomic(TETHER_OFFLOAD_SAVED, &prev)
        .await
        .is_err()
    {
        return false;
    }
    let put = settings(&["put", "global", OFFLOAD_KEY, "1"]).await;
    if put.is_some_and(|(code, _)| code == 0) {
        return true;
    }
    // Nothing changed: drop the record so the next poll tries again.
    remove_file(TETHER_OFFLOAD_SAVED).await;
    false
}

/// Put back the value [`suppress_hw_offload`] saved, if any. Idempotent; the saved
/// value is dropped only once the restore succeeded.
pub async fn restore_hw_offload() {
    let Some(saved) = read_text(TETHER_OFFLOAD_SAVED).await else {
        return;
    };
    let argv = restore_argv(&saved);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    if settings(&argv).await.is_some_and(|(code, _)| code == 0) {
        remove_file(TETHER_OFFLOAD_SAVED).await;
    }
}

/// The value to save out of `settings get` output: one token, `null` when unset.
fn saved_value(out: &str) -> Option<String> {
    let v = out.trim();
    (!v.is_empty() && !v.contains(char::is_whitespace) && v.len() <= 64).then(|| v.to_string())
}

/// The `settings` arguments that restore `saved`. An unset key is deleted, which
/// brings back Tethering's default (`OffloadHardwareInterface
/// .DEFAULT_TETHER_OFFLOAD_DISABLED` = 0); an unreadable saved file is treated the
/// same way.
fn restore_argv(saved: &str) -> Vec<String> {
    match saved_value(saved) {
        Some(v) if v != UNSET => ["put", "global", OFFLOAD_KEY, &v]
            .map(String::from)
            .to_vec(),
        _ => ["delete", "global", OFFLOAD_KEY].map(String::from).to_vec(),
    }
}

/// `(protocol, pref)` of the Tethering BPF upstream programs out of
/// `tc filter show dev <downstream> ingress`.
fn tether_bpf_filters(tc_out: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in tc_out.lines() {
        if !line.contains("tether_upstream") {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let field = |k: &str| {
            toks.windows(2)
                .find(|w| w[0] == k)
                .map(|w| w[1].to_string())
        };
        if let (Some(proto), Some(pref)) = (field("protocol"), field("pref"))
            && !found.contains(&(proto.clone(), pref.clone()))
        {
            found.push((proto, pref));
        }
    }
    found
}

/// Remove Tethering's BPF upstream programs from `iface`'s ingress, so its packets
/// take the kernel path through the steering rules.
pub async fn detach_tether_bpf(iface: &str) {
    let (_, out) = run_out(&[TC, "filter", "show", "dev", iface, "ingress"]).await;
    for (proto, pref) in tether_bpf_filters(&out) {
        silent(&[
            TC, "filter", "del", "dev", iface, "ingress", "protocol", &proto, "pref", &pref,
        ])
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_setting_is_deleted_on_restore() {
        // `settings get global tether_offload_disabled` on the reference phone.
        let saved = saved_value("null\n").unwrap();
        assert_eq!(restore_argv(&saved), ["delete", "global", OFFLOAD_KEY]);
    }

    #[test]
    fn a_set_value_is_put_back_exactly() {
        let saved = saved_value("0\n").unwrap();
        assert_eq!(restore_argv(&saved), ["put", "global", OFFLOAD_KEY, "0"]);
        assert_eq!(restore_argv("1"), ["put", "global", OFFLOAD_KEY, "1"]);
    }

    #[test]
    fn unreadable_settings_output_is_not_saved() {
        assert_eq!(saved_value(""), None);
        assert_eq!(saved_value("Error: no binder\n"), None);
        assert_eq!(
            restore_argv("garbage with spaces"),
            ["delete", "global", OFFLOAD_KEY]
        );
    }

    #[test]
    fn finds_the_tether_programs_in_captured_tc_output() {
        // `tc filter show dev rndis0 ingress` on the reference phone.
        let out = "\
filter protocol ipv6 pref 2 bpf chain 0
filter protocol ipv6 pref 2 bpf chain 0 handle 0x1 prog_offload_schedcls_tether_upstream6_ether:[*fsobj] direct-action not_in_hw id 5 tag f2fa64982b1a7903 jited
filter protocol ip pref 3 bpf chain 0
filter protocol ip pref 3 bpf chain 0 handle 0x1 prog_offload_schedcls_tether_upstream4_ether:[*fsobj] direct-action not_in_hw id 11 tag 40c2769c56431439 jited
";
        assert_eq!(
            tether_bpf_filters(out),
            [
                ("ipv6".to_string(), "2".to_string()),
                ("ip".to_string(), "3".to_string())
            ]
        );
    }

    #[test]
    fn other_ingress_filters_are_left_alone() {
        let out = "filter protocol all pref 1 bpf chain 0 handle 0x1 prog_clatd_schedcls_ingress6:[*fsobj] direct-action\n";
        assert!(tether_bpf_filters(out).is_empty());
        assert!(tether_bpf_filters("").is_empty());
    }
}

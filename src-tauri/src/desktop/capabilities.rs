//! Linux capability handling for the least-privilege desktop data-path helper.
//!
//! The helper is still *launched* as root via pkexec, but Phase 2 of the
//! least-privilege handoff makes it stop *holding* full root at runtime: on startup
//! it drops every capability from its bounding set except the few the data-path
//! provably needs. The bounding set is the hard ceiling a child process can ever
//! acquire, so this also constrains the exec'd cores / tun2socks / `ip` — the
//! immediate, packaging-free blast-radius win.
//!
//! Phase 3 (added later) layers an ambient `CAP_NET_RAW` raise for the test cores
//! so their uplink bind survives exec once the helper is caps-only rather than
//! root. All of this is a no-op for a non-root run (in-process dev): a process with
//! no privileges has nothing to drop.

use caps::{CapSet, Capability, CapsHashSet};

/// The capabilities the desktop data-path provably needs — the bounding-set the
/// helper keeps, with every other cap dropped.
///
/// - `NET_ADMIN` — create the tun, `ip addr/link/route`, tun2socks' fwmark
///   (`SO_MARK`, keeps its upstream out of the tunnel).
/// - `NET_RAW` — a test core's `SO_BINDTODEVICE` / `bind_interface` uplink bind so
///   it escapes an active tun. The *active* core needs none (it bypasses via
///   host-routes); only the throwaway test cores do.
/// - `CHOWN` — hand the privilege-helper unix socket to the unprivileged GUI uid.
/// - `DAC_OVERRIDE` — the helper writes logs/state into the *user-owned* datadir
///   (`~/.local/share/kasumi-proxy/*.log`) and creates run_dir under the user's
///   `0700` `XDG_RUNTIME_DIR`. Root is subject to ordinary DAC checks without it,
///   so the data-path would break the moment a log file is created. This retires
///   only once Phase 4b restructures datadir/log + run_dir ownership (then `CHOWN`
///   goes too).
///
/// Kept minimal and auditable: every entry is justified above, and the set is a
/// strict subset of root's ~40 caps.
pub fn keep_set() -> CapsHashSet {
    [
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_CHOWN,
        Capability::CAP_DAC_OVERRIDE,
    ]
    .into_iter()
    .collect()
}

/// Drop every capability from the current process's bounding set that is not in
/// [`keep_set`], returning the dropped capabilities (for the caller to log).
///
/// Idempotent (caps already absent are simply not in the read set) and a one-way
/// ratchet: once dropped a cap can never return to the bounding set, so this both
/// shrinks the helper *and* every child it execs. Only meaningful as root (a
/// non-root process has nothing to drop); callers gate on `geteuid() == 0`.
///
/// Reads the live bounding set first rather than dropping blindly, so a cap the
/// kernel already withheld (or a prior run already dropped) isn't re-attempted.
pub fn drop_unneeded_bounding() -> anyhow::Result<CapsHashSet> {
    let keep = keep_set();
    let current = caps::read(None, CapSet::Bounding)
        .map_err(|e| anyhow::anyhow!("read bounding set: {e}"))?;
    let mut dropped = CapsHashSet::new();
    for cap in current.difference(&keep) {
        caps::drop(None, CapSet::Bounding, *cap)
            .map_err(|e| anyhow::anyhow!("drop {cap} from bounding set: {e}"))?;
        dropped.insert(*cap);
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_set_covers_the_data_path_needs() {
        let keep = keep_set();
        // Every cap the data-path needs must be present; if a future change drops
        // one, this is the loud signal that the helper would break at runtime.
        assert!(keep.contains(&Capability::CAP_NET_ADMIN));
        assert!(keep.contains(&Capability::CAP_NET_RAW));
        assert!(keep.contains(&Capability::CAP_CHOWN));
        assert!(keep.contains(&Capability::CAP_DAC_OVERRIDE));
    }

    #[test]
    fn keep_set_drops_dangerous_caps() {
        // The high-value caps this effort exists to retire: full filesystem, ptrace,
        // arbitrary module/sysadmin, and the ability to grant more caps.
        let keep = keep_set();
        for cap in [
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SETPCAP,
            Capability::CAP_NET_BIND_SERVICE,
        ] {
            assert!(!keep.contains(&cap), "{cap} should not be in the keep-set");
        }
    }
}

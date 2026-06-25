//! Linux capabilities for the desktop data-path helper. Launched as root (pkexec)
//! or with file caps (NixOS `security.wrappers`), the helper drops its bounding set
//! to [`keep_set`] on startup — which also caps every core / tun2socks / `ip` it
//! execs — and raises an ambient `CAP_NET_RAW` for the test cores so their uplink
//! bind survives exec. All no-ops for an unprivileged in-process dev run.

use caps::{CapSet, Capability, CapsHashSet};

/// The caps the data-path needs; the helper keeps these and drops the rest.
///
/// - `NET_ADMIN` — tun creation, `ip` routing, tun2socks' fwmark.
/// - `NET_RAW` — a test core's uplink bind (`SO_BINDTODEVICE` / `bind_interface`);
///   the active core bypasses via host-routes and needs none.
/// - `CHOWN` — hand the helper socket to the GUI uid.
/// - `DAC_OVERRIDE` — write logs/state into the user-owned datadir + run_dir as
///   root. Retires with the socket/dir-ownership restructure (then `CHOWN` too).
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

/// The `setcap` argument that grants exactly [`keep_set`] as file caps (`+ep`),
/// built from the keep-set so the two can't drift. Used by the GUI's one-time
/// self-`setcap` (`privhelper::spawn`) and mirrored by the NixOS `security.wrappers`
/// capability string. `setcap` ignores ordering, so the unordered set is fine.
pub fn file_caps_setcap_arg() -> String {
    let names: Vec<String> = keep_set()
        .iter()
        .map(|c| c.to_string().to_lowercase())
        .collect();
    format!("{}+ep", names.join(","))
}

/// Drop every bounding-set capability not in [`keep_set`], returning what was
/// dropped (for logging). A one-way ratchet that also caps every child the helper
/// execs. Idempotent: reads the live set first, so already-absent caps are skipped.
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

/// Seed `CAP_NET_RAW` into the process's inheritable set, the precondition for the
/// test cores' ambient raise (`PR_CAP_AMBIENT_RAISE` needs the cap in both permitted
/// and inheritable, and both launchers start with an empty inheritable set). Needs
/// no `CAP_SETPCAP` (the cap is already permitted). Idempotent; run once at startup.
pub fn seed_test_core_inheritable() -> anyhow::Result<()> {
    let mut set = caps::read(None, CapSet::Inheritable)
        .map_err(|e| anyhow::anyhow!("read inheritable set: {e}"))?;
    if set.insert(Capability::CAP_NET_RAW) {
        caps::set(None, CapSet::Inheritable, &set)
            .map_err(|e| anyhow::anyhow!("seed CAP_NET_RAW into inheritable set: {e}"))?;
    }
    Ok(())
}

/// Whether this process owns the privileged data-path — checks effective
/// `CAP_NET_ADMIN` (tun + `ip` + fwmark) instead of `geteuid() == 0`, so it reads
/// true under both the root and the non-root file-cap launcher and false for
/// unprivileged dev. Fails closed on a query error.
pub fn is_privileged_data_path() -> bool {
    match caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN) {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            log::warn!(
                "could not query effective CAP_NET_ADMIN ({e}); data-path caps not applied"
            );
            false
        }
    }
}

/// Whether this process holds an effective `CAP_NET_RAW` — the real precondition
/// for a test core's uplink bind. Fails *closed* on a query error rather than
/// falling back to `euid == 0`: a false positive would route test traffic through
/// the active tun, the exact bug the bind prevents.
pub fn has_effective_net_raw() -> bool {
    match caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW) {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            log::warn!(
                "could not query effective CAP_NET_RAW ({e}); test cores won't bind the uplink"
            );
            false
        }
    }
}

/// `prctl` option + sub-op for the ambient set. libc 0.2 exports these only for
/// the android target, not plain linux, so the ABI-fixed values are pinned here
/// (stable kernel constants from `linux/uapi/prctl.h`).
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_int = 2;
/// Numeric capability number for `CAP_NET_RAW`, read off the `caps` enum so it
/// stays in lock-step with the crate (no hand-typed magic number); libc doesn't
/// export `CAP_*`.
const CAP_NET_RAW_NR: libc::c_uint = Capability::CAP_NET_RAW as libc::c_uint;

/// A `pre_exec` hook raising `CAP_NET_RAW` into the forked child's ambient set, the
/// only way to grant a cap across exec into the test core (it has no file caps).
/// Run ONLY here, never process-wide, so the cap stays off the helper's own threads
/// and the active core. Needs the cap in permitted + inheritable (see
/// [`seed_test_core_inheritable`]); inert under root, load-bearing when caps-only.
/// Fails closed: an `Err` aborts the exec rather than running a test core unbound.
///
/// # Async-signal-safety
///
/// A single raw `prctl(2)` — no allocation, locks, or stdio — per the `pre_exec`
/// contract.
pub fn raise_net_raw_ambient() -> std::io::Result<()> {
    // SAFETY: one prctl syscall; async-signal-safe per the contract above.
    let rc =
        unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW_NR, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
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
    fn setcap_arg_matches_the_keep_set() {
        let arg = file_caps_setcap_arg();
        let (caps, flags) = arg.rsplit_once('+').expect("setcap arg has a +flags suffix");
        assert_eq!(flags, "ep");
        let listed: std::collections::HashSet<&str> = caps.split(',').collect();
        // One token per kept cap, each the lowercased name `setcap` expects.
        assert_eq!(listed.len(), keep_set().len());
        for cap in keep_set() {
            assert!(
                listed.contains(cap.to_string().to_lowercase().as_str()),
                "{cap} missing from the setcap arg"
            );
        }
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

    // The honest gate: under a root test runner the effective set carries NET_RAW
    // (it's in the default root bounding set), so the predicate reads true; under an
    // unprivileged runner it reads false. Either way it returns a bool without
    // panicking — the load-bearing property, since a query error is fail-closed.
    #[test]
    fn has_effective_net_raw_does_not_panic() {
        let _ = has_effective_net_raw();
    }

    // Same property for the data-path-owner gate: must not panic regardless of how
    // the test is launched (root, caps, or unprivileged dev).
    #[test]
    fn is_privileged_data_path_does_not_panic() {
        let _ = is_privileged_data_path();
    }

    // Seeding is idempotent: running it twice (and under any starting inheritable
    // set) leaves NET_RAW inheritable and never errors on a root test runner; under
    // an unprivileged runner the insert/set is a no-op error that we only assert
    // doesn't panic. The ambient raise itself is verified at runtime on a box with
    // an active tun (see the handoff's verification section).
    #[test]
    fn seed_test_core_inheritable_is_idempotent() {
        let first = seed_test_core_inheritable();
        if first.is_ok() {
            // A successful seed must be stable on repeat.
            assert!(seed_test_core_inheritable().is_ok());
        }
    }

    // Lock the ABI values the raw prctl relies on: CAP_NET_RAW is capability 13 in
    // the kernel ABI, and the const is read off the caps enum (not hand-typed), so
    // this asserts they agree — a caps-crate remap would surface here, not at a
    // runtime where the ambient raise silently does nothing.
    #[test]
    fn cap_net_raw_nr_matches_the_kernel_abi() {
        assert_eq!(CAP_NET_RAW_NR, 13);
        assert_eq!(Capability::CAP_NET_RAW as libc::c_uint, 13);
    }
}

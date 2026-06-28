//! Linux capabilities for the desktop data-path helper. Launched as root (pkexec)
//! or with file caps (NixOS `security.wrappers`, the deb/rpm postinst), the helper
//! drops its bounding set to [`keep_set`] on startup — which also caps every core /
//! tun2socks / `ip` it execs — and raises caps into the forked children's ambient
//! set so they survive exec when the helper runs caps-only (not root): `CAP_NET_RAW`
//! for the test cores' uplink bind, `CAP_NET_ADMIN` for the active core's own tun
//! (sing-box) and tun2socks' tun + fwmark. All no-ops for an unprivileged in-process
//! dev run, and inert under a root helper where children already inherit every cap.

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

/// Seed the caps a forked child may raise into its ambient set — `CAP_NET_RAW` (test
/// cores' uplink bind) and `CAP_NET_ADMIN` (the active core's own tun / tun2socks'
/// tun + fwmark) — into the process's inheritable set, the precondition for that
/// raise (`PR_CAP_AMBIENT_RAISE` needs the cap in both permitted and inheritable, and
/// both launchers start with an empty inheritable set). Both are already permitted
/// (they're in [`keep_set`]), so this needs no `CAP_SETPCAP`. Idempotent; run once at
/// startup.
pub fn seed_child_inheritable() -> anyhow::Result<()> {
    let mut set = caps::read(None, CapSet::Inheritable)
        .map_err(|e| anyhow::anyhow!("read inheritable set: {e}"))?;
    let mut changed = false;
    for cap in [Capability::CAP_NET_RAW, Capability::CAP_NET_ADMIN] {
        changed |= set.insert(cap);
    }
    if changed {
        caps::set(None, CapSet::Inheritable, &set)
            .map_err(|e| anyhow::anyhow!("seed child caps into inheritable set: {e}"))?;
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
            log::warn!("could not query effective CAP_NET_ADMIN ({e}); data-path caps not applied");
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
/// Numeric capability numbers, read off the `caps` enum so they stay in lock-step
/// with the crate (no hand-typed magic number); libc doesn't export `CAP_*`.
const CAP_NET_RAW_NR: libc::c_uint = Capability::CAP_NET_RAW as libc::c_uint;
const CAP_NET_ADMIN_NR: libc::c_uint = Capability::CAP_NET_ADMIN as libc::c_uint;

/// Shared body of the `pre_exec` raises below: raise one capability into the ambient
/// set — the only way to grant a cap across exec into a core that has no file caps.
/// Needs the cap in permitted + inheritable (see [`seed_child_inheritable`]). A single
/// raw `prctl(2)`, so async-signal-safe per the `pre_exec` contract.
fn raise_ambient(cap_nr: libc::c_uint) -> std::io::Result<()> {
    // SAFETY: one prctl syscall; async-signal-safe per the contract above.
    let rc = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_nr, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A `pre_exec` hook raising `CAP_NET_RAW` into the forked child's ambient set, so a
/// test core's uplink bind survives exec. Run ONLY here, never process-wide, so the
/// cap stays off the helper's own threads and the active core; inert under root,
/// load-bearing when caps-only. Fails closed: an `Err` aborts the exec rather than
/// running a test core unbound.
pub fn raise_net_raw_ambient() -> std::io::Result<()> {
    raise_ambient(CAP_NET_RAW_NR)
}

/// A `pre_exec` hook raising `CAP_NET_ADMIN` into the forked child's ambient set, so
/// the active core can create its own tun (sing-box) and tun2socks can open the tun +
/// set its fwmark when the helper runs caps-only (not root). Inert under a root helper
/// where the child already inherits every cap. Fails closed: an `Err` aborts the exec
/// rather than running a core that can't open its tun.
pub fn raise_net_admin_ambient() -> std::io::Result<()> {
    raise_ambient(CAP_NET_ADMIN_NR)
}

/// A `pre_exec` hook tying a spawned data-path process (the core / tun2socks) to the
/// helper that is its parent: `PR_SET_PDEATHSIG(SIGTERM)` makes the kernel SIGTERM
/// the child the instant the helper dies — including an *unclean* exit (crash /
/// SIGKILL) where no teardown code can run. SIGTERM (not KILL) lets sing-box remove
/// its own tun + auto_route on the way out, so an orphaned core can't strand a tun /
/// routes and leave `service-state` reporting "stopped" while traffic is still
/// captured. The `getppid() == 1` guard closes the fork→prctl race: if the helper
/// already died (child reparented to init), PDEATHSIG would never fire, so exit
/// rather than exec an unsupervised core.
///
/// # Async-signal-safety
///
/// Only `prctl` / `getppid` / `_exit` — no allocation, locks, or stdio — per the
/// `pre_exec` contract.
pub fn die_with_parent() -> std::io::Result<()> {
    // SAFETY: async-signal-safe syscalls only, per the contract above.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGTERM as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getppid is async-signal-safe and never fails.
    if unsafe { libc::getppid() } == 1 {
        // SAFETY: _exit is async-signal-safe; the helper is already gone, so don't
        // bring up an unsupervised core that nothing would ever reap.
        unsafe { libc::_exit(0) };
    }
    Ok(())
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
        let (caps, flags) = arg
            .rsplit_once('+')
            .expect("setcap arg has a +flags suffix");
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
    // set) leaves NET_RAW + NET_ADMIN inheritable and never errors on a root test
    // runner; under an unprivileged runner the insert/set is a no-op error that we
    // only assert doesn't panic. The ambient raise itself is verified at runtime on a
    // box with an active tun (see the handoff's verification section).
    #[test]
    fn seed_child_inheritable_is_idempotent() {
        let first = seed_child_inheritable();
        if first.is_ok() {
            // A successful seed must be stable on repeat.
            assert!(seed_child_inheritable().is_ok());
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
        // CAP_NET_ADMIN is capability 12 in the kernel ABI.
        assert_eq!(CAP_NET_ADMIN_NR, 12);
        assert_eq!(Capability::CAP_NET_ADMIN as libc::c_uint, 12);
    }
}

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

/// Seed `CAP_NET_RAW` into the inheritable set of the current process.
///
/// `PR_CAP_AMBIENT_RAISE` (the test-core uplink grant) requires the capability to
/// be present in *both* the permitted and the inheritable sets. A pkexec-launched
/// root process starts with an empty inheritable set, so without this the ambient
/// raise would fail with `EPERM`. Under a future Phase-4 file-cap launcher
/// (`security.wrappers` with `+i`) the inheritable set is already populated, so
/// this is a harmless idempotent no-op. Idempotent in general: if `CAP_NET_RAW` is
/// already inheritable nothing changes.
///
/// A process may add to its inheritable set any capability already in its
/// permitted set (root: permitted = bounding ⊇ `NET_RAW`), so this needs no
/// `CAP_SETPCAP`. Process-wide and once-at-startup, so concurrent test-core
/// spawns always see the seeded set — there is no per-spawn race to close.
pub fn seed_test_core_inheritable() -> anyhow::Result<()> {
    let mut set = caps::read(None, CapSet::Inheritable)
        .map_err(|e| anyhow::anyhow!("read inheritable set: {e}"))?;
    if set.insert(Capability::CAP_NET_RAW) {
        caps::set(None, CapSet::Inheritable, &set)
            .map_err(|e| anyhow::anyhow!("seed CAP_NET_RAW into inheritable set: {e}"))?;
    }
    Ok(())
}

/// Whether the current process holds an effective `CAP_NET_RAW` — the real
/// precondition for a test core's uplink bind, replacing the old `geteuid() == 0`
/// proxy. Under a root (or caps-only) helper whose bounding set keeps `NET_RAW`
/// this reads true; under unprivileged in-process dev it reads false.
///
/// Fails *closed*: if the capability can't be queried (a `capget` failure, which
/// shouldn't happen in practice) it returns false rather than silently falling
/// back to `euid == 0`. A silent fall-back would mask a misconfiguration as a
/// working bind and route test traffic through the active tun — exactly the bug
/// the bind exists to prevent.
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

/// A `pre_exec` hook that raises `CAP_NET_RAW` into the ambient set of the forked
/// child, so the exec'd test core receives it in its effective + permitted sets and
/// its uplink bind (`SO_BINDTODEVICE` / `bind_interface`) survives exec. The test
/// core binary has no file caps of its own, so an ambient raise is the only
/// mechanism that grants a capability across exec into it.
///
/// Intended to run ONLY in a test core's `pre_exec`: ambient caps are per-forked
/// child, so this keeps `CAP_NET_RAW` out of the helper's own threads and out of
/// the active core / tun2socks / `ip` (least privilege; no per-spawn race under
/// concurrent test cores). Fails closed: on a raise failure it returns `Err`, which
/// aborts the exec — a test core never silently runs without the bind and routes
/// its traffic through the active tun.
///
/// Needs `CAP_NET_RAW` in both permitted and inheritable (see
/// [`seed_test_core_inheritable`]). Under root the raise is technically inert
/// (the exec'd child already inherits all bounding caps) but is load-bearing once
/// Phase 4 makes the helper caps-only.
///
/// # Async-signal-safety
///
/// A single raw `prctl(2)` syscall — no allocation, no locks, no stdio — so this
/// satisfies the `pre_exec` contract.
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

# Logging

One facade (`crates/kasumi-log`) serves all three processes: the Android daemon, the
desktop GUI and the privileged helper. Same record line, same level rules, same
redaction — so a line means the same thing wherever it was written.

## Using it

```rust
use kasumi_log::{Area, ks_error, ks_info, ks_warn};

ks_info!(Area::Lifecycle, "data-path started on {engine:?} (mode={mode})");
ks_warn!(Area::Proc, "core exited {code}; log tail:\n{tail}");
ks_error!(Area::Platform, "could not install the routing rules: {e}");
```

The area becomes the log target (`kasumi::lifecycle`, `kasumi::proc`, …), which is
what a level directive matches. Pick the area by subsystem, not by file: everything
that touches the OS is `Platform`, everything that runs a command is `Proc`,
everything about the data path's bring-up is `Lifecycle`, the `Service` itself is
`Service`.

Areas: `Lifecycle`, `Service`, `Platform`, `State`, `Jobs`, `Net`, `Sub`, `Asset`,
`Proc`, `Ws`, `Ui`, `Helper`, `Sys`.

## Levels

| Level | Means | Examples |
| --- | --- | --- |
| `error` | An action the user asked for did not happen. | start failed, boot init failed, helper exited |
| `warn` | Something degraded or was silently recovered from. | core log truncated at spawn, rotation skipped a file |
| `info` | A decision worth writing down. | start/stop/restart, profile switch, subscription applied |
| `debug` | Per-step detail, off in the field. | which config was written, a probe's verdict |

Default: `info,kasumi=debug` — our own areas loud, dependencies quiet. `RUST_LOG`
overrides it (`RUST_LOG=info,kasumi::lifecycle=debug`), and the **App log level**
setting overrides both, applied to the running process without a restart.

Inside a loop, ask first: `if kasumi_log::ks_enabled!(Area::Net, log::Level::Debug)`.

## Coverage you get for free

Most instrumentation does not need a call site, because the interesting failures
all pass through a few funnels:

- `Service::run_lifecycle` records every start, stop, restart and auto-update —
  which profile and mode, whether it finished, and why it failed.
- `crate::fs` / `crate::fsjson` separate "no file" (silent) from "cannot read it"
  (debug) and "not valid JSON" (warn), so a corrupt state file stops looking like a
  fresh install.
- `spawn_core` records that it truncated the core's log file, which is the one thing
  that makes a core that keeps dying look silent.
- The Android shell wrappers (`silent`, `run_out`) cover the whole `ip`/`iptables`
  layer: a failed invocation is a debug record, a command that could not start is a
  warning.
- `verify_core_alive` records both verdicts — "up" and "exited within N ms".

## What never goes in

A proxy configuration is mostly secrets.

- **Subscription URLs are credentials.** The fetch failure chain is logged whole, so
  every URL in it passes through `kasumi_log::redact::in_text`, which strips
  userinfo, query and fragment. Use `redact::url` / `redact::origin` when you have
  the string in hand.
- **Profiles carry passwords and UUIDs.** Log the profile id and its remarks, not
  its fields.
- `cookie_store` is pinned to info in every process: its debug lines print the
  cookies a provider set. `kasumi_log::pin_module` is what keeps that pin alive when
  the level changes.

## Where the records go

| Process | Sink | File |
| --- | --- | --- |
| daemon | stderr (`service.sh` folds it into the file, which also catches panics) | `<datadir>/daemon.log` |
| desktop GUI | stdout + file | `<datadir>/daemon.log` |
| privileged helper | stderr + file | `<run_dir>/kasumi-helper.log` |
| module scripts | file, via `klog` in `module/log.sh` | `<datadir>/module.log` |

`<datadir>` is `~/.local/share/kasumi-proxy` on the desktop and
`/data/adb/kasumi-proxy` on Android. The cores log separately, into `xray.log`,
`singbox.log` and `tun-engine.log`, at the level the *core* setting chooses.

## Reading a log

- The in-app viewer (`Command::Log`) reads `<datadir>/<target>.log` and shows it
  newest-first. Records are one line each, which is why a multi-line message is
  escaped rather than written as-is.
- Nothing renames a log. Growth is bounded by `trim_in_place`, which keeps the
  newest half — a `daemon.log.1` would be invisible to the viewer, which only reads
  the base name. The cap is the **Log rotation limit** setting (512 KB by default);
  the daemon trims at boot and on a background tick, and `module/log.sh` trims its
  own file the same way.
- Records before the log file existed are still in memory: the facade keeps the last
  512 per process. That window covers boot, which is when the interesting failures
  happen. An empty app log falls back to that tail, with a line saying where it came
  from; clearing the log clears it too.

## The UI's own records

`frontend/src/lib/logger.ts` keeps the last 200 UI-side records in memory and the
diagnostics section shows them: dropped WS frames, a dispatch that failed, a render
throw, an unawaited promise. Nothing goes to the backend — a phone user has no
console. Use `logError` / `logWarn` / `logDebug` at the point a call would otherwise
be swallowed, and keep a failing call's context (the command name, the id) in the
fields.

## Rules

- Log through the facade. `println!`/`eprintln!`/`dbg!` are banned outside test
  modules, and `crates/kasumi-log/tests/hygiene.rs` fails the build on them. The
  only exceptions are listed in that test, with reasons.
- One reason to log: a decision, a degradation, or a failure someone will ask about.
  Not a trace of every step — the default is already chatty for our own areas.
- Never log a whole config, a whole request or a whole response body.
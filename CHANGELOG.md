## v0.3.2 — 2026-06-07

### Changes

- e4cdcc1 feat(store): add pushActivity to upsertProfile + test coverage for all activity events
- 9fa8f76 feat(i18n): add activity.profileSaved to all 8 locales
- e60e3f4 feat(store): add pushActivity to speedTestAll/removeUnreachable/removeDuplicates/downloadAsset
- aff1b28 feat(i18n): add speedTest/unreachable/duplicates/asset activity keys to all 8 locales
- 150d3bf feat(overview): replace hardcoded recent array with live activity feed + relative timestamps
- 5e6aec3 feat(store): wire ActivityService into useAppStore — recentActivity slice + pushActivity on key actions
- ae06fed feat(i18n): add activity event keys + time.now/ago to all 8 locales
- 6e383bd feat(activity): add ActivityService — capped in-memory event feed
- 15bebde fix(changelog): strip quotes from core versions, exclude ci/chore commits, require non-empty OLD for core update entries
- 5b39c7d fix(ci): strip quotes from pinned version parse in changelog

## v0.3.1 — 2026-06-07

### Fixes

- **Real ping no longer returns -1 for all profiles when run in batch.**
  Concurrent `realPingAll` workers all received the same SOCKS port from
  `freePort` (TOCTOU — the test core binds asynchronously after `*Start`
  returns). Replaced per-worker `freePort` with a single `freePorts` call
  that allocates a distinct port block per worker from one snapshot.
  `freePort` removed from `kasumi-proxyctl`; `freePorts <start> <count>
  [<span>]` is the new API.

## v0.3.0 — 2026-06-07

### Fixes

- **WebUI no longer freezes during tests.** A KernelSU `ksu.exec` call blocks the
  WebView renderer for the whole duration of the shell command, so running a test
  (core warmup + a curl of up to 15s) inside one exec hung the entire UI. RealPing,
  SpeedTest and TCPing now run as background jobs — a quick `*Start` spawns the work
  and returns, the UI polls a quick `*Status` every 250ms — so no exec blocks the
  renderer for more than ~250ms.
- TCPing/RealPing job files are keyed per request, so concurrent runs no longer race
  on a shared temp file, and the backgrounded test cores are reniced to lowest
  priority so they don't compete with the UI.

### Features

- While any test (TCPing/RealPing/SpeedTest) is in progress, all test actions are
  disabled in the ping and profile sheets — not just the matching one.
- Config-affecting settings sections are disabled while the proxy is running.

## v0.2.0 — 2026-06-07


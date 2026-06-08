## v0.3.3 — 2026-06-08

### Changes

- [`059fe75`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/059fe75) fix(share): preserve full profile name when fragment contains spaces (#17)
- [`4b07317`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4b07317) fix(service): point xray asset dir at DATADIR
- [`62865b5`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/62865b5) fix(service): avoid SC2015 in sub auto-update guard
- [`52a3c45`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/52a3c45) feat(service): subscription auto-update daemon + proxyctl sub-cache commands
- [`de4f8ac`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/de4f8ac) feat(subscriptions): consume backend auto-update cache on hydrate
- [`347457b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/347457b) feat(subscriptions): edit interval as HH:MM time picker
- [`afb5a6b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/afb5a6b) feat(schema): version state by module version, migrate sub interval to minutes (#12)
- [`6f0bbd9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6f0bbd9) fix(subscriptions): auto-derive allowInsecure, warn on plain HTTP
- [`7135713`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7135713) fix(subscriptions): drop duplicate enable toggle in edit sheet
- [`6c06f29`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6c06f29) fix(subscriptions): show date and time of last update
- [`51132b8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/51132b8) i18n: use action verb for add-profile FAB across locales
- [`91e2733`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/91e2733) fix(profiles): keep FAB clear of last row, fix ru label
- [`d31b93c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d31b93c) fix(profiles): reset ping/speed stats on clone
- [`b4acddc`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b4acddc) docs(readme): add status badges
- [`8754a91`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8754a91) fix(deps): remove unused styling deps
- [`8aba4b3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8aba4b3) fix(ui): extract shared btn-reset utility class
- [`a747a9b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a747a9b) fix(editor): drop unsafe Profile/ProfileView double casts
- [`ac36cee`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ac36cee) fix(config): reuse splitCsv in sing-box generator
- [`46b2d2b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/46b2d2b) feat(subscriptions): inline new group in edit sheet
- [`66df59f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/66df59f) feat(profiles): group management sheet
- [`fe266d6`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/fe266d6) feat(store): delete group removes its profiles
- [`0eea5c4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0eea5c4) fix(overview): hide activity card when feed is empty
- [`52d380c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/52d380c) fix(changelog): link commit hashes to GitHub in CHANGELOG.md

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


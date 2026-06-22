## v0.4.1 — 2026-06-22

### Changes

- [`faf9069`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/faf9069) fix(profiles): stop group icons resizing on drag-drop
- [`5329240`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5329240) fix(desktop): fully collapse the side rail when hidden
- [`aa9cd08`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/aa9cd08) fix(profiles): keep delete dialogs mounted so they animate out
- [`32ba106`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/32ba106) fix(ui): animate dialog exit instead of unmounting instantly
- [`97a6ac0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/97a6ac0) fix(ui): animate bottom sheet on close instead of popping out
- [`038bb5b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/038bb5b) fix(ui): track sheet swipe on window so mouse drag works on desktop
- [`f164a28`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f164a28) feat(ui): swipe down to dismiss bottom sheets
- [`64727a9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/64727a9) fix(desktop): hide side rail while a bottom sheet is open
- [`b81be5c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b81be5c) fix(ci): detect changed areas from merge-base, not base..head
- [`503ba49`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/503ba49) fix(i18n): pluralize count-bearing strings via plural() helper
- [`4ff51a4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4ff51a4) feat(profiles): reorder groups via drag-and-drop
- [`6b15472`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6b15472) feat(subscriptions): per-subscription copy URL
- [`0af325c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0af325c) feat(subscriptions): import subscriptions from clipboard
- [`62dc8c3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/62dc8c3) feat(subscriptions): export subscriptions to clipboard
- [`a5e5c86`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a5e5c86) fix(ci): don't sign updater artifacts in nightly
- [`b207492`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b207492) test(core): init socks-auth test settings via struct update
- [`f0f08bb`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f0f08bb) feat(settings): wire up three dropped UI strings
- [`0f562b9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0f562b9) feat(settings): SOCKS/HTTP inbound authentication
- [`1fa5c28`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/1fa5c28) docs: refresh the PR template for the Rust/Tauri stack
- [`883ed7b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/883ed7b) feat(frontend): app version + auto-update controls in Settings
- [`84ac7e0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/84ac7e0) feat(desktop): wire the updater plugin + bundle signing config
- [`b997d03`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b997d03) docs: document the Linux portable zip
- [`9ca0b63`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9ca0b63) feat(desktop): honour a portable.dat marker on Linux
- [`0cb3c93`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0cb3c93) docs: Windows desktop install instructions
- [`9f8fa71`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9f8fa71) fix(frontend): use the standard card surface for quick actions
- [`81c983d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/81c983d) fix(frontend): lower the snackbar on desktop
- [`20ead8d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/20ead8d) fix(desktop): native backslash paths on Windows
- [`f9eece6`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f9eece6) fix(desktop): keep the inherited env on Windows so cores can use Winsock
- [`91a8e2b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/91a8e2b) fix(desktop): bundle the app, not the codegen bin (default-run)
- [`fc6b4ef`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/fc6b4ef) fix(desktop): suppress console windows when spawning on Windows
- [`489ed79`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/489ed79) docs: add Windows to the platform badge
- [`40174a8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/40174a8) fix(desktop): only the xray path needs wintun.dll on disk
- [`af03cbe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/af03cbe) build(desktop): bundle wintun.dll for the Windows target
- [`7bb5c72`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7bb5c72) feat(desktop): Windows Platform (wintun tun + route/netsh routing)
- [`a6ec99a`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a6ec99a) feat(backend): make tun2socks fwmark optional
- [`67c098e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/67c098e) feat(backend): portable process identity (POSIX + Windows)
- [`e4db159`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/e4db159) fix(core): drop uTLS from hysteria2/tuic sing-box outbounds
- [`104819b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/104819b) docs: publish the AppImage release signing public key

## v0.4.0 — 2026-06-20

### Cross-platform: Rust backend + Tauri desktop

Base migration off the original Bash backend (with its React WebUI) to a Rust
workspace (`kasumi-core` / `kasumi-backend` / `kasumi-daemon`), with two thin
shells over one shared `Service`:

- **Android** — the same KSU/Magisk/APatch module, now a Rust `kasumi-proxy`
  daemon (axum HTTP webroot + token-gated typed WS).
- **Linux desktop (new)** — a Tauri 2 app owning the data path with a real TUN:
  system tray + minimize-to-tray, autostart, single-instance, and window-state.

Highlights:

- Nested `Profile` model; the frontend runs on TypeScript bindings + Zod schemas
  + runtime defaults **generated from the Rust types** — one source of truth, no
  hand-duplicated values.
- Versioned on-disk migrations (flat → nested) — existing installs keep their
  profiles (verified on a 324-profile device dump).
- Truthful **5-state status** (`stopped / connecting / connected / noInternet /
  failed`) via an end-to-end probe; per-profile diagnostics stream as they finish.
- Desktop installers (deb / appimage / nsis / msi) bundle the cores;
  `nix build .#kasumi-desktop` is self-contained.

---

## v0.3.4 — 2026-06-10

### Changes

- [`042437c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/042437c) fix(store): restart active profile only when its config changes
- [`948f58f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/948f58f) feat(settings): add toggle to allow non-localhost proxy access (#43)
- [`7eaf0fe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7eaf0fe) fix(store): use daemon fetch timestamp for subscription lastUpdated (#42)
- [`65c19fe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/65c19fe) fix: preserve profiles manually moved from subscription group on update (#41)
- [`277b192`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/277b192) fix(overview): show the engine that is actually running
- [`20b5bf2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/20b5bf2) fix(module): report the running core's engine in status
- [`33dcac1`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/33dcac1) fix(editor): pin the engine selector to the forced core
- [`8facd2f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8facd2f) fix(singbox): emit sniff + hijack-dns route rules
- [`99d2964`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/99d2964) fix(core): run xray-style custom gRPC paths on xray only
- [`a366c25`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a366c25) feat(subscriptions): consume auto-update cache while the UI stays open
- [`6f7edc3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6f7edc3) fix(service): open sub-wake pipe read-write to unblock auto-update daemon
- [`cc51296`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/cc51296) fix(service): rename reserved awk variable breaking subscription listing
- [`6d208cc`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6d208cc) feat(settings): add dedup on sub update toggle (#36)
- [`9b3be55`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9b3be55) fix(profiles): scope ping, selectBest, removeUnreachable, and removeDuplicates to current group (#35)
- [`ef3f65e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ef3f65e) fix(profiles): sort offline profiles (ping=-1) to bottom when sorting by ping (#34)
- [`4e4cd86`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4e4cd86) fix(storage): persist large state via native file I/O, split profiles.json (#33)
- [`0ad455d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0ad455d) fix(schema): tolerate invalid profiles/settings and report skipped on import (#32)
- [`e24283d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/e24283d) fix(hydrate): show UI before slow asset/status I/O (#31)
- [`8f124ae`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8f124ae) fix(schema): drop grpc from TRANSPORT_NEEDS_PATH (#30)
- [`c58e18e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c58e18e) fix(schema): accept non-RFC-variant UUIDs via explicit hex regex (#29)
- [`fb855ef`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/fb855ef) fix(i18n): drop profiles count from backup summary
- [`f306939`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f306939) fix(backup): validate imported backup against schema in mock bridge
- [`5e10e32`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5e10e32) fix(backup): preserve current profiles when importing backup in replace mode
- [`d733789`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d733789) feat(backup): remove profile export from backup JSON
- [`c4b56bd`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c4b56bd) fix(schema): make profiles optional in AppStateSchema for backup compatibility
- [`72341dc`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/72341dc) feat(subscriptions): per-subscription download mode (auto/proxy/direct)
- [`4f34c5b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4f34c5b) fix(assets): restore download_asset_impl lost in helper refactor (#26)
- [`0a5b4a0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0a5b4a0) fix(assets): restore download_asset_impl lost in helper refactor
- [`4d5e143`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4d5e143) fix(profiles): stream batch ping/speed results progressively (#25)
- [`f75e862`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f75e862) feat(ui): add spinner for in-progress tests and red '—' for failures in profile rows (#24)
- [`75f31a3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/75f31a3) fix(install): ship bin/utils.sh in the module package (#22)
- [`a114c60`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a114c60) fix(schema): accept non-RFC-variant UUIDs for vless/vmess (#20)
- [`6546e9e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6546e9e) feat(subscriptions): wake sub-update daemon on upsertSub
- [`9af73fe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9af73fe) feat(service): replace 1-min polling with event-driven sub-update scheduling

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


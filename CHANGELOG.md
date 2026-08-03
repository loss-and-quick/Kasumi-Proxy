## v0.4.4 — 2026-08-03

### Core updates

- sing-box: `v1.13.14` → `v1.13.15`

### Changes

- [`49dc58f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/49dc58f) fix(desktop): propagate boot_init dir-creation errors
- [`0beef3c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0beef3c) fix(desktop): stop mutating the process-global umask in privhelper serve
- [`8b73874`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8b73874) fix(desktop): let settings stay editable while the proxy is running
- [`4789239`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4789239) feat(core): DataPathState document + read/write helpers
- [`a12e8ea`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a12e8ea) test(desktop): drop env mutation from path-dependent tests
- [`9fdcba8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9fdcba8) feat(frontend): pending-restart banner on the overview
- [`f2b20a0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f2b20a0) feat(backend): flag a running data path stale after settings mutations
- [`37f0aa3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/37f0aa3) feat(core): pendingRestart status flag + mutation-effect decision
- [`a878c4c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a878c4c) feat(desktop): skip the privileged helper in non-tun proxy modes
- [`04643a7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/04643a7) fix(desktop): hand helper-created runtime files to the GUI owner
- [`5617db8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5617db8) feat(desktop): make the PAC port a local-ports setting
- [`2463bb2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2463bb2) feat(desktop): snapshot and restore the OS proxy around system/pac
- [`157ee72`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/157ee72) feat(desktop): serve a PAC in pac mode
- [`af5f1e2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/af5f1e2) feat(desktop): set the OS proxy in system mode
- [`49196c3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/49196c3) feat(desktop): run a proxy-only data path + mode selector
- [`7839739`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7839739) feat(core): add proxyMode setting (tun/proxy-only/system/pac)
- [`64286d3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/64286d3) fix(desktop): tunnel root traffic on Linux; escape the core by fwmark
- [`91ea0b2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/91ea0b2) fix(core): make tun uid-0 exclusion a platform decision, not builder policy
- [`0063db2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0063db2) fix(tun): drive tun2socks through its YAML config

## v0.4.3 — 2026-07-13

### Core updates

- tun2socks: `v2.6.0` → `v2.7.0`

### Changes

- [`a735813`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a735813) Revert "feat(nix): Force use zsh in devshell"
- [`d68ee13`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d68ee13) build(nix): single-source rustfmt's edition from Cargo.toml
- [`cd8824e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/cd8824e) build(nix): single-source the Rust toolchain via rust-toolchain.toml
- [`d215fc4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d215fc4) fix(nix): exclude generated bun.nix from treefmt
- [`8d8d3cf`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8d8d3cf) feat(nix): Force use zsh in devshell
- [`4c96f90`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4c96f90) test(core): guard TS<->Rust core-resolution parity with generated fixtures
- [`5e0c423`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5e0c423) fix(profiles): route plain/(x)chacha20-poly1305 shadowsocks to the xray tag
- [`38c4050`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/38c4050) feat(tun): sing-box as an external TUN engine for xray (sidecar bridge)
- [`11767e3`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/11767e3) feat(settings): hev TUN engine option + tuning controls
- [`45dd592`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/45dd592) build(binaries): fetch hev-socks5-tunnel for desktop and android
- [`b988269`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b988269) feat(backend,desktop,daemon): launch the hev TUN engine
- [`518c9a7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/518c9a7) feat(core): hev-socks5-tunnel config builder + external-tun tuning
- [`db8c066`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/db8c066) fix(desktop): wrap raw-pointer deref in unsafe block (edition 2024)
- [`b51760a`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b51760a) feat(settings): TUN engine settings section
- [`7ee2f5d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7ee2f5d) feat(core,desktop,daemon): wire TUN engine into the data path
- [`cdf3078`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/cdf3078) fix(android): surface tun2socks spawn failure instead of swallowing it
- [`2401db9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2401db9) feat(core): per-core TUN engine selection (abstraction)
- [`c8c43f2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c8c43f2) fix(android): defer local-port guard until core is up

## v0.4.2 — 2026-06-29

### Core updates

- sing-box: `v1.13.13` → `v1.13.14`

### Changes

- [`7bd10f7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7bd10f7) fix(desktop): include xray dns.servers in the bypass CIDR set
- [`4c04ed5`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4c04ed5) fix(desktop): lift data-path caps into the helper's ambient set; one spawn path
- [`5aa72f1`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5aa72f1) test(core): expand validation matrix with per-field builder branches
- [`c5faf9b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c5faf9b) fix(desktop): grant the active core CAP_NET_ADMIN under the caps-only helper
- [`7907be5`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7907be5) feat(desktop): build rpm bundle
- [`1bf3b2e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/1bf3b2e) fix(singbox): PEM-wrap ECH config
- [`da607f7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/da607f7) fix(profiles): delete unreachable by id, keep test status
- [`244f276`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/244f276) fix(ui): close select on overlay click, not pointerdown
- [`3cfa31d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3cfa31d) feat(profiles): open the test-core log behind a failed result
- [`2d0542e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2d0542e) feat(backend): retain failed test-core logs per profile
- [`4f1c4eb`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4f1c4eb) fix(desktop): keep the windows resume watcher future Send
- [`da61579`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/da61579) fix(desktop): correct windows-sys power handle out-param type
- [`c6baa53`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c6baa53) feat(desktop): signal system resume to the service
- [`437a9a8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/437a9a8) feat(backend): restart the data-path on system resume
- [`8b28674`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/8b28674) fix(backend): wait for the core to be reaped after SIGKILL
- [`eb0946d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/eb0946d) fix(desktop): sweep orphaned sing-box auto_route rules on stop/start
- [`60e747c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/60e747c) fix(subs): replace native time picker with an in-house clock-dial
- [`eeef7f9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/eeef7f9) fix(frontend): stop batch ping/speed test from no-oping on a stale bridge cache
- [`4664f22`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4664f22) feat(logs): always reverse log order — newest lines on top
- [`479ab01`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/479ab01) fix(core): expand dedup key to full serialized profile minus bookkeeping
- [`5dd2f6f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5dd2f6f) fix(frontend): use Iconify-format SVGs for lan/wifi_off/stars icons
- [`3844188`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3844188) feat(core): intent-based AppState mutation + active-id fixup
- [`d092287`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d092287) fix(frontend): keep FAB scroll clearance in the desktop layout
- [`908a6fe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/908a6fe) fix(frontend): drop the obsolete list-row icon translateZ(0) hack
- [`5c6e442`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5c6e442) fix(frontend): inline icon SVGs so webkit2gtk stops rendering squares
- [`23efdec`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/23efdec) fix(desktop): pin the uplink source address so the tun-escape bind survives multi-homing
- [`2f689c2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2f689c2) fix(core): set ws Host to the server domain when the profile leaves it empty
- [`3bd4294`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3bd4294) fix(desktop): reap the data-path core when the helper dies
- [`fb1c4cc`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/fb1c4cc) feat(core): accept DNS URL schemes (DoH/DoT/DoQ) in sing-box config
- [`51d2d06`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/51d2d06) fix(nix): set tauri app version from appVersion
- [`b14d3e0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b14d3e0) fix(nix): run install hooks so the .desktop entry is copied
- [`3b624da`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3b624da) fix(ui): blur number inputs on wheel scroll
- [`22acc54`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/22acc54) fix(core): keep force-in off a custom http_port
- [`233a47c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/233a47c) feat(backend): route proxied fetches through force-in, not socks-in
- [`f753647`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f753647) feat(core): always-on force-in inbound that bypasses geo routing
- [`50c90a9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/50c90a9) fix(desktop): honor KASUMI_HELPER_BIN over the NixOS wrapper
- [`a0afc81`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a0afc81) fix(desktop): bind core egress outbounds to uplink to break geo-direct TUN loop
- [`05e3815`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/05e3815) test(core): add a settings/routing matrix to core_validation
- [`9c04b7a`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9c04b7a) test(core): drop byte-exact golden config fixtures
- [`3fb4c22`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3fb4c22) fix(desktop): write app log to datadir/daemon.log for the in-app viewer
- [`5d0d913`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5d0d913) fix(backend): surface subscription fetch cause, drop redundant URL
- [`d6e7270`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d6e7270) build(nix): source cores from the catalog, drop the geodat2srs clone app
- [`67fca8d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/67fca8d) build(cores): unify the fetch scripts behind a shared cores.json catalog
- [`754d9e6`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/754d9e6) fix(desktop): build and bundle geodat2srs for rule_set .srs generation
- [`1c8e77c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/1c8e77c) feat(nix): grant the helper caps by default, drop the opt-in + polkit path
- [`2472d44`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2472d44) fix(backend): gate the pre_exec spawn imports to cfg(unix)
- [`b53cc1b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/b53cc1b) style(desktop): rustfmt the stack, clarify the run_dir comment
- [`ff73fb2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ff73fb2) feat(nix): add a security.wrappers caps option for the helper
- [`2a40404`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2a40404) feat(desktop): setcap the helper from the deb postinstall
- [`ab45d2c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ab45d2c) feat(desktop): grant helper caps via a one-time pkexec setcap
- [`99a84b9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/99a84b9) feat(desktop): grant test cores an ambient CAP_NET_RAW across exec
- [`48cf9d9`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/48cf9d9) feat(desktop): seed inheritable CAP_NET_RAW + switch the bind gate to a real cap check
- [`f61ccb5`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f61ccb5) feat(backend): add a pre_exec spawn seam for the forked child
- [`6a8c9b8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6a8c9b8) feat(desktop): drop the helper's bounding set to least-privilege caps
- [`e51085c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/e51085c) build(desktop): add the caps crate for Linux least-privilege
- [`4f77603`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4f77603) fix(desktop): bind test cores to the uplink instead of per-test routes
- [`bd9c271`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/bd9c271) fix(nix): inject product version into Tauri config
- [`2ca61d7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2ca61d7) feat(frontend): sync service state to tray, route start/stop actions
- [`95d547d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/95d547d) feat(desktop): conditional tray menu — Start/Stop/Restart by proxy state
- [`da17020`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/da17020) feat(desktop): native file picker for backup & routing import/export
- [`ab4adf5`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ab4adf5) feat(desktop): tray quick-switch and restart
- [`00a8775`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/00a8775) feat(desktop): use the native clipboard with a web fallback
- [`57974e8`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/57974e8) fix(frontend): animate the side rail when an overlay opens
- [`c9fe024`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c9fe024) fix(desktop): report runtime version in app_version
- [`4a81d70`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4a81d70) fix(desktop): defer the data-path bring-up off the setup thread
- [`9455b47`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9455b47) feat(desktop): file logging for the GUI and the privileged helper
- [`da0dca0`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/da0dca0) fix(desktop): drop the duplicate tray icon from the config
- [`2a50851`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/2a50851) feat(module): add action/webui icons
- [`f8f3dec`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f8f3dec) feat(module): clean uninstall via `kasumi-proxy stop`
- [`680ed14`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/680ed14) test(desktop): cover quote_arg backslash/quote escaping
- [`e484dba`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/e484dba) fix(desktop): quote elevated helper args per CommandLineToArgvW
- [`ce9ea38`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ce9ea38) feat(desktop): portable Windows runs the helper transiently, not as a service
- [`83dc5d2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/83dc5d2) build(windows): register the data-path service from the NSIS installer
- [`57ef65b`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/57ef65b) feat(desktop): Windows data-path runs in a LocalSystem service
- [`f4d728e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f4d728e) fix(desktop): harden helper socket perms, drop dead unlink
- [`fd3d366`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/fd3d366) feat(nix): opt-in passwordless elevation scoped to the helper
- [`c3217f4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c3217f4) build: ship kasumi-helper in every package channel
- [`1651d38`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/1651d38) feat(desktop): GUI runs unprivileged, spawns the root helper (Linux)
- [`d332a4c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d332a4c) feat(desktop): privilege helper binary, elevated spawn + socket perms
- [`bb54bbd`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/bb54bbd) feat(desktop): RemotePlatform — GUI-side Platform over the helper
- [`3d0df60`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/3d0df60) feat(desktop): privsep server dispatcher + client transport
- [`cd0a3a6`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/cd0a3a6) feat(desktop): privilege-separation wire protocol
- [`d613233`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/d613233) feat(nix): add a programs.kasumi-proxy NixOS module
- [`4ddd1de`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4ddd1de) fix(desktop): forward iproute2 to the elevated Linux data-path on NixOS
- [`6749982`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6749982) fix(nix): give the @2x icon a legal store-path name
- [`6f30d0c`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/6f30d0c) feat(nix): make kasumi-desktop a proper installable package
- [`20c745e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/20c745e) feat(flake): declare the Cachix cache as a substituter in nixConfig
- [`c9f6a9e`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c9f6a9e) docs(readme): document the Cachix binary cache for local builds
- [`9ec1d0d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9ec1d0d) test(core): validate generated configs against real xray/sing-box
- [`bfb006f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/bfb006f) test(backend): cover pid_matches_any candidate scan
- [`0ec3efe`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0ec3efe) test(core): cover migrate intermediate-shape retag and version clamp
- [`0859d9a`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0859d9a) test(desktop): cover bypass-CIDR aggregation over literal servers
- [`c83bad4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c83bad4) test(backend): cover proxy-required fetch, port leasing, tun2 cleanup
- [`7a9f35f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/7a9f35f) test(core): cover config_shared, forced-core branches, sub-apply helpers
- [`f8508da`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f8508da) build(cores): ship libcronet next to sing-box for the naive outbound
- [`27501ca`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/27501ca) fix(singbox): drop uTLS from the naive outbound
- [`c88f201`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/c88f201) fix(core): route xray-only shadowsocks ciphers to xray
- [`4dd2fd1`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4dd2fd1) feat(profiles): explain why a group can't be deleted
- [`f77a855`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/f77a855) feat(settings): drop redundant current-core row from diagnostics
- [`ccbe82f`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/ccbe82f) feat(settings): surface installed core versions and TUN in diagnostics
- [`281d759`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/281d759) fix(ui): keep inline Escape edits from closing their sheet
- [`5c80afc`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/5c80afc) feat(ui): dismiss sheets and dialogs on Escape
- [`adab839`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/adab839) feat(subscriptions): unify add entry points and enrich bulk import
- [`a81e74d`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a81e74d) feat(frontend): cross-platform Material select dropdown
- [`0044ee2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/0044ee2) docs(readme): match portable zip names to the unified scheme
- [`99949cd`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/99949cd) feat(ui): animate search field expand and FAB entrance
- [`4834ea7`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/4834ea7) feat(ui): pop ping/speed results in when a test finishes
- [`a7415f2`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/a7415f2) fix(ui): keep the select-box arrow visible on focus
- [`9973558`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/9973558) feat(ui): show toasts as a dismissible queue
- [`31102c4`](https://github.com/loss-and-quick/Kasumi-Proxy/commit/31102c4) fix(ui): animate the toast on dismiss instead of vanishing

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


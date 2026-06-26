# AGENTS.md — Kasumi Proxy (repo root)

## What this is

Kasumi Proxy is a system-wide transparent proxy that runs Xray-core / sing-box + tun2socks: a
**Magisk / KernelSU / APatch module** on rooted Android (native `iptables` / `ip rule` routing, no
`VpnService`) and a **Tauri 2 app** on Linux desktop. Both shells drive one shared Rust backend; a
React Web UI manages it. Fork of `vincentng295/Magic_V2Ray`; most code is AI-written — review
before trusting.

## Layout (one workspace, two shells over a shared backend)

- `crates/kasumi-core/` — neutral, IO-free domain: profile/state types (serde + `specta::Type`),
  share parse/build, xray/sing-box config builders, sub-apply, on-disk migrations.
- `crates/kasumi-backend/` — neutral orchestration: the `Platform` trait, typed `Command`/`Response`
  + dispatch, lifecycle/jobs/sub-update, the `Service`. Depends on core. No IO of its own.
- `crates/kasumi-daemon/` — Android-only bin: axum (HTTP webroot + token-gated WS → the Service) +
  the Android `Platform`.
- `src-tauri/` — Tauri 2 desktop app: the same `Service` in managed state, the Linux `Platform`,
  and the codegen that emits the frontend's bindings/schemas/defaults.
- `frontend/` — React + TypeScript UI (built into `module/webroot/` for Android).
- `module/` — the installable Android zip root (Magisk dictates `module.prop`, `customize.sh`,
  `service.sh`, `action.sh`, `uninstall.sh`, `META-INF/` at the archive root); `package-release.sh`
  zips from inside it.
- `scripts/` — `fetch-binaries.sh android|desktop` (cores + extras, asset layout in `binaries.json`, pins in
  `binary-versions.sh`), `build-daemon-android.sh` (cross-builds the Rust daemon),
  `build-webroot.sh` (UI → `module/webroot/`), `package-release.sh` (assemble zip).

## Hard rules

- **One source of truth = Rust.** The frontend's `frontend/src/generated/{bindings,schemas,
  defaults}.ts` are generated from the Rust types — never hand-copy a Rust default/const/enum into
  the frontend; change the Rust source and regenerate. A drift test guards this.
- **No build artifacts in git.** Core/daemon binaries (`module/bin/<abi>/`, geoip/geosite), the
  built `module/webroot/`, and `src-tauri/gen/` are gitignored on purpose. Only
  `module/bin/{README.md,licenses/}` are tracked.
- **Comment style.** Rust documents the domain *why*, never "ported from / equals the TypeScript".
  Tests diff against committed reference fixtures — don't narrate that as "golden"/"oracle".
- **Renaming the project** touches the id everywhere: data path `/data/adb/kasumi-proxy`, the
  iptables chain, the `kasumi-proxy` binary name, `module.prop`, and string literals. Grep all case
  forms (`kasumi-proxy`, `Kasumi Proxy`, camelCase) before claiming done.

## Verify before declaring done

```sh
# Rust (the supported path is the nix dev shell; no system cargo needed)
nix develop --command cargo test --workspace
nix develop --command cargo clippy --workspace --all-targets -- -D warnings

# Frontend
cd frontend && bun install && bun run build && bunx vitest run
bunx tsc -p frontend/tsconfig.json --noEmit && bunx biome check
bun run frontend/scripts/check-i18n.ts

# Codegen drift (a Rust type/default change must regenerate the frontend files)
nix develop --command cargo run -p kasumi-desktop --bin codegen   # then check git is clean

# Module shell (Android mksh dialect)
shellcheck -s sh module/*.sh
```

CI (`.github/workflows/ci.yml`) runs the Rust gate (fmt + clippy `-D warnings` + test +
codegen-drift) and the frontend gate on every push — keep both green. The checks need bun,
shellcheck, zip, jq and curl on PATH; `nix develop` provides them, and the `nix run .#<script>`
wrappers run the build scripts.

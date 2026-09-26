# Contributing

## Repository layout

One Rust workspace and a React UI. Two thin shells sit on top of a shared backend.

```
crates/
  kasumi-core/      domain types and logic with no IO: profiles, share links, xray/sing-box config builders, migrations
  kasumi-backend/   orchestration: the Platform trait, typed Command/Response, lifecycle, jobs, the Service
  kasumi-daemon/    Android binary: axum HTTP (webroot) + token-gated WebSocket → Service
src-tauri/          Tauri 2 desktop app (Linux/Windows Platform) + codegen for the frontend
frontend/           React + TypeScript UI (Vite, Zustand, Biome)
module/             root of the Android module zip (module.prop, *.sh, META-INF/)
scripts/            fetching cores, building the daemon/webroot, packaging the release
nix/, flake.nix     optional Nix build, see docs/nix.md
```

Everything OS-specific lives behind the `Platform` trait. The frontend types, Zod schemas and
defaults in `frontend/src/generated/` are **generated from Rust**. Don't edit them by hand.

## Requirements

| Tool | What it's for |
| --- | --- |
| [rustup](https://rustup.rs) | Rust. The version is pinned in `rust-toolchain.toml` and installs on first use. |
| [bun](https://bun.sh) | The UI and the Tauri CLI dependencies. |
| Tauri system libraries | Linux: `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev`. Windows: WebView2 (usually preinstalled). |
| `shellcheck` | Linting `module/*.sh`. |
| For the Android build | Android NDK (`NDK_ROOT`), `cargo-ndk`, rustup targets `aarch64-linux-android` and `x86_64-linux-android`, Go, `curl`, `jq`, `unzip`, `zip`. |

With Nix, `nix develop` provides all of this, and you can prefix the commands below with
`nix develop --command`.

## First build

The Tauri crate embeds `frontend/dist` and checks that the bundle resources exist, so build the
UI and create the stubs once before you run `cargo`:

```sh
bun install
(cd frontend && bun run build)

# Linux: a placeholder for the libcronet resource
mkdir -p src-tauri/binaries && touch src-tauri/binaries/libcronet.so
# Windows: the same, for wintun.dll, libcronet.dll and msys-2.0.dll
```

To get the real cores and resources instead of stubs, run `scripts/fetch-binaries.sh desktop`.

## Everyday commands

```sh
# UI with a mock backend, no device needed
cd frontend && bun run dev

# Desktop app
cargo run -p kasumi-desktop

# Android module (fetches cores, cross-builds the daemon, builds the UI, zips)
scripts/package-release.sh build/kasumi-proxy.zip
```

## Checks before a PR

CI runs the same checks, and they must stay green.

```sh
# Rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Codegen: after changing Rust types, regenerate and commit the result
cargo run -p kasumi-desktop --bin codegen
git diff --exit-code -- frontend/src/generated

# Frontend
cd frontend
bun run build && bun run test
bun run check && bun run check:i18n

# Module scripts (Android mksh)
shellcheck -s sh module/*.sh
```

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/) with a scope, e.g.
  `fix(backend): …` or `feat(frontend): …`. `CHANGELOG.md` is generated from them by
  `scripts/gen-changelog.sh`.
- Fill in the PR description using [the template](.github/PULL_REQUEST_TEMPLATE.md).
- Don't commit build artifacts: `module/bin/<abi>/`, `module/webroot/`, `src-tauri/binaries/`,
  `src-tauri/gen/`.

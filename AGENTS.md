# AGENTS.md

Kasumi Proxy is a transparent proxy built on Xray-core / sing-box. It ships as an **Android root
module** (Magisk / KernelSU / APatch, routing via `iptables` / `ip rule`) and as a **Tauri 2
desktop app** (Linux, Windows). Both shells run one Rust backend. Most of the code was written by
AI, so verify it rather than trusting it.

The repository layout, build instructions and requirements are in
[CONTRIBUTING.md](CONTRIBUTING.md). Subdirectories have their own rules in
[frontend/AGENTS.md](frontend/AGENTS.md) and [module/AGENTS.md](module/AGENTS.md).

## Rules

- **Rust is the source of truth.** `frontend/src/generated/{bindings,schemas,defaults}.ts` are
  generated from Rust types. To change a type, default or enum, edit Rust and run codegen. Never
  copy values into TS by hand. A drift check in CI guards this.
- **OS-specific code lives behind the `Platform` trait**: Android in `kasumi-daemon`, desktop in
  `src-tauri`. `kasumi-core` does no IO, and `kasumi-backend` does IO only through `Platform`.
- **No build artifacts in git**: `module/bin/<abi>/`, `module/webroot/`, `src-tauri/binaries/`
  and `src-tauri/gen/`. Of `module/bin/` only `README.md` and `licenses/` are tracked.
- **Comments** explain the domain *why*. Don't write "ported from TypeScript" or call test
  fixtures "golden" or "oracle".
- **Renaming the project** touches the data path `/data/adb/kasumi-proxy`, the iptables chain,
  the `kasumi-proxy` binary, `module.prop` and string literals. Grep every case form.

## Checks before finishing

Run them with plain `cargo` / `bun`, or inside `nix develop --command …` if you have Nix. The
Tauri crate needs a built `frontend/dist` and stubs in `src-tauri/binaries/` (see CONTRIBUTING).

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p kasumi-desktop --bin codegen && git diff --exit-code -- frontend/src/generated

cd frontend && bun run build && bun run test && bun run check && bun run check:i18n

shellcheck -s sh module/*.sh
```

CI (`.github/workflows/ci.yml`) runs the same Rust and frontend checks on every push.

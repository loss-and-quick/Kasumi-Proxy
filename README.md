<p align="center">
  <img src=".github/logo.png" width="160" alt="Kasumi Proxy" />
</p>

<h1 align="center">Kasumi Proxy</h1>

<p align="center">
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/actions/workflows/ci.yml"><img src="https://github.com/loss-and-quick/Kasumi-Proxy/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/releases/latest"><img src="https://img.shields.io/github/v/release/loss-and-quick/Kasumi-Proxy?sort=semver" alt="Latest release" /></a>
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/issues"><img src="https://img.shields.io/github/issues/loss-and-quick/Kasumi-Proxy" alt="Open issues" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/loss-and-quick/Kasumi-Proxy" alt="License: GPL v3" /></a>
  <img src="https://img.shields.io/badge/platform-Android%20(root)%20%C2%B7%20Linux%20%C2%B7%20Windows-blue" alt="Platform: Android (root) / Linux / Windows" />
</p>

> A system-level transparent proxy for **rooted Android** and **Linux desktop** — routes all
> traffic through Xray-core / sing-box at the kernel level, with a clean React UI.

On Android, Kasumi Proxy is a **Magisk / KernelSU / APatch module** (not a standalone app): it
runs the proxy core as a system daemon and steers traffic with native Linux routing
(`iptables` / `ip rule`) instead of Android's user-space `VpnService`. On desktop it is a
**Tauri 2 app** that owns the same data path with a real TUN. Both shells drive one shared Rust
backend, so the domain logic — profiles, share links, config builders, subscriptions — lives in
exactly one place.

> 🍴 **Fork** of [vincentng295/Magic_V2Ray](https://github.com/vincentng295/Magic_V2Ray).
>
> 🤖 **AI SLOP WARNING.** Most of this codebase was written by AI — review before trusting.

---

## Why a root module instead of a VPN app?

If you come from v2rayNG, NekoBox, or Matsuri, here is what changes on Android:

- **Survives Low-Memory-Killer.** User-space apps get killed under memory pressure, dropping the
  tunnel and leaking your real IP. Kasumi Proxy runs as a root daemon the OS won't reap.
- **Kernel-level routing.** No virtual `tun0` software bottleneck for app traffic — packets are
  intercepted at the Netfilter layer and handed straight to the core, cutting latency and the
  CPU overhead of Java↔kernel context switching.
- **Seamless network switches.** Wi-Fi ↔ 4G/5G transitions hot-reload the routing rules in-kernel.
- **Universal root support.** Magisk, KernelSU, and APatch out of the box.

> ⚠️ **No root?** The Android side is a system module, not an app. For a regular GUI client, see
> the [Xray-core GUI clients](https://github.com/XTLS/Xray-core#gui-clients).

---

## Features

- **Dual core** — Xray-core for VLESS / VMess / Trojan / Shadowsocks / SOCKS / HTTP / WireGuard,
  sing-box for Hysteria2 / TUIC. The engine is resolved per profile.
- **Smart import** — paste subscription URLs, raw config strings, or mixed text; scan QR.
- **Category organizing** — group servers into folders, one-tap update a whole category.
- **Truthful status** — the main screen distinguishes *connecting / connected / no-internet /
  failed* via an end-to-end probe, not just "the process started".
- **Per-profile diagnostics** — tcp-ping, real-ping and a speed test, streamed as they finish.
- **Headless subscription auto-update** — applies in the background with no UI open.

---

## Install

**Android (root):**

1. Download the latest `kasumi-proxy-module-vX.Y.Z.zip` release.
2. Flash it in Magisk / KernelSU / APatch and reboot.
3. Open the module's **Action** (Magisk) or its WebUI entry — it launches the control center in
   your browser, authenticated with a per-install token.

State and logs live under `/data/adb/kasumi-proxy/`.

**Linux desktop:** install the `.deb` or run the `.AppImage` from the latest release, or build with
`nix build .#kasumi-desktop` (see below). For a no-install copy that keeps all state next to the
binary, download `kasumi-proxy-linux-portable-vX.Y.Z.zip`, unzip it, and run `./kasumi-desktop` — it
re-execs itself through `pkexec`/`sudo` for the tun adapter and routes.

**Windows desktop:** run the `-setup.exe` (NSIS) installer or the `.msi` from the latest release.
For a no-install copy — runs from anywhere, keeps all state next to the executable — download
`kasumi-proxy-windows-portable-vX.Y.Z.zip`, unzip it, and launch `kasumi-desktop.exe`. The app needs
administrator rights to bring up the tun adapter and routes, so accept the UAC prompt.

### Verifying release signatures

Release `.AppImage` bundles are GPG-signed with the project's release key
([`release-signing-key.asc`](release-signing-key.asc), fingerprint
`2AA0 03A9 D670 653C FAA8  F7B0 88BE 4761 6D49 65E9`):

```sh
gpg --import release-signing-key.asc
# AppImage signatures are embedded; extract and verify against the imported key:
./Kasumi*.AppImage --appimage-extract '.appimage_signature'
gpg --verify squashfs-root/.appimage_signature Kasumi*.AppImage
```

---

## Build from source

The repo is one Rust workspace + the React UI, with two thin shells over a shared backend:

```
.
├── crates/
│   ├── kasumi-core/     # neutral domain: profiles, share links, xray/sing-box config
│   │                    #   builders, sub-apply, on-disk migrations (serde + specta::Type)
│   ├── kasumi-backend/  # neutral orchestration: Platform trait, typed Command/Response +
│   │                    #   dispatch, lifecycle/jobs/sub-update, the Service
│   └── kasumi-daemon/   # Android-only bin: axum HTTP webroot + token-gated WS → the Service
├── src-tauri/           # Tauri 2 desktop app: the same Service in managed state + Linux Platform
├── frontend/            # React + TypeScript UI (Vite, Zustand, Biome); runs on generated bindings
├── module/              # contents that become the installable Android zip root
│   ├── module.prop customize.sh service.sh action.sh uninstall.sh META-INF/
│   ├── bin/             # kasumi-proxy daemon + xray/sing-box/tun2socks (built/fetched, gitignored)
│   └── webroot/         # built UI (generated, gitignored)
├── scripts/             # fetch-cores-{android,desktop}, build-daemon-android, build-webroot, package-release
├── Cargo.toml           # Rust workspace manifest
└── flake.nix            # Nix dev shell + crane-tauri desktop build + android daemon toolchain
```

The frontend's TypeScript bindings, Zod schemas and runtime defaults are **generated from the
Rust types** (`tauri-specta`), so the two sides can't drift. Everything OS-specific lives behind
the `Platform` trait — Android in `kasumi-daemon`, Linux desktop in `src-tauri`.

The Nix flake is the supported build path (no system Rust needed):

```sh
# Rust gate
nix develop --command cargo test --workspace
nix develop --command cargo clippy --workspace --all-targets -- -D warnings

# Frontend
cd frontend && bun install && bun run build && bunx vitest run

# Desktop app (reproducible)
nix build .#kasumi-desktop

# Android module zip (cross-builds the daemon + cores + webroot, then zips)
nix run .#package-release -- build/kasumi-proxy.zip
```

Core/daemon binaries and the built `module/webroot/` are intentionally **not** committed — they
are produced at release time (see `.gitignore`).

### Faster builds: the Cachix binary cache

`flake.nix` declares a public [Cachix](https://www.cachix.org/) cache (`kasumi-proxy`) as a
substituter, so `nix develop` / `nix build` pull the prebuilt Rust toolchain, webkit and devshell
closure instead of building them. Nix asks once to trust the flake's cache settings — accept the
prompt, pass `--accept-flake-config` (e.g. `nix develop --accept-flake-config`), or set
`accept-flake-config = true` in your `nix.conf`. CI already sets it.

Prompt-free alternative (writes the substituter straight to your own Nix config):

```sh
nix profile install nixpkgs#cachix   # once, if you don't already have cachix
cachix use kasumi-proxy
```

Reads are public — no token needed. (CI additionally caches the workspace's `cargo` build via the
GitHub Actions cache; that layer is CI-only — a local `cargo` build still compiles normally.)

### Install the desktop app via Nix

The flake exposes `kasumi-desktop` as a package, and **each release builds it and pushes it to the
`kasumi-proxy` Cachix cache**, so you can install a released tag without compiling. Add the cache to
**your own** Nix config first — a flake's `nixConfig` is *not* applied to downstream consumers, so
ours doesn't reach you automatically:

```sh
cachix use kasumi-proxy   # or add the substituter + key below to your nix.conf
nix build github:loss-and-quick/Kasumi-Proxy/vX.Y.Z#kasumi-desktop
```

Or wire it into your own flake:

```nix
{
  inputs.kasumi-proxy.url = "github:loss-and-quick/Kasumi-Proxy";
  # outputs: inputs.kasumi-proxy.packages.${system}.kasumi-desktop
  nixConfig = {
    extra-substituters = [ "https://kasumi-proxy.cachix.org" ];
    extra-trusted-public-keys = [
      "kasumi-proxy.cachix.org-1:V22nNqK4m1rSZRfuak86S1aY1eLlGhty05m8VtK25gM="
    ];
  };
}
```

Without our substituter in your config, the build still works — it just compiles from source instead
of pulling the prebuilt closure. The cache hit is per exact revision (the released tag), so build the
same tag you reference.

### Web UI development

```sh
cd frontend
bun install
bun run dev      # mock bridge — no device needed
bunx vitest run  # unit tests
bunx biome check # lint/format
```

The UI talks to the backend through a `Bridge` abstraction (`src/lib/bridge.ts`): the Tauri
build invokes the backend in-process, the Android build speaks a token-guarded WebSocket RPC to
the daemon, and `mock-bridge.ts` simulates it for local development — all carrying the same typed
`Command` / `Response`.

---

## How it works

- **One backend, two shells.** `kasumi-backend` owns the data-path lifecycle (core + `tun2socks`,
  routing, watchdogs, headless subscription updates) as a `Service`. On Android the
  `kasumi-proxy` daemon hosts it behind an axum WS server; on desktop the Tauri process *is* the
  backend. The UI never builds raw shell — it speaks one typed command set over the bridge.
- **Domain logic lives in `kasumi-core`.** Profiles in, engine config (`xray_config` /
  `singbox_config`) out, built server-side so subscription updates apply with no UI open.
- **`frontend/`** is the management UI, running on the generated bindings.

---

## Acknowledgments

Kasumi Proxy bundles pre-built binaries from these open-source projects:

- **[Xray-core](https://github.com/XTLS/Xray-core)** — primary proxy engine.
- **[sing-box](https://github.com/SagerNet/sing-box)** — second core.
- **[tun2socks](https://github.com/xjasonlyu/tun2socks)** — wraps the proxy into a TUN interface.

## License

See [LICENSE](./LICENSE).

# Kasumi Proxy

> A system-level transparent proxy engine for **rooted Android** — routes all device
> traffic through Xray-core / sing-box at the kernel level, with a clean Web UI.

Kasumi Proxy is a **Magisk / KernelSU / APatch module** (not a standalone app). It runs the
proxy core as a system daemon and steers traffic with native Linux routing
(`iptables` / `ip rule`), instead of Android's user-space `VpnService`.

> 🍴 **Fork.** Kasumi Proxy is a fork of
> [vincentng295/Magic_V2Ray](https://github.com/vincentng295/Magic_V2Ray)

> 🤖 **AI SLOP WARNING.** Most of this codebase was written by AI.

---

## Why a root module instead of a VPN app?

If you come from v2rayNG, NekoBox, or Matsuri, here is what changes:

- **Survives Low-Memory-Killer.** Standard apps run in user space and get killed under
  memory pressure, dropping the tunnel and leaking your real IP. Kasumi Proxy runs as a root
  daemon the OS won't reap.
- **Kernel-level routing.** No virtual `tun0` software bottleneck for app traffic —
  packets are intercepted at the Netfilter/Mangle layer and handed straight to the core,
  cutting latency and CPU overhead from Java↔kernel context switching.
- **Seamless network switches.** Wi-Fi ↔ 4G/5G transitions hot-reload the firewall rules
  in-kernel, without the usual multi-second freeze.
- **Universal root support.** Works on Magisk, KernelSU, and APatch out of the box.

> ⚠️ **No root?** This is a system module, not an app. For a regular GUI client, see the
> [Xray-core GUI clients](https://github.com/XTLS/Xray-core#gui-clients).

---

## Features

- **Dual core** — Xray-core for VLESS/VMess/Trojan/Shadowsocks/SOCKS/HTTP/WireGuard,
  sing-box for Hysteria2/TUIC. The core is selected per profile.
- **Smart import** — paste subscription URLs, raw config strings, or mixed text; scan QR.
- **Category organizing** — group servers into folders, one-tap update a whole category.
- **Web UI** — manage profiles, subscriptions, routing rules, and logs from the browser.
- **Native background processing** — lighter on battery than a user-space VPN app.

---

## Install

1. Download the latest `kasumi-proxy-vX.Y.Z.zip` release.
2. Flash it in Magisk / KernelSU / APatch and reboot.
3. Open the module's **Action** (Magisk) or WebUI entry — it launches the local control
   center in your browser, authenticated with a per-install secret token.

State and logs live under `/data/adb/kasumi-proxy/`.

---

## Build from source

The repo is split into the **source you edit** and the **module payload that ships**:

```
.
├── module/            # contents that become the installable zip root
│   ├── module.prop    # id=kasumi-proxy
│   ├── customize.sh service.sh proxy_control.sh action.sh uninstall.sh
│   ├── META-INF/      # Magisk installer
│   ├── bin/           # kasumi-proxyctl (tracked) + xray/sing-box/tun2socks (fetched)
│   └── webroot/       # cgi-bin/exec (tracked) + built UI (generated)
├── control-center/    # React + TypeScript Web UI (Vite, Zustand, Zod, Biome)
├── scripts/           # fetch-bin, build-webroot, package-release
└── flake.nix          # Nix dev shell (bun, curl, zip, jq, shellcheck)
```


```sh
# fetch core binaries (xray, sing-box, tun2socks) into module/bin/<abi>/
scripts/fetch-bin.sh        # or: nix run .#fetch-bin

# build the Web UI into module/webroot/
scripts/build-webroot.sh    # or: nix run .#build-webroot

# produce an installable module zip (fetches + builds + zips)
scripts/package-release.sh  # → build/kasumi-proxy-v0.0.1.zip
```

Core binaries and the built `webroot/` are intentionally **not** committed — they are
produced at release time (see `.gitignore`).

### Web UI development

```sh
cd control-center
bun install
bun run dev      # mock bridge — no device needed
bun test         # Vitest unit tests
bun run lint     # Biome
```

The UI talks to the module through a `Bridge` abstraction (`src/lib/bridge.ts`): the real
implementation (`ksu-bridge.ts`) invokes `kasumi-proxyctl <method>` via the KernelSU JS API or
a token-guarded CGI endpoint; `mock-bridge.ts` simulates it for local development.

---

## How it works

- **`module/bin/kasumi-proxyctl`** — a typed shell facade. The UI never builds raw shell; it
  calls fixed methods (`start`, `stop`, `status`, `log`, `ping`, `fetchSubscription`, …)
  which read/write `/data/adb/kasumi-proxy/` and drive `proxy_control.sh`.
- **`module/service.sh`** — the daemon: launches the selected core + `tun2socks`, sets up
  the TUN interface, and applies `iptables` / `ip rule` marking so device traffic is
  routed through the proxy.
- **`control-center/`** — generates the core config (`xray-config.ts` / `singbox-config.ts`
  from Zod-validated profiles) and renders the management UI.

---

## Acknowledgments

Kasumi Proxy bundles pre-built binaries from these open-source projects:

- **[Xray-core](https://github.com/XTLS/Xray-core)** — primary proxy engine.
- **[sing-box](https://github.com/SagerNet/sing-box)** — second core.
- **[tun2socks](https://github.com/xjasonlyu/tun2socks)** — wraps the proxy into a TUN
  interface.

## License

See [LICENSE](./LICENSE).

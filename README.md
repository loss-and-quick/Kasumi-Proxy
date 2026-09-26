<p align="center">
  <img src=".github/logo.png" width="160" alt="Kasumi Proxy" />
</p>

<h1 align="center">Kasumi Proxy</h1>

<p align="center">
  System-wide transparent proxy on Xray-core / sing-box for <b>rooted Android</b>, <b>Linux</b> and <b>Windows</b>.
</p>

<p align="center">
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/actions/workflows/ci.yml"><img src="https://github.com/loss-and-quick/Kasumi-Proxy/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/releases/latest"><img src="https://img.shields.io/github/v/release/loss-and-quick/Kasumi-Proxy?sort=semver" alt="Latest release" /></a>
  <a href="https://github.com/loss-and-quick/Kasumi-Proxy/issues"><img src="https://img.shields.io/github/issues/loss-and-quick/Kasumi-Proxy" alt="Open issues" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/loss-and-quick/Kasumi-Proxy" alt="License: GPL v3" /></a>
</p>

- **Android:** a Magisk / KernelSU / APatch module. It runs the core as a root daemon and routes
  traffic with `iptables` / `ip rule`, not through `VpnService`.
- **Desktop:** a Tauri 2 app that brings up a real TUN. Proxy-only, system-proxy and PAC modes
  are also available.

Both run the same Rust backend and the same React UI.

> [!NOTE]
> This is a fork of [vincentng295/Magic_V2Ray](https://github.com/vincentng295/Magic_V2Ray). Most
> of the code was written by AI, so review it before you trust it.

## Features

- **Two cores.** Xray-core and sing-box, picked per profile. Supported protocols are VLESS, VMess,
  Trojan, Shadowsocks, SOCKS, HTTP, WireGuard, Hysteria2, TUIC, AnyTLS, Naive and ShadowTLS.
- **Import.** Subscription URLs, share links, mixed text and QR codes.
- **Subscriptions.** Groups of servers that can be updated in one tap, or in the background
  with no UI open.
- **Honest status.** An end-to-end probe tells *connected* apart from *no internet* and *failed*.
- **Diagnostics.** TCP ping, real ping and a speed test for each profile.
- **Per-app routing** on Android, plus a choice of TUN engine: tun2socks, hev-socks5-tunnel or
  sing-box.

### Why a root module rather than a VPN app?

- The root daemon is not killed by the low-memory killer, so the tunnel does not drop and leak
  your IP.
- Traffic is intercepted in the kernel (Netfilter) and never passes through a user-space
  `tun0`.
- Switching between Wi-Fi and mobile data reapplies the routing rules on the fly.

> [!TIP]
> No root? Use an ordinary client from the
> [Xray-core GUI list](https://github.com/XTLS/Xray-core#gui-clients).

## Install

Download the file for your platform from the
[latest release](https://github.com/loss-and-quick/Kasumi-Proxy/releases/latest).

| Platform | File | Notes |
| --- | --- | --- |
| Android (root) | `kasumi-proxy-module-vX.Y.Z.zip` | Flash it in Magisk / KernelSU / APatch, then reboot. Open the UI with the module's **Action** button or its WebUI entry. |
| Linux | `.deb`, `.AppImage` | Asks for `pkexec` / `sudo` to set up the TUN and routes. |
| Linux, portable | `kasumi-proxy-linux-portable-vX.Y.Z.zip` | Unzip and run `./kasumi-desktop`. All state stays next to the binary. |
| Windows | `-setup.exe`, `.msi` | Needs administrator rights (UAC) for the TUN. |
| Windows, portable | `kasumi-proxy-windows-portable-vX.Y.Z.zip` | Unzip and run `kasumi-desktop.exe`. |
| Nix / NixOS | — | See [docs/nix.md](docs/nix.md). |

On Android, state and logs live in `/data/adb/kasumi-proxy/`.

<details>
<summary><b>Verifying the AppImage signature</b></summary>

AppImages are signed with the key in [`release-signing-key.asc`](release-signing-key.asc)
(`2AA0 03A9 D670 653C FAA8  F7B0 88BE 4761 6D49 65E9`):

```sh
gpg --import release-signing-key.asc
./Kasumi*.AppImage --appimage-extract '.appimage_signature'
gpg --verify squashfs-root/.appimage_signature Kasumi*.AppImage
```

</details>

## Development

Build steps, checks and the repository layout are in [CONTRIBUTING.md](CONTRIBUTING.md). Nix is
optional: plain `cargo` and `bun` are enough.

## Acknowledgments

Kasumi Proxy ships prebuilt binaries from
[Xray-core](https://github.com/XTLS/Xray-core), [sing-box](https://github.com/SagerNet/sing-box),
[tun2socks](https://github.com/xjasonlyu/tun2socks) and
[hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel). See
[module/bin/README.md](module/bin/README.md) for their licenses.

## License

[GPL-3.0](LICENSE)

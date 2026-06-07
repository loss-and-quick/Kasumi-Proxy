# AGENTS.md — Kasumi Proxy (repo root)

## What this is

Kasumi Proxy is a **Magisk / KernelSU / APatch module** for rooted Android: a system-wide
transparent proxy that runs Xray-core / sing-box + tun2socks and routes traffic with native
`iptables` / `ip rule` (no `VpnService`). A React Web UI manages it. Fork of
`vincentng295/Magic_V2Ray`; most code is AI-written — review before trusting.

## Two layers (source you edit vs package that ships)

- `module/` — everything that becomes the **installable zip root** (Magisk dictates that
  `module.prop`, `customize.sh`, `service.sh`, `action.sh`, `uninstall.sh`, `META-INF/` sit
  at the archive root). `package-release.sh` zips from **inside** `module/`.
- `control-center/` — React + TypeScript source for the Web UI (built into
  `module/webroot/`).
- `scripts/` — `fetch-bin.sh` (cores), `build-webroot.sh` (UI → `module/webroot/`),
  `package-release.sh` (assemble zip).
- `docs/` — `REVIEW.md` (code review), `component-decomposition-plan.md`.

## Hard rules

- **Never commit build artifacts.** Core binaries (`module/bin/<abi>/`, `geoip/geosite`) and
  the built `module/webroot/` (everything except `cgi-bin/`) are gitignored on purpose. Only
  `module/bin/{kasumi-proxyctl,README.md,LICENSE}` and `module/webroot/cgi-bin/exec` are tracked.
- **Renaming the project** touches the id everywhere: data path `/data/adb/kasumi-proxy`, the
  `KASUMI_PROXY_MARK` iptables chain, `kasumi-proxyctl`, `module.prop`, and string literals in shell +
  TS. Grep all case forms (`kasumi-proxy`, `Kasumi Proxy`, camelCase) before claiming done.

## Verify before declaring done

```sh
# Web UI
cd control-center && bun run build && bun run test && bun run check
# Module shell (Android mksh dialect)
shellcheck -s sh module/*.sh module/bin/kasumi-proxyctl module/webroot/cgi-bin/exec
```

A [Nix](https://nixos.org) dev shell (`nix develop`) provides bun, shellcheck, zip, jq, curl.
There is no CI — run the checks yourself.

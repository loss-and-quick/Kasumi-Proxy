# Bundled Binaries

These binaries are **not committed to git** — the cores are fetched by
`scripts/fetch-cores-android.sh` into `bin/arm64-v8a/` and `bin/x86_64/`, and the
`kasumi-proxy` daemon is cross-built per arch by
`scripts/build-daemon-android.sh`. Pinned core versions live in
`scripts/core-versions.sh`; override via env vars
`XRAY_VERSION` / `TUN2SOCKS_VERSION` / `SINGBOX_VERSION`.

---

## Xray-core

- **Source:** <https://github.com/XTLS/Xray-core>
- **License:** Mozilla Public License 2.0 — see [`licenses/xray-LICENSE`](licenses/xray-LICENSE)
- **Role:** Primary proxy core. Handles VLESS, VMess, Trojan, VLESS-XTLS-REALITY, Shadowsocks, and all other non-Hysteria2/TUIC protocols.

---

## sing-box

- **Source:** <https://github.com/SagerNet/sing-box>
- **License:** GNU General Public License v3.0 — see [`licenses/sing-box-LICENSE`](licenses/sing-box-LICENSE)
- **Role:** Secondary proxy core. Used for Hysteria2 and TUIC profiles. Also provides the tun inbound with `exclude_uid` / `include_uid` for per-profile app filtering.

---

## tun2socks

- **Source:** <https://github.com/xjasonlyu/tun2socks>
- **License:** MIT — see [`licenses/tun2socks-LICENSE`](licenses/tun2socks-LICENSE)
- **Role:** Userspace SOCKS5-to-tun bridge. Used in xray mode to forward tun-captured traffic into xray's SOCKS inbound.

---

## Fetching

```sh
scripts/fetch-cores-android.sh
```

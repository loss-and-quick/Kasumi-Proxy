# Bundled binaries

Nothing here is committed except this file and `licenses/`. The binaries are produced at build
time:

```sh
scripts/fetch-binaries.sh android   # cores + geodat2srs → bin/{arm64-v8a,x86_64}/
scripts/build-daemon-android.sh     # kasumi-proxy daemon → the same place
```

Versions are pinned in `scripts/binary-versions.sh` and can be overridden through environment
variables (`XRAY_VERSION`, `SINGBOX_VERSION`, `TUN2SOCKS_VERSION`, `HEV_VERSION`).

| Binary | Role | License |
| --- | --- | --- |
| [Xray-core](https://github.com/XTLS/Xray-core) | Main core: VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard | MPL-2.0, [`licenses/xray-LICENSE`](licenses/xray-LICENSE) |
| [sing-box](https://github.com/SagerNet/sing-box) | Second core: Hysteria2, TUIC, AnyTLS, Naive, ShadowTLS. Also a TUN engine | GPL-3.0, [`licenses/sing-box-LICENSE`](licenses/sing-box-LICENSE) |
| [tun2socks](https://github.com/xjasonlyu/tun2socks) | TUN → SOCKS5 bridge for Xray | MIT, [`licenses/tun2socks-LICENSE`](licenses/tun2socks-LICENSE) |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | Alternative TUN engine | MIT |
| [geodat2srs](https://github.com/loss-and-quick/geodat2srs) | Converts geoip/geosite `.dat` → sing-box `.srs`. Built from source | — |

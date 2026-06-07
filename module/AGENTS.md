# AGENTS.md — module (shell / Magisk payload)

This tree is the installable module payload. Its files sit at the **zip root** at install
time (see root AGENTS.md), so do not move `module.prop`, `customize.sh`, `service.sh`,
`action.sh`, `uninstall.sh`, or `META-INF/` relative to `module/`.

## Target shell is Android mksh (not POSIX/bash)

All scripts use `#!/system/bin/sh`, which on Android is **mksh**. mksh extensions are fine and
used throughout: `local`, `${var//…}` substitution. But `&>` is **not** valid — always write
`>file 2>&1`. Lint with the POSIX dialect and keep it clean:

```sh
shellcheck -s sh *.sh bin/kasumi-proxyctl webroot/cgi-bin/exec
```

The intentional mksh features (`local`, `${//}`) are silenced per-file with documented
`# shellcheck disable=SC3043,SC3060` directives — keep that pattern; don't rewrite them to
POSIX, and don't blanket-disable real warnings (`SC2046`, `SC2086`, `SC3020`) — fix those.

## Backend contract

- **`bin/kasumi-proxyctl`** is the typed facade the UI calls: `kasumi-proxyctl <method> [args]`, JSON on
  stdout, payloads on stdin. To avoid a `jq` dependency it never parses nested JSON. Add new
  capabilities as new methods in its `case "$method"` dispatch.
  - **A method must not block for more than a moment.** The UI calls these through `ksu.exec`,
    which freezes the WebView for the command's whole duration. So any long-running op is split
    into a fast `<op>Start` that backgrounds the work (`( … ) >/dev/null 2>&1 &`, writing a
    status/result file via `write_test_job` / `write_asset_job_status`) plus a fast `<op>Status`
    the UI polls — see `downloadAssetStart`/`downloadAssetStatus` and
    `pingStart`/`realpingStart`/`speedtestStart`.
- **`service.sh`** is the daemon (core + tun2socks + iptables/`ip rule` marking via the
  `KASUMI_PROXY_MARK` chain); `proxy_control.sh` is the start/stop/restart facade over the control
  pipe. State lives in `/data/adb/kasumi-proxy/`.

## Security (do not regress)

`webroot/cgi-bin/exec` is token-gated and **must never `eval` / `sh -c` request data**. It
receives structured fields (`argv` = base64 newline-joined `[method, ...args]`, optional
base64 `stdin`), rebuilds a fixed positional argv, and execs the **pinned** `kasumi-proxyctl`
binary. Keep it that way — any "run the posted command" shortcut reintroduces RCE.

`__SECRET_TOKEN__` in `customize.sh` / `cgi-bin/exec` is a placeholder replaced per-install;
leave it literal in the repo.

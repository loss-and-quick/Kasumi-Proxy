# AGENTS.md — module (shell / Magisk payload)

This tree is the installable module payload. Its files sit at the **zip root** at install
time (see root AGENTS.md), so do not move `module.prop`, `customize.sh`, `service.sh`,
`action.sh`, `uninstall.sh`, or `META-INF/` relative to `module/`.

## Target shell is Android mksh (not POSIX/bash)

All scripts use `#!/system/bin/sh`, which on Android is **mksh**. mksh extensions (`local`,
`${var//…}`) are fine, but `&>` is **not** valid — always write `>file 2>&1`. Lint with the
POSIX dialect and keep it clean:

```sh
shellcheck -s sh *.sh
```

Silence intentional mksh features per-file with documented `# shellcheck disable=…`
directives; don't blanket-disable real warnings (`SC2046`, `SC2086`, `SC3020`) — fix those.

## Backend contract

The backend is the single **`bin/kasumi-proxy`** binary (the Rust daemon, cross-built per arch by
`scripts/build-daemon-android.sh`; not committed), dispatched on argv:

- `kasumi-proxy daemon` — long-running root daemon launched by `service.sh`: boot init,
  control unix-socket, core + tun2socks lifecycle and routing, watchdogs, subscription
  auto-update, and the loopback HTTP/WS server (static `webroot/` + token-gated `/ws` RPC).
- `kasumi-proxy <cmd> [args]` — one-shot CLI for scripts and the manager-WebUI bootstrap:
  JSON on stdout, payloads on stdin.

The UI's live channel is the WebSocket. The manager WebUI gets `{port, token}` via one
`ksu.exec kasumi-proxy wsInfo`; `action.sh` reads the same bootstrap from
`/data/adb/kasumi-proxy/run/ws.json` and opens the UI in the browser. State lives in
`/data/adb/kasumi-proxy/`.

## Security (do not regress)

The HTTP/WS listener binds loopback only, and the WS upgrade + every RPC are gated by the
per-start random token. RPC dispatch is a fixed command registry (`runCommand` in
`packages/backend`) — never add a "run this posted shell string" passthrough; that
reintroduces RCE. Known trade-off: the browser flow puts the token in the page URL
(local apps can read it from history/intents) — see HANDOFF before changing the scheme.

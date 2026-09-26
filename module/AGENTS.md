# AGENTS.md — module (Magisk payload)

The contents of `module/` become the **root of the zip**. Do not move `module.prop`,
`customize.sh`, `service.sh`, `action.sh`, `uninstall.sh` or `META-INF/` out of it.

## The shell is Android mksh

The scripts start with `#!/system/bin/sh`, which is mksh on Android. `local` and `${var//…}` are
allowed, but `&>` is not: write `>file 2>&1`. Lint with the POSIX dialect:

```sh
shellcheck -s sh *.sh
```

Disable a check only per file, with a comment explaining why. Fix `SC2046`, `SC2086` and
`SC3020` rather than silencing them.

## The kasumi-proxy binary

`bin/kasumi-proxy` is the Rust daemon (`crates/kasumi-daemon`), cross-built by
`scripts/build-daemon-android.sh`:

- `kasumi-proxy daemon` is started by `service.sh`. It handles boot init, the core and TUN
  lifecycle, routing, watchdogs, subscription auto-update, and the HTTP/WS server (static
  `webroot/` + `/ws` RPC).
- `kasumi-proxy <cmd> [args]` is a one-shot CLI for scripts. It prints JSON to stdout.

The UI gets `{port, token}` from `kasumi-proxy wsInfo`. `action.sh` reads the same data from
`/data/adb/kasumi-proxy/run/ws.json` and opens `http://127.0.0.1:<port>/?token=…`. All state
lives in `/data/adb/kasumi-proxy/`.

## Security (do not regress)

- HTTP/WS listens on loopback only. The WS upgrade and every RPC check the random per-start
  token.
- RPC is the fixed typed `Command` set (`crates/kasumi-backend/src/commands.rs`). **Never** add
  a "run this shell string" command, because that is RCE.
- A known trade-off: the token travels in the page URL, so local apps can see it in history or
  intents.

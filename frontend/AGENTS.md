# AGENTS.md — frontend

React 19 + TypeScript, Vite (rolldown), Zustand, Zod, Biome. The toolchain is **bun**, not
npm/node.

## Commands

```sh
bun run dev         # vite + mock bridge, no device needed
bun run test        # vitest
bun run check       # Biome lint + format (autofix: bunx @biomejs/biome check --write src/)
bun run check:i18n  # every locale in sync with en
bun run build       # tsc -b && vite build
```

`test`, `check`, `check:i18n` and `build` must stay green.

## Rules

- **Types come from Rust.** `src/generated/` holds `bindings.ts`, `schemas.ts` and
  `defaults.ts`. They are generated from the Rust crates (`cargo run -p kasumi-desktop --bin
  codegen`), so don't edit them or duplicate them with hand-written types. Config builders and
  share-link parsing also live in Rust (`crates/kasumi-core`).
- **Strict typing.** No `any`, `as any` or `@ts-ignore`.
- **Backend access goes through `Bridge` only** (`src/lib/bridge.ts`). `bridge-provider.ts` picks
  the implementation: `tauri-bridge.ts` (desktop), `ws-bridge.ts` (WebSocket RPC to the Android
  daemon) or `mock-bridge.ts` (dev). The UI never builds shell strings. A new call is a
  `Bridge` method plus its implementations.
- **Live data is pushed, not polled.** The backend pushes status, traffic, logs and job
  progress, and the UI subscribes to them. Long tasks (tcping, realping, speed test, asset
  downloads) run as backend jobs, and their results arrive through callbacks such as
  `realPingAll(ids, onResult)`.
- `vite.config.ts` keeps `base: "./"`. The bundle is served by the daemon and by the WebView, so
  absolute paths break it.

## i18n

- The locale registry is `LOCALES` in `i18n/index.ts`. A new language is one entry there plus a
  dictionary file. Non-English dictionaries are lazy-loaded.
- Keys are typed from `i18n/en.ts`. When you change a user-visible string, update `en.ts` **and
  every** other locale (`ar`, `es`, `hi`, `pt`, `ru`, `vi`, `zh`) in the same change.
- Plurals and variants go through `plural` / `select` from `i18n/messages.ts`. Format dates,
  numbers and lists with `useFormatters` / `formatDateTime` / `formatNumber` / `formatList`, not
  raw `toLocaleString()` or `join(", ")`.
- Store translation keys in config arrays, not English strings.

## Icons

`<Icon name="…">` (`components/icons.tsx`) loads `src/assets/icons/<name>.svg`. A missing file
silently renders the `error` glyph. The set is Iconify **material-symbols, rounded**.
**Download** the SVG rather than typing it from memory:

```
https://api.iconify.design/material-symbols/<name>-rounded.svg
https://api.iconify.design/material-symbols/<name>.svg   # when there is no rounded variant
```

Save the file unchanged as `src/assets/icons/<name_with_underscores>.svg`.

## Tests

Tests live next to the code in `__tests__/` folders (`lib`, `store`, `components`, `i18n`,
`features/*`) and in `src/store/*.test.ts`.

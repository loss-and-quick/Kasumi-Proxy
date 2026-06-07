# AGENTS.md — control-center (Web UI)

React 19 + TypeScript, built with **Vite (rolldown)**, state in **Zustand**, validation with
**Zod**, lint/format with **Biome**. Toolchain is **bun** (not npm/node).

## Commands

```sh
bun install
bun run dev        # vite + mock bridge — no device needed
bun run test       # vitest run (unit tests)
bun run check      # Biome lint + format (must be clean)
bun run check:i18n # locale dictionaries must stay in sync with en
bun run build      # tsc -b && vite build
```

After any change, `bun run test` + `bun run check` must stay green. `bunx tsc -b` must be 0
errors. Use `bunx @biomejs/biome check --write src/` to auto-fix import order / formatting.

## Conventions

- **Strict typing.** No `any`, no `@ts-ignore`, no `as any`. Domain types come from the Zod
  schemas in `src/lib/schema/` — that's the single source of truth; don't hand-roll parallel
  types.
- **Backend access only through the `Bridge` abstraction** (`src/lib/bridge.ts`). The UI
  **never builds shell strings**. `bridge-provider.ts` picks the live impl: `ksu-bridge.ts`
  (device: KernelSU JS API or token CGI) or `mock-bridge.ts` (dev). Add UI-facing backend
  calls as `Bridge` methods + impls, not ad-hoc.
- **Config generators** `lib/xray-config.ts` / `lib/singbox-config.ts` turn a validated
  `Profile` into core JSON. Shared list helpers live in `lib/config-shared.ts` — reuse them,
  don't re-duplicate `splitCsv` / `splitList`.
- **i18n** is a single registry: `i18n/index.ts` `LOCALES`. Adding a language = one entry +
  its dictionary file; `Lang`, browser-language detection, formatters, and the picker all
  derive from it. Non-English locale dictionaries are lazy-loaded, so register new locales via
  the loader entry in `LOCALES`, not eager imports sprinkled around the app. Translation keys
  are typed from `i18n/en.ts`; prefer typed key maps over free-form template keys. If you add
  or change any user-visible string, update `i18n/en.ts` and every locale file (`ar.ts`, `es.ts`,
  `hi.ts`, `pt.ts`, `ru.ts`, `vi.ts`, `zh.ts` and so on ) in the same change — do not leave partial
  translations behind.
- The message layer supports plain strings, message functions, and reusable helpers in
  `i18n/messages.ts` (`plural`, `select`). Use those for count/state-sensitive text instead of
  `"item(s)"`-style strings or component-local branching.
- Use the i18n formatter layer (`useFormatters`, `formatDateTime`, `formatList`,
  `formatNumber`) instead of raw `toLocaleString()` / manual `join(", ")` in components.
- Do not hardcode user-visible English labels inside config arrays. Store translation keys
  there and resolve them at render time. Run `bun run check:i18n` after touching locale files.
- **Icons** are inline SVG masks loaded via `import.meta.glob("../assets/icons/*.svg")` in
  `components/icons.tsx`; `<Icon name="…">` looks up `src/assets/icons/<name>.svg` and falls
  back to the `error` glyph when the file is missing (so a missing icon silently renders the
  fallback — don't reference names you haven't added). The set is **Iconify `material-symbols`
  (rounded variant)**. When you need a new icon, **download the exact SVG** — do not hand-write
  the path from memory. Fetch `https://api.iconify.design/material-symbols/<name>-rounded.svg`
  (some glyphs like `block` have no rounded variant — fall back to
  `https://api.iconify.design/material-symbols/<name>.svg`), keep the file verbatim
  (`width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"`), and save it as
  `src/assets/icons/<name>.svg` using underscores (e.g. `arrow_back.svg`, `near_me.svg`).
- Tests live in `src/lib/__tests__/` and `src/store/`. The config generators and share-link
  parsing are well-covered round-trip — keep them passing when touching those files.

## Watch-outs

- **`ksu.exec` freezes the WebView renderer for the entire duration of the shell command.**
  Verified empirically: a `sleep 8` exec drops a 100ms `setInterval` to **0 ticks** — the whole
  WebUI hangs, not just our page. So a `Bridge` method must **never** issue one long-running
  exec. Anything that can take more than a moment runs as a background job: a fast `*Start` that
  spawns the work and returns immediately, polled by a fast `*Status` every 250ms until done.
  See `runTestJob` (tcping / realping / speedtest) and `downloadAsset` for the pattern.
- `vite.config.ts` uses `base: "./"` (relative asset paths) so the bundle works under BusyBox
  httpd and WebView — don't switch to absolute `/`.
- Large components (`features/{profiles,settings,editor}`) are slated for decomposition — see
  `docs/component-decomposition-plan.md` before splitting them; keep state in the parent.

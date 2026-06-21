<!--
  Thanks for contributing to Kasumi Proxy!
  Keep the title as a scoped Conventional Commit, e.g.
    fix(singbox): skip uTLS for QUIC outbounds
    feat(desktop): proxy mode selection
-->

## Summary

<!-- What does this PR change and why? Link any related issue: "Closes #123". -->

## Affected layer

<!-- Tick all that apply (see AGENTS.md "Layout"). These mirror the auto-applied labels. -->

- [ ] `frontend/` — React Web UI
- [ ] `crates/` · `src-tauri/` — Rust core / backend / Tauri desktop
- [ ] `module/` — Android installable zip (thin launcher over the Rust daemon)
- [ ] `scripts/` — build / release helpers
- [ ] CI / `.github/`
- [ ] Docs only

## Verification

<!-- Run the checks relevant to the layer you touched and tick them (AGENTS.md "Verify before declaring done"). The supported Rust path is the nix dev shell. -->

Rust (`crates/` · `src-tauri/`):

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Codegen drift: `cargo run -p kasumi-desktop --bin codegen` leaves `git` clean

Web UI (`frontend/`):

- [ ] `bun run check` — Biome lint + format clean
- [ ] `bun run test` — vitest green
- [ ] `bun run build` — `tsc -b` + vite build succeed
- [ ] `bun run check:i18n` — locale dictionaries in sync (if any user-visible string changed)

Module shell (`module/`):

- [ ] `shellcheck -s sh module/*.sh`

## Checklist

- [ ] Title is a scoped Conventional Commit; commits are logically split
- [ ] No build artifacts committed (`module/bin/<abi>/`, `geoip`/`geosite`, built `module/webroot/`, `src-tauri/gen/` — all gitignored on purpose)
- [ ] Generated `frontend/src/generated/` was regenerated from Rust, not hand-edited
- [ ] If user-visible strings changed: `i18n/en.ts` **and every** locale file updated (no partial translations)
- [ ] Renames touching the project id were grepped in all case forms (`kasumi-proxy`, `Kasumi Proxy`, camelCase)

## Notes for reviewers

<!-- Screenshots, trade-offs, follow-ups, anything out of scope intentionally left. -->

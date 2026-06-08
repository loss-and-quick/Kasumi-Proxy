<!--
  Thanks for contributing to Kasumi Proxy!
  Keep the title as a scoped Conventional Commit, e.g.
    fix(config): reuse splitCsv in sing-box generator
    feat(profiles): group management sheet
-->

## Summary

<!-- What does this PR change and why? Link any related issue: "Closes #123". -->

## Affected layer

<!-- Tick all that apply — this maps to the two-layer split in AGENTS.md. -->

- [ ] `control-center/` — React Web UI
- [ ] `module/` — Magisk/KernelSU/APatch payload (shell, `kasumi-proxyctl`, `cgi-bin/exec`)
- [ ] `scripts/` — build / release helpers
- [ ] CI / `.github/`
- [ ] Docs only

## Verification

<!-- Run the checks relevant to the layer you touched and tick them. -->

Web UI (`control-center/`):

- [ ] `bun run check` — Biome lint + format clean
- [ ] `bun run test` — vitest green
- [ ] `bun run build` — `tsc -b` + vite build succeed
- [ ] `bun run check:i18n` — locale dictionaries in sync (if any user-visible string changed)

Module shell (`module/`):

- [ ] `shellcheck -s sh module/*.sh module/bin/kasumi-proxyctl module/webroot/cgi-bin/exec`

## Checklist

- [ ] Title is a scoped Conventional Commit; commits are logically split
- [ ] No build artifacts committed (`module/bin/<abi>/`, `geoip`/`geosite`, built `module/webroot/` — all gitignored on purpose)
- [ ] If user-visible strings changed: `i18n/en.ts` **and every** locale file updated (no partial translations)
- [ ] Renames touching the project id were grepped in all case forms (`kasumi-proxy`, `Kasumi Proxy`, camelCase)

## Notes for reviewers

<!-- Screenshots, trade-offs, follow-ups, anything out of scope intentionally left. -->

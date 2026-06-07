// ============================================================
// src/lib/schema/index.ts
// Barrel: the single import surface for all domain schemas/types.
// Existing imports `from "../lib/schema"` keep working unchanged.
//
// Layout:
//   enums      — fixed value sets (z.enum)
//   mixins     — shared field groups + default factories
//   protocols/ — one file per protocol (schema + empty())
//   profile    — discriminated union, registry, emptyProfile
//   settings   — groups/subscriptions/advanced/app-state
//   core       — engine resolution (xray vs sing-box)
//
// Backend split lives in the config generators (xray-config.ts vs
// singbox-config.ts), NOT here — profiles are backend-agnostic.
// ============================================================

export * from "./core";
export * from "./enums";
export * from "./mixins";
export * from "./profile";
export * from "./protocols";
export * from "./settings";

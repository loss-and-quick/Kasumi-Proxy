import { describe, expect, it } from "vitest";
import { CORE_RESOLUTION_FIXTURES } from "../../generated/defaults";
import { EMPTY_SETTINGS } from "../../store/defaults";
import { resolveCore } from "../profile-utils";

// `profile-utils.ts::resolveCore` re-implements Rust's `core::resolve_core` matrix
// synchronously (for the `EngineTag`, which can't await a bridge round-trip). These
// fixtures are generated from Rust — each profile paired with the core Rust actually
// picks — so this test fails the moment the two resolvers drift.
describe("core resolution parity with Rust", () => {
  it("has fixtures to check", () => {
    expect(CORE_RESOLUTION_FIXTURES.length).toBeGreaterThan(0);
  });

  it.each(CORE_RESOLUTION_FIXTURES)("$name → $expectedCore", ({ profile, expectedCore }) => {
    expect(resolveCore(profile, EMPTY_SETTINGS)).toBe(expectedCore);
  });
});

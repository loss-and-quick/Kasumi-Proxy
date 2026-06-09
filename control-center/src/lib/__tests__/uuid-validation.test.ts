/**
 * Regression: VLESS/VMess ids render in the 8-4-4-4-12 hex layout but real
 * subscriptions ship UUIDs whose version/variant nibbles don't follow RFC 9562
 * (e.g. the "d" variant nibble in the profile that triggered the original
 * ZodError). Both Xray (common/uuid ParseString) and sing-box (sing-vmess
 * NewClient → gofrs uuid.FromString) accept those, so the schema must too.
 * We validate the layout via z.guid instead of Zod's strict z.uuid.
 */

import { describe, expect, it } from "vitest";
import { emptyProfile, ProfileSchema } from "../schema/profile";

// The id from the failing subscription: valid 8-4-4-4-12 hex, but the 4th group
// starts with "d" — not an RFC variant nibble ([89abAB]).
const NON_RFC_UUID = "ae225455-5e8c-491d-d931-c06ac56f4aee";

describe("vless/vmess uuid validation accepts non-RFC-variant UUIDs", () => {
  for (const protocol of ["vless", "vmess"] as const) {
    it(`${protocol}: accepts the 8-4-4-4-12 layout regardless of variant nibble`, () => {
      const profile = {
        ...emptyProfile(protocol),
        remarks: "r",
        address: "example.com",
        uuid: NON_RFC_UUID,
      };
      const res = ProfileSchema.safeParse(profile);
      expect(res.success).toBe(true);
    });

    it(`${protocol}: still rejects a non-UUID-shaped id`, () => {
      const profile = {
        ...emptyProfile(protocol),
        remarks: "r",
        address: "example.com",
        uuid: "not-a-uuid",
      };
      const res = ProfileSchema.safeParse(profile);
      expect(res.success).toBe(false);
    });
  }
});

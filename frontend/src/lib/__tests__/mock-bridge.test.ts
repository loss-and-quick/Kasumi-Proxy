import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import type { AppState_Serialize, Profile } from "../../generated/bindings";
import { AppStateSchema } from "../../generated/schemas";
import { mockBridge } from "../mock-bridge";

const flat = { protocol: "trojan", id: "t1", remarks: "Home", address: "ex.com", port: 443 };

/** The mock's state as a backup, with `profiles` in their place. */
async function backupWith(profiles: unknown[]): Promise<AppState_Serialize> {
  return { ...(await mockBridge.readState()), profiles: profiles as Profile[], schemaVersion: 0 };
}

describe("mockBridge", () => {
  it("reads back a backup exported from it", async () => {
    const text = await (await mockBridge.exportBackup()).text();
    const parsed = AppStateSchema.safeParse(JSON.parse(text));
    expect(parsed.success).toBe(true);
    const backup = await backupWith((await mockBridge.readState()).profiles);
    const restored = await mockBridge.importBackup(backup, "merge");
    expect(restored.skippedProfiles).toBe(0);
  });

  it("leaves out and counts a profile it would have to migrate", async () => {
    const before = await mockBridge.readState();
    const restored = await mockBridge.importBackup(await backupWith([flat]), "merge");
    expect(restored.skippedProfiles).toBe(1);
    expect(restored.state.profiles).toEqual(before.profiles);
  });

  it("refuses an import intent it would have to migrate", async () => {
    const before = await mockBridge.readState();
    const incoming = await backupWith([flat]);
    await expect(
      mockBridge.mutate({ kind: "importBackup", incoming, mode: "merge" }),
    ).rejects.toBeInstanceOf(ZodError);
    expect((await mockBridge.readState()).profiles).toEqual(before.profiles);
  });
});

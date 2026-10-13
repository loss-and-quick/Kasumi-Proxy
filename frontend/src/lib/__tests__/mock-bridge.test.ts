import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import type { AppState_Serialize, Profile } from "../../generated/bindings";
import { AppStateSchema } from "../../generated/schemas";
import { mockBridge } from "../mock-bridge";

describe("mockBridge", () => {
  it("reads back a backup exported from it", async () => {
    const text = await (await mockBridge.exportBackup()).text();
    expect(AppStateSchema.safeParse(JSON.parse(text)).success).toBe(true);
    await expect(mockBridge.importBackup(new Blob([text]), "merge")).resolves.toBeUndefined();
  });

  it("refuses a backup it would have to migrate", async () => {
    const before = await mockBridge.readState();
    const flat = { protocol: "trojan", id: "t1", remarks: "Home", address: "ex.com", port: 443 };
    const incoming: AppState_Serialize = {
      ...before,
      profiles: [flat] as unknown[] as Profile[],
      schemaVersion: 0,
    };
    await expect(
      mockBridge.mutate({ kind: "importBackup", incoming, mode: "merge" }),
    ).rejects.toBeInstanceOf(ZodError);
    expect((await mockBridge.readState()).profiles).toEqual(before.profiles);
  });
});

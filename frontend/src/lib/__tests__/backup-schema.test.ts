import { describe, expect, it } from "vitest";
import { AppStateSchema } from "../../generated/schemas";
import { BackupSchema } from "../backup-schema";

// What the first Backup screen exported: profiles with every field at the top level.
const flat = {
  protocol: "trojan",
  id: "t1",
  remarks: "Home",
  groupId: "g-main",
  address: "ex.com",
  port: 443,
  network: "tcp",
  security: "tls",
  sni: "ex.com",
  password: "pw",
};
const v0Backup = {
  profiles: [flat],
  groups: [{ id: "g-main", name: "Main" }],
  subscriptions: [],
  settings: {},
  activeId: "t1",
};

describe("BackupSchema", () => {
  it("passes profiles of an older shape through to the backend", () => {
    expect(AppStateSchema.safeParse(v0Backup).success).toBe(false);
    const parsed = BackupSchema.safeParse(v0Backup);
    expect(parsed.success && parsed.data.profiles).toEqual([flat]);
  });

  it("still refuses a document that isn't a backup", () => {
    expect(BackupSchema.safeParse({ profiles: [flat] }).success).toBe(false);
    expect(BackupSchema.safeParse({ ...v0Backup, groups: "Main" }).success).toBe(false);
  });
});

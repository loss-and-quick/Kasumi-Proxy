import { z } from "zod";
import { metaDefault, metaShape } from "../mixins";

export const CustomObj = z.object({
  ...metaShape,
  protocol: z.literal("custom"),
  raw: z.string().default(""), // full Xray config.json text
});
export type Custom = z.infer<typeof CustomObj>;

export function emptyCustom(groupId: string): Custom {
  return { ...metaDefault(groupId), protocol: "custom", raw: "" };
}

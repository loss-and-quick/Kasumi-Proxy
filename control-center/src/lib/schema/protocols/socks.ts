import { z } from "zod";
import { endpointDefault, endpointShape, metaDefault, metaShape } from "../mixins";

export const SocksObj = z.object({
  ...metaShape,
  ...endpointShape,
  protocol: z.literal("socks"),
  username: z.string().default(""),
  password: z.string().default(""),
});
export type Socks = z.infer<typeof SocksObj>;

export function emptySocks(groupId: string): Socks {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    protocol: "socks",
    username: "",
    password: "",
  };
}

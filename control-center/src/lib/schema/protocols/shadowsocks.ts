import { z } from "zod";
import { SsMethod } from "../enums";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
  transportDefault,
  transportShape,
} from "../mixins";

export const ShadowsocksObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...transportShape,
  ...tlsShape,
  protocol: z.literal("shadowsocks"),
  password: z.string().min(1, "Password required"),
  method: SsMethod.default("aes-256-gcm"),
});
export type Shadowsocks = z.infer<typeof ShadowsocksObj>;

export function emptyShadowsocks(groupId: string): Shadowsocks {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...transportDefault(),
    ...tlsDefault(),
    protocol: "shadowsocks",
    password: "",
    method: "aes-256-gcm",
  };
}

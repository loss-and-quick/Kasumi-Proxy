import { z } from "zod";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
} from "../mixins";

export const HttpObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("http"),
  username: z.string().default(""),
  password: z.string().default(""),
});
export type Http = z.infer<typeof HttpObj>;

export function emptyHttp(groupId: string): Http {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "http",
    username: "",
    password: "",
  };
}

import { z } from "zod";
import { Hysteria2Obfs } from "../enums";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
} from "../mixins";

// QUIC protocol only sing-box can run. Carries TLS but no Xray stream transport.
export const Hysteria2Obj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("hysteria2"),
  password: z.string().min(1, "Password required"),
  obfsType: Hysteria2Obfs.default(""),
  obfsPassword: z.string().default(""),
  ports: z.string().default(""), // port hopping, e.g. "1024:65535" or "10000-20000,30000"
  hopInterval: z.string().default(""), // seconds
  upMbps: z.coerce.number().int().min(0).default(0),
  downMbps: z.coerce.number().int().min(0).default(0),
  pinSha256: z.string().default(""), // certificate pin
});
export type Hysteria2 = z.infer<typeof Hysteria2Obj>;

export function emptyHysteria2(groupId: string): Hysteria2 {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "hysteria2",
    password: "",
    obfsType: "",
    obfsPassword: "",
    ports: "",
    hopInterval: "",
    upMbps: 0,
    downMbps: 0,
    pinSha256: "",
  };
}

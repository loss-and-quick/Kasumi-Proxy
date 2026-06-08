import type { Profile, Protocol } from "../../lib/schema";

/** Flat read-view over the union: every possible field, all optional. */
export interface ProfileView {
  protocol: Protocol;
  id: string;
  remarks: string;
  groupId: string;
  subId: string | null;
  ping: number | null;
  coreType?: string;
  address?: string;
  port?: number;
  network?: string;
  headerType?: string;
  host?: string;
  path?: string;
  wsEarlyData?: number;
  wsEarlyDataHeader?: string;
  wsHeartbeatPeriod?: number;
  serviceName?: string;
  authority?: string;
  grpcMode?: string;
  grpcIdleTimeout?: number;
  grpcHealthCheckTimeout?: number;
  grpcPingTimeout?: number;
  grpcPermitWithoutStream?: boolean;
  grpcInitialWindowsSize?: number;
  userAgent?: string;
  xhttpMode?: string;
  xhttpExtra?: string;
  kcpSeed?: string;
  kcpMtu?: number;
  kcpTti?: number;
  kcpUplink?: number;
  kcpDownlink?: number;
  muxEnabled?: boolean;
  security?: string;
  sni?: string;
  disableSni?: boolean;
  fingerprint?: string;
  alpn?: string;
  allowInsecure?: boolean;
  tlsMinVersion?: string;
  tlsMaxVersion?: string;
  tlsCipherSuites?: string;
  tlsCurvePreferences?: string;
  cert?: string;
  disableSystemRoot?: boolean;
  rejectUnknownSni?: boolean;
  enableSessionResumption?: boolean;
  publicKey?: string;
  shortId?: string;
  spiderX?: string;
  ech?: string;
  vcn?: string;
  pcs?: string;
  pqv?: string;
  uuid?: string;
  flow?: string;
  encryption?: string;
  packetEncoding?: string;
  alterId?: number;
  password?: string;
  method?: string;
  username?: string;
  secretKey?: string;
  peerPublicKey?: string;
  preSharedKey?: string;
  reserved?: string;
  localAddress?: string;
  mtu?: number;
  obfsType?: string;
  obfsPassword?: string;
  ports?: string;
  hopInterval?: string;
  upMbps?: number;
  downMbps?: number;
  pinSha256?: string;
  congestionControl?: string;
  udpRelayMode?: string;
  zeroRtt?: boolean;
  udpOverStream?: boolean;
  heartbeat?: string;
  idleSessionCheckInterval?: string;
  idleSessionTimeout?: string;
  minIdleSession?: number;
  workers?: number;
  persistentKeepalive?: number;
  naiveQuic?: boolean;
  insecureConcurrency?: number;
  version?: number;
  raw?: string;
}

export type ProfilePatch = Partial<ProfileView>;
export type ProfileSetter = (patch: ProfilePatch) => void;
export type FieldErrors = Record<string, string>;

// Boundary between the discriminated `Profile` union and the flat `ProfileView`.
// Every protocol embeds `metaShape`, so a Profile structurally satisfies the
// required ProfileView fields — reading is assignment, no cast.

/** Read a `Profile` as the flat view used by the editor form. */
export const asView = (p: Profile): ProfileView => p;

/** Re-narrow an edited flat view to `Profile`; validated by Zod on save. */
export const fromView = (v: ProfileView): Profile => v as Profile;

/** Copy one field between flat views, keeping the key↔value type link (no cast). */
export const copyViewField = <K extends keyof ProfileView>(
  into: ProfileView,
  from: ProfileView,
  key: K,
): void => {
  into[key] = from[key];
};

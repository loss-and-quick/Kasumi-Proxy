import {
  enableEdgeToEdge,
  exec as ksuExec,
  getPackagesInfo as ksuGetPackagesInfo,
  moduleInfo as ksuModuleInfo,
  toast as ksuToast,
} from "kernelsu";

export type RuntimeBridgeMode = "ksu-js" | "cgi" | "mock";
export type NativeExecResult = { errno: number; stdout: string; stderr: string };

declare global {
  interface Window {
    ksu?: {
      exec?: unknown;
      fullScreen?: unknown;
      enableEdgeToEdge?: unknown;
      toast?: unknown;
      moduleInfo?: unknown;
      exit?: unknown;
    };
  }
}

export function hasKsuNativeApi(): boolean {
  return typeof window !== "undefined" && typeof window.ksu?.exec === "function";
}

export function hasCgiToken(): boolean {
  return typeof window !== "undefined" && /(?:^|[?&])token=/.test(window.location.search);
}

export function getRuntimeBridgeMode(): RuntimeBridgeMode {
  if (hasKsuNativeApi()) return "ksu-js";
  if (hasCgiToken()) return "cgi";
  return "mock";
}

export function configureKsuWebUi(): void {
  if (!hasKsuNativeApi()) return;
  try {
    enableEdgeToEdge(true);
  } catch {
    // Ignore managers that expose exec but not the optional UI helpers.
  }
}

export async function execNative(command: string): Promise<NativeExecResult> {
  return ksuExec(command);
}

export function showNativeToast(message: string): boolean {
  if (!hasKsuNativeApi()) return false;
  try {
    ksuToast(message);
    return true;
  } catch {
    return false;
  }
}

export async function ksuListApps(): Promise<
  {
    pkg: string;
    uid: number;
    system: boolean;
    label?: string;
    iconUrl?: string;
  }[]
> {
  try {
    const userIds = [...(await ksuExec("pm list users")).stdout.matchAll(/UserInfo\{(\d+):/g)].map(
      (m) => Number(m[1]),
    );

    const apps: { pkg: string; uid: number; system: boolean; label?: string; iconUrl?: string }[] =
      [];
    const seen = new Set<string>();

    for (const userId of userIds) {
      const { stdout } = await ksuExec(`pm list packages -U --user ${userId}`);
      for (const line of stdout.split("\n")) {
        const m = line.match(/^package:(\S+)\s+uid:(\d+)/);
        if (!m) continue;
        const key = `${m[1]}:${m[2]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        apps.push({
          pkg: m[1],
          uid: Number(m[2]),
          system: false,
          label: undefined,
          iconUrl: `ksu://icon/${m[1]}`,
        });
      }
    }

    const infos = ksuGetPackagesInfo([...new Set(apps.map((a) => a.pkg))]);
    const infoMap = new Map(infos.map((i) => [i.packageName, i] as const));
    for (const app of apps) {
      const info = infoMap.get(app.pkg);
      if (info) {
        app.system = info.isSystem;
        app.label = info.appLabel || undefined;
      }
    }

    return apps;
  } catch {
    return [];
  }
}

export function getModuleId(defaultId = "kasumi-proxy"): string {
  if (!hasKsuNativeApi()) return defaultId;
  try {
    const raw = ksuModuleInfo();
    if (typeof raw !== "string" || !raw.trim()) return defaultId;
    // Some KernelSU builds return a plain module-id string;
    // others return JSON: {"moduleDir":"/data/adb/modules/<id>"}
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const dir = parsed.moduleDir;
      if (typeof dir === "string" && dir.trim()) {
        return dir.trim().replace(/\/$/, "").split("/").pop() || defaultId;
      }
    } catch {
      // not JSON — treat raw value as the module id directly
    }
    return raw.trim() || defaultId;
  } catch {
    return defaultId;
  }
}

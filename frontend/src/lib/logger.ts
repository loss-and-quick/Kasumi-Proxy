// ============================================================
// src/lib/logger.ts
// The UI's own diagnostics. Nothing here goes to the backend: a desktop user has a
// developer console and a phone user has none, so what the UI can do is keep the
// last records in memory and show them in the diagnostics section. That covers
// exactly the failures nobody sees otherwise — a render throw, a rejected promise,
// a frame the bridge dropped on the floor.
// ============================================================

export type LogLevel = "error" | "warn" | "info" | "debug";

export interface LogRecord {
  at: string;
  level: LogLevel;
  message: string;
  /** Context worth keeping: the command name, the profile id, the route. */
  fields?: Record<string, unknown>;
  stack?: string;
}

/** Enough to cover a session of a broken screen, few enough to keep on a phone. */
const LIMIT = 200;

const records: LogRecord[] = [];

/** `debug`/`info` are development noise; errors and warnings are always worth the
 *  console line, whoever is running the build. */
function consoleWorthy(level: LogLevel): boolean {
  return level === "error" || level === "warn" || Boolean(import.meta.env?.DEV);
}

/** Record one event. Never throws: a logger that breaks the app is worse than none. */
export function logEvent(
  level: LogLevel,
  message: string,
  fields?: Record<string, unknown>,
  stack?: string,
): void {
  try {
    const record: LogRecord = { at: new Date().toISOString(), level, message };
    if (fields && Object.keys(fields).length > 0) record.fields = fields;
    if (stack) record.stack = stack;
    records.push(record);
    if (records.length > LIMIT) records.shift();
    if (consoleWorthy(level)) {
      const suffix = record.fields ? ` ${JSON.stringify(record.fields)}` : "";
      const line = `[kasumi] ${record.message}${suffix}`;
      if (level === "error") console.error(line, stack ?? "");
      else if (level === "warn") console.warn(line);
      else if (level === "info") console.info(line);
      else console.debug(line);
    }
  } catch {
    // A diagnostics aid must not be able to break the screen it describes.
  }
}

export const logError = (message: string, fields?: Record<string, unknown>, stack?: string) =>
  logEvent("error", message, fields, stack);
export const logWarn = (message: string, fields?: Record<string, unknown>, stack?: string) =>
  logEvent("warn", message, fields, stack);
export const logInfo = (message: string, fields?: Record<string, unknown>) =>
  logEvent("info", message, fields);
export const logDebug = (message: string, fields?: Record<string, unknown>) =>
  logEvent("debug", message, fields);

/** The buffered records, oldest first. */
export function recentLogs(): LogRecord[] {
  return [...records];
}

export function clearLogs(): void {
  records.length = 0;
}

/** One record per line, the shape the diagnostics sheet shows and copies. */
export function formatLogs(entries: LogRecord[]): string {
  return entries
    .map((r) => {
      const fields = r.fields ? ` ${JSON.stringify(r.fields)}` : "";
      return `${r.at} ${r.level.toUpperCase().padEnd(5)} ${r.message}${fields}`;
    })
    .join("\n");
}

/** How many records are worth showing (anything but debug). */
export function notableCount(): number {
  return records.filter((r) => r.level !== "debug").length;
}

/** A thrown value's stack, when it is an Error. Hand it to any of the above. */
export function errorStack(e: unknown): string | undefined {
  return e instanceof Error ? e.stack : undefined;
}

/**
 * Catch what React will not: an error thrown outside a boundary, a promise nobody
 * awaited. Both end in a blank screen or a silently dead button otherwise.
 */
export function installGlobalHandlers(): void {
  if (typeof window === "undefined") return;
  window.addEventListener("error", (event) => {
    logError(
      event.message || "uncaught error",
      { source: event.filename, line: event.lineno },
      event.error instanceof Error ? event.error.stack : undefined,
    );
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    logError(
      reason instanceof Error ? reason.message : String(reason),
      { kind: "unhandledrejection" },
      reason instanceof Error ? reason.stack : undefined,
    );
  });
}

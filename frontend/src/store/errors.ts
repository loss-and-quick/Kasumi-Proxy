export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A failed write the store has already told the user about, so a caller that
 *  catches it for control flow doesn't toast it a second time. */
export class ReportedError extends Error {
  constructor(cause: unknown) {
    super(errorMessage(cause));
    this.name = "ReportedError";
  }
}

export const wasReported = (error: unknown): boolean => error instanceof ReportedError;

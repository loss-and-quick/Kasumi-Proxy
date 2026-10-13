import { z } from "zod";
import { AppState_DeserializeSchema } from "../generated/schemas";

/** A backup as the import reads it. Its profiles go to the backend unchecked: a
 *  backup can predate the current profile shape, and the backend's migrations
 *  lift an old profile before typing it, leaving out one that still doesn't fit. */
export const BackupSchema = AppState_DeserializeSchema.extend({
  profiles: z.array(z.unknown()).optional(),
});

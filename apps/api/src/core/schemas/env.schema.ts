import { z } from "zod";

export const envSchema = z.object({
  /** The database remote URL or local file */
  DB_URL: z.union([z.string().regex(/^file:/), z.url()]),
});

import { z } from "zod";

/**
 * @description The query params schema.
 */
export const queryParamsSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(10).max(50).default(10),
});

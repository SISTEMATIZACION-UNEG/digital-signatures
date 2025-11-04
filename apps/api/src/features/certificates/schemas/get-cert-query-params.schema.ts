import { z } from "zod";

import { certificateStatus } from "@/database/enums";

import { queryParamsSchema } from "@/core/schemas/query-params.schema";

export const getCertQueryParamsSchema = queryParamsSchema.extend({
  status: z.enum(certificateStatus).optional(),
});

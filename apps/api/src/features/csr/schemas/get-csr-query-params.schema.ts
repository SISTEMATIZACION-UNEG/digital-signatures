import { z } from "zod";

import { certificationRequestStatuses } from "@/database/enums";

import { queryParamsSchema } from "@/core/schemas/query-params.schema";

export const getCsrQueryParamsSchema = queryParamsSchema.extend({
  status: z.enum(certificationRequestStatuses).optional(),
});

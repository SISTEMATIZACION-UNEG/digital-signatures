import "dotenv/config";

import { envSchema } from "../schemas/env.schema";

/**
 * The environment variables.
 */
export const env = envSchema.parse(process.env);

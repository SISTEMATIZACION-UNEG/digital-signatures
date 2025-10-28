import { createClient } from "@libsql/client";
import "dotenv/config";
import { drizzle } from "drizzle-orm/libsql";

import { env } from "@/core/utils/env";

/** The database client. */
export const client = createClient({
  url: env.DB_URL,
});

/** The database instance. */
export const db = drizzle({ client });

import "dotenv/config";
import { defineConfig } from "drizzle-kit";

import { env } from "@/core/utils/env";

export default defineConfig({
  out: "./drizzle",
  schema: "./src/database/schema.ts",
  dialect: "sqlite",
  dbCredentials: {
    url: env.DB_URL,
  },
});

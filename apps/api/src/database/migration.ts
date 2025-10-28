import "dotenv/config";
import { migrate } from "drizzle-orm/libsql/migrator";

import { db } from "./client";

// This will run migrations on the database, skipping the ones already applied.
await migrate(db, { migrationsFolder: "./drizzle" });

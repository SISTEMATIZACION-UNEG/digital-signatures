import { Hono } from "hono";

import { authRoutes } from "./features/auth/auth.routes";

/**
 * @description The main app.
 */
export const app = new Hono();

app.route("/api/auth", authRoutes);

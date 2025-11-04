import { Hono } from "hono";

import { authRoutes } from "./features/auth/auth.routes";
import { csrRoutes } from "./features/csr/csr.routes";

/**
 * @description The main app.
 */
export const app = new Hono();

app.route("/api/auth", authRoutes);
app.route("/api/csr", csrRoutes);

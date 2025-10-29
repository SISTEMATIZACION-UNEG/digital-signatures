import { authMiddleware } from "@/middleware/auth.middleware";
import { Hono } from "hono";

import { AuthController } from "./controller";

/**
 * @description The auth routes.
 */
export const authRoutes = new Hono();

authRoutes.post("/sign-up", AuthController.signUp);
authRoutes.post("/login", AuthController.login);

// Protected routes.
authRoutes.use(...authMiddleware);
authRoutes.get("/me", AuthController.me);
authRoutes.post("/logout", AuthController.logout);

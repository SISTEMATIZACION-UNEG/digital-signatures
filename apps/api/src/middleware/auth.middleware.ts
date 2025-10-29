import { createMiddleware } from "hono/factory";
import { jwt } from "hono/jwt";

import { JwtService } from "@/core/services/jwt";
import { ApiResponse } from "@/core/utils/api-response";
import { env } from "@/core/utils/env";

/**
 * @description The authentication middleware.
 */
export const authMiddleware = [
  jwt({ secret: env.JWT_SECRET, cookie: JwtService.COOKIE_NAME }),
  createMiddleware(async (c, next) => {
    const payload = JwtService.getSafePayload(c);

    // The JWT payload is invalid.
    if (!payload) {
      return ApiResponse.error(c, {
        status: 401,
        message: "Invalid token",
      });
    }

    await next();
  }),
];

import dayjs from "dayjs";
import type { Context } from "hono";
import { deleteCookie, setCookie } from "hono/cookie";
import { sign } from "hono/jwt";

import { jwtPayloadSchema, type JwtPayload } from "../schemas/jwt.schema";
import { env } from "../utils/env";

/**
 * @description Utility class for working with JWT tokens.
 */
export class JwtService {
  /**
   * @description The JWT payload key in the context.
   */
  static readonly COOKIE_NAME = "auth-token";

  /**
   * @description Generates a JWT token.
   * @param userId - The user ID.
   * @returns The JWT token.
   */
  static async generate(userId: string) {
    const now = dayjs();

    const payload = {
      iat: now.unix(),
      nbf: now.unix(),
      exp: now.add(1, "day").unix(),
      sub: userId,
    } satisfies JwtPayload;

    const token = await sign(payload, env.JWT_SECRET);

    return token;
  }

  /**
   * @description Sets the JWT token cookie.
   * @param c - The context.
   * @param token - The JWT token.
   */
  static setTokenCookie(c: Context, token: string) {
    setCookie(c, JwtService.COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24,
    });
  }

  /**
   * @description Clears the JWT token cookie.
   * @param c - The context.
   */
  static clearTokenCookie(c: Context) {
    deleteCookie(c, JwtService.COOKIE_NAME);
  }

  /**
   * @description Gets the JWT payload from the context.
   * @param c - The context.
   * @returns The JWT payload.
   */
  static getSafePayload(c: Context) {
    const payload = jwtPayloadSchema.safeParse(c.get("jwtPayload"));

    return payload.success ? payload.data : null;
  }

  /**
   * @description Gets the JWT payload from the context.
   * @param c - The context.
   * @returns The JWT payload.
   */
  static getPayload(c: Context) {
    return jwtPayloadSchema.parse(c.get("jwtPayload"));
  }
}

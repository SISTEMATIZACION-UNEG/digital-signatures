import { z } from "zod";

/**
 * @description The JWT payload schema.
 */
export const jwtPayloadSchema = z.object({
  iat: z.number().int().positive(),
  nbf: z.number().int().positive(),
  exp: z.number().int().positive(),
  sub: z.ulid(),
});

export type JwtPayload = z.infer<typeof jwtPayloadSchema>;

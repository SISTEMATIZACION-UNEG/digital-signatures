import { z } from "zod";

export const envSchema = z.object({
  /** The database remote URL or local file */
  DB_URL: z.union([z.string().regex(/^file:/), z.url()]),
  /** The JWT secret */
  JWT_SECRET: z.string().min(1),
  /** The blockchain RPC URL. */
  BLOCKCHAIN_RPC_URL: z.url(),
  /** The file path to CA certificate. */
  CA_CERTIFICATE_PATH: z.string().min(1),
  /** The file path to CA key. */
  CA_KEY_PATH: z.string().min(1),
});

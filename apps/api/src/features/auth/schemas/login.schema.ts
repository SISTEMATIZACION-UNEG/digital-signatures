import { z } from "zod";

/**
 * @description The login schema.
 */
export const loginSchema = z.object({
  username: z.string().min(1, "Debe ingresar un nombre de usuario"),
  password: z.string().min(1, "Debe ingresar la contraseña"),
});

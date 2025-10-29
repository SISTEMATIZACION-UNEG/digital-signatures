import { z } from "zod";

/**
 * @description The sign up schema.
 */
export const signUpSchema = z.object({
  username: z
    .string()
    .min(1, "Debe ingresar un nombre de usuario")
    .max(20, "El nombre de usuario no puede tener más de 20 caracteres"),
  password: z
    .string()
    .min(1, "Debe ingresar la contraseña")
    .min(8, "La contraseña debe tener al menos 8 caracteres"),
});

export type SignUp = z.infer<typeof signUpSchema>;

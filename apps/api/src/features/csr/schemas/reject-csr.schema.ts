import z from "zod";

/**
 * @description The review certification request schema.
 */
export const rejectCsrSchema = z.object({
  rejectionReason: z
    .string()
    .min(1, "Debe ingresar el motivo de rechazo")
    .max(250, "El motivo de rechazo no puede tener más de 250 caracteres"),
});

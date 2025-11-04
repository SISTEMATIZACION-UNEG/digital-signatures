import forge from "node-forge";
import { z } from "zod";

import { isCountryCode } from "@/core/utils/iso-codes";

import type { OIDName } from "../csr.constants";

/**
 * @description The schema by attribute.
 */
const schemaByAttribute = {
  commonName: z.string().min(1, "Debe ingresar un nombre común"),
  organizationName: z.string().min(1, "Debe ingresar una organización"),
  organizationalUnitName: z
    .string()
    .min(1, "Debe ingresar un nombre de unidad de organización"),
  countryName: z
    .string()
    .length(2, "Debe ingresar el código del país")
    .refine(isCountryCode, "El código del país no es un código ISO válido"),
  stateOrProvinceName: z.string().min(1, "Debe ingresar un estado"),
  localityName: z.string().min(1, "Debe ingresar una localidad"),
  emailAddress: z.email("Debe ingresar un correo electrónico válido"),
} as const satisfies Partial<Record<OIDName, z.ZodType>>;

/**
 * @description The CSR schema.
 */
export const csrSchema = z.object({
  request: z.string("Debe ingresar el CSR").superRefine((value, ctx) => {
    let csr: forge.pki.CertificateSigningRequest | undefined;

    try {
      csr = forge.pki.certificationRequestFromPem(value);

      // Verify the CSR.
      if (!csr.verify()) throw new Error();
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: "CSR inválido",
      });

      return;
    }

    // The CSR doesn't have a public key.
    if (!csr.publicKey) {
      ctx.addIssue({
        code: "custom",
        message: "CSR no tiene una clave pública asociada",
      });
    }

    if (csr.attributes.length === 0) {
      // The CSR doesn't have attributes.
      ctx.addIssue({
        code: "custom",
        message: "CSR no tiene atributos",
      });
    } else {
      let hasInvalidAttributes = false;

      // Validate the attributes.
      for (const attribute in schemaByAttribute) {
        const value = csr.getAttribute({
          name: attribute,
        })?.value;

        // Validate the attribute.
        const parsedAttribute =
          schemaByAttribute[
            attribute as keyof typeof schemaByAttribute
          ].safeParse(value);

        if (!parsedAttribute.success) {
          hasInvalidAttributes = true;

          ctx.addIssue({
            code: "custom",
            path: ["attributes", attribute],
            message:
              parsedAttribute.error.issues[0]?.message || "Valor inválido",
          });
        }
      }

      // The CSR contains invalid attributes.
      if (hasInvalidAttributes) {
        ctx.addIssue({
          code: "custom",
          message: "CSR contiene atributos inválidos",
        });
      }
    }
  }),
});

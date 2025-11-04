import type { Context } from "hono";

import { CertificateDao } from "@/database/dao/certificate.dao";

import { JwtService } from "@/core/services/jwt.service";
import { ApiResponse } from "@/core/utils/api-response";

import { getCertQueryParamsSchema } from "./schemas/get-cert-query-params.schema";
import { hashSchema } from "./schemas/hash.schema";

export class CertificatesController {
  /**
   * @description Gets all the certificates.
   * @param c - The context.
   * @returns The response.
   */
  static async getCertificates(c: Context) {
    const parsedQueryParams = getCertQueryParamsSchema.safeParse(c.req.query());

    const queryParams = parsedQueryParams.data ?? {
      page: 1,
      limit: 10,
    };

    // Get the certificates.
    const certificates = await CertificateDao.getCertificates(queryParams);

    return ApiResponse.success(c, {
      data: certificates,
      status: 200,
    });
  }

  /**
   * @description Gets all the certificates of the current user.
   * @param c - The context.
   * @returns The response.
   */
  static async getMyCertificates(c: Context) {
    const parsedQueryParams = getCertQueryParamsSchema.safeParse(c.req.query());

    const queryParams = parsedQueryParams.data ?? {
      page: 1,
      limit: 10,
    };

    // Get the user.
    const userId = JwtService.getPayload(c).sub;

    // Get the certificates.
    const certificates = await CertificateDao.getCertificates({
      ...queryParams,
      userId,
    });

    return ApiResponse.success(c, {
      data: certificates,
      status: 200,
    });
  }

  /**
   * @description Verifies a certificate.
   * @param c - The context.
   * @param hash - The certificate hash.
   * @returns The response.
   */
  static async verifyCertificate(c: Context, hash: string) {
    // Verify the hash.
    const parsedHash = hashSchema.safeParse(hash);

    if (!parsedHash.success) {
      return ApiResponse.error(c, {
        message: "Hash no válido",
        status: 400,
      });
    }

    // Get the certificate.
    const certificate = await CertificateDao.findByHash(parsedHash.data);

    if (!certificate) {
      return ApiResponse.success(c, {
        data: {
          found: false,
          trust: false,
          message: "Certificado no encontrado",
        },
        status: 404,
      });
    }

    // Handle when the certificate hasn't been registered in the blockchain.
    if (certificate.status === "pending-signature") {
      return ApiResponse.success(c, {
        data: {
          found: true,
          trust: false,
          message: "Certificado aún no ha sido registrado en la blockchain",
        },
        status: 200,
      });
    }

    return ApiResponse.success(c, {
      data: {
        found: true,
        trust: true,
        message: "Certificado válido",
      },
      status: 200,
    });
  }
}

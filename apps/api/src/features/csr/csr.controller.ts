import type { Context } from "hono";
import forge from "node-forge";
import z from "zod";

import { CertificationRequestDao } from "@/database/dao/certification-request";

import { CertificateService } from "@/core/services/certificate.service";
import { JwtService } from "@/core/services/jwt.service";
import { ApiResponse } from "@/core/utils/api-response";

import { binaryToCsr, certificateToBinary, csrToBinary } from "./csr.utils";
import { csrSchema } from "./schemas/csr.schema";
import { getCsrQueryParamsSchema } from "./schemas/get-csr-query-params.schema";
import { rejectCsrSchema } from "./schemas/reject-csr.schema";

export class CsrController {
  /**
   * @description Requests a new certificate.
   * @param c - The context.
   * @returns The response.
   */
  static async requestCertificate(c: Context) {
    const body = await c.req.json();
    const parsedBody = csrSchema.safeParse(body);

    // The request is invalid.
    if (!parsedBody.success) {
      return ApiResponse.failure(c, {
        status: 400,
        data: z.treeifyError(parsedBody.error).properties,
      });
    }

    // Get the user.
    const user = JwtService.getPayload(c);

    // Check if the user has a pending certification request.
    const hasPendingRequest =
      await CertificationRequestDao.userHasPendingRequest(user.sub);

    if (hasPendingRequest) {
      return ApiResponse.error(c, {
        status: 400,
        message: "Ya tienes una solicitud de certificado pendiente",
      });
    }

    // Get the CSR.
    const csr = forge.pki.certificationRequestFromPem(parsedBody.data.request);
    const csrAsBinary = csrToBinary(csr);

    // Get the public key fingerprint.
    const publicKeyFingerprint = forge.pki
      .getPublicKeyFingerprint(csr.publicKey as forge.pki.PublicKey, {
        md: forge.md.sha256.create(),
      })
      .toHex();

    // Check if the public key fingerprint is taken.
    const isPublicKeyFingerprintTaken =
      await CertificationRequestDao.isPublicKeyFingerprintTaken(
        publicKeyFingerprint,
      );

    if (isPublicKeyFingerprintTaken) {
      return ApiResponse.error(c, {
        status: 409,
        message: "Debe generar un nuevo par de claves",
      });
    }

    // Store the certification request.
    const certificationRequest = await CertificationRequestDao.create({
      userId: user.sub,
      csr: csrAsBinary,
      publicKeyFingerprint,
    });

    if (!certificationRequest) {
      return ApiResponse.error(c, {
        status: 500,
        message: "Error al crear la solicitud de certificado",
      });
    }

    return ApiResponse.success(c, {
      status: 200,
      data: certificationRequest,
    });
  }

  /**
   * @description Gets all certification requests.
   * @param c - The context.
   * @returns The response.
   */
  static async getCertificationRequests(c: Context) {
    const parsedQueryParams = getCsrQueryParamsSchema.safeParse(c.req.query());

    const queryParams = parsedQueryParams.data ?? {
      page: 1,
      limit: 10,
    };

    // Get the certification requests.
    const certificationRequests =
      await CertificationRequestDao.getCertificationRequests(queryParams);

    return ApiResponse.success(c, {
      status: 200,
      data: certificationRequests,
    });
  }

  /**
   * @description Gets all certification requests for the current user.
   * @param c - The context.
   * @returns The response.
   */
  static async getMyCertificationRequests(c: Context) {
    const userId = JwtService.getPayload(c).sub;
    const parsedQueryParams = getCsrQueryParamsSchema.safeParse(c.req.query());

    const queryParams = parsedQueryParams.data ?? {
      page: 1,
      limit: 10,
    };

    // Get the certification requests.
    const certificationRequests =
      await CertificationRequestDao.getCertificationRequests({
        userId,
        ...queryParams,
      });

    return ApiResponse.success(c, {
      status: 200,
      data: certificationRequests,
    });
  }

  /**
   * @description Rejects a certification request.
   * @param c - The context.
   * @param id - The certification request ID.
   * @returns The response.
   */
  static async rejectCertificationRequest(c: Context, id: string) {
    const body = await c.req.json();
    const parsedBody = rejectCsrSchema.safeParse(body);

    // The request is invalid.
    if (!parsedBody.success) {
      return ApiResponse.failure(c, {
        status: 400,
        data: z.treeifyError(parsedBody.error).properties,
      });
    }

    // Get the certification request.
    const certificationRequest = await CertificationRequestDao.findById(id);

    if (!certificationRequest) {
      return ApiResponse.error(c, {
        status: 404,
        message: "CSR no encontrado",
      });
    }

    if (certificationRequest.status !== "pending") {
      return ApiResponse.error(c, {
        status: 400,
        message: "CSR ya fue revisado",
      });
    }

    // Reject the certification request.
    const rejectedCertificationRequest = await CertificationRequestDao.reject({
      id,
      rejectionReason: parsedBody.data.rejectionReason,
    });

    if (!rejectedCertificationRequest) {
      return ApiResponse.error(c, {
        status: 500,
        message: "Error al rechazar el CSR",
      });
    }

    return ApiResponse.success(c, {
      status: 200,
      data: rejectedCertificationRequest,
    });
  }

  /**
   * @description Approves a certification request.
   * @param c - The context.
   * @param id - The certification request ID.
   * @returns The response.
   */
  static async approveCertificationRequest(c: Context, id: string) {
    // Get the certification request.
    const certificationRequest =
      await CertificationRequestDao.findByIdWithCsr(id);

    if (!certificationRequest) {
      return ApiResponse.error(c, {
        status: 404,
        message: "CSR no encontrado",
      });
    }

    if (certificationRequest.status !== "pending") {
      return ApiResponse.error(c, {
        status: 400,
        message: "CSR ya fue revisado",
      });
    }

    // Generate the certificate from the CSR.
    const certificate = await CertificateService.generate({
      userId: certificationRequest.userId,
      csr: binaryToCsr(certificationRequest.csr),
    });

    const certificateHash = certificate.md.digest().toHex();

    // Store the certificate.
    const userId = JwtService.getPayload(c).sub;
    const certificateAsBinary = certificateToBinary(certificate);

    const storedCertificate = await CertificationRequestDao.approve({
      certificate: certificateAsBinary,
      certificateHash,
      certificateRequestId: certificationRequest.id,
      userId,
    });

    if (!storedCertificate) {
      return ApiResponse.error(c, {
        status: 400,
        message: "Ocurrió un error al aprobar CSR",
      });
    }

    return ApiResponse.success(c, {
      status: 200,
      data: {
        certificate: forge.pki.certificateToPem(certificate),
      },
    });
  }
}

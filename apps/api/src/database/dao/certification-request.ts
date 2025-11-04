import { count, eq, sql } from "drizzle-orm";

import { createPaginationResult } from "@/core/utils/create-pagination-result";

import { db } from "../client";
import type { CertificationRequestStatus } from "../enums";
import { certificates, certificationRequests } from "../schema";

export class CertificationRequestDao {
  /**
   * @description Creates a new certificate request.
   * @param certificateRequest - The certificate request to create.
   * @returns The created certificate request.
   */
  static async create({
    userId,
    csr,
    publicKeyFingerprint,
  }: {
    userId: string;
    csr: Buffer;
    publicKeyFingerprint: string;
  }) {
    const [insertedCertificationRequest] = await db
      .insert(certificationRequests)
      .values({
        userId,
        csr,
        publicKeyFingerprint,
      })
      .returning();

    if (!insertedCertificationRequest) return null;

    // Remove the CSR from the certification request.
    const { csr: _, ...certificationRequest } = insertedCertificationRequest;

    return certificationRequest;
  }

  /**
   * @description Checks if a user has a pending certification request.
   * @param userId - The user ID.
   * @returns True if the user has a pending certification request, false otherwise.
   */
  static async userHasPendingRequest(userId: string) {
    const certificationRequest = await db.query.certificationRequests.findFirst(
      {
        columns: {
          id: true,
        },
        where: (certificationRequests, { eq, and }) =>
          and(
            eq(certificationRequests.userId, userId),
            eq(certificationRequests.status, "pending"),
          ),
      },
    );

    return Boolean(certificationRequest);
  }

  /**
   * @description Checks if a public key fingerprint is taken.
   * @param publicKeyFingerprint - The public key fingerprint to check.
   * @returns True if the public key fingerprint is taken, false otherwise.
   */
  static async isPublicKeyFingerprintTaken(publicKeyFingerprint: string) {
    const certificationRequest = await db.query.certificationRequests.findFirst(
      {
        columns: {
          id: true,
        },
        where: (certificationRequests, { eq }) =>
          eq(certificationRequests.publicKeyFingerprint, publicKeyFingerprint),
      },
    );

    return Boolean(certificationRequest);
  }

  /**
   * @description Finds a certification request by ID.
   * @param id - The certification request ID.
   * @returns The certification request.
   */
  static async findById(id: string) {
    return db.query.certificationRequests.findFirst({
      columns: {
        csr: false,
      },
      where: (certificationRequests, { eq }) =>
        eq(certificationRequests.id, id),
    });
  }

  /**
   * @description Finds a certification request by ID with the CSR.
   * @param id - The certification request ID.
   * @returns The certification request.
   */
  static async findByIdWithCsr(id: string) {
    return db.query.certificationRequests.findFirst({
      where: (certificationRequests, { eq }) =>
        eq(certificationRequests.id, id),
    });
  }

  /**
   * @description Gets all certification requests.
   * @returns The certification requests.
   */
  static async getCertificationRequests({
    page,
    limit,
    status,
    userId,
  }: {
    page: number;
    limit: number;
    status?: CertificationRequestStatus;
    userId?: string;
  }) {
    // Calculate the offset.
    const offset = (page - 1) * limit;

    const results = await db.query.certificationRequests.findMany({
      columns: {
        csr: false,
      },
      with: {
        user: {
          columns: {
            id: true,
            username: true,
          },
        },
      },
      limit,
      offset,
      where:
        !status && !userId
          ? undefined
          : (certificationRequests, { eq, and }) =>
              and(
                status ? eq(certificationRequests.status, status) : undefined,
                userId ? eq(certificationRequests.userId, userId) : undefined,
              ),
      orderBy: (certificationRequests, { desc }) =>
        desc(certificationRequests.createdAt),
    });

    const [total] = await db
      .select({ count: count() })
      .from(certificationRequests);

    return createPaginationResult({
      items: results,
      total: total?.count ?? 0,
      page,
      limit,
    });
  }

  /**
   * @description Rejects a certification request.
   * @param id - The certification request ID.
   * @param rejectionReason - The rejection reason.
   * @returns The rejected certification request.
   */
  static async reject({
    id,
    rejectionReason,
  }: {
    id: string;
    rejectionReason: string;
  }) {
    const [updatedCertificationRequest] = await db
      .update(certificationRequests)
      .set({
        status: "rejected",
        rejectionReason,
        reviewedAt: sql`(CURRENT_TIMESTAMP)`,
      })
      .where(eq(certificationRequests.id, id))
      .returning();

    if (!updatedCertificationRequest) return null;

    // Remove the CSR from the certification request.
    const { csr: _, ...certificationRequest } = updatedCertificationRequest;

    return certificationRequest;
  }

  /**
   * @description Approves the CSR and stores the certificate.
   * @param certificate - The data to store a new certificate.
   * @returns The stored certificate on success, otherwise null.
   */
  static async approve({
    certificate,
    certificateHash,
    certificateRequestId,
    userId,
  }: {
    certificateRequestId: string;
    userId: string;
    certificate: Buffer;
    certificateHash: string;
  }) {
    try {
      const newCertificate = await db.transaction(async (tx) => {
        // Approve the request.
        const [csr] = await tx
          .update(certificationRequests)
          .set({
            status: "approved",
            reviewedAt: sql`(CURRENT_TIMESTAMP)`,
          })
          .returning({
            status: certificationRequests.status,
          });

        if (!csr || csr.status !== "approved") {
          tx.rollback();
          return null;
        }

        console.log({
          userId,
          certificateHash,
          certificateRequestId,
          certificate: certificate.length,
        });

        // Store the certificate.
        const [insertedCertificate] = await tx
          .insert(certificates)
          .values({
            userId,
            hash: certificateHash,
            certificate,
            certificateRequestId,
          })
          .returning();

        if (!insertedCertificate) {
          tx.rollback();
          return null;
        }

        const { certificate: _, ...restOfCertificate } = insertedCertificate;

        return restOfCertificate;
      });

      return newCertificate;
    } catch (e) {
      console.error(e);

      return null;
    }
  }
}

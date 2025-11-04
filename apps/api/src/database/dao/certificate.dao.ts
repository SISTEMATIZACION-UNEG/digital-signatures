import { count } from "drizzle-orm";

import { createPaginationResult } from "@/core/utils/create-pagination-result";

import { db } from "../client";
import type { CertificateStatus } from "../enums";
import { certificates } from "../schema";

export class CertificateDao {
  /**
   * @description Gets all certificates.
   * @returns The certificates.
   */
  static async getCertificates({
    page,
    limit,
    status,
    userId,
  }: {
    page: number;
    limit: number;
    status?: CertificateStatus;
    userId?: string;
  }) {
    // Calculate the offset.
    const offset = (page - 1) * limit;

    const results = await db.query.certificates.findMany({
      columns: {
        certificate: false,
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
          : (certificates, { eq, and }) =>
              and(
                status ? eq(certificates.status, status) : undefined,
                userId ? eq(certificates.userId, userId) : undefined,
              ),
      orderBy: (certificates, { desc }) => desc(certificates.createdAt),
    });

    const [total] = await db.select({ count: count() }).from(certificates);

    return createPaginationResult({
      items: results,
      total: total?.count ?? 0,
      page,
      limit,
    });
  }

  /**
   * @description Finds a certificate by its hash.
   * @param hash - The hash of the certificate.
   * @returns The certificate if exists, otherwise null.
   */
  static async findByHash(hash: string) {
    const certificate = await db.query.certificates.findFirst({
      columns: {
        certificate: false,
      },
      where: (fields, { eq }) => eq(fields.hash, hash),
    });

    return certificate ?? null;
  }
}

import { relations, sql } from "drizzle-orm";
import { sqliteTable, text, blob } from "drizzle-orm/sqlite-core";

import { createUlid } from "@/core/utils/create-ulid";

import type {
  UserRole,
  CertificationRequestStatus,
  CertificateStatus,
} from "./enums";

/** The users table. */
export const users = sqliteTable("users", {
  id: text()
    .$defaultFn(() => createUlid())
    .primaryKey(),
  username: text({ length: 80 }).notNull().unique(),
  password: text().notNull(),
  role: text().$type<UserRole>().notNull().default("user"),
});

export const usersRelations = relations(users, ({ many }) => ({
  certificationRequests: many(certificationRequests),
  certificates: many(certificates),
}));

/** The certificate signing requests table. */
export const certificationRequests = sqliteTable("certification_requests", {
  id: text()
    .$defaultFn(() => createUlid())
    .primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  csr: blob({ mode: "buffer" }).notNull(),
  publicKeyFingerprint: text("public_key_fingerprint").notNull().unique(),
  status: text()
    .$type<CertificationRequestStatus>()
    .notNull()
    .default("pending"),
  rejectionReason: text("rejection_reason", { length: 255 }),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`),
  reviewedAt: text("reviewed_at"),
  updatedAt: text("updated_at")
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`)
    .$onUpdateFn(() => sql`(CURRENT_TIMESTAMP)`),
});

export const certificationRequestsRelations = relations(
  certificationRequests,
  ({ one }) => ({
    user: one(users, {
      fields: [certificationRequests.userId],
      references: [users.id],
    }),
    certificateRequest: one(certificates, {
      fields: [certificationRequests.id],
      references: [certificates.certificateRequestId],
    }),
  }),
);

/** The certificates table. */
export const certificates = sqliteTable("certificates", {
  id: text()
    .$defaultFn(() => createUlid())
    .primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  certificateRequestId: text("certificate_request_id").references(
    () => certificationRequests.id,
  ),
  certificate: blob({ mode: "buffer" }).notNull(),
  hash: text().notNull().unique(),
  status: text()
    .$type<CertificateStatus>()
    .notNull()
    .default("pending-signature"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`),
});

export const certificatesRelations = relations(certificates, ({ one }) => ({
  user: one(users, {
    fields: [certificates.userId],
    references: [users.id],
  }),
  certificateRequest: one(certificationRequests, {
    fields: [certificates.certificateRequestId],
    references: [certificationRequests.id],
  }),
}));

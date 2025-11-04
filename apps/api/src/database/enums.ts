export const userRoles = ["admin", "user"] as const;

/** The role of a user. */
export type UserRole = (typeof userRoles)[number];

export const certificationRequestStatuses = [
  "pending",
  "approved",
  "rejected",
] as const;

/** The status of a certification request. */
export type CertificationRequestStatus =
  (typeof certificationRequestStatuses)[number];

export const certificateStatus = ["pending-signature", "confirmed"] as const;

/** The status of a certificate. */
export type CertificateStatus = (typeof certificateStatus)[number];

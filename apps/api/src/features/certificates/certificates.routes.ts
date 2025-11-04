import { authMiddleware } from "@/middleware/auth.middleware";
import { Hono } from "hono";

import { CertificatesController } from "./certificates.controller";

/**
 * @description The certificates routes.
 */
export const certificatesRoutes = new Hono();

certificatesRoutes.get("/:hash/verify", (c) => {
  const hash = c.req.param("hash");

  return CertificatesController.verifyCertificate(c, hash);
});

// Protected routes.
certificatesRoutes.use(...authMiddleware);
certificatesRoutes.get("/", CertificatesController.getCertificates);
certificatesRoutes.get("/my", CertificatesController.getMyCertificates);

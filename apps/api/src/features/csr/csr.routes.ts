import { authMiddleware } from "@/middleware/auth.middleware";
import { Hono } from "hono";

import { CsrController } from "./csr.controller";

/**
 * @description The CSR routes.
 */
export const csrRoutes = new Hono();

csrRoutes.use(...authMiddleware);

csrRoutes.post("/", CsrController.requestCertificate);
csrRoutes.get("/", CsrController.getCertificationRequests);
csrRoutes.get("/my", CsrController.getMyCertificationRequests);

csrRoutes.post("/:id/reject", (c) => {
  const id = c.req.param("id");

  return CsrController.rejectCertificationRequest(c, id);
});

csrRoutes.post("/:id/approve", (c) => {
  const id = c.req.param("id");

  return CsrController.approveCertificationRequest(c, id);
});

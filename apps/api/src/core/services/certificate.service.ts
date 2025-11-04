import forge from "node-forge";

import { createSerialNumber } from "../utils/create-serial-number";
import { CertificateAuthorityService } from "./ca.service";

export class CertificateService {
  /**
   * @description Generates a certificate.
   * @param csr - The CSR.
   * @returns The certificate.
   */
  static async generate({
    userId,
    csr,
  }: {
    userId: string;
    csr: forge.pki.CertificateSigningRequest;
  }) {
    // Build the certificate.
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = csr.publicKey as forge.pki.PublicKey;
    certificate.serialNumber = createSerialNumber();

    // Set the validity period (1 year).
    const fromDate = new Date();
    const toDate = new Date();
    toDate.setFullYear(toDate.getFullYear() + 1);

    certificate.validity.notBefore = fromDate;
    certificate.validity.notAfter = toDate;

    // Set the subject and extensions.
    certificate.setSubject(csr.subject.attributes);
    certificate.setExtensions([
      {
        name: "basicConstraints",
        basicConstraints: true,
        cA: false,
      },
      {
        name: "keyUsage",
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
      },
      {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true,
      },
      {
        name: "subjectKeyIdentifier",
        id: userId,
      },
    ]);

    // Set the issuer and sign the certificate.
    const ca = await CertificateAuthorityService.getCertificateAuthority();
    certificate.setIssuer(ca.certificate.subject.attributes);
    certificate.sign(ca.key, forge.md.sha256.create());

    return certificate;
  }
}

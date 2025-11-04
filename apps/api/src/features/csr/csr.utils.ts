import forge from "node-forge";

/**
 * @description Converts a CSR to a binary buffer.
 * @param csr - The CSR.
 * @returns The binary buffer.
 */
export function csrToBinary(csr: forge.pki.CertificateSigningRequest) {
  const asn1 = forge.pki.certificationRequestToAsn1(csr);
  const der = forge.asn1.toDer(asn1).getBytes();

  return Buffer.from(der, "binary");
}

/**
 * @description Converts a binary buffer to a CSR.
 * @param binary - The binary buffer.
 * @returns The CSR.
 */
export function binaryToCsr(binary: Buffer) {
  const buffer = forge.util.createBuffer(Buffer.from(binary));
  const asn1 = forge.asn1.fromDer(buffer);

  return forge.pki.certificationRequestFromAsn1(asn1);
}

/**
 * @description Converts a certificate to a binary buffer.
 * @param certificate - The certificate.
 * @returns The binary buffer.
 */
export function certificateToBinary(certificate: forge.pki.Certificate) {
  const asn1 = forge.pki.certificateToAsn1(certificate);
  const der = forge.asn1.toDer(asn1).getBytes();

  return Buffer.from(der, "binary");
}

/**
 * @description Converts a binary buffer to a certificate.
 * @param binary - The binary buffer.
 * @returns The certificate.
 */
export function binaryToCertificate(binary: Buffer) {
  const buffer = forge.util.createBuffer(Buffer.from(binary));
  const asn1 = forge.asn1.fromDer(buffer);

  return forge.pki.certificateFromAsn1(asn1);
}

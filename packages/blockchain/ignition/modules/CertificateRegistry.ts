import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("CertificateRegistryModule", (m) => {
  const certificateRegistry = m.contract("CertificateRegistry");

  return { certificateRegistry };
});

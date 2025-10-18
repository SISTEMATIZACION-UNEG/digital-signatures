import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("PKIModule", (m) => {
  const pki = m.contract("PKI");

  return { pki };
});

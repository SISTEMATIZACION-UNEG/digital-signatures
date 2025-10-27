import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("PKIRegistryModule", (m) => {
  const pkiRegistry = m.contract("PKIRegistry");

  return { pkiRegistry };
});

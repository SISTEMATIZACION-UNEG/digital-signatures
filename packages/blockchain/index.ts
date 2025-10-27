import pkiRegistryAbi from "./abi/PKIRegistry.json";

/**
 * @description The networks.
 */
export type Network = "localhost" | "unegia";

/**
 * @description The names of the contracts.
 */
export type ContractName = "pkiRegistry";

/**
 * @description The settings of the contracts.
 */
type ContractSettings = {
  abi: any;
  address: Record<Network, `0x${string}`>;
};

/**
 * @description The contracts.
 */
export const contracts: Record<ContractName, ContractSettings> = {
  pkiRegistry: {
    abi: pkiRegistryAbi,
    address: {
      localhost: "0x0000000000000000000000000000000000000000",
      unegia: "0x0000000000000000000000000000000000000000",
    },
  },
};

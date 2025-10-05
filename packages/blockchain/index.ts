import certificateRegistry from "./abi/CertificateRegistry.json";

/**
 * @description The ABI of the contracts.
 */
export const abis = {
  certificateRegistry,
} as const;

/**
 * @description The address of the contracts by network.
 */
export type ContractAddress = Record<Network, string>;

/**
 * @description The networks.
 */
export type Network = "localhost";

/**
 * @description The addresses of the contracts.
 */
export const contractAddresses: Record<keyof typeof abis, ContractAddress> = {
  certificateRegistry: {
    localhost: "0x0000000000000000000000000000000000000000",
  },
} as const;

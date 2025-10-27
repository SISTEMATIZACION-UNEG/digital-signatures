import type { HardhatUserConfig } from "hardhat/config";
import hardhatAbiExporter from "@solidstate/hardhat-abi-exporter";

import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";
import { configVariable } from "hardhat/config";

const config: HardhatUserConfig = {
  plugins: [hardhatToolboxViemPlugin, hardhatAbiExporter],
  abiExporter: {
    path: "./abi",
    runOnCompile: true,
    clear: true,
    flat: true,
    format: "json",
    // Exclude test contracts from ABI export.
    except: [/Test$/],
  },
  solidity: {
    profiles: {
      default: {
        version: "0.8.28",
      },
      production: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    hardhatOp: {
      type: "edr-simulated",
      chainType: "op",
    },
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_PRIVATE_KEY")],
    },
    unegia: {
      type: "http",
      url: "http://127.0.0.1:5600",
      accounts: [configVariable("UNEGIA_PRIVATE_KEY")],
      timeout: 60000,
      chainId: 963741852,
      from: "0x5b1483201715c90db2acd38bff8dfbd50222fb64",
      gas: 25000000,
      gasPrice: 1000000000,
    },
  },
};

export default config;

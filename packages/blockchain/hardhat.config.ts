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
      chainType: "l1",
      url: configVariable("UNEGIA_RPC_URL"),
      accounts: [configVariable("UNEGIA_PRIVATE_KEY")],
    },
  },
};

export default config;

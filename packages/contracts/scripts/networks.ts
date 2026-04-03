/**
 * Multi-chain network configuration.
 *
 * Each entry defines a supported network for clearproof contract deployment.
 * The relayer and deploy scripts iterate over these networks.
 */

export interface NetworkConfig {
  name: string;
  chainId: number;
  rpcEnvVar: string;
  defaultRpc: string;
  explorerUrl: string;
  explorerApiEnvVar: string;
  /** Whether this is a testnet (affects confirmation messages) */
  testnet: boolean;
}

export const NETWORKS: Record<string, NetworkConfig> = {
  // --- Testnets ---
  sepolia: {
    name: "sepolia",
    chainId: 11155111,
    rpcEnvVar: "SEPOLIA_RPC_URL",
    defaultRpc: "https://rpc.sepolia.org",
    explorerUrl: "https://sepolia.etherscan.io",
    explorerApiEnvVar: "ETHERSCAN_API_KEY",
    testnet: true,
  },
  "base-sepolia": {
    name: "base-sepolia",
    chainId: 84532,
    rpcEnvVar: "BASE_SEPOLIA_RPC_URL",
    defaultRpc: "https://sepolia.base.org",
    explorerUrl: "https://sepolia.basescan.org",
    explorerApiEnvVar: "BASESCAN_API_KEY",
    testnet: true,
  },
  "arbitrum-sepolia": {
    name: "arbitrum-sepolia",
    chainId: 421614,
    rpcEnvVar: "ARBITRUM_SEPOLIA_RPC_URL",
    defaultRpc: "https://sepolia-rollup.arbitrum.io/rpc",
    explorerUrl: "https://sepolia.arbiscan.io",
    explorerApiEnvVar: "ARBISCAN_API_KEY",
    testnet: true,
  },
  "polygon-amoy": {
    name: "polygon-amoy",
    chainId: 80002,
    rpcEnvVar: "POLYGON_AMOY_RPC_URL",
    defaultRpc: "https://rpc-amoy.polygon.technology",
    explorerUrl: "https://amoy.polygonscan.com",
    explorerApiEnvVar: "POLYGONSCAN_API_KEY",
    testnet: true,
  },
  "optimism-sepolia": {
    name: "optimism-sepolia",
    chainId: 11155420,
    rpcEnvVar: "OPTIMISM_SEPOLIA_RPC_URL",
    defaultRpc: "https://sepolia.optimism.io",
    explorerUrl: "https://sepolia-optimistic.etherscan.io",
    explorerApiEnvVar: "OPTIMISM_ETHERSCAN_API_KEY",
    testnet: true,
  },

  // --- Mainnets ---
  ethereum: {
    name: "ethereum",
    chainId: 1,
    rpcEnvVar: "ETHEREUM_RPC_URL",
    defaultRpc: "https://eth.llamarpc.com",
    explorerUrl: "https://etherscan.io",
    explorerApiEnvVar: "ETHERSCAN_API_KEY",
    testnet: false,
  },
  arbitrum: {
    name: "arbitrum",
    chainId: 42161,
    rpcEnvVar: "ARBITRUM_RPC_URL",
    defaultRpc: "https://arb1.arbitrum.io/rpc",
    explorerUrl: "https://arbiscan.io",
    explorerApiEnvVar: "ARBISCAN_API_KEY",
    testnet: false,
  },
  base: {
    name: "base",
    chainId: 8453,
    rpcEnvVar: "BASE_RPC_URL",
    defaultRpc: "https://mainnet.base.org",
    explorerUrl: "https://basescan.org",
    explorerApiEnvVar: "BASESCAN_API_KEY",
    testnet: false,
  },
  polygon: {
    name: "polygon",
    chainId: 137,
    rpcEnvVar: "POLYGON_RPC_URL",
    defaultRpc: "https://polygon-rpc.com",
    explorerUrl: "https://polygonscan.com",
    explorerApiEnvVar: "POLYGONSCAN_API_KEY",
    testnet: false,
  },
  optimism: {
    name: "optimism",
    chainId: 10,
    rpcEnvVar: "OPTIMISM_RPC_URL",
    defaultRpc: "https://mainnet.optimism.io",
    explorerUrl: "https://optimistic.etherscan.io",
    explorerApiEnvVar: "OPTIMISM_ETHERSCAN_API_KEY",
    testnet: false,
  },
};

/**
 * Return networks that have an RPC URL configured (env var set or default available).
 * If `filter` is provided, only return those network names.
 */
export function getConfiguredNetworks(filter?: string[]): NetworkConfig[] {
  const entries = Object.values(NETWORKS);
  if (filter && filter.length > 0) {
    return entries.filter((n) => filter.includes(n.name));
  }
  return entries;
}

/**
 * Get the RPC URL for a network, preferring env var over default.
 */
export function getRpcUrl(network: NetworkConfig): string {
  return process.env[network.rpcEnvVar] || network.defaultRpc;
}

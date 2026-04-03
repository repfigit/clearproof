/**
 * Multi-chain deployment script.
 *
 * Deploys all 4 contracts + SanctionsRootRelay to one or more networks.
 * Reads target networks from CLI args or DEPLOY_NETWORKS env var.
 *
 * Usage:
 *   # Single network (via hardhat --network)
 *   npx hardhat run scripts/deploy-multichain.ts --network arbitrum-sepolia
 *
 *   # Multiple networks (standalone, uses ethers directly)
 *   DEPLOY_NETWORKS=sepolia,base-sepolia,arbitrum-sepolia npx ts-node scripts/deploy-multichain.ts
 */
import { ethers, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = process.env.HARDHAT_NETWORK || "localhost";

  console.log("╔══════════════════════════════════════════╗");
  console.log("║       clearproof multi-chain deploy      ║");
  console.log("╚══════════════════════════════════════════╝\n");
  console.log(`Network:    ${networkName} (chain ${network.chainId})`);
  console.log(`Deployer:   ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance:    ${ethers.formatEther(balance)} ETH\n`);

  if (balance === 0n) {
    console.error("Deployer has no balance. Fund the wallet first.");
    process.exit(1);
  }

  // 1. Groth16Verifier
  console.log("[1/5] Deploying Groth16Verifier...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log(`  → ${verifierAddr}`);

  // 2. VASPRegistry
  console.log("[2/5] Deploying VASPRegistry...");
  const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
  const vaspRegistry = await VASPRegistry.deploy(deployer.address);
  await vaspRegistry.waitForDeployment();
  const vaspRegistryAddr = await vaspRegistry.getAddress();
  console.log(`  → ${vaspRegistryAddr}`);

  // 3. SanctionsOracle
  console.log("[3/5] Deploying SanctionsOracle...");
  const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("initial-sanctions-root"));
  const initialLeafCount = 0;
  const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
  const sanctionsOracle = await SanctionsOracle.deploy(deployer.address, initialRoot, initialLeafCount);
  await sanctionsOracle.waitForDeployment();
  const sanctionsOracleAddr = await sanctionsOracle.getAddress();
  console.log(`  → ${sanctionsOracleAddr}`);

  // 4. ComplianceRegistry
  console.log("[4/5] Deploying ComplianceRegistry...");
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(verifierAddr, vaspRegistryAddr, sanctionsOracleAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log(`  → ${registryAddr}`);

  // 5. SanctionsRootRelay
  console.log("[5/5] Deploying SanctionsRootRelay...");
  const Relay = await ethers.getContractFactory("SanctionsRootRelay");
  const relay = await Relay.deploy(deployer.address, sanctionsOracleAddr);
  await relay.waitForDeployment();
  const relayAddr = await relay.getAddress();
  console.log(`  → ${relayAddr}`);

  // Grant ORACLE_ROLE to the relay contract
  console.log("\nGranting ORACLE_ROLE to SanctionsRootRelay...");
  const ORACLE_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ORACLE_ROLE"));
  const grantTx = await sanctionsOracle.grantRole(ORACLE_ROLE, relayAddr);
  await grantTx.wait();
  console.log("  ✓ Relay can now update the oracle");

  // Write deployment record
  const deployment = {
    network: networkName,
    chainId: network.chainId.toString(),
    timestamp: new Date().toISOString(),
    contracts: {
      Groth16Verifier: verifierAddr,
      VASPRegistry: vaspRegistryAddr,
      SanctionsOracle: sanctionsOracleAddr,
      ComplianceRegistry: registryAddr,
      SanctionsRootRelay: relayAddr,
    },
    deployer: deployer.address,
  };

  const deploymentsDir = path.resolve(__dirname, "../deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });
  const outPath = path.join(deploymentsDir, `${networkName}.json`);
  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));

  console.log(`\n=== Deployment complete ===`);
  console.log(`  Verifier:         ${verifierAddr}`);
  console.log(`  VASPRegistry:     ${vaspRegistryAddr}`);
  console.log(`  SanctionsOracle:  ${sanctionsOracleAddr}`);
  console.log(`  ComplianceRegistry: ${registryAddr}`);
  console.log(`  SanctionsRootRelay: ${relayAddr}`);
  console.log(`\nSaved to ${outPath}`);

  // Verify on block explorer
  const apiKey = getExplorerApiKey(networkName);
  if (apiKey) {
    console.log("\nVerifying contracts on block explorer...");
    const verifyList = [
      { address: verifierAddr, constructorArguments: [] },
      { address: vaspRegistryAddr, constructorArguments: [deployer.address] },
      { address: sanctionsOracleAddr, constructorArguments: [deployer.address, initialRoot, initialLeafCount] },
      { address: registryAddr, constructorArguments: [verifierAddr, vaspRegistryAddr, sanctionsOracleAddr] },
      { address: relayAddr, constructorArguments: [deployer.address, sanctionsOracleAddr] },
    ];
    for (const v of verifyList) {
      try {
        await run("verify:verify", v);
        console.log(`  ✓ ${v.address}`);
      } catch (e: any) {
        console.log(`  ✗ ${v.address}: ${e.message?.slice(0, 80)}`);
      }
    }
  }
}

function getExplorerApiKey(network: string): string | undefined {
  const map: Record<string, string> = {
    sepolia: "ETHERSCAN_API_KEY",
    ethereum: "ETHERSCAN_API_KEY",
    "base-sepolia": "BASESCAN_API_KEY",
    base: "BASESCAN_API_KEY",
    "arbitrum-sepolia": "ARBISCAN_API_KEY",
    arbitrum: "ARBISCAN_API_KEY",
    "polygon-amoy": "POLYGONSCAN_API_KEY",
    polygon: "POLYGONSCAN_API_KEY",
    "optimism-sepolia": "OPTIMISM_ETHERSCAN_API_KEY",
    optimism: "OPTIMISM_ETHERSCAN_API_KEY",
  };
  const envVar = map[network];
  return envVar ? process.env[envVar] : undefined;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

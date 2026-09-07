/**
 * Multi-chain deployment script.
 *
 * Deploys the legacy contracts, verifier router and relay to the selected Hardhat network.
 * Verifier activation remains pending until its recorded timelock expires.
 *
 * Usage:
 *   # Single network (via hardhat --network)
 *   npx hardhat run scripts/deploy-multichain.ts --network arbitrum-sepolia
 *
 *   # Repeat the command for each explicitly selected network.
 */
import { ethers, run, network as selectedNetwork } from "hardhat";
import { prepareLegacyVerifier } from "./legacy-verifier";
import * as fs from "fs";
import * as path from "path";

/**
 * Canonical jurisdiction thresholds. ComplianceRegistry takes the default entry
 * as a constructor argument (AIF-95) so a registry can never exist unseeded;
 * the per-jurisdiction entries are seeded after deployment.
 */
const thresholdConfig = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../../config/jurisdiction_thresholds.json"), "utf-8")
);

function encodeJurisdiction(code: string): number {
  const buf = Buffer.from(code.toUpperCase(), "ascii");
  if (buf.length !== 2) throw new Error(`Jurisdiction code must be alpha-2: ${code}`);
  return (buf[0] << 8) | buf[1];
}


async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = selectedNetwork.name;

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

  const { router, verifier, selector, activation, timelockPeriod } = await prepareLegacyVerifier();
  const verifierAddr = await verifier.getAddress();
  const routerAddr = await router.getAddress();
  console.log("Verifier registration pending until chain timestamp:", activation.activateAfter);

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
  const registry = await Registry.deploy(
    routerAddr,
    selector,
    vaspRegistryAddr,
    sanctionsOracleAddr,
    thresholdConfig.default.tier2,
    thresholdConfig.default.tier3,
    thresholdConfig.default.tier4
  );
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log(`  → ${registryAddr}`);

  for (const [code, t] of Object.entries(thresholdConfig.jurisdictions) as [
    string,
    { tier2: number; tier3: number; tier4: number },
  ][]) {
    const tx = await registry.setJurisdictionThresholds(encodeJurisdiction(code), t.tier2, t.tier3, t.tier4);
    await tx.wait();
  }
  console.log(`  seeded ${Object.keys(thresholdConfig.jurisdictions).length} jurisdiction thresholds`);

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
      VerifierRouter: routerAddr,
      Groth16Verifier: verifierAddr,
      VASPRegistry: vaspRegistryAddr,
      SanctionsOracle: sanctionsOracleAddr,
      ComplianceRegistry: registryAddr,
      SanctionsRootRelay: relayAddr,
    },
    deployer: deployer.address,
    verifierActivation: activation,
  };

  const deploymentsDir = process.env.CLEARPROOF_DEPLOYMENTS_DIR || path.resolve(__dirname, "../deployments");
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
  if (apiKey && !["hardhat", "localhost"].includes(networkName)) {
    console.log("\nVerifying contracts on block explorer...");
    const verifyList = [
      { address: routerAddr, constructorArguments: [timelockPeriod] },
      { address: verifierAddr, constructorArguments: [] },
      { address: vaspRegistryAddr, constructorArguments: [deployer.address] },
      { address: sanctionsOracleAddr, constructorArguments: [deployer.address, initialRoot, initialLeafCount] },
      { address: registryAddr, constructorArguments: [routerAddr, selector, vaspRegistryAddr, sanctionsOracleAddr,
        thresholdConfig.default.tier2, thresholdConfig.default.tier3, thresholdConfig.default.tier4] },
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

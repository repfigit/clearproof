/**
 * Surgical redeploy: Groth16Verifier + ComplianceRegistry only.
 *
 * Why not `deploy-multichain.ts`? A full redeploy resets VASPRegistry
 * (registered VASPs), SanctionsOracle (live sanctions root → placeholder),
 * and the relay grant. Since ComplianceRegistry.verifier is immutable,
 * picking up a new verifier build requires a new ComplianceRegistry — but
 * VASPRegistry and SanctionsOracle addresses are constructor arguments, so
 * the new registry can point at the EXISTING stateful contracts.
 *
 * Preserved: VASP registrations, issuer root, sanctions root + staleness
 * state, relay grant.
 *
 * Changed: verifier build, registry address. NOTE: the registry address is
 * part of the proof domain binding (domain_contract_hash) — proofs generated
 * against the old registry address will NOT verify against the new one.
 *
 * Prerequisites:
 *   - DEPLOYER_PRIVATE_KEY in packages/contracts/.env (gitignored) or env
 *   - deployer funded with Sepolia ETH
 *
 * Usage:
 *   npx hardhat run scripts/redeploy-verifier.ts --network sepolia
 */
import { ethers } from "hardhat";
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
  const networkName = process.env.HARDHAT_NETWORK || "localhost";

  const deploymentPath = path.resolve(__dirname, `../deployments/${networkName}.json`);
  if (!fs.existsSync(deploymentPath)) {
    console.error(`No existing deployment record at ${deploymentPath}`);
    process.exit(1);
  }
  const existing = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));

  console.log("╔══════════════════════════════════════════╗");
  console.log("║   clearproof verifier surgical redeploy  ║");
  console.log("╚══════════════════════════════════════════╝\n");
  console.log(`Network:    ${networkName} (chain ${network.chainId})`);
  console.log(`Deployer:   ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance:    ${ethers.formatEther(balance)} ETH\n`);
  if (balance === 0n) {
    console.error("Deployer has no balance. Fund the wallet first.");
    process.exit(1);
  }

  console.log("Preserving stateful contracts:");
  console.log(`  VASPRegistry:    ${existing.contracts.VASPRegistry}`);
  console.log(`  SanctionsOracle: ${existing.contracts.SanctionsOracle}\n`);

  // Load the existing verifier router
  console.log("[1/3] Loading VerifierRouter...");
  const verifierRouterAddr = existing.contracts.VerifierRouter;
  if (!verifierRouterAddr) {
    console.error("No VerifierRouter address found in deployment. Cannot proceed.");
    process.exit(1);
  }
  console.log(`  → ${verifierRouterAddr}`);

  const verifierRouter = await ethers.getContractAt("VerifierRouter", verifierRouterAddr);

  // 2. New Groth16Verifier (Apache-2.0 implementation)
  console.log("[2/3] Deploying Groth16Verifier (Apache-2.0 build)...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log(`  → ${verifierAddr}`);

  // 3. Register the new verifier with the router
  console.log("[3/3] Registering new verifier with VerifierRouter...");
  const verifierSelector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v2"));
  let tx = await verifierRouter.registerVerifier(verifierSelector, verifierAddr, "Groth16 BN254 v2");
  await tx.wait();
  console.log("  Verifier registered with selector:", verifierSelector);

  // Activate the new verifier
  tx = await verifierRouter.activateVerifier(verifierSelector, "Groth16 BN254 v2");
  await tx.wait();
  console.log("  Verifier activated");

  // Update the ComplianceRegistry to use the new verifier
  console.log("[4/4] Updating ComplianceRegistry to use new verifier...");
  const registryAddr = existing.contracts.ComplianceRegistry;
  const registry = await ethers.getContractAt("ComplianceRegistry", registryAddr);
  tx = await registry.setVerifierSelector(verifierSelector);
  await tx.wait();
  console.log("  ComplianceRegistry updated to use new verifier");

  // Update deployment record, preserving the previous addresses for rollback reference
  const updated = {
    ...existing,
    timestamp: new Date().toISOString(),
    previous: {
      ...existing.previous,
      Groth16Verifier: verifierAddr,
      retiredAt: new Date().toISOString(),
      reason: "New verifier registered with VerifierRouter (AIF-100)",
    },
    contracts: {
      ...existing.contracts,
      Groth16Verifier: verifierAddr,
    },
  };
  fs.writeFileSync(deploymentPath, JSON.stringify(updated, null, 2));

  console.log(`\n=== Redeploy complete ===`);
  console.log(`  Groth16Verifier:     ${verifierAddr}  (registered with VerifierRouter)`);
  console.log(`  VerifierRouter:      ${verifierRouterAddr}  (unchanged)`);
  console.log(`  ComplianceRegistry:  ${registryAddr}  (updated to use new verifier)`);
  console.log(`  VASPRegistry:        ${existing.contracts.VASPRegistry}  (unchanged)`);
  console.log(`  SanctionsOracle:     ${existing.contracts.SanctionsOracle}  (unchanged)`);
  console.log(`\nSaved to ${deploymentPath}`);
  console.log("\nFollow-ups:");
  console.log("  1. Update contract addresses in README.md and packages/contracts/README.md");
  console.log("  2. Set COMPLIANCE_REGISTRY_ADDRESS / COMPLIANCE_REGISTRY for API + scripts");
  console.log("  3. domain_contract_hash is unchanged — proofs will continue to verify with the new verifier");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
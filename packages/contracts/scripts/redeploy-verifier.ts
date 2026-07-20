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

  // 1. New Groth16Verifier (Apache-2.0 implementation)
  console.log("[1/2] Deploying Groth16Verifier (Apache-2.0 build)...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log(`  → ${verifierAddr}`);

  // 2. New ComplianceRegistry pointing at the new verifier + existing state
  console.log("[2/2] Deploying ComplianceRegistry...");
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(
    verifierAddr,
    existing.contracts.VASPRegistry,
    existing.contracts.SanctionsOracle,
  );
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log(`  → ${registryAddr}`);

  // Update deployment record, preserving the previous addresses for rollback reference
  const updated = {
    ...existing,
    timestamp: new Date().toISOString(),
    previous: {
      Groth16Verifier: existing.contracts.Groth16Verifier,
      ComplianceRegistry: existing.contracts.ComplianceRegistry,
      retiredAt: new Date().toISOString(),
      reason: "Apache-2.0 verifier redeploy (ADR 0001 Option B)",
    },
    contracts: {
      ...existing.contracts,
      Groth16Verifier: verifierAddr,
      ComplianceRegistry: registryAddr,
    },
  };
  fs.writeFileSync(deploymentPath, JSON.stringify(updated, null, 2));

  console.log(`\n=== Redeploy complete ===`);
  console.log(`  Groth16Verifier:     ${verifierAddr}  (was ${existing.contracts.Groth16Verifier})`);
  console.log(`  ComplianceRegistry:  ${registryAddr}  (was ${existing.contracts.ComplianceRegistry})`);
  console.log(`  VASPRegistry:        ${existing.contracts.VASPRegistry}  (unchanged)`);
  console.log(`  SanctionsOracle:     ${existing.contracts.SanctionsOracle}  (unchanged — no relay needed)`);
  console.log(`\nSaved to ${deploymentPath}`);
  console.log("\nFollow-ups:");
  console.log("  1. Update contract addresses in README.md and packages/contracts/README.md");
  console.log("  2. Set COMPLIANCE_REGISTRY_ADDRESS / COMPLIANCE_REGISTRY for API + scripts");
  console.log("  3. domain_contract_hash changed — proofs bound to the old registry will not verify");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

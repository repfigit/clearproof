/**
 * Check whether a transfer ID has been recorded in ComplianceRegistry.
 *
 * Environment:
 *   TRANSFER_ID           bytes32 transfer ID, or text to hash with ethers.id()
 *   COMPLIANCE_REGISTRY   Optional registry address; otherwise deployments/<network>.json
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

function loadDeploymentAddress(networkName: string): string {
  if (process.env.COMPLIANCE_REGISTRY) {
    return process.env.COMPLIANCE_REGISTRY;
  }

  const deploymentPath = path.resolve(__dirname, `../deployments/${networkName}.json`);
  if (!fs.existsSync(deploymentPath)) {
    throw new Error(
      `Set COMPLIANCE_REGISTRY or create deployment file: ${deploymentPath}`,
    );
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  return deployment.contracts.ComplianceRegistry;
}

function transferIdFromEnv(): string {
  const value = process.env.TRANSFER_ID || "recipe-transfer-001";
  return /^0x[0-9a-fA-F]{64}$/.test(value) ? value : ethers.id(value);
}

async function main() {
  const networkName = process.env.HARDHAT_NETWORK || "localhost";
  const registryAddress = loadDeploymentAddress(networkName);
  const transferId = transferIdFromEnv();
  const registry = await ethers.getContractAt("ComplianceRegistry", registryAddress);

  const isVerified = await registry.isVerified(transferId);
  const record = await registry.proofs(transferId);

  console.log("=== Check Compliance Transfer ===");
  console.log(`Network:              ${networkName}`);
  console.log(`ComplianceRegistry:   ${registryAddress}`);
  console.log(`Transfer ID:          ${transferId}`);
  console.log(`Verified:             ${isVerified}`);
  if (record.timestamp > 0n) {
    console.log(`Proof hash:           ${record.proofHash}`);
    console.log(`Recorded at:          ${new Date(Number(record.timestamp) * 1000).toISOString()}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

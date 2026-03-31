import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  // 1. Groth16Verifier
  console.log("\nDeploying Groth16Verifier...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("Groth16Verifier deployed to:", verifierAddr);

  // 2. VASPRegistry
  console.log("Deploying VASPRegistry...");
  const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
  const vaspRegistry = await VASPRegistry.deploy(deployer.address);
  await vaspRegistry.waitForDeployment();
  const vaspRegistryAddr = await vaspRegistry.getAddress();
  console.log("VASPRegistry deployed to:", vaspRegistryAddr);

  // 3. SanctionsOracle
  console.log("Deploying SanctionsOracle...");
  const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("initial-sanctions-root"));
  const initialLeafCount = 0;
  const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
  const sanctionsOracle = await SanctionsOracle.deploy(deployer.address, initialRoot, initialLeafCount);
  await sanctionsOracle.waitForDeployment();
  const sanctionsOracleAddr = await sanctionsOracle.getAddress();
  console.log("SanctionsOracle deployed to:", sanctionsOracleAddr);

  // 4. ComplianceRegistry
  console.log("Deploying ComplianceRegistry...");
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(verifierAddr, vaspRegistryAddr, sanctionsOracleAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("ComplianceRegistry deployed to:", registryAddr);

  console.log("\nDeployment complete:");
  console.log(`  Verifier:         ${verifierAddr}`);
  console.log(`  VASPRegistry:     ${vaspRegistryAddr}`);
  console.log(`  SanctionsOracle:  ${sanctionsOracleAddr}`);
  console.log(`  Registry:         ${registryAddr}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

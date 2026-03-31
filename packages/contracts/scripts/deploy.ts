import { ethers } from "hardhat";

async function main() {
  console.log("Deploying Groth16Verifier...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("Groth16Verifier deployed to:", verifierAddr);

  console.log("Deploying ComplianceRegistry...");
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("ComplianceRegistry deployed to:", registryAddr);

  console.log("\nDeployment complete:");
  console.log(`  Verifier:  ${verifierAddr}`);
  console.log(`  Registry:  ${registryAddr}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

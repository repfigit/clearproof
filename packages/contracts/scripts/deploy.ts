import { ethers, run } from "hardhat";

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

  console.log("\n=== Deployment complete ===");
  console.log(`  Verifier:         ${verifierAddr}`);
  console.log(`  VASPRegistry:     ${vaspRegistryAddr}`);
  console.log(`  SanctionsOracle:  ${sanctionsOracleAddr}`);
  console.log(`  Registry:         ${registryAddr}`);

  // Write deployment addresses to file for downstream tools
  const fs = await import("fs");
  const deployment = {
    network: process.env.HARDHAT_NETWORK || "localhost",
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    contracts: {
      Groth16Verifier: verifierAddr,
      VASPRegistry: vaspRegistryAddr,
      SanctionsOracle: sanctionsOracleAddr,
      ComplianceRegistry: registryAddr,
    },
    deployer: deployer.address,
  };
  const outPath = `deployments/${deployment.network}.json`;
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));
  console.log(`\nAddresses written to ${outPath}`);

  // Verify on Etherscan if API key is set
  if (process.env.ETHERSCAN_API_KEY || process.env.BASESCAN_API_KEY) {
    console.log("\nVerifying contracts on block explorer...");
    try {
      await run("verify:verify", { address: verifierAddr, constructorArguments: [] });
      await run("verify:verify", { address: vaspRegistryAddr, constructorArguments: [deployer.address] });
      await run("verify:verify", { address: sanctionsOracleAddr, constructorArguments: [deployer.address, initialRoot, initialLeafCount] });
      await run("verify:verify", { address: registryAddr, constructorArguments: [verifierAddr, vaspRegistryAddr, sanctionsOracleAddr] });
      console.log("All contracts verified!");
    } catch (e: any) {
      console.log("Verification failed (can retry later):", e.message?.slice(0, 100));
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

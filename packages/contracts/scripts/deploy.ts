import { ethers, run } from "hardhat";
import { readFileSync } from "fs";
import { resolve } from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  // 1. VerifierRouter
  console.log("\nDeploying VerifierRouter...");
  const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
  const timelockPeriod = 24 * 60 * 60; // 24 hours in seconds
  const verifierRouter = await VerifierRouter.deploy(timelockPeriod);
  await verifierRouter.waitForDeployment();
  const verifierRouterAddr = await verifierRouter.getAddress();
  console.log("VerifierRouter deployed to:", verifierRouterAddr);

  // 2. Groth16Verifier
  console.log("\nDeploying Groth16Verifier...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("Groth16Verifier deployed to:", verifierAddr);

  // 3. Register the verifier with the router
  console.log("\nRegistering verifier with router...");
  const verifierSelector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
  let tx = await verifierRouter.registerVerifier(verifierSelector, verifierAddr, "Groth16 BN254 v1");
  await tx.wait();
  console.log("Verifier registered with selector:", verifierSelector);

  // 4. Activate the verifier
  console.log("\nActivating verifier...");
  tx = await verifierRouter.activateVerifier(verifierSelector, "Groth16 BN254 v1");
  await tx.wait();
  console.log("Verifier activated");

  // 5. VASPRegistry
  console.log("Deploying VASPRegistry...");
  const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
  const vaspRegistry = await VASPRegistry.deploy(deployer.address);
  await vaspRegistry.waitForDeployment();
  const vaspRegistryAddr = await vaspRegistry.getAddress();
  console.log("VASPRegistry deployed to:", vaspRegistryAddr);

  // 6. SanctionsOracle
  console.log("Deploying SanctionsOracle...");
  const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("initial-sanctions-root"));
  const initialLeafCount = 0;
  const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
  const sanctionsOracle = await SanctionsOracle.deploy(deployer.address, initialRoot, initialLeafCount);
  await sanctionsOracle.waitForDeployment();
  const sanctionsOracleAddr = await sanctionsOracle.getAddress();
  console.log("SanctionsOracle deployed to:", sanctionsOracleAddr);

  // 7. ComplianceRegistry
  console.log("Deploying ComplianceRegistry...");
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const thresholdConfig = JSON.parse(
    readFileSync(resolve(__dirname, "../../../config/jurisdiction_thresholds.json"), "utf-8")
  );
  const registry = await Registry.deploy(
    verifierRouterAddr,
    verifierSelector,
    vaspRegistryAddr,
    sanctionsOracleAddr,
    thresholdConfig.default.tier2,
    thresholdConfig.default.tier3,
    thresholdConfig.default.tier4
  );
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("ComplianceRegistry deployed to:", registryAddr);

  // 8. Seed the per-jurisdiction thresholds (AIF-79).
  //
  // tier2/3/4_threshold are unconstrained circuit inputs, so verifyAndRecord
  // rejects any proof whose thresholds disagree with this table. The default
  // entry is a constructor argument (AIF-95) so a registry can never exist in
  // a state where it accepts nothing; only the per-jurisdiction overrides are
  // seeded here.
  console.log("\nSeeding jurisdiction thresholds...");
  console.log(
    `  DEFAULT (constructor): ${thresholdConfig.default.tier2}/` +
      `${thresholdConfig.default.tier3}/${thresholdConfig.default.tier4}`
  );

  const encodeJurisdiction = (code: string): number => {
    const buf = Buffer.from(code.toUpperCase(), "ascii");
    if (buf.length !== 2) throw new Error(`Jurisdiction code must be alpha-2: ${code}`);
    return (buf[0] << 8) | buf[1];
  };

  const seed = async (key: number, label: string, t: { tier2: number; tier3: number; tier4: number }) => {
    const tx = await registry.setJurisdictionThresholds(key, t.tier2, t.tier3, t.tier4);
    await tx.wait();
    console.log(`  ${label}: ${t.tier2}/${t.tier3}/${t.tier4}`);
  };

  for (const [code, t] of Object.entries(thresholdConfig.jurisdictions)) {
    await seed(encodeJurisdiction(code), code, t as { tier2: number; tier3: number; tier4: number });
  }

  console.log("\n=== Deployment complete ===");
  console.log(`  VerifierRouter:     ${verifierRouterAddr}`);
  console.log(`  Groth16Verifier:    ${verifierAddr}`);
  console.log(`  VASPRegistry:       ${vaspRegistryAddr}`);
  console.log(`  SanctionsOracle:    ${sanctionsOracleAddr}`);
  console.log(`  Registry:           ${registryAddr}`);

  // Write deployment addresses to file for downstream tools
  const fs = await import("fs");
  const deployment = {
    network: process.env.HARDHAT_NETWORK || "localhost",
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    contracts: {
      VerifierRouter: verifierRouterAddr,
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
      await run("verify:verify", { address: verifierRouterAddr, constructorArguments: [timelockPeriod] });
      await run("verify:verify", { address: verifierAddr, constructorArguments: [] });
      await run("verify:verify", { address: vaspRegistryAddr, constructorArguments: [deployer.address] });
      await run("verify:verify", { address: sanctionsOracleAddr, constructorArguments: [deployer.address, initialRoot, initialLeafCount] });
      await run("verify:verify", { address: registryAddr, constructorArguments: [verifierRouterAddr, verifierSelector, vaspRegistryAddr, sanctionsOracleAddr] });
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
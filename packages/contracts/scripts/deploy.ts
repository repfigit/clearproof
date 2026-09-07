import { ethers, run, network as selectedNetwork } from "hardhat";
import { prepareLegacyVerifier } from "./legacy-verifier";
import { readFileSync } from "fs";
import { resolve } from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const { router: verifierRouter, verifier, selector: verifierSelector, activation, timelockPeriod } =
    await prepareLegacyVerifier();
  const verifierRouterAddr = await verifierRouter.getAddress();
  const verifierAddr = await verifier.getAddress();
  console.log("Verifier registration pending until chain timestamp:", activation.activateAfter);

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
    network: selectedNetwork.name,
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
    verifierActivation: activation,
  };
  const outputDir = process.env.CLEARPROOF_DEPLOYMENTS_DIR || resolve(__dirname, "../deployments");
  const outPath = resolve(outputDir, `${deployment.network}.json`);
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));
  console.log(`\nAddresses written to ${outPath}`);

  // Verify on Etherscan if API key is set
  if (!["hardhat", "localhost"].includes(selectedNetwork.name) &&
      (process.env.ETHERSCAN_API_KEY || process.env.BASESCAN_API_KEY)) {
    console.log("\nVerifying contracts on block explorer...");
    try {
      await run("verify:verify", { address: verifierRouterAddr, constructorArguments: [timelockPeriod] });
      await run("verify:verify", { address: verifierAddr, constructorArguments: [] });
      await run("verify:verify", { address: vaspRegistryAddr, constructorArguments: [deployer.address] });
      await run("verify:verify", { address: sanctionsOracleAddr, constructorArguments: [deployer.address, initialRoot, initialLeafCount] });
      await run("verify:verify", { address: registryAddr, constructorArguments: [verifierRouterAddr, verifierSelector, vaspRegistryAddr, sanctionsOracleAddr,
        thresholdConfig.default.tier2, thresholdConfig.default.tier3, thresholdConfig.default.tier4] });
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
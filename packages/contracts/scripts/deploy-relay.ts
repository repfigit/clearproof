/**
 * Deploy only SanctionsRootRelay against an existing SanctionsOracle deployment.
 *
 * Use when the core 4 contracts are already deployed (from scripts/deploy.ts)
 * and you need to bring the relay online without redeploying everything.
 *
 * Reads the current deployments/<network>.json for the oracle address,
 * deploys the relay, grants ORACLE_ROLE, and patches the deployment record.
 *
 * Usage:
 *   npx hardhat run scripts/deploy-relay.ts --network sepolia
 */
import { ethers, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = process.env.HARDHAT_NETWORK || "localhost";
  const deploymentPath = path.resolve(
    __dirname,
    `../deployments/${networkName}.json`
  );

  if (!fs.existsSync(deploymentPath)) {
    console.error(`No deployment found at ${deploymentPath}`);
    console.error("Run scripts/deploy.ts first.");
    process.exit(1);
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  const oracleAddr = deployment.contracts.SanctionsOracle;

  if (!oracleAddr) {
    console.error("No SanctionsOracle in deployment record — run deploy.ts first.");
    process.exit(1);
  }

  console.log("=== Deploy SanctionsRootRelay ===");
  console.log(`Network:  ${networkName} (chain ${network.chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Oracle:   ${oracleAddr}`);

  const Relay = await ethers.getContractFactory("SanctionsRootRelay");
  const relay = await Relay.deploy(deployer.address, oracleAddr);
  await relay.waitForDeployment();
  const relayAddr = await relay.getAddress();
  console.log(`\nSanctionsRootRelay deployed to: ${relayAddr}`);

  // Grant ORACLE_ROLE so the relay can call oracle.updateRoot()
  const oracle = await ethers.getContractAt("SanctionsOracle", oracleAddr);
  const ORACLE_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ORACLE_ROLE"));
  const alreadyHas = await oracle.hasRole(ORACLE_ROLE, relayAddr);
  if (alreadyHas) {
    console.log("Relay already has ORACLE_ROLE. Skipping grant.");
  } else {
    console.log("Granting ORACLE_ROLE to relay...");
    const tx = await oracle.grantRole(ORACLE_ROLE, relayAddr);
    const r = await tx.wait();
    console.log(`  confirmed in block ${r!.blockNumber}`);
  }

  // Patch deployment record
  deployment.contracts.SanctionsRootRelay = relayAddr;
  deployment.timestamp = new Date().toISOString();
  fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
  console.log(`\nUpdated ${deploymentPath}`);

  // Verify on block explorer
  if (process.env.ETHERSCAN_API_KEY) {
    console.log("\nVerifying on block explorer...");
    try {
      await run("verify:verify", {
        address: relayAddr,
        constructorArguments: [deployer.address, oracleAddr],
      });
      console.log("  verified.");
    } catch (e: any) {
      console.log(`  verification: ${e.message?.slice(0, 120)}`);
    }
  }

  console.log(`\n✓ SanctionsRootRelay online at ${relayAddr}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

/**
 * Operator tool: update the on-chain SanctionsOracle root.
 *
 * Reads the latest sanctions tree from artifacts/sanctions_tree.json,
 * compares it with the current on-chain root, and submits updateRoot()
 * after explicit operator confirmation.
 *
 * Usage:
 *   npx hardhat run scripts/update-sanctions-root.ts --network sepolia
 *
 * Environment:
 *   DEPLOYER_PRIVATE_KEY — wallet with ORACLE_ROLE on SanctionsOracle
 *   SKIP_CONFIRM=1       — skip interactive confirmation (for scripted use)
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

const ARTIFACTS_DIR = path.resolve(__dirname, "../../../artifacts");
const TREE_PATH = path.join(ARTIFACTS_DIR, "sanctions_tree.json");

async function confirm(prompt: string): Promise<boolean> {
  if (process.env.SKIP_CONFIRM === "1") return true;

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
    });
  });
}

async function main() {
  // 1. Determine network and load deployment
  const network = await ethers.provider.getNetwork();
  const networkName = process.env.HARDHAT_NETWORK || "localhost";
  const deploymentPath = path.resolve(
    __dirname,
    `../deployments/${networkName}.json`
  );

  if (!fs.existsSync(deploymentPath)) {
    console.error(`No deployment found at ${deploymentPath}`);
    console.error(`Available: ${fs.readdirSync(path.dirname(deploymentPath)).join(", ")}`);
    return process.exit(1);
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  const oracleAddress = deployment.contracts.SanctionsOracle;

  console.log("=== Sanctions Oracle Root Update ===\n");
  console.log(`Network:          ${networkName} (chain ${network.chainId})`);
  console.log(`SanctionsOracle:  ${oracleAddress}`);

  // 2. Load sanctions tree
  if (!fs.existsSync(TREE_PATH)) {
    console.error(`\nSanctions tree not found at ${TREE_PATH}`);
    console.error("Run: python scripts/build_sanctions_tree.py");
    return process.exit(1);
  }

  const tree = JSON.parse(fs.readFileSync(TREE_PATH, "utf-8"));
  const newRoot = tree.root;
  const newLeafCount = tree.leaf_count;
  if (!Number.isSafeInteger(newLeafCount) || newLeafCount < 0 || newLeafCount > 0xffffffff) {
    throw new Error("Tree leaf_count must be a uint32 integer");
  }
  const treeTimestamp = tree.source_metadata?.fetch_timestamp || "unknown";

  // Convert root string to bytes32 (Poseidon root is a decimal string)
  const newRootBytes32 = ethers.zeroPadValue(
    ethers.toBeHex(BigInt(newRoot)),
    32
  );

  console.log(`\nTree file:        ${TREE_PATH}`);
  console.log(`Tree built:       ${treeTimestamp}`);
  console.log(`New root:         ${newRoot}`);
  console.log(`New root (hex):   ${newRootBytes32}`);
  console.log(`Leaf count:       ${newLeafCount}`);

  // Check tree age
  const treeAge = (Date.now() - fs.statSync(TREE_PATH).mtimeMs) / 1000;
  if (treeAge > 86400) {
    console.warn(
      `\n⚠  Tree file is ${(treeAge / 3600).toFixed(1)} hours old. Consider rebuilding first.`
    );
  }

  // 3. Connect to oracle and read current state
  const [signer] = await ethers.getSigners();
  console.log(`\nOperator wallet:  ${signer.address}`);

  const oracle = await ethers.getContractAt("SanctionsOracle", oracleAddress);

  const currentRoot = await oracle.currentRoot();
  const currentLeafCount = await oracle.leafCount();
  const lastUpdated = await oracle.lastUpdated();
  const isStale = await oracle.isStale();
  const cooldownEnd = lastUpdated + await oracle.UPDATE_COOLDOWN();
  const block = await ethers.provider.getBlock("latest");
  if (!block) throw new Error("Latest block unavailable for cooldown check");
  const chainNow = BigInt(block.timestamp);

  console.log(`\n--- Current on-chain state ---`);
  console.log(`Current root:     ${currentRoot}`);
  console.log(`Leaf count:       ${currentLeafCount}`);
  console.log(`Last updated:     ${new Date(Number(lastUpdated) * 1000).toISOString()}`);
  console.log(`Stale:            ${isStale}`);

  // 4. Checks
  if (newRootBytes32 === currentRoot) {
    if (currentLeafCount !== BigInt(newLeafCount)) throw new Error("Root matches but leaf count differs");
    console.log("\n✓ On-chain root already matches tree. Nothing to do.");
    return process.exit(0);
  }

  if (chainNow < cooldownEnd) {
    const wait = cooldownEnd - chainNow;
    console.error(
      `\n✗ Cooldown active — ${wait}s remaining (until ${new Date(Number(cooldownEnd) * 1000).toISOString()})`
    );
    return process.exit(1);
  }

  // Leaf count floor check (contract enforces >= 50% of current)
  const minLeafCount = Math.floor(Number(currentLeafCount) / 2);
  if (newLeafCount < minLeafCount && Number(currentLeafCount) > 0) {
    console.error(
      `\n✗ Leaf count ${newLeafCount} is below floor (${minLeafCount}, 50% of ${currentLeafCount}).`
    );
    console.error("This could indicate a fetch failure. Investigate before forcing.");
    return process.exit(1);
  }

  // 5. Show diff
  console.log(`\n--- Proposed update ---`);
  console.log(`Root:       ${currentRoot}`);
  console.log(`         -> ${newRootBytes32}`);
  console.log(`Leaves:     ${currentLeafCount} -> ${newLeafCount}`);

  if (tree.source_metadata?.sources) {
    console.log(`\nData sources:`);
    for (const [name, meta] of Object.entries(tree.source_metadata.sources) as any) {
      const status = meta.fetched ? `✓ ${meta.addresses_found ?? 0} addresses` : `✗ ${meta.error}`;
      console.log(`  ${name}: ${status}`);
    }
  }

  // 6. Confirm
  const ok = await confirm("\nSubmit updateRoot() transaction? [y/N] ");
  if (!ok) {
    console.log("Aborted.");
    return process.exit(0);
  }

  // 7. Submit
  console.log("\nSubmitting transaction...");
  const tx = await oracle.updateRoot(newRootBytes32, newLeafCount);
  console.log(`TX hash: ${tx.hash}`);

  const receipt = await tx.wait();
  console.log(`Confirmed in block ${receipt!.blockNumber} (gas: ${receipt!.gasUsed})`);

  // Verify
  const updatedRoot = await oracle.currentRoot();
  const updatedLeafCount = await oracle.leafCount();
  console.log(`\nVerification:`);
  console.log(`  Root:       ${updatedRoot}`);
  console.log(`  Leaf count: ${updatedLeafCount}`);
  if (updatedRoot !== newRootBytes32 || updatedLeafCount !== BigInt(newLeafCount)) {
    throw new Error("Post-update state does not match the requested root and leaf count");
  }
  console.log("\n✓ Sanctions oracle root updated successfully.");
  console.log("  Match:      ✓");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

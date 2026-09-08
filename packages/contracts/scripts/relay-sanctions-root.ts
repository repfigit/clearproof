/**
 * Multi-chain sanctions root relayer.
 *
 * Reads the latest sanctions tree, then updates the SanctionsOracle
 * on every configured network via the SanctionsRootRelay contract.
 *
 * Usage:
 *   # Relay to specific networks
 *   RELAY_NETWORKS=sepolia,base-sepolia npx ts-node scripts/relay-sanctions-root.ts
 *
 *   # Relay to all deployed networks (reads deployments/ directory)
 *   npx ts-node scripts/relay-sanctions-root.ts
 *
 * Environment:
 *   DEPLOYER_PRIVATE_KEY — wallet with RELAYER_ROLE on each SanctionsRootRelay
 *   RELAY_NETWORKS       — comma-separated network names (optional, defaults to all deployed)
 *   SKIP_CONFIRM=1       — skip interactive confirmation
 */
import { ethers as ethersLib } from "ethers";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import { NETWORKS, getRpcUrl } from "./networks";

const ARTIFACTS_DIR = path.resolve(__dirname, "../../../artifacts");
const TREE_PATH = path.join(ARTIFACTS_DIR, "sanctions_tree.json");
const DEPLOYMENTS_DIR = path.resolve(__dirname, "../deployments");

// Minimal ABIs — only what the relayer needs
const RELAY_ABI = [
  "function receiveRoot(bytes32 newRoot, uint32 leafCount) external",
];
const ORACLE_ABI = [
  "function currentRoot() view returns (bytes32)",
  "function leafCount() view returns (uint32)",
  "function lastUpdated() view returns (uint64)",
  "function isStale() view returns (bool)",
];

interface RelayResult {
  network: string;
  success: boolean;
  txHash?: string;
  gasUsed?: string;
  error?: string;
  skipped?: string;
}

async function confirm(prompt: string): Promise<boolean> {
  if (process.env.SKIP_CONFIRM === "1") return true;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
    });
  });
}

const providers: ethersLib.JsonRpcProvider[] = [];
function closeProviders() {
  while (providers.length) providers.pop()!.destroy();
}
function stop(code: number) {
  closeProviders();
  return process.exit(code);
}

async function main() {
  console.log("╔══════════════════════════════════════════╗");
  console.log("║    clearproof sanctions root relayer     ║");
  console.log("╚══════════════════════════════════════════╝\n");

  // 1. Load sanctions tree
  if (!fs.existsSync(TREE_PATH)) {
    console.error(`Sanctions tree not found at ${TREE_PATH}`);
    console.error("Run: python scripts/build_sanctions_tree.py");
    return stop(1);
  }

  const tree = JSON.parse(fs.readFileSync(TREE_PATH, "utf-8"));
  const newRoot = tree.root;
  const newLeafCount = tree.leaf_count;
  if (!Number.isSafeInteger(newLeafCount) || newLeafCount < 0 || newLeafCount > 0xffffffff) {
    throw new Error("Tree leaf_count must be a uint32 integer");
  }
  const newRootBytes32 = ethersLib.zeroPadValue(
    ethersLib.toBeHex(BigInt(newRoot)),
    32
  );

  console.log(`Tree root:    ${newRootBytes32}`);
  console.log(`Leaf count:   ${newLeafCount}`);

  // Check tree freshness
  const treeAge = (Date.now() - fs.statSync(TREE_PATH).mtimeMs) / 1000;
  if (treeAge > 86400) {
    console.warn(`⚠  Tree is ${(treeAge / 3600).toFixed(1)}h old. Consider rebuilding.\n`);
  }

  // 2. Determine target networks
  const targetNames = process.env.RELAY_NETWORKS
    ? [...new Set(process.env.RELAY_NETWORKS.split(",").map((s) => s.trim()).filter(Boolean))]
    : getDeployedNetworks();

  if (targetNames.length === 0) {
    console.error("No target networks. Set RELAY_NETWORKS or deploy to at least one network.");
    return stop(1);
  }

  console.log(`\nTarget networks: ${targetNames.join(", ")}\n`);

  // 3. Check deployer key
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!privateKey) {
    console.error("DEPLOYER_PRIVATE_KEY not set");
    return stop(1);
  }

  // 4. Pre-flight: check each network's current state
  console.log("--- Pre-flight checks ---\n");
  const updates: { network: string; provider: ethersLib.JsonRpcProvider; deployment: any }[] = [];

  const results: RelayResult[] = [];
  for (const name of targetNames) {
    const netConfig = NETWORKS[name];
    if (!netConfig) {
      results.push({ network: name, success: false, error: "Unknown network" });
      console.log(`  ${name}: ✗ Unknown network, skipping`);
      continue;
    }

    const deploymentPath = path.join(DEPLOYMENTS_DIR, `${name}.json`);
    if (!fs.existsSync(deploymentPath)) {
      results.push({ network: name, success: false, error: "No deployment found" });
      console.log(`  ${name}: ✗ No deployment found, skipping`);
      continue;
    }

    const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
    const relayAddr = deployment.contracts.SanctionsRootRelay;
    const oracleAddr = deployment.contracts.SanctionsOracle;

    if (!relayAddr || !oracleAddr) {
      results.push({ network: name, success: false, error: "Missing relay or oracle address" });
      console.log(`  ${name}: ✗ No SanctionsRootRelay in deployment, skipping`);
      console.log(`         Redeploy with: npx hardhat run scripts/deploy-multichain.ts --network ${name}`);
      continue;
    }

    const rpcUrl = getRpcUrl(netConfig);
    const provider = new ethersLib.JsonRpcProvider(rpcUrl);
    providers.push(provider);

    try {
      if ((await provider.getNetwork()).chainId !== BigInt(netConfig.chainId)) {
        throw new Error("RPC chain does not match the target network");
      }
      const oracle = new ethersLib.Contract(oracleAddr, ORACLE_ABI, provider);
      const currentRoot = await oracle.currentRoot();
      const currentLeafCount = await oracle.leafCount();
      const isStale = await oracle.isStale();

      if (currentRoot === newRootBytes32) {
        if (currentLeafCount !== BigInt(newLeafCount)) throw new Error("Root matches but leaf count differs");
        console.log(`  ${name}: ✓ Already up to date`);
        continue;
      }

      console.log(`  ${name}: needs update (root: ${currentRoot.slice(0, 18)}... → ${newRootBytes32.slice(0, 18)}..., leaves: ${currentLeafCount} → ${newLeafCount}, stale: ${isStale})`);
      updates.push({ network: name, provider, deployment });
    } catch (e: any) {
      const error = e.message?.slice(0, 60) || "unknown preflight error";
      results.push({ network: name, success: false, error });
      console.log(`  ${name}: ✗ RPC error: ${error}`);
    }
  }

  if (updates.length === 0 && results.length === 0) {
    console.log("\nAll networks are up to date. Nothing to do.");
    return stop(0);
  }

  // 5. Confirm
  const ok = updates.length === 0 || await confirm(`\nUpdate ${updates.length} network(s)? [y/N] `);
  if (!ok) {
    console.log("Aborted.");
    return stop(0);
  }

  // 6. Execute updates sequentially
  console.log("\n--- Relaying ---\n");
  for (const { network, provider, deployment } of updates) {
    const relayAddr = deployment.contracts.SanctionsRootRelay;
    try {
      const wallet = new ethersLib.Wallet(privateKey, provider);
      const relay = new ethersLib.Contract(relayAddr, RELAY_ABI, wallet);
      // Estimate gas first
      const gasEstimate = await relay.receiveRoot.estimateGas(newRootBytes32, newLeafCount);
      const feeData = await provider.getFeeData();
      const estimatedCost = ethersLib.formatEther(gasEstimate * (feeData.gasPrice || 0n));

      console.log(`  ${network}: sending tx (est. ${gasEstimate} gas, ~${estimatedCost} ETH)...`);

      const tx = await relay.receiveRoot(newRootBytes32, newLeafCount);
      const receipt = await tx.wait();
      const oracle = new ethersLib.Contract(deployment.contracts.SanctionsOracle, ORACLE_ABI, provider);
      const verifiedRoot = await oracle.currentRoot({ blockTag: receipt!.blockNumber });
      const verifiedCount = await oracle.leafCount({ blockTag: receipt!.blockNumber });
      if (verifiedRoot !== newRootBytes32 || verifiedCount !== BigInt(newLeafCount)) {
        throw new Error("Post-relay state does not match the requested root and leaf count");
      }

      console.log(`  ${network}: ✓ confirmed block ${receipt!.blockNumber} (gas: ${receipt!.gasUsed})`);
      results.push({
        network,
        success: true,
        txHash: tx.hash,
        gasUsed: receipt!.gasUsed.toString(),
      });
    } catch (e: any) {
      const reason = e.reason || e.message?.slice(0, 100) || "unknown error";
      console.error(`  ${network}: ✗ ${reason}`);
      results.push({ network, success: false, error: reason });
    }
  }

  // 7. Summary
  console.log("\n=== Summary ===\n");
  const succeeded = results.filter((r) => r.success);
  const failed = results.filter((r) => !r.success);

  for (const r of succeeded) {
    console.log(`  ✓ ${r.network.padEnd(20)} tx: ${r.txHash}  gas: ${r.gasUsed}`);
  }
  for (const r of failed) {
    console.log(`  ✗ ${r.network.padEnd(20)} ${r.error}`);
  }

  console.log(`\n  ${succeeded.length} succeeded, ${failed.length} failed`);

  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

/** List networks that have a deployment JSON file */
function getDeployedNetworks(): string[] {
  if (!fs.existsSync(DEPLOYMENTS_DIR)) return [];
  return fs
    .readdirSync(DEPLOYMENTS_DIR)
    .filter((f) => f.endsWith(".json") && !f.endsWith("-bls-bench.json"))
    .map((f) => f.replace(".json", ""));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(closeProviders);

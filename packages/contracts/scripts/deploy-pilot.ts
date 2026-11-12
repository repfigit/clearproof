/**
 * Deploy the current pilot (`pilot-transfer-v3`) contracts: PilotGroth16Verifier,
 * PilotCurrentRegistry and PilotRootCheckpoint. Restartable; see `pilot-deployment.ts`.
 *
 * Testnets and local Hardhat networks only. The verifier embeds
 * `assurance = "development-unapproved"` keys, so there is no mainnet path or override.
 *
 * Usage:
 *   npx hardhat run scripts/deploy-pilot.ts --network sepolia
 *   make deploy-pilot NETWORK=sepolia
 *
 * Environment (or the same values in the JSON file named by PILOT_DEPLOY_CONFIG):
 *   PILOT_REGISTRY_ADMIN        — default admin and pauser of PilotCurrentRegistry
 *   PILOT_CHECKPOINT_ADMIN      — default admin and pauser of PilotRootCheckpoint
 *   PILOT_ARTIFACTS_DIR         — bundle with manifest.json and its verification key
 *   PILOT_MANIFEST_DIGEST       — reviewed artifact manifest digest (64 lowercase hex)
 *   PILOT_ALLOW_DEPLOYER_ADMIN=1 — local networks only: use the deployer for unset admins
 *   SKIP_CONFIRM=1              — skip the typed "deploy" confirmation (scripted use)
 *   CLEARPROOF_DEPLOYMENTS_DIR  — manifest directory (default: packages/contracts/deployments)
 *   DEPLOYER_PRIVATE_KEY        — deployer account for public testnets (hardhat.config.ts)
 *
 * Writes deployments/<network>-pilot.json. Run it again to resume an interrupted
 * deployment or to verify a finished one against the chain.
 */
import { ethers, network } from "hardhat";
import { execFileSync } from "child_process";
import * as path from "path";
import * as readline from "readline";
import { deployPilot } from "./pilot-deployment";

function ask(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  await deployPilot({
    ethers,
    networkName: network.name,
    env: process.env,
    deploymentsDir: process.env.CLEARPROOF_DEPLOYMENTS_DIR || path.resolve(__dirname, "../deployments"),
    confirm: ask,
    log: (line) => console.log(line),
    git: (args) => execFileSync("git", args, { cwd: __dirname, encoding: "utf8" }),
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

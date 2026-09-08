/**
 * Replace the legacy verifier through its existing router without redeploying
 * stateful contracts. Run again after the router timelock to finish activation.
 * The deployment record retains the pending replacement for retries, including
 * retries after activation or registry selection succeeds but recording fails.
 * No local time travel or timelock bypass is performed by this script.
 *
 * Usage: npx hardhat run scripts/redeploy-verifier.ts --network sepolia
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = process.env.HARDHAT_NETWORK || "localhost";
  const deploymentPath = path.resolve(__dirname, `../deployments/${networkName}.json`);
  if (!fs.existsSync(deploymentPath)) throw new Error(`No existing deployment record at ${deploymentPath}`);
  const existing = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  if (existing.chainId !== network.chainId.toString()) throw new Error("Deployment record chain does not match provider");
  const routerAddress = existing.contracts.VerifierRouter;
  const registryAddress = existing.contracts.ComplianceRegistry;
  if (!routerAddress || !registryAddress || !existing.contracts.Groth16Verifier) {
    throw new Error("Existing router, registry and verifier addresses are required");
  }
  if (await ethers.provider.getBalance(deployer.address) === 0n) throw new Error("Deployer has no balance");
  const router = await ethers.getContractAt("VerifierRouter", routerAddress);
  const registry = await ethers.getContractAt("ComplianceRegistry", registryAddress);
  if ((await registry.verifierRouter()).toLowerCase() !== routerAddress.toLowerCase()) {
    throw new Error("Registry is connected to a different verifier router");
  }
  const currentSelector = await registry.verifierSelector();
  const selector = ethers.id("groth16-bn254-v2");
  const name = "Groth16 BN254 v2";
  const save = () => {
    const temporary = `${deploymentPath}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(temporary, JSON.stringify(existing, null, 2));
      fs.renameSync(temporary, deploymentPath);
    } catch (error) {
      fs.rmSync(temporary, { force: true });
      throw error;
    }
  };
  let pending = existing.pendingVerifierReplacement;
  if (pending) {
    if (pending.chainId !== network.chainId.toString() || pending.router !== routerAddress ||
        pending.registry !== registryAddress || pending.selector !== selector ||
        pending.previousVerifier !== existing.contracts.Groth16Verifier) {
      throw new Error("Pending replacement does not match the deployment record");
    }
    if (currentSelector !== pending.previousSelector && currentSelector !== selector) {
      throw new Error("Registry selector changed outside this replacement");
    }
  } else {
    const verifier = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
    await verifier.waitForDeployment();
    pending = {
      verifier: await verifier.getAddress(), selector, chainId: network.chainId.toString(),
      router: routerAddress, registry: registryAddress,
      previousVerifier: existing.contracts.Groth16Verifier, previousSelector: currentSelector,
    };
    existing.pendingVerifierReplacement = pending;
    // Persist before registration so a failed registration can reuse this verifier.
    save();
  }

  const info = await router.verifiers(selector);
  if (info.verifier.toLowerCase() === pending.verifier.toLowerCase() && !info.active) {
    throw new Error("Replacement verifier was disabled; explicit review is required");
  }
  if (!(info.active && info.verifier.toLowerCase() === pending.verifier.toLowerCase())) {
    const registered = await router.pendingRegistrations(selector);
    if (registered !== ethers.ZeroAddress && registered.toLowerCase() !== pending.verifier.toLowerCase()) {
      throw new Error("Router has a different pending replacement");
    }
    if (registered === ethers.ZeroAddress) {
      await (await router.registerVerifier(selector, pending.verifier, name)).wait();
    }
    const activateAfter = await router.timelocks(selector);
    pending.activateAfter = activateAfter.toString();
    save();
    const block = await ethers.provider.getBlock("latest");
    if (!block) throw new Error("Latest block unavailable");
    if (BigInt(block.timestamp) < activateAfter) {
      console.log(`Awaiting verifier timelock until ${activateAfter}; run this command again afterwards.`);
      return;
    }
    await (await router.activateVerifier(selector, name)).wait();
  }
  if (currentSelector !== selector) {
    await (await registry.setVerifierSelector(selector)).wait();
  }
  existing.previous = {
    ...existing.previous, Groth16Verifier: pending.previousVerifier,
    verifierSelector: pending.previousSelector, retiredAt: new Date().toISOString(),
    reason: "Verifier replaced through existing router",
  };
  existing.contracts.Groth16Verifier = pending.verifier;
  existing.verifierActivation = { status: "active", selector, name, verifier: pending.verifier };
  existing.timestamp = new Date().toISOString();
  delete existing.pendingVerifierReplacement;
  save();
  console.log(`Verifier replacement complete; stateful contract addresses preserved. Saved to ${deploymentPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

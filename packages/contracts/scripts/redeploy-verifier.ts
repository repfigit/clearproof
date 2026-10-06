/**
 * Replace the legacy verifier through its existing router without redeploying
 * stateful contracts. Resume after registration and default-selection timelocks.
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
  if (!deployer) throw new Error("Configure the existing authorized deployer account");
  if (await ethers.provider.getBalance(deployer.address) === 0n) throw new Error("Deployer has no balance");
  const router = await ethers.getContractAt("VerifierRouter", routerAddress);
  const registry = await ethers.getContractAt("ComplianceRegistry", registryAddress);
  if ((await registry.verifierRouter()).toLowerCase() !== routerAddress.toLowerCase()) {
    throw new Error("Registry is connected to a different verifier router");
  }
  const currentSelector = await registry.verifierSelector();
  const selector = ethers.id("groth16-bn254-v2");
  const name = "Groth16 BN254 v2";
  // Older deployed routers/registries cannot gain these source changes in place.
  // Refuse to deploy a replacement before detecting the reviewed governance ABI.
  await router.timelockFloor();
  await registry.verifierSelectionDelay();
  if (!existing.pendingVerifierReplacement && currentSelector === selector) {
    if ((await router.getVerifier(selector)).toLowerCase() !== existing.contracts.Groth16Verifier.toLowerCase() ||
        !await router.isVerifierActive(selector)) throw new Error("Completed replacement is not current");
    console.log("Verifier replacement complete; recorded replacement is already current.");
    return;
  }
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
    const scheduled = await registry.pendingVerifierSelector();
    if (scheduled !== ethers.ZeroHash && scheduled !== selector) {
      throw new Error("Registry has a different pending verifier selection");
    }
    if (scheduled === ethers.ZeroHash) {
      await (await registry.setVerifierSelector(selector)).wait();
    }
    const selectAfter = await registry.verifierSelectionAfter();
    pending.selectAfter = selectAfter.toString();
    save();
    const block = await ethers.provider.getBlock("latest");
    if (!block) throw new Error("Latest block unavailable");
    if (BigInt(block.timestamp) < selectAfter) {
      console.log(`Awaiting verifier selection timelock until ${selectAfter}; run this command again afterwards.`);
      return;
    }
    await (await registry.activateVerifierSelector()).wait();
  }
  existing.previous = {
    ...existing.previous, Groth16Verifier: pending.previousVerifier,
    verifierSelector: pending.previousSelector, cutoverAt: new Date().toISOString(),
    registryGraceEndsAt: (await registry.previousSelectorUntil(pending.previousSelector)).toString(),
    retirementStatus: "Router retirement must be scheduled separately; see decommissioning runbook",
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

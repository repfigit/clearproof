import { ethers } from "hardhat";
import { NETWORKS } from "./networks";

const LOCAL_CHAIN_ID = 31337n;

/**
 * The legacy Groth16Verifier embeds development-only keys, so it may be deployed
 * only to a local Hardhat chain or a chain listed as `testnet: true` in
 * `networks.ts`. The check uses the chain ID the RPC reports, not the network
 * name, and has no override.
 */
export async function assertDevelopmentKeyChain(): Promise<void> {
  const { chainId } = await ethers.provider.getNetwork();
  const allowed = [LOCAL_CHAIN_ID, ...Object.values(NETWORKS).filter((n) => n.testnet).map((n) => BigInt(n.chainId))];
  if (!allowed.includes(BigInt(chainId))) {
    throw new Error(
      `Refusing to deploy the legacy verifier to chain ${chainId}: it embeds development-only keys. ` +
      "Only local Hardhat chains and networks marked testnet: true in scripts/networks.ts are allowed; there is no override.",
    );
  }
}

/** Register the legacy verifier without bypassing the router activation timelock. */
export async function prepareLegacyVerifier(timelockPeriod = 86400) {
  if (!Number.isSafeInteger(timelockPeriod) || timelockPeriod < 1) throw new Error("Invalid verifier timelock");
  await assertDevelopmentKeyChain();
  const router = await (await ethers.getContractFactory("VerifierRouter")).deploy(timelockPeriod);
  const verifier = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
  await Promise.all([router.waitForDeployment(), verifier.waitForDeployment()]);
  const selector = ethers.id("groth16-bn254-v1");
  await (await router.registerVerifier(selector, await verifier.getAddress(), "Legacy Groth16 BN254 v1")).wait();
  const activation = {
    status: "pending-timelock" as const,
    selector,
    name: "Legacy Groth16 BN254 v1",
    activateAfter: (await router.timelocks(selector)).toString(),
  };
  return { router, verifier, selector, activation, timelockPeriod };
}

import { ethers } from "hardhat";

/** Register the legacy verifier without bypassing the router activation timelock. */
export async function prepareLegacyVerifier(timelockPeriod = 86400) {
  if (!Number.isSafeInteger(timelockPeriod) || timelockPeriod < 1) throw new Error("Invalid verifier timelock");
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

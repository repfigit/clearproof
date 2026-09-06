import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

/** Exercise the deployed router API, including registration and activation. */
export async function routeVerifier(address: string) {
  const Router = await ethers.getContractFactory("VerifierRouter");
  const router = await Router.deploy(1);
  await router.waitForDeployment();
  const selector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
  await router.registerVerifier(selector, address, "Legacy Groth16 test verifier");
  await time.increase(2);
  await router.activateVerifier(selector, "Legacy Groth16 test verifier");
  return { router, selector };
}

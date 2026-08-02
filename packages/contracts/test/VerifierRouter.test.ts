import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("VerifierRouter", function () {
  async function deployVerifierRouter() {
    const [admin, emergency, other] = await ethers.getSigners();
    const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
    const timelockPeriod = 24 * 60 * 60; // 24 hours
    const router = await VerifierRouter.deploy(timelockPeriod);
    await router.waitForDeployment();
    return { router, admin, emergency, other, timelockPeriod };
  }

  async function deployGroth16Verifier() {
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    return verifier;
  }

  it("should deploy with correct timelock", async function () {
    const { router, timelockPeriod } = await deployVerifierRouter();
    expect(await router.minTimelock()).to.equal(timelockPeriod);
  });
});

describe("ComplianceRegistry with VerifierRouter", function () {
  async function deployAll() {
    const [admin, revoker, vaspWallet, other] = await ethers.getSigners();

    const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
    const timelockPeriod = 24 * 60 * 60; // 24 hours
    const verifierRouter = await VerifierRouter.deploy(timelockPeriod);
    await verifierRouter.waitForDeployment();

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const selector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
    await verifierRouter.registerVerifier(selector, await verifier.getAddress(), "Groth16 BN254 v1");
    await time.increase(24 * 60 * 60 + 1);
    await verifierRouter.activateVerifier(selector, "Groth16 BN254 v1");

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
    await sanctionsOracle.waitForDeployment();

    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifierRouter.getAddress(),
      selector,
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress(),
      250,
      1000,
      10000
    );
    await registry.waitForDeployment();

    return { verifierRouter, verifier, vaspRegistry, sanctionsOracle, registry, admin, revoker, vaspWallet, other, selector };
  }

  it("should deploy with VerifierRouter", async function () {
    const { registry, verifierRouter, selector } = await deployAll();
    expect(await registry.verifierRouter()).to.equal(await verifierRouter.getAddress());
    expect(await registry.verifierSelector()).to.equal(selector);
  });
});
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

  const selector = ethers.id("synthetic-router-verifier");
  const pA: [number, number] = [0, 0];
  const pB: [[number, number], [number, number]] = [[0, 0], [0, 0]];
  const pC: [number, number] = [0, 0];
  const signals = Array(16).fill(0);

  async function activeRouter() {
    const state = await deployVerifierRouter();
    const verifier = await deployGroth16Verifier();
    await state.router.registerVerifier(selector, await verifier.getAddress(), "Synthetic verifier");
    await time.increaseTo(await state.router.timelocks(selector));
    await state.router.activateVerifier(selector, "Synthetic verifier");
    return { ...state, verifier };
  }

  it("rejects zero addresses and operations on absent verifiers", async function () {
    const { router } = await deployVerifierRouter();
    await expect(router.registerVerifier(selector, ethers.ZeroAddress, "Invalid"))
      .to.be.revertedWithCustomError(router, "ZeroAddress");
    expect(await router.getVerifier(selector)).to.equal(ethers.ZeroAddress);
    expect(await router.isVerifierActive(selector)).to.equal(false);
    await expect(router.activateVerifier(selector, "Missing")).to.be.revertedWithCustomError(router, "VerifierNotFound");
    await expect(router.disableVerifier(selector)).to.be.revertedWithCustomError(router, "VerifierNotFound");
    await expect(router.scheduleRetirement(selector)).to.be.revertedWithCustomError(router, "VerifierNotFound");
    await expect(router.completeRetirement(selector)).to.be.revertedWithCustomError(router, "VerifierNotFound");
    await expect(router.verifyProof(selector, pA, pB, pC, signals)).to.be.revertedWithCustomError(router, "VerifierNotFound");
  });

  it("activates at the exact timelock boundary and clears pending state", async function () {
    const { router } = await deployVerifierRouter();
    const verifier = await deployGroth16Verifier();
    const address = await verifier.getAddress();
    await router.registerVerifier(selector, address, "Synthetic verifier");
    const ready = await router.timelocks(selector);
    await time.setNextBlockTimestamp(ready - 1n);
    await expect(router.activateVerifier(selector, "Synthetic verifier")).to.be.revertedWithCustomError(router, "Unauthorized");
    expect(await router.pendingRegistrations(selector)).to.equal(address);
    await time.setNextBlockTimestamp(ready);
    await expect(router.activateVerifier(selector, "Activated"))
      .to.emit(router, "VerifierActivated").withArgs(selector, address);
    const info = await router.verifiers(selector);
    expect(info.registeredAt).to.equal(ready);
    expect(info.disabledAt).to.equal(0);
    expect(info.name).to.equal("Activated");
    expect(await router.getVerifier(selector)).to.equal(address);
    expect(await router.isVerifierActive(selector)).to.equal(true);
    expect(await router.timelocks(selector)).to.equal(0);
    expect(await router.pendingRegistrations(selector)).to.equal(ethers.ZeroAddress);
  });

  it("disables immediately and rejects repeated disable and verification", async function () {
    const { router, verifier } = await activeRouter();
    await expect(router.disableVerifier(selector))
      .to.emit(router, "VerifierDisabled").withArgs(selector, await verifier.getAddress());
    expect(await router.isVerifierActive(selector)).to.equal(false);
    expect((await router.verifiers(selector)).disabledAt).to.equal(await time.latest());
    await expect(router.disableVerifier(selector)).to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
    await expect(router.verifyProof(selector, pA, pB, pC, signals))
      .to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
  });

  it("keeps a retiring verifier active until the exact retirement boundary", async function () {
    const { router, verifier } = await activeRouter();
    await expect(router.scheduleRetirement(selector))
      .to.emit(router, "VerifierRetired").withArgs(selector, await verifier.getAddress());
    const ready = await router.timelocks(selector);
    expect(await router.pendingRetirements(selector)).to.equal(true);
    await time.setNextBlockTimestamp(ready - 1n);
    await expect(router.completeRetirement(selector)).to.be.revertedWithCustomError(router, "Unauthorized");
    expect(await router.isVerifierActive(selector)).to.equal(true);
    await time.setNextBlockTimestamp(ready);
    await router.completeRetirement(selector);
    expect(await router.isVerifierActive(selector)).to.equal(false);
    expect((await router.verifiers(selector)).disabledAt).to.equal(ready);
    expect(await router.pendingRetirements(selector)).to.equal(false);
    expect(await router.timelocks(selector)).to.equal(0);
    await expect(router.completeRetirement(selector)).to.be.revertedWithCustomError(router, "VerifierNotFound");
  });

  it("updates the delay for future registrations without shortening an existing schedule", async function () {
    const { router } = await deployVerifierRouter();
    const verifier = await deployGroth16Verifier();
    await router.registerVerifier(selector, await verifier.getAddress(), "First");
    const original = await router.timelocks(selector);
    await expect(router.updateTimelock(60)).to.emit(router, "TimelockUpdated").withArgs(60);
    expect(await router.minTimelock()).to.equal(60);
    expect(await router.timelocks(selector)).to.equal(original);
    const next = ethers.id("second-synthetic-verifier");
    await router.registerVerifier(next, await verifier.getAddress(), "Second");
    expect(await router.timelocks(next)).to.equal(BigInt(await time.latest()) + 60n);
  });

  it("separates emergency pause authority from administrative recovery", async function () {
    const { router, emergency, other, verifier } = await activeRouter();
    const adminRole = await router.ADMIN_ROLE();
    const emergencyRole = await router.EMERGENCY_ROLE();
    await router.grantRole(emergencyRole, emergency.address);
    for (const call of [
      () => router.connect(other).registerVerifier(selector, verifier.getAddress(), "Forbidden"),
      () => router.connect(other).activateVerifier(selector, "Forbidden"),
      () => router.connect(other).scheduleRetirement(selector),
      () => router.connect(other).completeRetirement(selector),
      () => router.connect(other).updateTimelock(0),
      () => router.connect(other).unpause(),
    ]) {
      await expect(call()).to.be.revertedWithCustomError(router, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, adminRole);
    }
    await expect(router.connect(other).disableVerifier(selector))
      .to.be.revertedWithCustomError(router, "AccessControlUnauthorizedAccount").withArgs(other.address, emergencyRole);
    await expect(router.connect(other).pause())
      .to.be.revertedWithCustomError(router, "AccessControlUnauthorizedAccount").withArgs(other.address, emergencyRole);
    await router.connect(emergency).pause();
    await expect(router.verifyProof(selector, pA, pB, pC, signals)).to.be.revertedWithCustomError(router, "EnforcedPause");
    await expect(router.connect(emergency).unpause())
      .to.be.revertedWithCustomError(router, "AccessControlUnauthorizedAccount").withArgs(emergency.address, adminRole);
    await router.unpause();
    // Actual Groth16 verifier rejects this invalid proof after routing resumes.
    expect(await router.verifyProof(selector, pA, pB, pC, signals)).to.equal(false);
    await router.connect(emergency).disableVerifier(selector);
    expect(await router.isVerifierActive(selector)).to.equal(false);
  });

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
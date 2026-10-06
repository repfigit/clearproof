import { expect } from "chai";
import { ethers, network } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const a: [number, number] = [0, 0];
const b: [[number, number], [number, number]] = [[0, 0], [0, 0]];
const c: [number, number] = [0, 0];
const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const v1 = ethers.id("groth16-bn254-v1");
const v2 = ethers.id("groth16-bn254-v2");

async function fixture(initialSelector = v1) {
  const [admin, wallet, other] = await ethers.getSigners();
  const router = await (await ethers.getContractFactory("VerifierRouter")).deploy(60);
  const first = await (await ethers.getContractFactory("MockVerifier")).deploy();
  const second = await (await ethers.getContractFactory("MockVerifier")).deploy();
  await router.registerVerifier(v1, await first.getAddress(), "Groth16 BN254 v1");
  await router.registerVerifier(v2, await second.getAddress(), "Groth16 BN254 v2");
  await time.increase(61);
  await router.activateVerifier(v1, "Groth16 BN254 v1");
  await router.activateVerifier(v2, "Groth16 BN254 v2");
  const vasps = await (await ethers.getContractFactory("VASPRegistry")).deploy(admin.address);
  const root = ethers.id("synthetic-governance-sanctions");
  const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, root, 50);
  const registry = await (await ethers.getContractFactory("ComplianceRegistry")).deploy(
    await router.getAddress(), initialSelector, await vasps.getAddress(), await oracle.getAddress(), 250, 1000, 10000);
  const did = ethers.id("did:web:synthetic-governance.example");
  await vasps.registerVASP(did, wallet.address, "US", "");
  const issued = BigInt(await time.latest());
  async function statement(label: string, nullifier = 1n) {
    const transfer = ethers.id(label);
    const signals = [1n, 0n, BigInt(root), 0n, 1n, issued, 0x5553n, 0n, 250n, 1000n, 10000n,
      (await ethers.provider.getNetwork()).chainId,
      BigInt(ethers.solidityPackedKeccak256(["address"], [await registry.getAddress()])) % field,
      BigInt(ethers.solidityPackedKeccak256(["bytes32"], [transfer])) % field, nullifier, issued + 172800n];
    return { transfer, signals };
  }
  async function switchDefault() {
    await registry.setVerifierSelector(v2);
    const ready = await registry.verifierSelectionAfter();
    await time.setNextBlockTimestamp(ready);
    await registry.activateVerifierSelector();
  }
  return { admin, wallet, other, router, first, second, vasps, root, oracle, registry, did, statement, switchDefault };
}

describe("Permanent legacy verifier bindings", function () {
  it("rejects zero delays, empty selectors, EOAs and replacement of pending or historical bindings", async function () {
    const Factory = await ethers.getContractFactory("VerifierRouter");
    await expect(Factory.deploy(0)).to.be.revertedWithCustomError(Factory, "InvalidTimelock");
    const { router, first, second, other } = await fixture();
    await expect(router.registerVerifier(ethers.ZeroHash, first.getAddress(), "bad"))
      .to.be.revertedWithCustomError(router, "InvalidSelector");
    await expect(router.registerVerifier(ethers.id("eoa"), other.address, "bad"))
      .to.be.revertedWithCustomError(router, "VerifierNotContract");
    const pending = ethers.id("groth16-bn254-v3");
    await router.registerVerifier(pending, first.getAddress(), "pending");
    const ready = await router.timelocks(pending);
    await expect(router.registerVerifier(pending, second.getAddress(), "replace"))
      .to.be.revertedWithCustomError(router, "SelectorAlreadyReserved");
    expect(await router.timelocks(pending)).to.equal(ready);
    await expect(router.registerVerifier(v1, second.getAddress(), "replace"))
      .to.be.revertedWithCustomError(router, "SelectorAlreadyReserved");
    await router.disableVerifier(v1);
    await expect(router.registerVerifier(v1, second.getAddress(), "reuse"))
      .to.be.revertedWithCustomError(router, "SelectorAlreadyReserved");
    expect(await router.getVerifier(v1)).to.equal(await first.getAddress());
  });

  it("pins code at scheduling and at every verification", async function () {
    const { router, first, second } = await fixture();
    const pending = ethers.id("groth16-bn254-v3");
    await router.registerVerifier(pending, second.getAddress(), "pending");
    await time.increase(61);
    await network.provider.send("hardhat_setCode", [await second.getAddress(), "0x00"]);
    await expect(router.activateVerifier(pending, "changed"))
      .to.be.revertedWithCustomError(router, "VerifierCodeChanged");
    await network.provider.send("hardhat_setCode", [await first.getAddress(), "0x00"]);
    await expect(router.verifyProof(v1, a, b, c, Array(16).fill(0)))
      .to.be.revertedWithCustomError(router, "VerifierCodeChanged");
  });

  it("bounds retirement grace and lets emergency authority terminate it immediately", async function () {
    const { router } = await fixture();
    await router.scheduleRetirement(v1);
    await expect(router.scheduleRetirement(v1)).to.be.revertedWithCustomError(router, "VerifierAlreadyRetiring");
    await time.increaseTo(await router.timelocks(v1));
    await router.completeRetirement(v1);
    const info = await router.verifiers(v1);
    const old = Array(16).fill(0n); old[5] = info.retiredAt;
    expect(await router.verifyProof(v1, a, b, c, old)).to.equal(true);
    const newer = [...old]; newer[5] += 1n;
    await expect(router.verifyProof(v1, a, b, c, newer)).to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
    await expect(router.scheduleRetirement(v1)).to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
    await time.increaseTo(info.graceEndsAt);
    expect(await router.verifyProof(v1, a, b, c, old)).to.equal(true);
    await router.disableVerifier(v1);
    expect(await router.isVerifierResolvable(v1)).to.equal(false);
    await expect(router.verifyProof(v1, a, b, c, old)).to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
  });

  it("never turns an emergency disable into retirement grace", async function () {
    const { router } = await fixture();
    await router.scheduleRetirement(v1);
    await router.disableVerifier(v1);
    await time.increaseTo(await router.timelocks(v1));
    await expect(router.completeRetirement(v1)).to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
    expect(await router.isVerifierResolvable(v1)).to.equal(false);
  });
});

describe("Governed default and in-flight legacy proofs", function () {
  it("separately timelocks swaps, supports cancellation and rechecks the target", async function () {
    const { registry, router, other } = await fixture();
    const role = await registry.DEFAULT_ADMIN_ROLE();
    for (const action of [() => registry.connect(other).activateVerifierSelector(),
      () => registry.connect(other).cancelVerifierSelection()]) {
      await expect(action()).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, role);
    }
    await expect(registry.cancelVerifierSelection()).to.be.revertedWithCustomError(registry, "VerifierSelectorNotSet");
    await expect(registry.activateVerifierSelector()).to.be.revertedWithCustomError(registry, "VerifierSelectorNotSet");
    await expect(registry.setVerifierSelector(v1)).to.be.revertedWithCustomError(registry, "VerifierUnavailable");
    await registry.setVerifierSelector(v2);
    const ready = await registry.verifierSelectionAfter();
    await expect(registry.setVerifierSelector(v2)).to.be.revertedWithCustomError(registry, "SelectionAlreadyPending");
    await time.setNextBlockTimestamp(ready - 1n);
    await expect(registry.activateVerifierSelector()).to.be.revertedWithCustomError(registry, "SelectionNotReady");
    expect(await registry.verifierSelector()).to.equal(v1);
    await registry.cancelVerifierSelection();
    expect(await registry.pendingVerifierSelector()).to.equal(ethers.ZeroHash);
    await registry.setVerifierSelector(v2);
    await router.disableVerifier(v2);
    await time.increaseTo(await registry.verifierSelectionAfter());
    await expect(registry.activateVerifierSelector()).to.be.revertedWithCustomError(registry, "VerifierUnavailable");
    expect(await registry.verifierSelector()).to.equal(v1);
  });

  it("preserves a registry's deployment delay after a later permitted router-delay reduction", async function () {
    const { registry, router, vasps, oracle } = await fixture();
    await router.updateTimelock(120);
    await time.increaseTo(await router.timelockUpdateAfter());
    await router.completeTimelockUpdate();
    const newerRegistry = await (await ethers.getContractFactory("ComplianceRegistry")).deploy(
      await router.getAddress(), v1, await vasps.getAddress(), await oracle.getAddress(), 250, 1000, 10000);
    expect(await newerRegistry.verifierSelectionDelay()).to.equal(120);
    await router.updateTimelock(60);
    await time.increaseTo(await router.timelockUpdateAfter());
    await router.completeTimelockUpdate();
    await newerRegistry.setVerifierSelector(v2);
    expect(await newerRegistry.verifierSelectionAfter()).to.equal(BigInt(await time.latest()) + 120n);
    expect(await registry.verifierSelectionDelay()).to.equal(60);
  });

  it("pauses explicit-selector submissions with the same administration as default submissions", async function () {
    const { registry, wallet, did, statement, switchDefault } = await fixture();
    await switchDefault();
    const input = await statement("paused-grace");
    await registry.pause();
    await expect(registry.connect(wallet).verifyAndRecordWithSelector(v1, input.transfer, a, b, c, input.signals, did))
      .to.be.revertedWithCustomError(registry, "EnforcedPause");
    expect(await registry.isVerified(input.transfer)).to.equal(false);
    await registry.unpause();
    await registry.connect(wallet).verifyAndRecordWithSelector(v1, input.transfer, a, b, c, input.signals, did);
    expect(await registry.isVerified(input.transfer)).to.equal(true);
  });

  it("accepts exactly at the inclusive registry deadline and rejects the following block", async function () {
    const { registry, oracle, wallet, did, statement, switchDefault } = await fixture();
    await switchDefault();
    await oracle.setGracePeriod(172800);
    const input = await statement("inclusive-registry-grace", 1n);
    const until = await registry.previousSelectorUntil(v1);
    await time.setNextBlockTimestamp(until);
    await registry.connect(wallet).verifyAndRecordWithSelector(v1, input.transfer, a, b, c, input.signals, did);
    expect(await registry.isVerified(input.transfer)).to.equal(true);
    const late = await statement("expired-registry-grace", 2n);
    await expect(registry.connect(wallet).verifyAndRecordWithSelector(v1, late.transfer, a, b, c, late.signals, did))
      .to.be.revertedWithCustomError(registry, "SelectorGraceExpired");
    expect(await registry.isVerified(late.transfer)).to.equal(false);
  });

  it("preserves records, accepts a former default within grace and shares replay protection", async function () {
    const { registry, router, wallet, did, statement, switchDefault } = await fixture();
    const address = await registry.getAddress();
    const recorded = await statement("before-swap", 1n);
    await registry.connect(wallet).verifyAndRecord(recorded.transfer, a, b, c, recorded.signals, did);
    const record = await registry.proofs(recorded.transfer);
    await switchDefault();
    expect(await registry.getAddress()).to.equal(address);
    expect(await registry.proofs(recorded.transfer)).to.deep.equal(record);
    const inflight = await statement("in-flight", 2n);
    await registry.connect(wallet).verifyAndRecordWithSelector(v1, inflight.transfer, a, b, c, inflight.signals, did);
    expect(await registry.isVerified(inflight.transfer)).to.equal(true);
    await expect(registry.connect(wallet).verifyAndRecord(inflight.transfer, a, b, c, inflight.signals, did))
      .to.be.revertedWithCustomError(registry, "TransferAlreadyRecorded");
    const reused = await statement("reused-nullifier", 2n);
    await expect(registry.connect(wallet).verifyAndRecordWithSelector(v2, reused.transfer, a, b, c, reused.signals, did))
      .to.be.revertedWithCustomError(registry, "ProofAlreadyUsed");
    const fresh = await statement("new-default", 3n);
    await registry.connect(wallet).verifyAndRecordWithSelector(v2, fresh.transfer, a, b, c, fresh.signals, did);
    await router.disableVerifier(v1);
    const disabled = await statement("killed-former-default", 4n);
    await expect(registry.connect(wallet).verifyAndRecordWithSelector(v1, disabled.transfer, a, b, c, disabled.signals, did))
      .to.be.revertedWithCustomError(router, "VerifierAlreadyDisabled");
    expect(await registry.isVerified(disabled.transfer)).to.equal(false);
  });

  it("rejects unknown selectors, late transfer timestamps and submissions after grace", async function () {
    const { registry, wallet, did, statement, switchDefault } = await fixture();
    await switchDefault();
    const input = await statement("grace-boundary");
    const submit = (selector: string, signals = input.signals) => registry.connect(wallet)
      .verifyAndRecordWithSelector(selector, input.transfer, a, b, c, signals, did);
    await expect(submit(ethers.id("unselected-version"))).to.be.revertedWithCustomError(registry, "SelectorGraceExpired");
    const late = [...input.signals]; late[5] = (await registry.previousSelectorCutoff(v1)) + 1n;
    await expect(submit(v1, late)).to.be.revertedWithCustomError(registry, "SelectorGraceExpired");
    await time.increaseTo((await registry.previousSelectorUntil(v1)) + 1n);
    await expect(submit(v1)).to.be.revertedWithCustomError(registry, "SelectorGraceExpired");
  });

  it("keeps the registry address as the domain under both submission paths", async function () {
    const { registry, router, wallet, did, statement, switchDefault } = await fixture();
    await switchDefault();
    const input = await statement("adversarial-domain");
    for (const selector of [v1, v2]) {
      for (const [index, value, error] of [
        [11, input.signals[11] + 1n, "WrongChain"],
        [12, BigInt(ethers.solidityPackedKeccak256(["address"], [await router.getAddress()])) % field, "WrongContract"],
        [13, input.signals[13] + 1n, "TransferIDMismatch"],
      ] as [number, bigint, string][]) {
        const altered = [...input.signals]; altered[index] = value;
        await expect(registry.connect(wallet).verifyAndRecordWithSelector(selector, input.transfer, a, b, c, altered, did))
          .to.be.revertedWithCustomError(registry, error);
        expect(await registry.isVerified(input.transfer)).to.equal(false);
        expect(await registry.usedNullifiers(ethers.zeroPadValue("0x01", 32))).to.equal(false);
      }
    }
  });

  it("never accepts a retired verifier as the default", async function () {
    const { registry, router, wallet, did, statement } = await fixture();
    await router.scheduleRetirement(v1);
    await time.increaseTo(await router.timelocks(v1));
    await router.completeRetirement(v1);
    const input = await statement("retired-default");
    await expect(registry.connect(wallet).verifyAndRecord(input.transfer, a, b, c, input.signals, did))
      .to.be.revertedWithCustomError(registry, "VerifierUnavailable");
  });

  it("fails closed while a newly deployed registry has no selected verifier", async function () {
    const { registry, wallet, did, statement } = await fixture(ethers.ZeroHash);
    const input = await statement("unconfigured-default");
    await expect(registry.connect(wallet).verifyAndRecord(input.transfer, a, b, c, input.signals, did))
      .to.be.revertedWithCustomError(registry, "VerifierSelectorNotSet");
  });
});

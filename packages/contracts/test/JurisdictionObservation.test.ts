import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { routeVerifier } from "./helpers/verifier";

// Most cases isolate registry behavior with mock pairing. Rejection also uses
// the actual verifier; valid real proofs stay covered by the artifact suites.
describe("Legacy jurisdiction observations", function () {
  for (const registered of ["US", "EU", "malformed", "@S", "[S", "U@", "U["]) {
    it(`reports ${registered} without changing acceptance`, async function () {
      const [admin, vaspWallet] = await ethers.getSigners();
      const mock = await (await ethers.getContractFactory("MockVerifier")).deploy();
      const { router, selector } = await routeVerifier(await mock.getAddress());
      const vasps = await (await ethers.getContractFactory("VASPRegistry")).deploy(admin.address);
      const root = ethers.keccak256(ethers.toUtf8Bytes("jurisdiction-observation-root"));
      const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, root, 50);
      const registry = await (await ethers.getContractFactory("ComplianceRegistry")).deploy(
        await router.getAddress(), selector, await vasps.getAddress(), await oracle.getAddress(), 250, 1000, 10000,
      );
      const did = ethers.keccak256(ethers.toUtf8Bytes("did:web:observation.example"));
      await vasps.registerVASP(did, vaspWallet.address, registered, "");
      const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
      const transfer = ethers.keccak256(ethers.toUtf8Bytes("observation-transfer"));
      const now = BigInt(await time.latest());
      const signals = [1n, 0n, BigInt(root), 0n, 1n, now, 0x5553n, 0n, 250n, 1000n, 10000n,
        (await ethers.provider.getNetwork()).chainId,
        BigInt(ethers.solidityPackedKeccak256(["address"], [await registry.getAddress()])) % field,
        BigInt(ethers.solidityPackedKeccak256(["bytes32"], [transfer])) % field, 1n, now + 600n];
      if (registered === "US") {
        const revoked = ethers.zeroPadValue("0x01", 32);
        await registry.revokeCredential(revoked);
        async function unchanged() {
          expect(await registry.isVerified(transfer)).to.equal(false);
          expect((await registry.proofs(transfer)).timestamp).to.equal(0);
          expect(await registry.usedNullifiers(ethers.zeroPadValue(ethers.toBeHex(signals[14]), 32))).to.equal(false);
          expect(await registry.queryFilter(registry.filters.JurisdictionCodeMismatch())).to.have.length(0);
          expect(await registry.queryFilter(registry.filters.ProofVerified())).to.have.length(0);
        }
        const rejectedClaims = [0x10000n, 0x4053n, 0x5b53n, 0x5540n, 0x555bn];
        const changes = [
          { index: 11, value: signals[11] + 1n, error: "WrongChain" },
          { index: 12, value: signals[12] + 1n, error: "WrongContract" },
          { index: 15, value: now - 1n, error: "ProofExpired" },
          { index: 5, value: now + 500n, error: "ProofTimestampInFuture" },
          { index: 2, value: signals[2] + 1n, error: "SanctionsRootMismatch" },
          { index: 3, value: 1n, error: "IssuerRootMismatch" },
          { index: 13, value: signals[13] + 1n, error: "TransferIDMismatch" },
          { index: 7, value: BigInt(revoked), error: "CredentialAlreadyRevoked" },
          ...rejectedClaims.map(value => ({ index: 6, value, error: "MalformedJurisdictionCode" })),
          ...[8, 9, 10].map(index => ({ index, value: signals[index] + 1n, error: "ThresholdMismatch" })),
        ];
        for (const { index, value, error } of changes) {
          const altered = [...signals];
          altered[index] = value;
          await expect(registry.connect(vaspWallet).verifyAndRecord(
            transfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], altered, did,
          )).to.be.revertedWithCustomError(registry, error);
          await unchanged();
        }
        const submit = () => registry.connect(vaspWallet).verifyAndRecord(
          transfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], signals, did,
        );
        await oracle.pause();
        await expect(submit()).to.be.revertedWithCustomError(registry, "SanctionsOraclePaused");
        await unchanged();
        await oracle.unpause();
        await vasps.pause();
        await expect(submit()).to.be.revertedWithCustomError(registry, "VASPRegistryPaused");
        await unchanged();
        await vasps.unpause();
        await expect(registry.connect(admin).verifyAndRecord(
          transfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], signals, did,
        )).to.be.revertedWithCustomError(registry, "NotRegisteredVASPWallet");
        await unchanged();
        await registry.setVerifierSelector(ethers.ZeroHash);
        await expect(submit()).to.be.revertedWithCustomError(registry, "VerifierSelectorNotSet");
        await unchanged();
        const actualVerifier = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
        const actualSelector = ethers.id("actual-pairing-rejection");
        await router.registerVerifier(actualSelector, await actualVerifier.getAddress(), "Actual pairing verifier");
        await time.increase(2);
        await router.activateVerifier(actualSelector, "Actual pairing verifier");
        await registry.setVerifierSelector(actualSelector);
        await expect(submit()).to.be.revertedWith("Pairing: ecpairing failed");
        await unchanged();
        // Infinity points have canonical encodings but do not satisfy this key.
        await expect(registry.connect(vaspWallet).verifyAndRecord(
          transfer, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], signals, did,
        )).to.be.revertedWithCustomError(registry, "ProofVerificationFailed");
        await unchanged();
        await registry.setVerifierSelector(selector);
      }
      const tx = registry.connect(vaspWallet).verifyAndRecord(
        transfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], signals, did,
      );
      if (registered === "US") {
        await expect(tx).not.to.emit(registry, "JurisdictionCodeMismatch");
      } else {
        await expect(tx).to.emit(registry, "JurisdictionCodeMismatch")
          .withArgs(transfer, 0x5553n, registered === "EU" ? 0x4555n : 0n);
      }
      expect(await registry.isVerified(transfer)).to.equal(true);
      if (registered === "US") {
        await expect(registry.connect(vaspWallet).verifyAndRecord(
          transfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], signals, did,
        )).to.be.revertedWithCustomError(registry, "TransferAlreadyRecorded");
        const otherTransfer = ethers.id("synthetic-nullifier-reuse");
        const reused = [...signals];
        reused[13] = BigInt(ethers.solidityPackedKeccak256(["bytes32"], [otherTransfer])) % field;
        await expect(registry.connect(vaspWallet).verifyAndRecord(
          otherTransfer, [1n, 2n], [[1n, 2n], [3n, 4n]], [1n, 2n], reused, did,
        )).to.be.revertedWithCustomError(registry, "ProofAlreadyUsed");
        expect(await registry.isVerified(otherTransfer)).to.equal(false);
        expect((await registry.proofs(otherTransfer)).timestamp).to.equal(0);
        expect(await registry.queryFilter(registry.filters.ProofVerified())).to.have.length(1);
      }
    });
  }
});

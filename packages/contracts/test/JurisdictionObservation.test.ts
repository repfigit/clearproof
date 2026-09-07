import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { routeVerifier } from "./helpers/verifier";

// Mock pairing isolates the informational registry behavior; real pairing stays
// covered by the separate legacy/pilot artifact suites.
describe("Legacy jurisdiction observations", function () {
  for (const registered of ["US", "EU", "malformed"]) {
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
    });
  }
});

import { expect } from "chai";
import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import type { PilotGroth16Verifier } from "../typechain-types/contracts/PilotGroth16Verifier";

const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
type G1 = [string, string];
type G2 = [G1, G1];
const g1 = (p: string[]): G1 => [p[0], p[1]];
const g2 = (p: string[][]): G2 => [[p[0][1], p[0][0]], [p[1][1], p[1][0]]];
const hash = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const location = process.env.CLEARPROOF_PILOT_TEST_ARTIFACTS;

(location ? describe : describe.skip)("PilotGroth16Verifier real development pairing", function () {
  this.timeout(120000);
  async function fixture() {
    const directory = path.resolve(location!);
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, "manifest.json"), "utf8"));
    const rawKey = fs.readFileSync(path.join(directory, "verification-key.json"));
    expect(manifest.proof_profile).to.equal("pilot-transfer-v2");
    expect(manifest.verification_key.filename).to.equal("verification-key.json");
    expect(manifest.verification_key.sha256).to.equal(hash(rawKey));
    expect(manifest.verification_key.size).to.equal(rawKey.length);
    const pin = fs.readFileSync(path.join(directory, "development-manifest-pin.txt"), "utf8").trim();
    expect(pin).to.match(/^[0-9a-f]{64}$/);
    const context = JSON.parse(fs.readFileSync(path.join(directory, "synthetic-context.json"), "utf8"));
    expect(context.artifact_manifest_digest).to.equal(pin);
    const vk = JSON.parse(rawKey.toString("utf8"));
    expect([vk.protocol, vk.curve, vk.nPublic, vk.IC.length]).to.deep.equal(["groth16", "bn128", 8, 9]);
    const key = { alpha: g1(vk.vk_alpha_1), beta: g2(vk.vk_beta_2), gamma: g2(vk.vk_gamma_2),
      delta: g2(vk.vk_delta_2), ic: vk.IC.map(g1) as PilotGroth16Verifier.VerificationKeyStruct["ic"] };
    const factory = await ethers.getContractFactory("PilotGroth16Verifier");
    const contract = await factory.deploy(key, "0x" + pin);
    const proof = JSON.parse(fs.readFileSync(path.join(directory, "proof.json"), "utf8"));
    const signals: string[] = JSON.parse(fs.readFileSync(path.join(directory, "public.json"), "utf8"));
    const expected = JSON.parse(fs.readFileSync(path.join(directory, "expected-public.json"), "utf8"));
    expect(signals).to.deep.equal(expected);
    return { contract, factory, key, pin, proof, signals, vk,
      a: g1(proof.pi_a), b: g2(proof.pi_b), c: g1(proof.pi_c) };
  }

  it("matches snarkjs on the Python-tested proof and each changed public signal", async function () {
    const { contract, key, pin, proof, signals, vk, a, b, c } = await fixture();
    const { groth16 } = require("snarkjs");
    expect(await contract.assurance()).to.equal("development-unapproved");
    expect(await contract.proofProfile()).to.equal("pilot-transfer-v2");
    expect(await contract.artifactManifestDigest()).to.equal("0x" + pin);
    const commitment = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["tuple(uint256[2] alpha,uint256[2][2] beta,uint256[2][2] gamma,uint256[2][2] delta,uint256[2][9] ic)"], [key]));
    expect(await contract.verificationKeyCommitment()).to.equal(commitment);
    expect(await groth16.verify(vk, signals, proof)).to.equal(true);
    expect(await contract.verifyProof(a, b, c, signals)).to.equal(true);
    for (let i = 0; i < 8; i++) {
      const changed = [...signals]; changed[i] = ((BigInt(changed[i]) + 1n) % R).toString();
      expect(await groth16.verify(vk, changed, proof)).to.equal(false);
      expect(await contract.verifyProof(a, b, c, changed)).to.equal(false);
    }
    // Pairing is read-only: repeated inspection does not spend a nullifier.
    expect(await contract.verifyProof(a, b, c, signals)).to.equal(true);
  });

  it("rejects wrong proof points, noncanonical coordinates/scalars and legacy ABI input", async function () {
    const { contract, proof, signals, vk, a, b, c } = await fixture();
    const { groth16 } = require("snarkjs");
    const negativeC: G1 = [c[0], (Q - BigInt(c[1])).toString()];
    expect(await groth16.verify(vk, signals, { ...proof, pi_c: [...negativeC, "1"] })).to.equal(false);
    expect(await contract.verifyProof(a, b, negativeC, signals)).to.equal(false);
    for (const [badA, badB, badC] of [
      [[a[0], (BigInt(a[1]) + Q).toString()], b, c],
      [a, [[Q.toString(), b[0][1]], b[1]], c],
      [a, b, [Q.toString(), c[1]]],
    ]) {
      await expect(contract.verifyProof(badA as any, badB as any, badC as any, signals))
        .to.be.revertedWithCustomError(contract, "InvalidCoordinate");
    }
    await expect(contract.verifyProof(["1", "1"], b, c, signals)).to.be.reverted;
    for (let i = 0; i < 8; i++) {
      const changed = [...signals]; changed[i] = R.toString();
      await expect(contract.verifyProof(a, b, c, changed)).to.be.revertedWithCustomError(contract, "NoncanonicalSignal");
    }
    let rejected = false;
    try { await contract.verifyProof(a, b, c, [...signals, ...signals]); } catch { rejected = true; }
    expect(rejected).to.equal(true);
  });

  it("rejects invalid key points and commits independently to changed key material", async function () {
    const { contract, factory, key, pin, a, b, c, signals } = await fixture();
    await expect(factory.deploy(key, ethers.ZeroHash)).to.be.revertedWithCustomError(contract, "InvalidKey");
    await expect(factory.deploy({ ...key, alpha: ["0", "0"] }, "0x" + pin))
      .to.be.revertedWithCustomError(contract, "InvalidKey");
    await expect(factory.deploy({ ...key, alpha: [Q.toString(), "1"] }, "0x" + pin))
      .to.be.revertedWithCustomError(contract, "InvalidCoordinate");
    await expect(factory.deploy({ ...key, beta: [["1", "1"], ["1", "1"]] }, "0x" + pin)).to.be.reverted;
    const changed = { ...key, alpha: g1([key.alpha[0], (Q - BigInt(key.alpha[1])).toString()]) };
    const other = await factory.deploy(changed, "0x" + pin);
    expect(await other.verificationKeyCommitment()).not.to.equal(await contract.verificationKeyCommitment());
    expect(await other.verifyProof(a, b, c, signals)).to.equal(false);
  });
});

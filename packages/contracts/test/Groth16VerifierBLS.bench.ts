import { expect } from "chai";
import hre from "hardhat";
import fs from "fs";

/**
 * Gas benchmark for the BLS12-381 Groth16 verifier (ADR 0002, Open Task 1).
 *
 * Compares verifyProof gas between:
 *   - Groth16Verifier     (BN128, EIP-196/197 precompiles) — production
 *   - Groth16VerifierBLS  (BLS12-381, EIP-2537 precompiles, Pectra+) — candidate
 *
 * Inputs come from a committed-style BLS12-381 proof generated against
 * compliance.circom (see docs/adr/0002-bls12381-migration.md).
 */

const REPO_ROOT = __dirname + "/../../..";
const BLS_ARTIFACTS =
  process.env.BLS_ARTIFACTS_DIR || `${REPO_ROOT}/tests/vectors/compliance-bls`;
const BN_ARTIFACTS = `${REPO_ROOT}/tests/vectors/compliance`;

// BLS12-381 base field q (for tampering with a proof point deterministically)
const Q = BigInt(
  "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
);

function fp(v: string | bigint): string {
  return BigInt(v).toString(16).padStart(128, "0");
}

function encodeBlsProof(proof: any): string {
  // pi_a (G1) || pi_b (G2, swap c1/c0 to match EIP-2537) || pi_c (G1)
  const a = fp(proof.pi_a[0]) + fp(proof.pi_a[1]);
  const b =
    fp(proof.pi_b[0][0]) + fp(proof.pi_b[0][1]) + fp(proof.pi_b[1][0]) + fp(proof.pi_b[1][1]);
  const c = fp(proof.pi_c[0]) + fp(proof.pi_c[1]);
  return "0x" + a + b + c;
}

describe("Groth16VerifierBLS (BLS12-381 / EIP-2537) gas benchmark", function () {
  it("verifies a valid BLS12-381 proof on-chain and reports gas", async function () {
    const proof = JSON.parse(fs.readFileSync(`${BLS_ARTIFACTS}/proof_bls.json`, "utf-8"));
    const pubSignals: string[] = JSON.parse(
      fs.readFileSync(`${BLS_ARTIFACTS}/public_bls.json`, "utf-8")
    );
    const proofBytes = encodeBlsProof(proof);

    const Factory = await hre.ethers.getContractFactory("Groth16VerifierBLS");
    const verifier = await Factory.deploy();
    await verifier.waitForDeployment();

    expect(await verifier.verifyProof.staticCall(proofBytes, pubSignals)).to.equal(true);

    // Gas: eth_call doesn't meter gas — estimate via estimateGas
    const gas = await verifier.verifyProof.estimateGas(proofBytes, pubSignals);
    console.log(`\n    BLS12-381 verifyProof gas (estimate): ${gas.toString()}`);
  });

  it("rejects malformed proof lengths and signal counts before accepting the original proof", async function () {
    const proof = JSON.parse(fs.readFileSync(`${BLS_ARTIFACTS}/proof_bls.json`, "utf-8"));
    const pubSignals: string[] = JSON.parse(fs.readFileSync(`${BLS_ARTIFACTS}/public_bls.json`, "utf-8"));
    const proofBytes = encodeBlsProof(proof);
    const verifier = await (await hre.ethers.getContractFactory("Groth16VerifierBLS")).deploy();
    expect(hre.ethers.getBytes(proofBytes)).to.have.length(512);
    expect(pubSignals).to.have.length(16);
    for (const malformed of ["0x", proofBytes.slice(0, -2), proofBytes + "00"]) {
      await expect(verifier.verifyProof(malformed, pubSignals))
        .to.be.revertedWith("Proof must be 512 bytes (G1 || G2 || G1)");
    }
    for (const malformed of [[], pubSignals.slice(0, -1), [...pubSignals, "0"]]) {
      await expect(verifier.verifyProof(proofBytes, malformed))
        .to.be.revertedWith("Wrong public signal count");
    }
    expect(await verifier.verifyProof(proofBytes, pubSignals)).to.equal(true);
  });

  it("rejects a tampered BLS12-381 proof", async function () {
    const proof = JSON.parse(fs.readFileSync(`${BLS_ARTIFACTS}/proof_bls.json`, "utf-8"));
    const pubSignals: string[] = JSON.parse(
      fs.readFileSync(`${BLS_ARTIFACTS}/public_bls.json`, "utf-8")
    );

    // Tamper: y -> q - y on pA (valid point, wrong proof)
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.pi_a[1] = (Q - BigInt(proof.pi_a[1])).toString();
    const proofBytes = encodeBlsProof(tampered);

    const Factory = await hre.ethers.getContractFactory("Groth16VerifierBLS");
    const verifier = await Factory.deploy();
    await verifier.waitForDeployment();

    expect(await verifier.verifyProof.staticCall(proofBytes, pubSignals)).to.equal(false);
  });

  it("compares against the BN128 verifier gas (committed parity vector)", async function () {
    const proof = JSON.parse(fs.readFileSync(`${BN_ARTIFACTS}/proof.json`, "utf-8"));
    const pubSignals: string[] = JSON.parse(
      fs.readFileSync(`${BN_ARTIFACTS}/public.json`, "utf-8")
    );

    const Factory = await hre.ethers.getContractFactory("Groth16Verifier");
    const verifier = await Factory.deploy();
    await verifier.waitForDeployment();

    const pA: [string, string] = [proof.pi_a[0], proof.pi_a[1]];
    const pB: [[string, string], [string, string]] = [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ];
    const pC: [string, string] = [proof.pi_c[0], proof.pi_c[1]];

    expect(await verifier.verifyProof.staticCall(pA, pB, pC, pubSignals)).to.equal(true);

    const gas = await verifier.verifyProof.estimateGas(pA, pB, pC, pubSignals);
    console.log(`    BN128     verifyProof gas (estimate): ${gas.toString()}`);
  });
});

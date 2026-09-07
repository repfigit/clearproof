import { routeVerifier } from "./helpers/verifier";
import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

describe("Groth16Verifier", function () {
  it("should verify a valid compliance proof", async function () {
    // Read the committed parity test vector (tests/vectors/compliance/).
    // Regenerate with: node packages/cli/dist/index.js demo --export tests/vectors/compliance
    const vectorDir = path.resolve(__dirname, "../../../tests/vectors/compliance");
    const proofPath = path.join(vectorDir, "proof.json");
    const publicPath = path.join(vectorDir, "public.json");

    if (!fs.existsSync(proofPath) || !fs.existsSync(publicPath)) {
      this.skip();  // Parity vector not committed — see tests/vectors/README.md
      return;
    }

    const proof = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf-8"));

    // Deploy the verifier
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Format proof for the contract call
    // pA: [x, y]
    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];

    // pB: [[x1, x2], [y1, y2]] — note: snarkjs outputs b in a different order
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];

    // pC: [x, y]
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

    // Public signals
    const pubSignals = publicSignals.map((s: string) => BigInt(s));

    // Verify the proof on-chain
    const result = await verifier.verifyProof(pA, pB, pC, pubSignals);
    expect(result).to.equal(true);
  });

  it("should reject an invalid proof", async function () {
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Use garbage values for the proof
    const pA: [bigint, bigint] = [BigInt(1), BigInt(2)];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(1), BigInt(2)],
      [BigInt(3), BigInt(4)],
    ];
    const pC: [bigint, bigint] = [BigInt(1), BigInt(2)];
    const pubSignals = Array(16).fill(BigInt(0));

    // Exact rejection: a broad catch would also swallow a failed assertion.
    await expect(verifier.verifyProof(pA, pB, pC, pubSignals)).to.be.revertedWith("Pairing: ecpairing failed");
  });

  it("should reject a public signal outside the scalar field", async function () {
    const vectorDir = path.resolve(__dirname, "../../../tests/vectors/compliance");
    const proofPath = path.join(vectorDir, "proof.json");
    const publicPath = path.join(vectorDir, "public.json");
    if (!fs.existsSync(proofPath) || !fs.existsSync(publicPath)) {
      this.skip();
      return;
    }

    const proof = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf-8"));

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

    // Replace one signal with the scalar field order r itself — must revert.
    const SNARK_SCALAR_FIELD = BigInt(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    const tampered = publicSignals.map((s: string) => BigInt(s));
    tampered[4] = SNARK_SCALAR_FIELD;

    await expect(
      verifier.verifyProof(pA, pB, pC, tampered),
    ).to.be.revertedWithCustomError(verifier, "PublicSignalExceedsScalarField");
  });

  it("should reject a tampered-but-in-field public signal with false", async function () {
    const vectorDir = path.resolve(__dirname, "../../../tests/vectors/compliance");
    const proofPath = path.join(vectorDir, "proof.json");
    const publicPath = path.join(vectorDir, "public.json");
    if (!fs.existsSync(proofPath) || !fs.existsSync(publicPath)) {
      this.skip();
      return;
    }

    const proof = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf-8"));

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

    // Flip amount_tier 2 -> 3: in-field, but wrong for this proof.
    const tampered = publicSignals.map((s: string) => BigInt(s));
    tampered[4] = BigInt(3);

    const result = await verifier.verifyProof(pA, pB, pC, tampered);
    expect(result).to.equal(false);
  });
});

describe("ComplianceRegistry (domain-bound)", function () {
  it("rejects a committed proof from a different chain", async function () {
    // NOTE: This test requires a proof generated with domain_chain_id matching
    // the Hardhat network chain ID (31337). Since our test proof uses Sepolia (11155111),
    // we test that the domain check correctly rejects mismatched chains.
    // Full proof generation with matching domains is tested in E2E.test.ts.
    const proofPath = path.resolve(__dirname, "../../../tests/vectors/compliance/proof.json");
    const publicPath = path.resolve(__dirname, "../../../tests/vectors/compliance/public.json");

    if (!fs.existsSync(proofPath) || !fs.existsSync(publicPath)) {
      this.skip();  // Circuit fixtures required — run circuit tests first
      return;
    }

    const proof = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf-8"));

    const [admin] = await ethers.getSigners();

    // Deploy verifier, VASP registry, sanctions oracle, and compliance registry
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 10);
    await sanctionsOracle.waitForDeployment();

    const { router, selector } = await routeVerifier(await verifier.getAddress());
    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await router.getAddress(),
      selector,
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress(),
      250,
      1000,
      10000
    );
    await registry.waitForDeployment();

    // Register a VASP
    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:test-vasp.example"));
    await vaspRegistry.registerVASP(vaspDid, admin.address, "US", "");

    // Format proof
    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
    const pubSignals = publicSignals.map((s: string) => BigInt(s));

    const transferId = ethers.id("test-transfer-001");

    // The test proof was generated with domain_chain_id=11155111 (Sepolia)
    // but Hardhat runs on chain 31337. The contract correctly rejects this.
    await expect(
      registry.verifyAndRecord(transferId, pA, pB, pC, pubSignals, vaspDid)
    ).to.be.revertedWithCustomError(registry, "WrongChain");
  });
});

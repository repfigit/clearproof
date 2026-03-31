/**
 * End-to-end integration test: generate proof (snarkjs) -> submit on-chain -> verify.
 *
 * This test exercises the full flow:
 *   1. Generate a Groth16 proof using the compiled circuit + proving key
 *   2. Deploy all contracts to Hardhat network
 *   3. Submit the proof to ComplianceRegistry.verifyAndRecord()
 *   4. Verify the proof was recorded on-chain
 *
 * Requires circuit artifacts in artifacts/ (run `bash scripts/compile_circuits.sh`).
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";

// Resolve paths relative to monorepo root
const ARTIFACTS_DIR = path.resolve(__dirname, "../../../artifacts");
const WASM_PATH = path.join(ARTIFACTS_DIR, "compliance_js", "compliance.wasm");
const ZKEY_PATH = path.join(ARTIFACTS_DIR, "compliance_final.zkey");
const VKEY_PATH = path.join(ARTIFACTS_DIR, "verification_key.json");

describe("E2E: Prove -> Submit On-Chain -> Verify", function () {
  // Circuit proof generation can take a few seconds
  this.timeout(30000);

  before(function () {
    // Skip if circuit artifacts are not built
    if (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH)) {
      this.skip();
    }
  });

  it("should generate a proof, submit it on-chain, and verify it was recorded", async function () {
    const [admin] = await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    // ================================================================
    // 1. Deploy all contracts
    // ================================================================
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const sanctionsRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, sanctionsRoot, 10);
    await sanctionsOracle.waitForDeployment();

    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifier.getAddress(),
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress()
    );
    await registry.waitForDeployment();

    // Register a VASP (admin is the VASP wallet)
    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:e2e-vasp.example"));
    await vaspRegistry.registerVASP(vaspDid, admin.address, "US");

    // Update sanctions root to match what we'll put in the proof
    const sanctionsTreeRoot =
      "5165912880528319654224975632916389245447155966222261466225444971111963668911";
    await time.increase(3601); // pass cooldown
    await sanctionsOracle.updateRoot(
      ethers.zeroPadValue(ethers.toBeHex(BigInt(sanctionsTreeRoot)), 32),
      16
    );

    // Update issuer root to match proof
    const issuerTreeRoot =
      "2679583485444090814519739490480408597587979659313135468790553999186444635148";
    await vaspRegistry.updateIssuerRoot(
      ethers.zeroPadValue(ethers.toBeHex(BigInt(issuerTreeRoot)), 32)
    );

    // ================================================================
    // 2. Compute domain binding values
    // ================================================================
    const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

    const registryAddress = await registry.getAddress();
    const domainContractHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["address"], [registryAddress]))
    ) % BN128_R).toString();

    const transferId = ethers.id("e2e-transfer-001");
    const transferIdHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["bytes32"], [transferId]))
    ) % BN128_R).toString();

    // Credential commitment (matches demo input)
    const credentialCommitment =
      "3946334516594870472864654055107878340628457451312090927820290073103136770198";

    // Compute nullifier = Poseidon(credentialCommitment, transferIdHash)
    // We need circomlibjs for this
    const { buildPoseidon } = require("circomlibjs");
    const poseidon = await buildPoseidon();
    const nullifierHash = poseidon([
      BigInt(credentialCommitment),
      BigInt(transferIdHash),
    ]);
    const credentialNullifier = poseidon.F.toString(nullifierHash, 10);

    // Get current block timestamp for proof_expires_at
    const currentTime = await time.latest();
    const proofExpiresAt = currentTime + 600; // 10 min from now

    // ================================================================
    // 3. Generate proof with snarkjs
    // ================================================================
    const circuitInput: Record<string, string | string[]> = {
      sanctions_tree_root: sanctionsTreeRoot,
      issuer_tree_root: issuerTreeRoot,
      amount_tier: "2",
      transfer_timestamp: String(currentTime),
      jurisdiction_code: "21843", // "US"
      credential_commitment: credentialCommitment,
      tier2_threshold: "25000",
      tier3_threshold: "300000",
      tier4_threshold: "1000000",
      domain_chain_id: String(chainId),
      domain_contract_hash: domainContractHash,
      transfer_id_hash: transferIdHash,
      credential_nullifier: credentialNullifier,
      proof_expires_at: String(proofExpiresAt),
      // Private inputs
      issuer_did: "123456789",
      kyc_tier: "2",
      sanctions_clear: "1",
      issued_at: "1700000000",
      expires_at: "1800000000",
      issuer_path_elements: Array(10).fill("0"),
      issuer_path_indices: Array(10).fill("0"),
      wallet_address_hash: "500",
      left_key: "100",
      right_key: "1000",
      left_path_elements: [
        "19403184926589903505792940814745119867051186734744914561909518986732862166057",
        ...Array(19).fill("0"),
      ],
      left_path_indices: Array(20).fill("0"),
      right_path_elements: [
        "9326983004124375216551096032771341412132084386804905225430866942582012914771",
        ...Array(19).fill("0"),
      ],
      right_path_indices: ["1", ...Array(19).fill("0")],
      actual_amount: "100000",
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      WASM_PATH,
      ZKEY_PATH
    );

    // Verify off-chain first
    const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf-8"));
    const offChainValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    expect(offChainValid).to.equal(true, "Off-chain verification should pass");
    expect(publicSignals).to.have.length(16);
    expect(publicSignals[0]).to.equal("1", "is_compliant should be 1");

    // ================================================================
    // 4. Submit proof on-chain
    // ================================================================
    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
    const pubSignals = publicSignals.map((s: string) => BigInt(s));

    const tx = await registry.verifyAndRecord(
      transferId,
      pA,
      pB,
      pC,
      pubSignals,
      vaspDid
    );
    const receipt = await tx.wait();
    expect(receipt!.status).to.equal(1, "Transaction should succeed");

    // ================================================================
    // 5. Verify on-chain state
    // ================================================================
    expect(await registry.isVerified(transferId)).to.equal(true);

    // Verify replay protection — submitting same proof for the same transfer should fail
    await expect(
      registry.verifyAndRecord(transferId, pA, pB, pC, pubSignals, vaspDid)
    ).to.be.revertedWith("Transfer already recorded");
  });
});

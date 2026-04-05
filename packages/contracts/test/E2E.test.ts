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
    await vaspRegistry.registerVASP(vaspDid, admin.address, "US", "");

    // ================================================================
    // 2. Build sanctions + issuer trees dynamically with Poseidon
    // ================================================================
    const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const { buildPoseidon } = require("circomlibjs");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Helper: Poseidon hash and return decimal string
    const pH = (inputs: bigint[]): string => F.toString(poseidon(inputs), 10);

    // Build a minimal sorted sanctions tree (depth=20):
    //   Leaves: [left_key=100, right_key=1000] padded to 2^20 with zeros.
    //   The circuit now treats left_key/right_key AS leaf values directly
    //   (no SanctionsLeafHash re-hashing).
    //   wallet_address_hash=500 falls in the gap: 100 < 500 < 1000.
    const leftKey = "100";
    const rightKey = "1000";
    const walletHash = "500";

    // Build tree bottom-up: 2 real leaves at indices 0,1; rest are 0-padding
    // Level 0 (leaves): [100, 1000, 0, 0, ...]
    // Internal nodes: Poseidon(left_child, right_child)
    const treeDepth = 20;
    const numLeaves = 2 ** treeDepth;
    // We only need to compute the path — not the whole tree.
    // Left leaf is at index 0, right leaf is at index 1.
    // Sibling of index 0 is index 1 (value=1000).
    // Sibling of index 1 is index 0 (value=100).
    // All higher siblings are Poseidon(0, 0) since the rest of the tree is empty.

    // Precompute Poseidon(0, 0) for empty subtrees at each level
    const zeroHashes: string[] = ["0"];
    for (let i = 1; i <= treeDepth; i++) {
      zeroHashes.push(pH([BigInt(zeroHashes[i - 1]), BigInt(zeroHashes[i - 1])]));
    }

    // Left path (index 0): sibling is right leaf, then empty subtrees
    const leftPathElements = [rightKey, ...zeroHashes.slice(1, treeDepth)];
    const leftPathIndices = Array(treeDepth).fill("0"); // index 0 = all-left

    // Right path (index 1): sibling is left leaf, then empty subtrees
    const rightPathElements = [leftKey, ...zeroHashes.slice(1, treeDepth)];
    const rightPathIndices = ["1", ...Array(treeDepth - 1).fill("0")]; // index 1 = right at level 0

    // Compute sanctions root: hash up from leaves
    let currentLeft = leftKey;
    let currentRight = rightKey;
    // Level 0 parent: Poseidon(100, 1000)
    let node = pH([BigInt(currentLeft), BigInt(currentRight)]);
    // Levels 1+: Poseidon(node, zeroHash[level])
    for (let i = 1; i < treeDepth; i++) {
      node = pH([BigInt(node), BigInt(zeroHashes[i])]);
    }
    const sanctionsTreeRoot = node;

    await time.increase(3601); // pass cooldown
    await sanctionsOracle.updateRoot(
      ethers.zeroPadValue(ethers.toBeHex(BigInt(sanctionsTreeRoot)), 32),
      16
    );

    // Build issuer tree (depth=10): single issuer at index 0, rest zeros
    // Issuer leaf = Poseidon(0x02, issuer_did) per domain separation
    const issuerDid = "123456789";
    const issuerLeaf = pH([2n, BigInt(issuerDid)]);
    const issuerZeroHashes: string[] = ["0"];
    for (let i = 1; i <= 10; i++) {
      issuerZeroHashes.push(pH([BigInt(issuerZeroHashes[i - 1]), BigInt(issuerZeroHashes[i - 1])]));
    }
    let issuerNode = issuerLeaf;
    for (let i = 0; i < 10; i++) {
      issuerNode = pH([BigInt(issuerNode), BigInt(issuerZeroHashes[i])]);
    }
    const issuerTreeRoot = issuerNode;

    await vaspRegistry.updateIssuerRoot(
      ethers.zeroPadValue(ethers.toBeHex(BigInt(issuerTreeRoot)), 32)
    );

    // ================================================================
    // 3. Compute domain binding + credential values
    // ================================================================
    const registryAddress = await registry.getAddress();
    const domainContractHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["address"], [registryAddress]))
    ) % BN128_R).toString();

    const transferId = ethers.id("e2e-transfer-001");
    const transferIdHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["bytes32"], [transferId]))
    ) % BN128_R).toString();

    // Credential commitment = Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
    const credentialCommitment = pH([
      BigInt(issuerDid), 2n, 1n, 1700000000n, 1800000000n,
    ]);

    // Nullifier = Poseidon(credentialCommitment, transferIdHash)
    const credentialNullifier = pH([
      BigInt(credentialCommitment), BigInt(transferIdHash),
    ]);

    // Get current block timestamp for proof_expires_at
    const currentTime = await time.latest();
    const proofExpiresAt = currentTime + 600; // 10 min from now

    // ================================================================
    // 4. Generate proof with snarkjs
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
      issuer_did: issuerDid,
      kyc_tier: "2",
      sanctions_clear: "1",
      issued_at: "1700000000",
      expires_at: "1800000000",
      issuer_path_elements: issuerZeroHashes.slice(0, 10),
      issuer_path_indices: Array(10).fill("0"),
      wallet_address_hash: walletHash,
      left_key: leftKey,
      right_key: rightKey,
      left_path_elements: leftPathElements,
      left_path_indices: leftPathIndices,
      right_path_elements: rightPathElements,
      right_path_indices: rightPathIndices,
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

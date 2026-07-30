import { expect } from "chai";
import { ethers } from "hardhat";

/**
 * AIF-79 — threshold binding.
 *
 * tier2/3/4_threshold (public signals 8-10) are unconstrained public inputs:
 * the circuit does not derive them, the prover supplies them. Without a
 * verifier-side check, a prover submits tier2_threshold = 2**63, lands any
 * amount in tier 1, and the proof verifies — defeating both the tier
 * attestation and the SAR review flag (tier >= 3).
 *
 * These tests drive verifyAndRecord all the way past every upstream check so
 * that _checkThresholds is genuinely reached. The differential is the point:
 * with correct thresholds the call proceeds to the pairing check and fails
 * there (ProofVerificationFailed, because the proof is a dummy); with tampered
 * thresholds it fails earlier with ThresholdMismatch.
 */

const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// config/jurisdiction_thresholds.json
const US = { code: 0x5553n, tier2: 250n, tier3: 3000n, tier4: 10000n }; // "US"
const EU = { code: 0x4555n, tier2: 250n, tier3: 1000n, tier4: 10000n }; // "EU"
const DEFAULT_KEY = 0;
const DEFAULT_T = { tier2: 250n, tier3: 1000n, tier4: 10000n };

async function deployAll() {
  const [admin, vaspWallet, other] = await ethers.getSigners();

  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();

  const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
  const vaspRegistry = await VASPRegistry.deploy(admin.address);
  await vaspRegistry.waitForDeployment();

  // Reduce mod r: Groth16Verifier reverts PublicSignalExceedsScalarField on any
  // public signal >= the BN254 scalar field order, and the root travels as one.
  const initialRoot = ethers.zeroPadValue(
    ethers.toBeHex(BigInt(ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"))) % BN128_R),
    32
  );
  const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
  const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
  await sanctionsOracle.waitForDeployment();

  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(
    await verifier.getAddress(),
    await vaspRegistry.getAddress(),
    await sanctionsOracle.getAddress()
  );
  await registry.waitForDeployment();

  // Seed the threshold table the way deploy.ts does.
  await registry.setJurisdictionThresholds(DEFAULT_KEY, DEFAULT_T.tier2, DEFAULT_T.tier3, DEFAULT_T.tier4);
  await registry.setJurisdictionThresholds(Number(US.code), US.tier2, US.tier3, US.tier4);
  await registry.setJurisdictionThresholds(Number(EU.code), EU.tier2, EU.tier3, EU.tier4);

  const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
  await vaspRegistry.registerVASP(didHash, vaspWallet.address, "US", "");

  return { verifier, vaspRegistry, sanctionsOracle, registry, admin, vaspWallet, other, didHash, initialRoot };
}

/**
 * Public signals that satisfy every check upstream of _checkThresholds, so the
 * only thing under test is threshold binding.
 */
async function buildSignals(
  registryAddress: string,
  sanctionsRoot: string,
  issuerRoot: bigint,
  transferId: string,
  overrides: Partial<Record<number, bigint>> = {}
): Promise<bigint[]> {
  const now = BigInt(await ethers.provider.getBlock("latest").then((b) => b!.timestamp));
  const chainId = (await ethers.provider.getNetwork()).chainId;

  const s = Array(16).fill(0n) as bigint[];
  s[0] = 1n; // is_compliant
  s[1] = 0n; // sar_review_flag
  s[2] = BigInt(sanctionsRoot); // sanctions_tree_root
  s[3] = issuerRoot; // issuer_tree_root
  s[4] = 2n; // amount_tier
  s[5] = now - 60n; // transfer_timestamp (not in future)
  s[6] = US.code; // jurisdiction_code
  s[7] = 0n; // credential_commitment (not revoked)
  s[8] = US.tier2;
  s[9] = US.tier3;
  s[10] = US.tier4;
  s[11] = chainId; // domain_chain_id
  s[12] = BigInt(ethers.keccak256(ethers.solidityPacked(["address"], [registryAddress]))) % BN128_R;
  s[13] = BigInt(ethers.keccak256(ethers.solidityPacked(["bytes32"], [transferId]))) % BN128_R;
  s[14] = 12345n; // credential_nullifier (unused)
  s[15] = now + 3600n; // proof_expires_at

  for (const [idx, val] of Object.entries(overrides)) s[Number(idx)] = val!;
  return s;
}

function dummyProofParts() {
  return {
    pA: [1n, 2n] as [bigint, bigint],
    pB: [
      [1n, 2n],
      [3n, 4n],
    ] as [[bigint, bigint], [bigint, bigint]],
    pC: [1n, 2n] as [bigint, bigint],
  };
}

describe("ComplianceRegistry — threshold binding (AIF-79)", function () {
  it("reaches the pairing check when thresholds are correct", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet, didHash } = await deployAll();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-ok"));
    const signals = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId
    );
    const p = dummyProofParts();

    // Proves _checkThresholds passed: execution reached the pairing check, which
    // rejects the dummy proof points. Asserted as "not a threshold error" rather
    // than on the pairing library's revert string, which is not our contract.
    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.not.be.revertedWithCustomError(registry, "ThresholdMismatch");
  });

  it("rejects a prover-chosen tier2_threshold that would land any amount in tier 1", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet, didHash } = await deployAll();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-tampered"));
    const signals = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId,
      { 8: 2n ** 63n } // the actual attack
    );
    const p = dummyProofParts();

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.be.revertedWithCustomError(registry, "ThresholdMismatch");
  });

  it("rejects thresholds borrowed from another jurisdiction", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet, didHash } = await deployAll();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-crossjur"));
    // EU tier3 (1000) submitted while claiming US (3000).
    const signals = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId,
      { 9: EU.tier3 }
    );
    const p = dummyProofParts();

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.be.revertedWithCustomError(registry, "ThresholdMismatch");
  });

  it("rejects a malformed jurisdiction code", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet, didHash } = await deployAll();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-badjur"));
    const signals = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId,
      { 6: 0x3031n } // "01" — digits, not uppercase letters
    );
    const p = dummyProofParts();

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.be.revertedWithCustomError(registry, "MalformedJurisdictionCode");
  });

  it("falls back to the default entry for an unregistered jurisdiction", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet, didHash } = await deployAll();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-unregistered"));
    // "GB" is not seeded; the FATF default applies. US tier3 (3000) must fail.
    const signals = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId,
      { 6: 0x4742n }
    );
    const p = dummyProofParts();

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.be.revertedWithCustomError(registry, "ThresholdMismatch");

    const defaulted = await buildSignals(
      await registry.getAddress(),
      await sanctionsOracle.currentRoot(),
      BigInt(await vaspRegistry.issuerMerkleRoot()),
      transferId,
      { 6: 0x4742n, 9: DEFAULT_T.tier3 }
    );
    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, defaulted, didHash)
    ).to.not.be.revertedWithCustomError(registry, "ThresholdMismatch");
  });

  describe("setJurisdictionThresholds", function () {
    it("rejects out-of-order thresholds", async function () {
      const { registry } = await deployAll();
      await expect(
        registry.setJurisdictionThresholds(Number(US.code), 5000n, 1000n, 10000n)
      ).to.be.revertedWithCustomError(registry, "ThresholdsNotOrdered");
    });

    it("is role-gated", async function () {
      const { registry, other } = await deployAll();
      await expect(
        registry.connect(other).setJurisdictionThresholds(Number(US.code), 250n, 3000n, 10000n)
      ).to.be.reverted;
    });

    it("exposes the resolved table", async function () {
      const { registry } = await deployAll();
      const us = await registry.thresholdsFor(Number(US.code));
      expect(us.tier3).to.equal(US.tier3);
      const gb = await registry.thresholdsFor(0x4742);
      expect(gb.tier3).to.equal(DEFAULT_T.tier3);
    });
  });
});

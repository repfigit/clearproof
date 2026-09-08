import { routeVerifier } from "./helpers/verifier";
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

  const { router, selector } = await routeVerifier(await verifier.getAddress());
  const Registry = await ethers.getContractFactory("ComplianceRegistry");
  const registry = await Registry.deploy(
    await router.getAddress(),
    selector,
    await vaspRegistry.getAddress(),
    await sanctionsOracle.getAddress(),
    DEFAULT_T.tier2,
    DEFAULT_T.tier3,
    DEFAULT_T.tier4
  );
  await registry.waitForDeployment();

  // Seed the per-jurisdiction entries the way deploy.ts does. The default entry
  // is set by the constructor — see AIF-95.
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

    // The exact pairing-precompile rejection proves all earlier checks passed.
    await expect(
      registry.connect(vaspWallet).verifyAndRecord(transferId, p.pA, p.pB, p.pC, signals, didHash)
    ).to.be.revertedWith("Pairing: ecpairing failed");
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
    ).to.be.revertedWith("Pairing: ecpairing failed");
  });

  describe("constructor-set default (AIF-95)", function () {
    it("resolves the default with no post-deploy transaction", async function () {
      const [admin] = await ethers.getSigners();

      const Verifier = await ethers.getContractFactory("Groth16Verifier");
      const verifier = await Verifier.deploy();
      const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
      const vaspRegistry = await VASPRegistry.deploy(admin.address);
      const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
      const oracle = await SanctionsOracle.deploy(
        admin.address,
        ethers.zeroPadValue(ethers.toBeHex(1234n), 32),
        50
      );

      const { router, selector } = await routeVerifier(await verifier.getAddress());
      const Registry = await ethers.getContractFactory("ComplianceRegistry");
      const registry = await Registry.deploy(
        await router.getAddress(),
        selector,
        await vaspRegistry.getAddress(),
        await oracle.getAddress(),
        DEFAULT_T.tier2,
        DEFAULT_T.tier3,
        DEFAULT_T.tier4
      );
      await registry.waitForDeployment();

      // No setJurisdictionThresholds call has been made. Before AIF-95 the table
      // was empty here and the registry accepted nothing at all.
      const resolved = await registry.thresholdsFor(Number(US.code));
      expect(resolved.registered).to.equal(true);
      expect(resolved.tier2).to.equal(DEFAULT_T.tier2);
      expect(resolved.tier3).to.equal(DEFAULT_T.tier3);
      expect(resolved.tier4).to.equal(DEFAULT_T.tier4);
    });

    it("preserves a registered fallback across accepted and rejected table updates", async function () {
      const { registry, other } = await deployAll();
      const unregistered = 0x4742;
      async function checkFallback() {
        const fallback = await registry.jurisdictionThresholds(DEFAULT_KEY);
        expect(fallback.registered).to.equal(true);
        for (const code of [0, 1, 0x4141, Number(US.code), Number(EU.code), 0x5a5a, 0xffff]) {
          expect((await registry.thresholdsFor(code)).registered).to.equal(true);
        }
        expect((await registry.jurisdictionThresholds(unregistered)).registered).to.equal(false);
        expect(await registry.thresholdsFor(unregistered)).to.deep.equal(fallback);
      }
      await checkFallback();
      for (const values of [[1000n, 1000n, 2000n], [1n, 3n, 2n]] as const) {
        const previous = await registry.jurisdictionThresholds(DEFAULT_KEY);
        await expect(registry.setJurisdictionThresholds(DEFAULT_KEY, ...values))
          .to.be.revertedWithCustomError(registry, "ThresholdsNotOrdered");
        expect(await registry.jurisdictionThresholds(DEFAULT_KEY)).to.deep.equal(previous);
        await checkFallback();
      }
      await expect(registry.connect(other).setJurisdictionThresholds(DEFAULT_KEY, 1, 2, 3))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, await registry.THRESHOLD_ADMIN_ROLE());
      await checkFallback();
      await registry.setJurisdictionThresholds(DEFAULT_KEY, 0, 1, (1n << 64n) - 1n);
      await checkFallback();
      await registry.setJurisdictionThresholds(DEFAULT_KEY, DEFAULT_T.tier2, DEFAULT_T.tier3, DEFAULT_T.tier4);
      await checkFallback();
      await registry.setJurisdictionThresholds(unregistered, 1, 2, 3);
      const explicit = await registry.thresholdsFor(unregistered);
      expect(explicit.registered).to.equal(true);
      expect(explicit.tier3).to.equal(2);
      expect((await registry.thresholdsFor(0x4141)).tier3).to.equal(DEFAULT_T.tier3);
    });

    it("rejects an out-of-order default at construction", async function () {
      const [admin] = await ethers.getSigners();

      const Verifier = await ethers.getContractFactory("Groth16Verifier");
      const verifier = await Verifier.deploy();
      const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
      const vaspRegistry = await VASPRegistry.deploy(admin.address);
      const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
      const oracle = await SanctionsOracle.deploy(
        admin.address,
        ethers.zeroPadValue(ethers.toBeHex(1234n), 32),
        50
      );

      const { router, selector } = await routeVerifier(await verifier.getAddress());
      const Registry = await ethers.getContractFactory("ComplianceRegistry");
      // The constructor shares validation with the external setter, so it
      // cannot be used to install a table the setter would reject.
      await expect(
        Registry.deploy(
          await router.getAddress(),
          selector,
          await vaspRegistry.getAddress(),
          await oracle.getAddress(),
          5000n,
          1000n,
          10000n
        )
      ).to.be.revertedWithCustomError(Registry, "ThresholdsNotOrdered");
    });
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

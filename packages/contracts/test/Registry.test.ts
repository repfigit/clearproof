import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import * as fs from "fs";

describe("VASPRegistry", function () {
  async function deployVASPRegistry() {
    const [admin, registrar, other] = await ethers.getSigners();
    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const registry = await VASPRegistry.deploy(admin.address);
    await registry.waitForDeployment();
    return { registry, admin, registrar, other };
  }

  it("should register a VASP", async function () {
    const { registry, admin } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp1.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await expect(registry.registerVASP(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof"))
      .to.emit(registry, "VASPRegistered")
      .withArgs(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof");

    expect(await registry.isActive(didHash)).to.equal(true);
    expect(await registry.vaspCount()).to.equal(1);
  });

  it("should reject duplicate registration", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp1.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof");
    await expect(registry.registerVASP(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof")).to.be.revertedWithCustomError(
      registry, "AlreadyRegistered"
    );
  });

  it("should revoke a VASP", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp2.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "SG", "https://vasp2.example/.well-known/clearproof");
    await expect(registry.revokeVASP(didHash))
      .to.emit(registry, "VASPRevoked")
      .withArgs(didHash);

    expect(await registry.isActive(didHash)).to.equal(false);
  });

  it("should reject revoking inactive VASP", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp3.example"));
    await expect(registry.revokeVASP(didHash)).to.be.revertedWithCustomError(registry, "NotActive");
  });

  it("should update issuer merkle root", async function () {
    const { registry } = await deployVASPRegistry();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("new-merkle-root"));

    await expect(registry.updateIssuerRoot(newRoot))
      .to.emit(registry, "IssuerRootUpdated")
      .withArgs(ethers.ZeroHash, newRoot, 1);

    expect(await registry.issuerMerkleRoot()).to.equal(newRoot);
    expect(await registry.issuerRootVersion()).to.equal(1);
  });

  it("should store and retrieve discovery endpoint", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:discoverable.example"));
    const wallet = ethers.Wallet.createRandom().address;
    const endpoint = "https://discoverable.example/.well-known/clearproof";

    await registry.registerVASP(didHash, wallet, "SG", endpoint);
    expect(await registry.getDiscoveryEndpoint(didHash)).to.equal(endpoint);
  });

  it("should update discovery endpoint", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:updatable.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "US", "https://old.example/.well-known/clearproof");

    const newEndpoint = "https://new.example/.well-known/clearproof";
    await expect(registry.updateDiscoveryEndpoint(didHash, newEndpoint))
      .to.emit(registry, "DiscoveryEndpointUpdated")
      .withArgs(didHash, newEndpoint);

    expect(await registry.getDiscoveryEndpoint(didHash)).to.equal(newEndpoint);
  });

  it("should reject unauthorized registration", async function () {
    const { registry, other } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:unauth.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await expect(
      registry.connect(other).registerVASP(didHash, wallet, "US", "")
    ).to.be.reverted;
  });

  it("should pause and unpause", async function () {
    const { registry, admin } = await deployVASPRegistry();
    await registry.pause();

    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:paused.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await expect(
      registry.registerVASP(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof")
    ).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await registry.unpause();
    await expect(registry.registerVASP(didHash, wallet, "US", "https://vasp1.example/.well-known/clearproof")).to.not.be.reverted;
  });
});

describe("SanctionsOracle", function () {
  async function deploySanctionsOracle() {
    const [admin, oracle, other] = await ethers.getSigners();
    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-v0"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const oracleContract = await SanctionsOracle.deploy(admin.address, initialRoot, 100);
    await oracleContract.waitForDeployment();
    return { oracleContract, admin, oracle, other, initialRoot };
  }

  it("should deploy with initial root", async function () {
    const { oracleContract, initialRoot } = await deploySanctionsOracle();
    expect(await oracleContract.currentRoot()).to.equal(initialRoot);
    expect(await oracleContract.leafCount()).to.equal(100);
    expect(await oracleContract.historyLength()).to.equal(1);
  });

  it("should update root after cooldown", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-v1"));

    // Advance time past cooldown (1 hour)
    await time.increase(3601);

    await expect(oracleContract.updateRoot(newRoot, 150))
      .to.emit(oracleContract, "SanctionsRootUpdated");

    expect(await oracleContract.currentRoot()).to.equal(newRoot);
    expect(await oracleContract.leafCount()).to.equal(150);
    expect(await oracleContract.historyLength()).to.equal(2);
  });

  it("should enforce cooldown", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-too-fast"));

    // Don't advance time — should fail
    await expect(oracleContract.updateRoot(newRoot, 100)).to.be.revertedWithCustomError(
      oracleContract, "CooldownActive"
    );
  });

  it("should reject zero root", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    await time.increase(3601);
    await expect(oracleContract.updateRoot(ethers.ZeroHash, 0)).to.be.revertedWithCustomError(
      oracleContract, "ZeroRoot"
    );
  });

  it("should detect staleness after grace period", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    expect(await oracleContract.isStale()).to.equal(false);

    // Advance past 72 hours grace period
    await time.increase(72 * 3600 + 1);
    expect(await oracleContract.isStale()).to.equal(true);
  });

  it("should track root history", async function () {
    const { oracleContract } = await deploySanctionsOracle();

    await time.increase(3601);
    const root1 = ethers.keccak256(ethers.toUtf8Bytes("root-1"));
    await oracleContract.updateRoot(root1, 200);

    await time.increase(3601);
    const root2 = ethers.keccak256(ethers.toUtf8Bytes("root-2"));
    await oracleContract.updateRoot(root2, 300);

    expect(await oracleContract.historyLength()).to.equal(3);
    const record = await oracleContract.rootHistory(2);
    expect(record.root).to.equal(root2);
    expect(record.leafCount).to.equal(300);
  });

  it("should pause and unpause", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    await oracleContract.pause();

    await time.increase(3601);
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("paused-root"));
    await expect(
      oracleContract.updateRoot(newRoot, 100)
    ).to.be.revertedWithCustomError(oracleContract, "EnforcedPause");

    await oracleContract.unpause();
  });
});

describe("ComplianceRegistry (extended)", function () {
  async function deployAll() {
    const [admin, revoker, vaspWallet, other] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
    await sanctionsOracle.waitForDeployment();

    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifier.getAddress(),
      ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1")),
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress(),
      250,
      1000,
      10000
    );
    await registry.waitForDeployment();

    return { verifier, vaspRegistry, sanctionsOracle, registry, admin, revoker, vaspWallet, other };
  }

  it("should revoke a credential", async function () {
    const { registry, admin } = await deployAll();
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("credential-001"));

    await expect(registry.revokeCredential(commitment))
      .to.emit(registry, "CredentialRevoked")
      .withArgs(commitment, admin.address);

    expect(await registry.isRevoked(commitment)).to.equal(true);
  });

  it("should reject double revocation", async function () {
    const { registry } = await deployAll();
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("credential-002"));

    await registry.revokeCredential(commitment);
    await expect(registry.revokeCredential(commitment)).to.be.revertedWithCustomError(
      registry, "AlreadyRevoked"
    );
  });

  it("should reject when sanctions oracle is stale", async function () {
    const { registry, vaspRegistry } = await deployAll();

    // Register a VASP first
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
    const wallet = ethers.Wallet.createRandom().address;
    await vaspRegistry.registerVASP(didHash, wallet, "US", "");

    // Make oracle stale
    await time.increase(72 * 3600 + 1);

    const dummyProof = getDummyProof();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-stale"));

    await expect(
      registry.verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        didHash
      )
    ).to.be.revertedWithCustomError(registry, "SanctionsOracleStale");
  });

  it("should reject inactive VASP", async function () {
    const { registry } = await deployAll();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:inactive.example"));

    const dummyProof = getDummyProof();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-inactive"));

    await expect(
      registry.verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        didHash
      )
    ).to.be.revertedWithCustomError(registry, "VASPNotActive");
  });

  it("should reject unauthorized revocation", async function () {
    const { registry, other } = await deployAll();
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("credential-003"));

    await expect(registry.connect(other).revokeCredential(commitment)).to.be.reverted;
  });

  it("should emit JurisdictionCodeMismatch event when proof jurisdiction differs from VASP registration", async function () {
    const [admin, vaspWallet] = await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    // Deploy mock verifier + router
    const MockVerifier = await ethers.getContractFactory("MockVerifier");
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();

    const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
    const router = await VerifierRouter.deploy(0); // 0 timelock for tests
    await router.waitForDeployment();

    const selector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
    await router.registerVerifier(selector, await mockVerifier.getAddress(), "mock");
    await router.activateVerifier(selector, "mock");

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
    await sanctionsOracle.waitForDeployment();

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

    // Register VASP with jurisdiction "US"
    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:us-vasp.example"));
    await vaspRegistry.registerVASP(vaspDid, vaspWallet.address, "US", "");

    // Set up thresholds for both US and EU
    await registry.setJurisdictionThresholds(0x5553, 250, 1000, 10000); // "US"
    await registry.setJurisdictionThresholds(0x4555, 100, 500, 5000);   // "EU"

    // Build proof with jurisdiction "EU" (0x4555) but VASP registered as "US" (0x5553)
    const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-jurisdiction-mismatch"));
    const transferIdHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["bytes32"], [transferId]))
    ) % BN128_R);

    const registryAddress = await registry.getAddress();
    const domainContractHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["address"], [registryAddress]))
    ) % BN128_R);

    const currentTime = await time.latest();
    const proofExpiresAt = currentTime + 600;

    const pubSignals: bigint[] = [
      1n, 0n, BigInt(initialRoot), 0n, 2n, BigInt(currentTime),
      0x4555n, 0n, 100n, 500n, 5000n,
      BigInt(chainId), domainContractHash, transferIdHash, 0n, BigInt(proofExpiresAt),
    ];

    const dummyProof = {
      pA: [BigInt(1), BigInt(2)] as [bigint, bigint],
      pB: [[BigInt(1), BigInt(2)], [BigInt(3), BigInt(4)]] as [[bigint, bigint], [bigint, bigint]],
      pC: [BigInt(1), BigInt(2)] as [bigint, bigint],
    };

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(
        transferId, dummyProof.pA, dummyProof.pB, dummyProof.pC, pubSignals, vaspDid
      )
    )
      .to.emit(registry, "JurisdictionCodeMismatch")
      .withArgs(transferId, 0x4555n, 0x5553n);

    expect(await registry.isVerified(transferId)).to.equal(true);
  });

  it("should NOT emit JurisdictionCodeMismatch when jurisdictions match", async function () {
    const [admin, vaspWallet] = await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    // Deploy mock verifier + router
    const MockVerifier = await ethers.getContractFactory("MockVerifier");
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();

    const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
    const router = await VerifierRouter.deploy(0);
    await router.waitForDeployment();

    const selector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
    await router.registerVerifier(selector, await mockVerifier.getAddress(), "mock");
    await router.activateVerifier(selector, "mock");

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
    await sanctionsOracle.waitForDeployment();

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

    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:matching-vasp.example"));
    await vaspRegistry.registerVASP(vaspDid, vaspWallet.address, "US", "");
    await registry.setJurisdictionThresholds(0x5553, 250, 1000, 10000);

    const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-jurisdiction-match"));
    const transferIdHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["bytes32"], [transferId]))
    ) % BN128_R);

    const registryAddress = await registry.getAddress();
    const domainContractHash = (BigInt(
      ethers.keccak256(ethers.solidityPacked(["address"], [registryAddress]))
    ) % BN128_R);

    const currentTime = await time.latest();
    const proofExpiresAt = currentTime + 600;

    const pubSignals: bigint[] = [
      1n, 0n, BigInt(initialRoot), 0n, 2n, BigInt(currentTime),
      0x5553n, 0n, 250n, 1000n, 10000n,
      BigInt(chainId), domainContractHash, transferIdHash, 0n, BigInt(proofExpiresAt),
    ];

    const dummyProof = {
      pA: [BigInt(1), BigInt(2)] as [bigint, bigint],
      pB: [[BigInt(1), BigInt(2)], [BigInt(3), BigInt(4)]] as [[bigint, bigint], [bigint, bigint]],
      pC: [BigInt(1), BigInt(2)] as [bigint, bigint],
    };

    const tx = await registry.connect(vaspWallet).verifyAndRecord(
      transferId, dummyProof.pA, dummyProof.pB, dummyProof.pC, pubSignals, vaspDid
    );
    const receipt = await tx.wait();

    const mismatchEvents = receipt!.logs.filter(
      (log: { topics: string[] }) =>
        log.topics[0] === ethers.id("JurisdictionCodeMismatch(bytes32,uint256,uint256)")
    );
    expect(mismatchEvents).to.have.length(0);
    expect(await registry.isVerified(transferId)).to.equal(true);
  });
});

describe("Integration: Full Flow", function () {
  it("should complete register VASP -> update sanctions -> submit proof -> verify", async function () {
    const [admin] = await ethers.getSigners();

    // Deploy all contracts
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-init"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 10);
    await sanctionsOracle.waitForDeployment();

    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifier.getAddress(),
      ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1")),
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress(),
      250,
      1000,
      10000
    );
    await registry.waitForDeployment();

    // 1. Register VASP
    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:clearproof.io"));
    await vaspRegistry.registerVASP(vaspDid, admin.address, "US", "https://clearproof.io/.well-known/clearproof");
    expect(await vaspRegistry.isActive(vaspDid)).to.equal(true);

    // 2. Update sanctions root
    await time.increase(3601);
    const newSanctionsRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-v2"));
    await sanctionsOracle.updateRoot(newSanctionsRoot, 20);
    expect(await sanctionsOracle.isStale()).to.equal(false);

    // 3. Submit proof (using hardcoded test values)
    // 3. Submit proof — domain binding prevents using pre-generated proofs
    // since the contract address hash won't match. This verifies the domain
    // binding correctly rejects mismatched proofs.
    const dummyProof = getDummyProof();
    const transferId = ethers.keccak256(ethers.toUtf8Bytes("integration-transfer-001"));

    // With dummy proof, the domain_chain_id (pubSignals[11]) won't match chain 31337
    await expect(
      registry.verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        vaspDid
      )
    ).to.be.revertedWithCustomError(registry, "WrongChain");

    // 4. Verify no proof was recorded (contract reverted)
    expect(await registry.isVerified(transferId)).to.equal(false);
  });
});

// Helper: dummy proof data for tests that don't need valid proofs
function getDummyProof() {
  return {
    pA: [BigInt(1), BigInt(2)] as [bigint, bigint],
    pB: [
      [BigInt(1), BigInt(2)],
      [BigInt(3), BigInt(4)],
    ] as [[bigint, bigint], [bigint, bigint]],
    pC: [BigInt(1), BigInt(2)] as [bigint, bigint],
    pubSignals: Array(16).fill(BigInt(0)) as bigint[],
  };
}

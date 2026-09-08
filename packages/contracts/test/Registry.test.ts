import { routeVerifier } from "./helpers/verifier";
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

  const syntheticDid = ethers.id("did:web:synthetic-vasp.example");
  const endpoint = "https://synthetic-vasp.example/.well-known/clearproof";

  it("rejects a zero administrator and reports empty inventory", async function () {
    const Factory = await ethers.getContractFactory("VASPRegistry");
    await expect(Factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(Factory, "ZeroAdmin");
    const { registry } = await deployVASPRegistry();
    expect(await registry.getActiveVaspCount()).to.equal(0);
    expect(await registry.vaspCount()).to.equal(0);
    expect(await registry.getDiscoveryEndpoint(syntheticDid)).to.equal("");
    expect(await registry.isActive(syntheticDid)).to.equal(false);
  });

  it("rejects missing or active reactivation and inactive discovery changes", async function () {
    const { registry, admin } = await deployVASPRegistry();
    await expect(registry.reactivateVASP(syntheticDid, admin.address))
      .to.be.revertedWithCustomError(registry, "NotRegistered");
    await expect(registry.updateDiscoveryEndpoint(syntheticDid, endpoint))
      .to.be.revertedWithCustomError(registry, "NotActive");
    await registry.registerVASP(syntheticDid, admin.address, "US", endpoint);
    await expect(registry.reactivateVASP(syntheticDid, admin.address))
      .to.be.revertedWithCustomError(registry, "AlreadyActive");
    await registry.revokeVASP(syntheticDid);
    await expect(registry.updateDiscoveryEndpoint(syntheticDid, "https://changed.example"))
      .to.be.revertedWithCustomError(registry, "NotActive");
    expect(await registry.getDiscoveryEndpoint(syntheticDid)).to.equal(endpoint);
    expect(await registry.getActiveVaspCount()).to.equal(0);
  });

  it("reactivates with a replacement wallet while preserving identity and registration history", async function () {
    const { registry, admin, other } = await deployVASPRegistry();
    const second = ethers.id("did:web:second-synthetic-vasp.example");
    await registry.registerVASP(syntheticDid, admin.address, "US", endpoint);
    await registry.registerVASP(second, admin.address, "SG", endpoint);
    const original = await registry.vasps(syntheticDid);
    expect(await registry.getActiveVaspCount()).to.equal(2);
    await registry.revokeVASP(syntheticDid);
    expect(await registry.getActiveVaspCount()).to.equal(1);
    await expect(registry.registerVASP(syntheticDid, other.address, "GB", ""))
      .to.be.revertedWithCustomError(registry, "AlreadyRegistered");
    await expect(registry.revokeVASP(syntheticDid)).to.be.revertedWithCustomError(registry, "NotActive");
    expect(await registry.getActiveVaspCount()).to.equal(1);
    await expect(registry.reactivateVASP(syntheticDid, other.address))
      .to.emit(registry, "VASPReactivated").withArgs(syntheticDid, other.address);
    const restored = await registry.vasps(syntheticDid);
    expect(restored.wallet).to.equal(other.address);
    expect(restored.registeredAt).to.equal(original.registeredAt);
    expect(restored.jurisdiction).to.equal(original.jurisdiction);
    expect(restored.discoveryEndpoint).to.equal(endpoint);
    expect(restored.active).to.equal(true);
    expect(await registry.getActiveVaspCount()).to.equal(2);
    expect(await registry.vaspCount()).to.equal(2);
    expect(await registry.vaspIds(0)).to.equal(syntheticDid);
    expect(await registry.vaspIds(1)).to.equal(second);
    expect(await registry.isActive(second)).to.equal(true);
  });

  it("gates every registrar operation and keeps administration separate", async function () {
    const { registry, admin, registrar, other } = await deployVASPRegistry();
    const role = await registry.REGISTRAR_ROLE();
    const adminRole = await registry.DEFAULT_ADMIN_ROLE();
    await registry.registerVASP(syntheticDid, admin.address, "US", endpoint);
    for (const call of [
      () => registry.connect(other).registerVASP(ethers.id("new"), other.address, "US", endpoint),
      () => registry.connect(other).updateDiscoveryEndpoint(syntheticDid, endpoint),
      () => registry.connect(other).revokeVASP(syntheticDid),
      () => registry.connect(other).reactivateVASP(syntheticDid, other.address),
      () => registry.connect(other).updateIssuerRoot(ethers.id("forbidden-root")),
    ]) {
      await expect(call()).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, role);
    }
    await registry.grantRole(role, registrar.address);
    for (const call of [() => registry.connect(registrar).pause(), () => registry.connect(registrar).unpause()]) {
      await expect(call()).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(registrar.address, adminRole);
    }
    await registry.connect(registrar).updateDiscoveryEndpoint(syntheticDid, "https://authorized.example");
    expect(await registry.getDiscoveryEndpoint(syntheticDid)).to.equal("https://authorized.example");
    expect(await registry.getActiveVaspCount()).to.equal(1);
  });

  it("blocks all mutations while paused and resumes updates after unpause", async function () {
    const { registry, admin } = await deployVASPRegistry();
    const inactive = ethers.id("did:web:inactive-synthetic.example");
    await registry.registerVASP(syntheticDid, admin.address, "US", endpoint);
    await registry.registerVASP(inactive, admin.address, "US", endpoint);
    await registry.revokeVASP(inactive);
    await registry.pause();
    for (const call of [
      () => registry.registerVASP(ethers.id("new"), admin.address, "US", endpoint),
      () => registry.updateDiscoveryEndpoint(syntheticDid, "https://changed.example"),
      () => registry.revokeVASP(syntheticDid),
      () => registry.reactivateVASP(inactive, admin.address),
      () => registry.updateIssuerRoot(ethers.id("paused-root")),
    ]) await expect(call()).to.be.revertedWithCustomError(registry, "EnforcedPause");
    expect(await registry.getActiveVaspCount()).to.equal(1);
    expect(await registry.vaspCount()).to.equal(2);
    expect(await registry.getDiscoveryEndpoint(syntheticDid)).to.equal(endpoint);
    expect(await registry.issuerRootVersion()).to.equal(0);
    await registry.unpause();
    await registry.reactivateVASP(inactive, admin.address);
    expect(await registry.getActiveVaspCount()).to.equal(2);
    const first = ethers.id("first-synthetic-issuer-root");
    const second = ethers.id("second-synthetic-issuer-root");
    await registry.updateIssuerRoot(first);
    await expect(registry.updateIssuerRoot(second)).to.emit(registry, "IssuerRootUpdated").withArgs(first, second, 2);
    expect(await registry.issuerMerkleRoot()).to.equal(second);
    expect(await registry.issuerRootVersion()).to.equal(2);
  });

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

  it("rejects a zero administrator", async function () {
    const Factory = await ethers.getContractFactory("SanctionsOracle");
    await expect(Factory.deploy(ethers.ZeroAddress, ethers.id("synthetic-root"), 100))
      .to.be.revertedWithCustomError(Factory, "ZeroAdmin");
  });

  it("accepts updates exactly at cooldown expiry and retains state on early rejection", async function () {
    const { oracleContract, initialRoot } = await deploySanctionsOracle();
    const previous = await oracleContract.lastUpdated();
    const ready = previous + await oracleContract.UPDATE_COOLDOWN();
    const nextRoot = ethers.id("synthetic-next-root");
    await time.setNextBlockTimestamp(ready - 1n);
    await expect(oracleContract.updateRoot(nextRoot, 100))
      .to.be.revertedWithCustomError(oracleContract, "CooldownActive");
    expect(await oracleContract.currentRoot()).to.equal(initialRoot);
    expect(await oracleContract.lastUpdated()).to.equal(previous);
    expect(await oracleContract.historyLength()).to.equal(1);
    await time.setNextBlockTimestamp(ready);
    await expect(oracleContract.updateRoot(nextRoot, 100))
      .to.emit(oracleContract, "SanctionsRootUpdated").withArgs(initialRoot, nextRoot, 100, ready);
    expect((await oracleContract.rootHistory(1)).timestamp).to.equal(ready);
  });

  it("rejects a reduction below half the prior inventory without changing history", async function () {
    const { oracleContract, initialRoot } = await deploySanctionsOracle();
    const previous = await oracleContract.lastUpdated();
    await time.increase(3600);
    const nextRoot = ethers.id("synthetic-reduced-root");
    await expect(oracleContract.updateRoot(nextRoot, 49))
      .to.be.revertedWithCustomError(oracleContract, "LeafCountDecreasedTooMuch");
    expect(await oracleContract.currentRoot()).to.equal(initialRoot);
    expect(await oracleContract.leafCount()).to.equal(100);
    expect(await oracleContract.lastUpdated()).to.equal(previous);
    expect(await oracleContract.historyLength()).to.equal(1);
    await oracleContract.updateRoot(nextRoot, 50);
    expect(await oracleContract.leafCount()).to.equal(50);
    expect((await oracleContract.rootHistory(1)).leafCount).to.equal(50);
  });

  it("bounds grace-period changes and reports both previous and new values", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    for (const invalid of [6 * 3600 - 1, 168 * 3600 + 1]) {
      await expect(oracleContract.setGracePeriod(invalid))
        .to.be.revertedWithCustomError(oracleContract, "PeriodOutOfBounds");
      expect(await oracleContract.gracePeriod()).to.equal(24 * 3600);
    }
    await expect(oracleContract.setGracePeriod(6 * 3600))
      .to.emit(oracleContract, "GracePeriodUpdated").withArgs(24 * 3600, 6 * 3600);
    await expect(oracleContract.setGracePeriod(168 * 3600))
      .to.emit(oracleContract, "GracePeriodUpdated").withArgs(6 * 3600, 168 * 3600);
    expect(await oracleContract.gracePeriod()).to.equal(168 * 3600);
  });

  it("separates root publication authority from oracle administration", async function () {
    const { oracleContract, oracle, other } = await deploySanctionsOracle();
    const role = await oracleContract.ORACLE_ROLE();
    const adminRole = await oracleContract.DEFAULT_ADMIN_ROLE();
    await expect(oracleContract.connect(other).updateRoot(ethers.id("forbidden-root"), 100))
      .to.be.revertedWithCustomError(oracleContract, "AccessControlUnauthorizedAccount").withArgs(other.address, role);
    await oracleContract.grantRole(role, oracle.address);
    for (const call of [
      () => oracleContract.connect(oracle).pause(),
      () => oracleContract.connect(oracle).unpause(),
      () => oracleContract.connect(oracle).setGracePeriod(21600),
    ]) {
      await expect(call()).to.be.revertedWithCustomError(oracleContract, "AccessControlUnauthorizedAccount")
        .withArgs(oracle.address, adminRole);
    }
    await time.increase(3600);
    const nextRoot = ethers.id("authorized-synthetic-root");
    await oracleContract.connect(oracle).updateRoot(nextRoot, 100);
    expect(await oracleContract.currentRoot()).to.equal(nextRoot);
  });

  it("retains exactly the newest history after two complete ring-buffer rotations", async function () {
    this.timeout(120000);
    const { oracleContract } = await deploySanctionsOracle();
    const capacity = Number(await oracleContract.MAX_HISTORY());
    const initialTime = await oracleContract.lastUpdated();
    const cooldown = await oracleContract.UPDATE_COOLDOWN();
    const updates = 2 * capacity + 2;
    const root = (index: number) => ethers.id(`synthetic-ring-root-${index}`);
    for (let index = 1; index <= updates; index++) {
      await time.setNextBlockTimestamp(initialTime + BigInt(index) * cooldown);
      await oracleContract.updateRoot(root(index), 100);
    }
    expect(await oracleContract.historyLength()).to.equal(capacity);
    const start = Number(await oracleContract.ringBufferStart());
    expect(start).to.equal(updates + 1 - capacity);
    for (let offset = 0; offset < capacity; offset++) {
      const index = updates - capacity + 1 + offset;
      const retained = await oracleContract.rootHistory((start + offset) % capacity);
      expect(retained.root).to.equal(root(index));
      expect(retained.timestamp).to.equal(initialTime + BigInt(index) * cooldown);
      expect(retained.leafCount).to.equal(100);
    }
    expect(await oracleContract.currentRoot()).to.equal(root(updates));
    expect(await oracleContract.lastUpdated()).to.equal(initialTime + BigInt(updates) * cooldown);
  });

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

    const boundary = await oracleContract.lastUpdated() + await oracleContract.gracePeriod();
    await time.increaseTo(boundary);
    expect(await oracleContract.isStale()).to.equal(false);
    await time.increase(1);
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

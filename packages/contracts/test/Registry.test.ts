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

    await expect(registry.registerVASP(didHash, wallet, "US"))
      .to.emit(registry, "VASPRegistered")
      .withArgs(didHash, wallet, "US");

    expect(await registry.isActive(didHash)).to.equal(true);
    expect(await registry.vaspCount()).to.equal(1);
  });

  it("should reject duplicate registration", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp1.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "US");
    await expect(registry.registerVASP(didHash, wallet, "US")).to.be.revertedWith(
      "Already registered"
    );
  });

  it("should revoke a VASP", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp2.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "SG");
    await expect(registry.revokeVASP(didHash))
      .to.emit(registry, "VASPRevoked")
      .withArgs(didHash);

    expect(await registry.isActive(didHash)).to.equal(false);
  });

  it("should reject revoking inactive VASP", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp3.example"));
    await expect(registry.revokeVASP(didHash)).to.be.revertedWith("Not active");
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

  it("should reject unauthorized registration", async function () {
    const { registry, other } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:unauth.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await expect(
      registry.connect(other).registerVASP(didHash, wallet, "US")
    ).to.be.reverted;
  });

  it("should pause and unpause", async function () {
    const { registry, admin } = await deployVASPRegistry();
    await registry.pause();

    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:paused.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await expect(
      registry.registerVASP(didHash, wallet, "US")
    ).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await registry.unpause();
    await expect(registry.registerVASP(didHash, wallet, "US")).to.not.be.reverted;
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
    await expect(oracleContract.updateRoot(newRoot, 100)).to.be.revertedWith(
      "Cooldown active"
    );
  });

  it("should reject zero root", async function () {
    const { oracleContract } = await deploySanctionsOracle();
    await time.increase(3601);
    await expect(oracleContract.updateRoot(ethers.ZeroHash, 0)).to.be.revertedWith(
      "Zero root"
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
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress()
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
    await expect(registry.revokeCredential(commitment)).to.be.revertedWith(
      "Already revoked"
    );
  });

  it("should reject when sanctions oracle is stale", async function () {
    const { registry, vaspRegistry } = await deployAll();

    // Register a VASP first
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
    const wallet = ethers.Wallet.createRandom().address;
    await vaspRegistry.registerVASP(didHash, wallet, "US");

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
    ).to.be.revertedWith("Sanctions oracle is stale");
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
    ).to.be.revertedWith("VASP not active");
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

    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifier.getAddress(),
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress()
    );
    await registry.waitForDeployment();

    // 1. Register VASP
    const vaspDid = ethers.keccak256(ethers.toUtf8Bytes("did:web:clearproof.io"));
    await vaspRegistry.registerVASP(vaspDid, admin.address, "US");
    expect(await vaspRegistry.isActive(vaspDid)).to.equal(true);

    // 2. Update sanctions root
    await time.increase(3601);
    const newSanctionsRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-v2"));
    await sanctionsOracle.updateRoot(newSanctionsRoot, 20);
    expect(await sanctionsOracle.isStale()).to.equal(false);

    // 3. Submit proof (using hardcoded test values)
    const proofPath = "/tmp/clearproof_proof.json";
    const publicPath = "/tmp/clearproof_public.json";

    const proof = fs.existsSync(proofPath)
      ? JSON.parse(fs.readFileSync(proofPath, "utf-8"))
      : {
          pi_a: [
            "8073921222709435687021728565040895226166720324601874996228166134859997239713",
            "21250026926575850493955798764612127336741546312913502650341026345846850015483",
            "1",
          ],
          pi_b: [
            [
              "15316175069298117144645790753102903219137181100390843428010978955699023654362",
              "13492439875076482042420295595895000234680578744588959415780712842977368804170",
            ],
            [
              "5314759809315125583597383793946467371139319384084053497719437608667363710596",
              "19481713981857858479177256065389077193051153217163245318247677728892162922414",
            ],
          ],
          pi_c: [
            "20775433742215878416115779669211868112105475476050753602416342585315294717025",
            "10902228172408724648940327734425470731823942523922651429611190462177051601323",
            "1",
          ],
        };

    const publicSignals = fs.existsSync(publicPath)
      ? JSON.parse(fs.readFileSync(publicPath, "utf-8"))
      : [
          "1", "0",
          "5165912880528319654224975632916389245447155966222261466225444971111963668911",
          "2679583485444090814519739490480408597587979659313135468790553999186444635148",
          "2", "1711670400", "21843",
          "3946334516594870472864654055107878340628457451312090927820290073103136770198",
          "25000", "300000", "1000000",
        ];

    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
    const pubSignals = publicSignals.map((s: string) => BigInt(s));

    const transferId = ethers.keccak256(ethers.toUtf8Bytes("integration-transfer-001"));

    const tx = await registry.verifyAndRecord(transferId, pA, pB, pC, pubSignals, vaspDid);
    const receipt = await tx.wait();
    expect(receipt?.status).to.equal(1);

    // 4. Verify the proof is recorded
    expect(await registry.isVerified(transferId)).to.equal(true);
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
    pubSignals: Array(11).fill(BigInt(0)) as bigint[],
  };
}

import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("Domain Binding Adversarial Test", function () {
  async function deployAll() {
    const [admin, vaspWallet] = await ethers.getSigners();

    // Deploy VerifierRouter
    const VerifierRouter = await ethers.getContractFactory("VerifierRouter");
    const timelockPeriod = 24 * 60 * 60; // 24 hours
    const verifierRouter = await VerifierRouter.deploy(timelockPeriod);
    await verifierRouter.waitForDeployment();

    // Deploy Groth16Verifier
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Register and activate verifier
    const selector = ethers.keccak256(ethers.toUtf8Bytes("groth16-bn254-v1"));
    await verifierRouter.registerVerifier(selector, await verifier.getAddress(), "Groth16 BN254 v1");
    await time.increase(24 * 60 * 60 + 1);
    await verifierRouter.activateVerifier(selector, "Groth16 BN254 v1");

    // Deploy VASPRegistry
    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const vaspRegistry = await VASPRegistry.deploy(admin.address);
    await vaspRegistry.waitForDeployment();

    // Deploy SanctionsOracle
    const initialRoot = ethers.zeroPadValue(ethers.toBeHex(12345n), 32);
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const sanctionsOracle = await SanctionsOracle.deploy(admin.address, initialRoot, 50);
    await sanctionsOracle.waitForDeployment();

    // Deploy ComplianceRegistry
    const Registry = await ethers.getContractFactory("ComplianceRegistry");
    const registry = await Registry.deploy(
      await verifierRouter.getAddress(),
      selector,
      await vaspRegistry.getAddress(),
      await sanctionsOracle.getAddress(),
      250,
      1000,
      10000
    );
    await registry.waitForDeployment();

    return { verifierRouter, verifier, vaspRegistry, sanctionsOracle, registry, admin, vaspWallet, selector };
  }

  it("should reject proofs with wrong contract address", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet } = await deployAll();

    // Register a VASP
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
    await vaspRegistry.registerVASP(didHash, vaspWallet.address, "US", "");

    // Create a dummy proof with wrong contract address in pubSignals[12]
    const dummyProof = getDummyProof();
    
    // Modify the domain_contract_hash (pubSignals[12]) to a wrong value
    dummyProof.pubSignals[11] = (await ethers.provider.getNetwork()).chainId;
    dummyProof.pubSignals[12] = 1n;

    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-wrong-contract"));

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        didHash
      )
    ).to.be.revertedWithCustomError(registry, "WrongContract");
  });

  it("should reject proofs with wrong chain ID", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet } = await deployAll();

    // Register a VASP
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
    await vaspRegistry.registerVASP(didHash, vaspWallet.address, "US", "");

    // Create a dummy proof with wrong chain ID in pubSignals[11]
    const dummyProof = getDummyProof();
    
    // Set chain ID to a wrong value (Hardhat's chain ID is 31337)
    dummyProof.pubSignals[11] = BigInt(12345);

    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-wrong-chain"));

    await expect(
      registry.connect(vaspWallet).verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        didHash
      )
    ).to.be.revertedWithCustomError(registry, "WrongChain");
  });

  it("reaches the pairing check with correct domain binding", async function () {
    const { registry, vaspRegistry, sanctionsOracle, vaspWallet } = await deployAll();

    // Register a VASP
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:vasp.example"));
    await vaspRegistry.registerVASP(didHash, vaspWallet.address, "US", "");

    // Create a dummy proof with correct domain binding
    const dummyProof = getDummyProof();
    
    // Set the correct chain ID
    dummyProof.pubSignals[11] = BigInt((await ethers.provider.getNetwork()).chainId);
    
    // Set the correct contract address hash
    const BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const contractHash = BigInt(ethers.keccak256(ethers.solidityPacked(["address"], [await registry.getAddress()]))) % BN128_R;
    dummyProof.pubSignals[12] = contractHash;

    const transferId = ethers.keccak256(ethers.toUtf8Bytes("transfer-correct-domain"));
    const now = BigInt(await time.latest());
    dummyProof.pubSignals[2] = BigInt(await sanctionsOracle.currentRoot());
    dummyProof.pubSignals[3] = BigInt(await vaspRegistry.issuerMerkleRoot());
    dummyProof.pubSignals[5] = now;
    dummyProof.pubSignals[6] = 0x5553n;
    dummyProof.pubSignals[8] = 250n;
    dummyProof.pubSignals[9] = 1000n;
    dummyProof.pubSignals[10] = 10000n;
    dummyProof.pubSignals[13] = BigInt(ethers.keccak256(transferId)) % BN128_R;
    dummyProof.pubSignals[15] = now + 3600n;

    // Invalid curve points must reach the pairing precompile after all context checks.
    await expect(
      registry.connect(vaspWallet).verifyAndRecord(
        transferId,
        dummyProof.pA,
        dummyProof.pB,
        dummyProof.pC,
        dummyProof.pubSignals,
        didHash
      )
    ).to.be.revertedWith("Pairing: ecpairing failed");
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
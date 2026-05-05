/**
 * Submit a generated Groth16 proof to ComplianceRegistry.verifyAndRecord().
 *
 * Environment:
 *   PROOF_PATH            JSON file containing `proof`/`groth16_proof` and public signals
 *   TRANSFER_ID           bytes32 transfer ID, or text to hash with ethers.id()
 *   VASP_DID              DID string to hash with ethers.id() (default: did:web:vasp.example.com)
 *   VASP_DID_HASH         Optional bytes32 hash; overrides VASP_DID
 *   COMPLIANCE_REGISTRY   Optional registry address; otherwise deployments/<network>.json
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

type Groth16Proof = {
  pi_a: Array<string | number | bigint>;
  pi_b: Array<Array<string | number | bigint>>;
  pi_c: Array<string | number | bigint>;
};

function loadDeploymentAddress(networkName: string): string {
  if (process.env.COMPLIANCE_REGISTRY) {
    return process.env.COMPLIANCE_REGISTRY;
  }

  const deploymentPath = path.resolve(__dirname, `../deployments/${networkName}.json`);
  if (!fs.existsSync(deploymentPath)) {
    throw new Error(
      `Set COMPLIANCE_REGISTRY or create deployment file: ${deploymentPath}`,
    );
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  return deployment.contracts.ComplianceRegistry;
}

function bytes32FromEnv(name: string, value: string): string {
  return /^0x[0-9a-fA-F]{64}$/.test(value) ? value : ethers.id(value);
}

function readProofFile(): { proof: Groth16Proof; publicSignals: bigint[] } {
  const proofPath = process.env.PROOF_PATH || path.resolve(__dirname, "../../../artifacts/latest_proof.json");
  if (!fs.existsSync(proofPath)) {
    throw new Error(`Proof file not found: ${proofPath}`);
  }

  const data = JSON.parse(fs.readFileSync(proofPath, "utf-8"));
  const proof =
    data.proof ||
    data.groth16_proof ||
    data.compliance_proof?.proof ||
    data.compliance_proof?.groth16_proof;
  const signals =
    data.publicSignals ||
    data.public_signals ||
    data.compliance_proof?.publicSignals ||
    data.compliance_proof?.public_signals;

  if (!proof?.pi_a || !proof?.pi_b || !proof?.pi_c || !Array.isArray(signals)) {
    throw new Error(
      "Proof JSON must contain proof/groth16_proof with pi_a, pi_b, pi_c and publicSignals/public_signals",
    );
  }
  if (signals.length !== 16) {
    throw new Error(`Expected 16 public signals, got ${signals.length}`);
  }

  return {
    proof,
    publicSignals: signals.map((signal: string | number | bigint) => BigInt(signal)),
  };
}

async function main() {
  const networkName = process.env.HARDHAT_NETWORK || "localhost";
  const registryAddress = loadDeploymentAddress(networkName);
  const transferId = bytes32FromEnv("TRANSFER_ID", process.env.TRANSFER_ID || "recipe-transfer-001");
  const vaspDidHash =
    process.env.VASP_DID_HASH ||
    ethers.id(process.env.VASP_DID || "did:web:vasp.example.com");
  const { proof, publicSignals } = readProofFile();

  const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const pB: [[bigint, bigint], [bigint, bigint]] = [
    [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
    [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
  ];
  const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];

  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt("ComplianceRegistry", registryAddress);

  console.log("=== Submit Compliance Proof ===");
  console.log(`Network:              ${networkName}`);
  console.log(`Signer:               ${signer.address}`);
  console.log(`ComplianceRegistry:   ${registryAddress}`);
  console.log(`Transfer ID:          ${transferId}`);
  console.log(`VASP DID hash:        ${vaspDidHash}`);

  const tx = await registry.verifyAndRecord(
    transferId,
    pA,
    pB,
    pC,
    publicSignals,
    vaspDidHash,
  );
  console.log(`TX hash:              ${tx.hash}`);

  const receipt = await tx.wait();
  console.log(`Confirmed block:      ${receipt!.blockNumber}`);
  console.log(`Gas used:             ${receipt!.gasUsed}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

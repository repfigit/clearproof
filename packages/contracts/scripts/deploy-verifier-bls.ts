/**
 * Deploy the BLS12-381 Groth16 verifier (ADR 0002 confirmation deploy).
 *
 * This is the final gating step before ADR 0002 can move to DECIDED:
 * deploy Groth16VerifierBLS.sol to Sepolia and verify the committed
 * BLS12-381 parity vector on-chain (valid proof accepted, tampered
 * rejected) with measured gas, mirroring the local Prague-EVM benchmark.
 *
 * IMPORTANT: Groth16VerifierBLS.sol is a GENERATED file (dev trusted
 * setup, single-party — see tests/vectors/compliance-bls/MANIFEST.json).
 * This deployment is a benchmark confirmation, NOT production. The
 * production verifier is generated at the MPC ceremony.
 *
 * Prerequisites:
 *   - DEPLOYER_PRIVATE_KEY in packages/contracts/.env (gitignored) or env
 *   - deployer funded with Sepolia ETH
 *   - tests/vectors/compliance-bls/ present (proof_bls.json, public_bls.json)
 *
 * Usage:
 *   npx hardhat run scripts/deploy-verifier-bls.ts --network sepolia
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// BLS12-381 base field q (for the tamper case: y -> q - y)
const Q = BigInt(
  "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
);

function fp(v: string | bigint): string {
  return BigInt(v).toString(16).padStart(128, "0");
}

function encodeProof(proof: any, tamper = false): string {
  const ay = tamper ? Q - BigInt(proof.pi_a[1]) : BigInt(proof.pi_a[1]);
  const a = fp(proof.pi_a[0]) + fp(ay);
  const b =
    fp(proof.pi_b[0][0]) + fp(proof.pi_b[0][1]) + fp(proof.pi_b[1][0]) + fp(proof.pi_b[1][1]);
  const c = fp(proof.pi_c[0]) + fp(proof.pi_c[1]);
  return "0x" + a + b + c;
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = process.env.HARDHAT_NETWORK || "localhost";

  const vectorsDir = path.resolve(__dirname, "../../../tests/vectors/compliance-bls");
  for (const f of ["proof_bls.json", "public_bls.json"]) {
    if (!fs.existsSync(path.join(vectorsDir, f))) {
      console.error(`Missing ${f} in ${vectorsDir} — see MANIFEST.json`);
      return process.exit(1);
    }
  }
  const proof = JSON.parse(fs.readFileSync(path.join(vectorsDir, "proof_bls.json"), "utf-8"));
  const pubSignals: string[] = JSON.parse(
    fs.readFileSync(path.join(vectorsDir, "public_bls.json"), "utf-8"),
  );

  console.log("╔══════════════════════════════════════════╗");
  console.log("║  clearproof BLS12-381 verifier deploy    ║");
  console.log("║  (ADR 0002 confirmation — dev setup)     ║");
  console.log("╚══════════════════════════════════════════╝\n");
  console.log(`Network:    ${networkName} (chain ${network.chainId})`);
  console.log(`Deployer:   ${deployer.address}`);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance:    ${ethers.formatEther(balance)} ETH\n`);
  if (balance === 0n) {
    console.error("Deployer has no balance. Fund the wallet first.");
    return process.exit(1);
  }

  // 1. Deploy
  console.log("Deploying Groth16VerifierBLS…");
  const Factory = await ethers.getContractFactory("Groth16VerifierBLS");
  const verifier = await Factory.deploy();
  const deployReceipt = await verifier.deploymentTransaction()?.wait();
  const address = await verifier.getAddress();
  console.log(`  address:      ${address}`);
  console.log(`  deploy gas:   ${deployReceipt?.gasUsed.toString()}`);

  // 2. Valid proof must verify
  console.log("\nVerifying committed BLS12-381 vector on-chain…");
  const validGas = await verifier.verifyProof.estimateGas(encodeProof(proof), pubSignals);
  const valid = await verifier.verifyProof.staticCall(encodeProof(proof), pubSignals);
  console.log(`  valid proof accepted: ${valid}  (estimateGas: ${validGas})`);
  if (!valid) {
    console.error("FAIL: valid proof rejected on-chain");
    return process.exit(1);
  }

  // 3. Tampered proof must reject
  const tampered = encodeProof(proof, true);
  const invalid = await verifier.verifyProof.staticCall(tampered, pubSignals);
  console.log(`  tampered proof rejected: ${!invalid}`);
  if (invalid) {
    console.error("FAIL: tampered proof accepted on-chain");
    return process.exit(1);
  }

  // 4. Record alongside other deployment artifacts
  const recordPath = path.resolve(__dirname, `../deployments/${networkName}-bls-bench.json`);
  fs.writeFileSync(
    recordPath,
    JSON.stringify(
      {
        contract: "Groth16VerifierBLS",
        address,
        network: networkName,
        chainId: network.chainId.toString(),
        deployedAt: new Date().toISOString(),
        deployer: deployer.address,
        deployGas: deployReceipt?.gasUsed.toString(),
        verifyGasEstimate: validGas.toString(),
        note: "ADR 0002 confirmation deploy. DEV trusted setup — not production.",
      },
      null,
      2,
    ),
  );
  console.log(`\nDeployment recorded: ${recordPath}`);
  if (network.chainId === 11155111n) {
    console.log("ADR 0002 Open Task 1 (Sepolia confirmation) is now complete.");
  } else {
    console.log("Benchmark verified on this network; Sepolia confirmation remains a separate task.");
  }
}

main().catch((err) => {
  console.error(err);
  return process.exit(1);
});

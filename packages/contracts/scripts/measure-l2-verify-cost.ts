/**
 * AIF-99: live L2 verify cost for Groth16 vs fflonk.
 *
 * Deploys both verifiers, submits real verifyProof transactions, and records
 * execution gas plus rollup L1/DA fee fields from the receipts.
 *
 * The fflonk verifier is GPL three (snarkjs export). It must live only under
 * contracts/bench/local/ (gitignored). Never commit that Solidity file.
 *
 * Usage:
 *   npx hardhat run scripts/measure-l2-verify-cost.ts --network base-sepolia
 *   npx hardhat run scripts/measure-l2-verify-cost.ts --network arbitrum-sepolia
 *   npx hardhat run scripts/measure-l2-verify-cost.ts --network optimism-sepolia
 */
import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const G16_VECTOR = path.join(REPO_ROOT, "tests/vectors/compliance");
const FFLONK_BUILD = path.join(REPO_ROOT, "build");
const FFLONK_ARTIFACT = path.join(
  __dirname,
  "../artifacts/contracts/bench/local/FflonkVerifier.sol/FflonkVerifier.json",
);
const OUT_DIR = path.join(__dirname, "../deployments");

type SystemResult = {
  address: string;
  deploy_tx: string;
  deploy_gas: string;
  verify_tx: string;
  verify_gas_used: string;
  verify_ok: boolean;
  estimate_gas: string;
  l1_fee_wei: string | null;
  gas_used_for_l1: string | null;
  effective_gas_price_wei: string | null;
  tx_fee_wei: string;
  signed_tx_bytes: number;
  calldata_bytes: number;
};

function parseFflonkCalldata(text: string): { proof: string[]; pubSignals: string[] } {
  // snarkjs soliditycalldata: [p0,...,p23],[s0,...,s15]
  const match = text.trim().match(/^\[([^\]]+)\],\[([^\]]+)\]$/);
  if (!match) throw new Error(`unrecognized fflonk calldata shape in build/fflonk_calldata.txt`);
  const proof = match[1].split(",").map((s) => s.trim());
  const pubSignals = match[2].split(",").map((s) => s.trim());
  if (proof.length !== 24) throw new Error(`expected 24 fflonk proof words, got ${proof.length}`);
  if (pubSignals.length !== 16) throw new Error(`expected 16 pub signals, got ${pubSignals.length}`);
  return { proof, pubSignals };
}

async function fetchEthUsd(): Promise<{ usd: number; source: string; as_of: string }> {
  try {
    const res = await fetch("https://api.coinbase.com/v2/prices/ETH-USD/spot");
    if (!res.ok) throw new Error(`coinbase ${res.status}`);
    const body = (await res.json()) as { data: { amount: string } };
    return {
      usd: Number(body.data.amount),
      source: "coinbase ETH-USD spot",
      as_of: new Date().toISOString(),
    };
  } catch (err) {
    console.warn("ETH/USD fetch failed; recording null:", err);
    return { usd: NaN, source: "unavailable", as_of: new Date().toISOString() };
  }
}

function receiptL1Fee(receipt: any): string | null {
  // OP Stack (Base, Optimism): l1Fee is on the receipt
  if (receipt.l1Fee != null) return BigInt(receipt.l1Fee).toString();
  if (receipt.l1GasPrice != null && receipt.l1GasUsed != null) {
    // older shape: approximate
    const fee = BigInt(receipt.l1GasUsed) * BigInt(receipt.l1GasPrice);
    return fee.toString();
  }
  return null;
}

function receiptGasUsedForL1(receipt: any): string | null {
  // Arbitrum Nitro
  if (receipt.gasUsedForL1 != null) return BigInt(receipt.gasUsedForL1).toString();
  return null;
}

async function waitForCode(address: string, attempts = 15): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    const code = await ethers.provider.getCode(address);
    if (code && code !== "0x") return;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`bytecode not visible at ${address} after deploy`);
}

async function withCallRetry<T>(label: string, fn: () => Promise<T>, attempts = 5): Promise<T> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      last = err;
      console.warn(`  ${label} attempt ${i + 1}/${attempts} failed: ${(err as Error).message?.slice(0, 120)}`);
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  throw last;
}

async function measureSystem(
  label: string,
  deploy: () => Promise<{ address: string; deployTx: any; contract: any }>,
  callVerify: (contract: any) => Promise<{ tx: any; estimate: bigint; calldata: string; ok: boolean }>,
): Promise<SystemResult> {
  console.log(`\n--- ${label} ---`);
  const { address, deployTx, contract } = await deploy();
  const deployReceipt = await deployTx.wait();
  console.log(`  deployed ${address}`);
  console.log(`  deploy gas ${deployReceipt.gasUsed.toString()}`);
  await waitForCode(address);

  const { tx, estimate, calldata, ok } = await callVerify(contract);
  const receipt = await tx.wait();
  if (!receipt) throw new Error(`${label}: missing verify receipt`);

  const effective = receipt.gasPrice ?? tx.gasPrice ?? 0n;
  const txFee = receipt.gasUsed * BigInt(effective);

  // Re-fetch raw receipt for L2-specific fields ethers may drop
  const raw = await ethers.provider.send("eth_getTransactionReceipt", [receipt.hash]);

  const result: SystemResult = {
    address,
    deploy_tx: deployTx.hash,
    deploy_gas: deployReceipt.gasUsed.toString(),
    verify_tx: receipt.hash,
    verify_gas_used: receipt.gasUsed.toString(),
    verify_ok: ok,
    estimate_gas: estimate.toString(),
    l1_fee_wei: receiptL1Fee(raw) ?? receiptL1Fee(receipt),
    gas_used_for_l1: receiptGasUsedForL1(raw) ?? receiptGasUsedForL1(receipt),
    effective_gas_price_wei: effective ? BigInt(effective).toString() : null,
    tx_fee_wei: txFee.toString(),
    signed_tx_bytes: 0,
    calldata_bytes: (calldata.length - 2) / 2,
  };

  // Signed envelope size (what OP Stack FastLZ-compresses)
  try {
    const rawTx = await ethers.provider.send("eth_getRawTransactionByHash", [receipt.hash]);
    if (typeof rawTx === "string" && rawTx.startsWith("0x")) {
      result.signed_tx_bytes = (rawTx.length - 2) / 2;
    }
  } catch {
    const fullTx = await ethers.provider.getTransaction(receipt.hash);
    const serialized = fullTx?.serialized ?? (fullTx as any)?.raw;
    if (typeof serialized === "string") {
      result.signed_tx_bytes = (serialized.length - 2) / 2;
    }
  }

  console.log(`  verify ok=${ok} gasUsed=${result.verify_gas_used} estimate=${result.estimate_gas}`);
  console.log(`  l1Fee=${result.l1_fee_wei} gasUsedForL1=${result.gas_used_for_l1}`);
  console.log(`  calldata=${result.calldata_bytes}B signed≈${result.signed_tx_bytes}B`);
  return result;
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log("╔══════════════════════════════════════════╗");
  console.log("║  clearproof L2 verify cost (AIF-99)      ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log(`network:  ${network.name} (chain ${net.chainId})`);
  console.log(`deployer: ${deployer.address}`);
  console.log(`balance:  ${ethers.formatEther(balance)} ETH`);
  if (balance === 0n) {
    console.error("Deployer has no balance.");
    process.exit(1);
  }

  if (!fs.existsSync(FFLONK_ARTIFACT)) {
    console.error(
      `Missing ${FFLONK_ARTIFACT}\nCopy build/FflonkVerifier.sol to contracts/bench/local/ and compile.`,
    );
    process.exit(1);
  }
  for (const f of ["proof.json", "public.json"]) {
    if (!fs.existsSync(path.join(G16_VECTOR, f))) {
      console.error(`Missing ${f} in ${G16_VECTOR}`);
      process.exit(1);
    }
  }
  if (!fs.existsSync(path.join(FFLONK_BUILD, "fflonk_calldata.txt"))) {
    console.error("Missing build/fflonk_calldata.txt — regenerate per FFLONK_BENCHMARK.md");
    process.exit(1);
  }

  const g16Proof = JSON.parse(fs.readFileSync(path.join(G16_VECTOR, "proof.json"), "utf-8"));
  const g16Public: string[] = JSON.parse(fs.readFileSync(path.join(G16_VECTOR, "public.json"), "utf-8"));
  const pA: [string, string] = [g16Proof.pi_a[0], g16Proof.pi_a[1]];
  const pB: [[string, string], [string, string]] = [
    [g16Proof.pi_b[0][1], g16Proof.pi_b[0][0]],
    [g16Proof.pi_b[1][1], g16Proof.pi_b[1][0]],
  ];
  const pC: [string, string] = [g16Proof.pi_c[0], g16Proof.pi_c[1]];

  const fflonk = parseFflonkCalldata(
    fs.readFileSync(path.join(FFLONK_BUILD, "fflonk_calldata.txt"), "utf-8"),
  );

  const ethUsd = await fetchEthUsd();
  console.log(`ETH/USD:  ${ethUsd.usd} (${ethUsd.source})`);

  const feeData = await ethers.provider.getFeeData();
  const block = await ethers.provider.getBlock("latest");

  const groth16 = await measureSystem(
    "Groth16",
    async () => {
      const Factory = await ethers.getContractFactory("Groth16Verifier");
      const contract = await Factory.deploy();
      const deployTx = contract.deploymentTransaction();
      if (!deployTx) throw new Error("Groth16: missing deploy tx");
      await contract.waitForDeployment();
      return { address: await contract.getAddress(), deployTx, contract };
    },
    async (contract) => {
      // Public L2 RPCs often use a low eth_call gas cap; pin a limit.
      const callOpts = { gasLimit: 2_000_000n };
      const ok = await withCallRetry("groth16 staticCall", () =>
        contract.verifyProof.staticCall(pA, pB, pC, g16Public, callOpts),
      );
      if (!ok) throw new Error("Groth16: committed vector rejected on-chain");
      const estimate = await withCallRetry("groth16 estimateGas", () =>
        contract.verifyProof.estimateGas(pA, pB, pC, g16Public, callOpts),
      );
      const calldata = contract.interface.encodeFunctionData("verifyProof", [pA, pB, pC, g16Public]);
      // Send as a real tx so the receipt includes L1/DA fees.
      const tx = await contract.verifyProof.populateTransaction(pA, pB, pC, g16Public).then((req) =>
        deployer.sendTransaction({ ...req, gasLimit: estimate + 50_000n }),
      );
      return { tx, estimate, calldata, ok: true };
    },
  );

  const fflonkArtifact = JSON.parse(fs.readFileSync(FFLONK_ARTIFACT, "utf-8"));
  const fflonkResult = await measureSystem(
    "fflonk",
    async () => {
      const Factory = new ethers.ContractFactory(
        fflonkArtifact.abi,
        fflonkArtifact.bytecode,
        deployer,
      );
      const contract = await Factory.deploy();
      const deployTx = contract.deploymentTransaction();
      if (!deployTx) throw new Error("fflonk: missing deploy tx");
      await contract.waitForDeployment();
      return { address: await contract.getAddress(), deployTx, contract };
    },
    async (contract) => {
      const callOpts = { gasLimit: 2_000_000n };
      const ok = await withCallRetry("fflonk staticCall", () =>
        contract.verifyProof.staticCall(fflonk.proof, fflonk.pubSignals, callOpts),
      );
      if (!ok) throw new Error("fflonk: build vector rejected on-chain");
      const estimate = await withCallRetry("fflonk estimateGas", () =>
        contract.verifyProof.estimateGas(fflonk.proof, fflonk.pubSignals, callOpts),
      );
      const calldata = contract.interface.encodeFunctionData("verifyProof", [
        fflonk.proof,
        fflonk.pubSignals,
      ]);
      const tx = await contract.verifyProof
        .populateTransaction(fflonk.proof, fflonk.pubSignals)
        .then((req: any) => deployer.sendTransaction({ ...req, gasLimit: estimate + 100_000n }));
      return { tx, estimate, calldata, ok: true };
    },
  );

  const out = {
    purpose: "AIF-99 live L2 verify cost: Groth16 vs fflonk",
    network: network.name,
    chain_id: Number(net.chainId),
    measured_at: new Date().toISOString(),
    deployer: deployer.address,
    eth_usd: ethUsd,
    fee_snapshot: {
      gas_price_wei: feeData.gasPrice?.toString() ?? null,
      max_fee_per_gas_wei: feeData.maxFeePerGas?.toString() ?? null,
      base_fee_per_gas_wei: block?.baseFeePerGas?.toString() ?? null,
      block_number: block?.number ?? null,
    },
    vectors: {
      groth16: "tests/vectors/compliance (committed)",
      fflonk: "build/fflonk_calldata.txt (AIF-86 local build; GPL verifier not committed)",
    },
    notes: [
      "fflonk verifier is snarkjs GPL three export; source kept gitignored under contracts/bench/local/",
      "verifyProof is a view function sent as a transaction so the receipt includes rollup L1/DA fees",
      "l1_fee_wei is OP-Stack (Base/Optimism); gas_used_for_l1 is Arbitrum Nitro",
    ],
    groth16,
    fflonk: fflonkResult,
  };

  // USD helpers when we have prices
  const price = ethUsd.usd;
  if (Number.isFinite(price) && price > 0) {
    const weiToUsd = (wei: string | null) =>
      wei == null ? null : (Number(BigInt(wei)) / 1e18) * price;
    (out as any).usd = {
      eth_price: price,
      groth16_tx_fee_usd: weiToUsd(groth16.tx_fee_wei),
      groth16_l1_fee_usd: weiToUsd(groth16.l1_fee_wei),
      fflonk_tx_fee_usd: weiToUsd(fflonkResult.tx_fee_wei),
      fflonk_l1_fee_usd: weiToUsd(fflonkResult.l1_fee_wei),
    };
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const outPath = path.join(OUT_DIR, `${network.name}-l2-verify-cost.json`);
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
  console.log(`\nWrote ${outPath}`);

  const gGas = BigInt(groth16.verify_gas_used);
  const fGas = BigInt(fflonkResult.verify_gas_used);
  const ratio = Number(fGas) / Number(gGas);
  console.log(`\nExecution gas ratio fflonk/groth16: ${ratio.toFixed(3)}×`);
  if (groth16.l1_fee_wei && fflonkResult.l1_fee_wei) {
    const gL1 = BigInt(groth16.l1_fee_wei);
    const fL1 = BigInt(fflonkResult.l1_fee_wei);
    const gTotal = BigInt(groth16.tx_fee_wei) + gL1;
    const fTotal = BigInt(fflonkResult.tx_fee_wei) + fL1;
    // On OP Stack, tx_fee is L2 execution only; l1Fee is separate.
    // On some clients tx_fee already embeds everything — still report both.
    console.log(
      `L1 fee ratio fflonk/groth16: ${(Number(fL1) / Number(gL1)).toFixed(3)}×`,
    );
    console.log(
      `tx_fee+l1Fee ratio: ${(Number(fTotal) / Number(gTotal)).toFixed(3)}×`,
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

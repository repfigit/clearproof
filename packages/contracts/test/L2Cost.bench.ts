import hre from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Calldata + execution-gas inputs for the L2 cost model (AIF-99).
 *
 * On an L2 the cost of `verifyAndRecord` is execution gas *plus* the L1
 * data-availability charge, and the DA charge is driven by the compressed
 * size of the transaction's calldata. fflonk's proof is 24 field elements
 * against Groth16's 8, so it pays 512 extra bytes of DA on every proof —
 * the term ADR 0003's L1-only gas table does not price.
 *
 * This bench emits the two numbers the model needs per proof system:
 *   1. execution gas for the verifier call
 *   2. the exact calldata the VASP posts, so the model can FastLZ/brotli it
 *
 * Groth16 numbers are measured here. There is no fflonk verifier in this
 * repo, so its calldata is *synthesised* at the correct shape and entropy
 * (see `syntheticFflonkCalldata`) and its execution gas is taken from the
 * AIF-86 spike. Both are declared as assumptions in
 * docs/internal/FFLONK_BENCHMARK.md.
 *
 * Run:  npx hardhat test test/L2Cost.bench.ts
 * Then: uv run python scripts/l2_cost_model.py --inputs <emitted json>
 */

const REPO_ROOT = path.resolve(__dirname, "../../..");
const VECTOR_DIR = path.join(REPO_ROOT, "tests/vectors/compliance");
const OUT_PATH = process.env.L2_COST_INPUTS || "/tmp/l2-cost-inputs.json";

/** fflonk proofs are 24 field elements; snarkjs emits `bytes32[24] proof`. */
const FFLONK_PROOF_WORDS = 24;

function byteStats(hex: string) {
  const bytes = Buffer.from(hex.slice(2), "hex");
  let zero = 0;
  for (const b of bytes) if (b === 0) zero++;
  return { bytes: bytes.length, zero_bytes: zero, nonzero_bytes: bytes.length - zero, hex };
}

/**
 * OP Stack meters DA on the *whole signed transaction*, not the calldata
 * (op-geth `Transaction.RollupCostData` FastLZ-compresses `MarshalBinary()`).
 * So the model needs the serialised envelope, signature included.
 */
async function signedTx(to: string, data: string) {
  // A throwaway key: only the envelope's *size* matters, and a signature is
  // 65 bytes whoever produced it.
  const signer = new hre.ethers.Wallet(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  );
  return signer.signTransaction({
    to,
    data,
    chainId: 8453,
    nonce: 42,
    gasLimit: 500_000,
    maxFeePerGas: 50_000_000n,
    maxPriorityFeePerGas: 1_000_000n,
    value: 0,
    type: 2,
  });
}

/**
 * fflonk proof words are curve coordinates and field evaluations: uniformly
 * distributed over ~254 bits, so essentially incompressible. Deriving them
 * with keccak from the real Groth16 proof reproduces that entropy exactly
 * while keeping the vector deterministic. Using zeroed placeholders here
 * would understate fflonk's DA cost by ~500 bytes — the whole quantity
 * under measurement.
 */
function syntheticFflonkCalldata(seed: string, pubSignals: bigint[]): string {
  const words: string[] = [];
  for (let i = 0; i < FFLONK_PROOF_WORDS; i++) {
    words.push(hre.ethers.keccak256(hre.ethers.solidityPacked(["string", "uint256"], [seed, i])));
  }
  const iface = new hre.ethers.Interface([
    "function verifyProof(bytes32[24] proof, uint256[16] pubSignals) view returns (bool)",
  ]);
  return iface.encodeFunctionData("verifyProof", [words, pubSignals]);
}

describe("L2 cost inputs: Groth16 execution gas + calldata footprint", function () {
  it("emits per-proof-system gas and calldata for the L2 model", async function () {
    if (!fs.existsSync(path.join(VECTOR_DIR, "proof.json"))) {
      this.skip();
      return;
    }

    const proof = JSON.parse(fs.readFileSync(path.join(VECTOR_DIR, "proof.json"), "utf-8"));
    const publicSignals: string[] = JSON.parse(
      fs.readFileSync(path.join(VECTOR_DIR, "public.json"), "utf-8")
    );

    const pA: [bigint, bigint] = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ];
    const pC: [bigint, bigint] = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
    const pubSignals = publicSignals.map((s) => BigInt(s));

    const Verifier = await hre.ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // estimateGas on a view function meters it as a transaction, so this is
    // intrinsic (21k + calldata) + execution — the number an L2 charges at
    // the L2 gas price. The model subtracts nothing; it adds the L1 term.
    const groth16Gas = await verifier.verifyProof.estimateGas(pA, pB, pC, pubSignals);

    const groth16Calldata = verifier.interface.encodeFunctionData("verifyProof", [
      pA,
      pB,
      pC,
      pubSignals,
    ]);
    const fflonkCalldata = syntheticFflonkCalldata(proof.pi_a[0], pubSignals);

    const to = await verifier.getAddress();
    const out = {
      generated_by: "packages/contracts/test/L2Cost.bench.ts",
      vector: "tests/vectors/compliance",
      groth16: {
        execution_gas: Number(groth16Gas),
        execution_gas_source: "measured (hardhat estimateGas, this run)",
        calldata: byteStats(groth16Calldata),
        signed_tx: byteStats(await signedTx(to, groth16Calldata)),
      },
      fflonk: {
        execution_gas: 232646,
        execution_gas_source: "AIF-86 spike (L1 measurement, not reproduced here)",
        calldata: { ...byteStats(fflonkCalldata), synthetic: true },
        signed_tx: { ...byteStats(await signedTx(to, fflonkCalldata)), synthetic: true },
      },
    };

    fs.writeFileSync(OUT_PATH, JSON.stringify(out, null, 2));

    console.log(`\n    Groth16 verifyProof gas : ${out.groth16.execution_gas}`);
    console.log(`    Groth16 calldata        : ${out.groth16.calldata.bytes} B`);
    console.log(`    fflonk  calldata (synth): ${out.fflonk.calldata.bytes} B`);
    console.log(`    wrote ${OUT_PATH}\n`);
  });
});

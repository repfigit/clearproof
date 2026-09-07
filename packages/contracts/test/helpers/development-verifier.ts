import { run } from "hardhat";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, TASK_COMPILE_SOLIDITY_RUN_SOLC,
  TASK_COMPILE_SOLIDITY_RUN_SOLCJS } from "hardhat/builtin-tasks/task-names";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

/** Local test compilation only: never replace the checked-in legacy verifier/key. */
export async function developmentVerifier(keyPath: string) {
  const root = path.resolve(__dirname, "../../../..");
  const key = JSON.parse(fs.readFileSync(keyPath, "utf8"));
  if (key.protocol !== "groth16" || key.curve !== "bn128" || key.nPublic !== 16 || key.IC?.length !== 17) {
    throw new Error("Legacy development test requires a sixteen-signal Groth16 key");
  }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-legacy-verifier-"));
  try {
    const source = path.join(temporary, "Groth16Verifier.sol");
    execFileSync(process.execPath, [path.join(root, "scripts/generate_verifier.mjs"), keyPath, source],
      { timeout: 30000, stdio: "pipe" });
    const input = {
      language: "Solidity",
      sources: {
        "Groth16Verifier.sol": { content: fs.readFileSync(source, "utf8") },
        "Pairing.sol": { content: fs.readFileSync(path.join(root, "packages/contracts/contracts/Pairing.sol"), "utf8") },
      },
      settings: { optimizer: { enabled: true, runs: 200 },
        outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } },
    };
    const compiler = await run(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, { quiet: true, solcVersion: "0.8.24" });
    const output = await run(compiler.isSolcJs ? TASK_COMPILE_SOLIDITY_RUN_SOLCJS : TASK_COMPILE_SOLIDITY_RUN_SOLC,
      compiler.isSolcJs ? { input, solcJsPath: compiler.compilerPath } :
        { input, solcPath: compiler.compilerPath, solcVersion: "0.8.24" });
    if (output.errors?.some((error: { severity: string }) => error.severity === "error")) {
      throw new Error("Legacy development verifier compilation failed");
    }
    const artifact = output.contracts["Groth16Verifier.sol"].Groth16Verifier;
    return { abi: artifact.abi, bytecode: "0x" + artifact.evm.bytecode.object };
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

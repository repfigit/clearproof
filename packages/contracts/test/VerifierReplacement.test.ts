import { expect } from "chai";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

describe("Verifier replacement entrypoint", function () {
  it("preserves state and resumes the same verifier only after its real router timelock", async function () {
    this.timeout(60000);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-verifier-replacement-"));
    try {
      fs.mkdirSync(path.join(directory, "packages/contracts/scripts"), { recursive: true });
      fs.mkdirSync(path.join(directory, "packages/contracts/deployments"));
      for (const name of ["node_modules", "config"]) {
        fs.symlinkSync(path.resolve(__dirname, "../../..", name), path.join(directory, name), "dir");
      }
      fs.copyFileSync(path.resolve(__dirname, "../scripts/redeploy-verifier.ts"),
        path.join(directory, "packages/contracts/scripts/redeploy-verifier.ts"));
      fs.writeFileSync(path.join(directory, "bootstrap.cjs"), `
const { ethers, network } = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
(async () => {
 const [admin] = await ethers.getSigners();
 const router = await (await ethers.getContractFactory("VerifierRouter")).deploy(60);
 const old = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
 const v1 = ethers.id("groth16-bn254-v1");
 await (await router.registerVerifier(v1, await old.getAddress(), "old")).wait();
 await network.provider.send("evm_increaseTime", [61]);
 await network.provider.send("evm_mine");
 await (await router.activateVerifier(v1, "old")).wait();
 const vasp = await (await ethers.getContractFactory("VASPRegistry")).deploy(admin.address);
 const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, ethers.id("synthetic"), 0);
 const registry = await (await ethers.getContractFactory("ComplianceRegistry")).deploy(
   await router.getAddress(), v1, await vasp.getAddress(), await oracle.getAddress(), 10, 20, 30);
 const recordPath = path.join(__dirname, "packages/contracts/deployments/hardhat.json");
 const original = { VerifierRouter: await router.getAddress(), Groth16Verifier: await old.getAddress(),
   ComplianceRegistry: await registry.getAddress(), VASPRegistry: await vasp.getAddress(), SanctionsOracle: await oracle.getAddress() };
 fs.writeFileSync(recordPath, JSON.stringify({ chainId: "31337", contracts: original, marker: "preserved" }));
 const script = require.resolve("./packages/contracts/scripts/redeploy-verifier.ts");
 async function runReplacement() {
   const log = console.log, error = console.error;
   try {
     await new Promise((resolve, reject) => {
       console.log = (...args) => { log(...args); if (/^(Awaiting verifier|Verifier replacement complete)/.test(String(args[0]))) resolve(); };
       console.error = (...args) => { error(...args); reject(new Error(String(args[0]))); };
       delete require.cache[script]; require(script);
     });
   } finally { console.log = log; console.error = error; }
 }
 await runReplacement();
 let record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
 const pending = record.pendingVerifierReplacement;
 assert(pending && pending.verifier !== original.Groth16Verifier);
 assert.equal(await registry.verifierSelector(), v1);
 assert.deepEqual(record.contracts, original);
 const nonce = await ethers.provider.getTransactionCount(admin.address);
 await runReplacement();
 assert.equal(await ethers.provider.getTransactionCount(admin.address), nonce);
 assert.equal(JSON.parse(fs.readFileSync(recordPath, "utf8")).pendingVerifierReplacement.verifier, pending.verifier);
 await network.provider.send("evm_setNextBlockTimestamp", [Number(pending.activateAfter)]);
 await network.provider.send("evm_mine");
 await runReplacement();
 record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
 const v2 = ethers.id("groth16-bn254-v2");
 assert.equal(await registry.verifierSelector(), v2);
 assert.equal((await router.verifiers(v2)).verifier, pending.verifier);
 assert.equal(record.previous.Groth16Verifier, original.Groth16Verifier);
 assert.equal(record.previous.verifierSelector, v1);
 assert.equal(record.pendingVerifierReplacement, undefined);
 assert.deepEqual(record.contracts, { ...original, Groth16Verifier: pending.verifier });
 assert.equal(record.marker, "preserved");
 console.log("REAL_REPLACEMENT_TIMELOCK_VERIFIED");
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
      const result = await execute(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "run",
        path.join(directory, "bootstrap.cjs"), "--network", "hardhat", "--no-compile"], {
        cwd: path.resolve(__dirname, ".."), timeout: 45000,
      });
      expect(result.stdout).to.contain("REAL_REPLACEMENT_TIMELOCK_VERIFIED");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});

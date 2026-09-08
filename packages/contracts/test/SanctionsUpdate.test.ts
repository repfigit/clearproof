import { expect } from "chai";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

describe("Sanctions update entrypoint", function () {
  it("updates an isolated oracle after chain cooldown using only synthetic tree data", async function () {
    this.timeout(60000);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-sanctions-update-"));
    try {
      fs.mkdirSync(path.join(directory, "packages/contracts/scripts"), { recursive: true });
      fs.mkdirSync(path.join(directory, "packages/contracts/deployments"));
      fs.mkdirSync(path.join(directory, "artifacts"));
      fs.symlinkSync(path.resolve(__dirname, "../../../node_modules"), path.join(directory, "node_modules"), "dir");
      fs.copyFileSync(path.resolve(__dirname, "../scripts/update-sanctions-root.ts"),
        path.join(directory, "packages/contracts/scripts/update-sanctions-root.ts"));
      fs.writeFileSync(path.join(directory, "artifacts/sanctions_tree.json"), JSON.stringify({ root: "123", leaf_count: 100 }));
      fs.writeFileSync(path.join(directory, "bootstrap.cjs"), `
const { ethers, network } = require("hardhat");
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
(async () => {
 const [admin] = await ethers.getSigners();
 const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, ethers.id("synthetic-old"), 100);
 await oracle.waitForDeployment();
 const previousTime = await oracle.lastUpdated();
 fs.writeFileSync(path.join(__dirname, "packages/contracts/deployments/hardhat.json"),
   JSON.stringify({ contracts: { SanctionsOracle: await oracle.getAddress() } }));
 await network.provider.send("evm_increaseTime", [3601]);
 await network.provider.send("evm_mine");
 const log = console.log, error = console.error;
 try {
   await new Promise((resolve, reject) => {
     console.log = (...args) => { log(...args); if (String(args[0]).startsWith("  Match:")) resolve(); };
     console.error = (...args) => { error(...args); reject(new Error(String(args[0]))); };
     require("./packages/contracts/scripts/update-sanctions-root.ts");
   });
 } finally { console.log = log; console.error = error; }
 assert.equal(await oracle.currentRoot(), ethers.zeroPadValue(ethers.toBeHex(123n), 32));
 assert.equal(await oracle.leafCount(), 100n);
 assert(await oracle.lastUpdated() >= previousTime + 3600n);
 console.log("REAL_SYNTHETIC_UPDATE_VERIFIED");
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
      const result = await execute(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "run",
        path.join(directory, "bootstrap.cjs"), "--network", "hardhat", "--no-compile"], {
        cwd: path.resolve(__dirname, ".."), env: { ...process.env, SKIP_CONFIRM: "1" }, timeout: 45000,
      });
      expect(result.stdout).to.contain("REAL_SYNTHETIC_UPDATE_VERIFIED");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});

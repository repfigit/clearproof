import { expect } from "chai";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

describe("Relay deployment entrypoint", function () {
  it("deploys a real relay, grants its oracle role and preserves existing deployment metadata", async function () {
    this.timeout(60000);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-relay-deployment-"));
    try {
      fs.mkdirSync(path.join(directory, "scripts"));
      fs.mkdirSync(path.join(directory, "deployments"));
      fs.symlinkSync(path.resolve(__dirname, "../../../node_modules"), path.join(directory, "node_modules"), "dir");
      fs.copyFileSync(path.resolve(__dirname, "../scripts/deploy-relay.ts"), path.join(directory, "scripts/deploy-relay.ts"));
      fs.writeFileSync(path.join(directory, "bootstrap.cjs"), `
const { ethers } = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const [admin] = await ethers.getSigners();
  const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, ethers.id("synthetic"), 0);
  await oracle.waitForDeployment();
  const recordPath = path.join(__dirname, "deployments/hardhat.json");
  fs.writeFileSync(recordPath, JSON.stringify({ network: "hardhat", marker: "preserve",
    contracts: { SanctionsOracle: await oracle.getAddress() } }));
  require("./scripts/deploy-relay.ts");
  const deadline = Date.now() + 15000;
  let record;
  while (Date.now() < deadline) {
    record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
    if (record.contracts.SanctionsRootRelay) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  const relay = record.contracts.SanctionsRootRelay;
  if (!relay || await ethers.provider.getCode(relay) === "0x") throw new Error("Relay was not deployed");
  if (!await oracle.hasRole(ethers.id("ORACLE_ROLE"), relay)) throw new Error("Relay oracle role was not granted");
  if (record.marker !== "preserve") throw new Error("Existing metadata was lost");
  if (record.contracts.SanctionsOracle !== await oracle.getAddress()) throw new Error("Oracle address changed");
  if (!Number.isFinite(Date.parse(record.timestamp))) throw new Error("Deployment timestamp missing");
  console.log("REAL_RELAY_DEPLOYMENT_VERIFIED");
})().catch(error => { console.error(error); process.exitCode = 1; });
`);
      const env = { ...process.env };
      delete env.ETHERSCAN_API_KEY;
      const result = await execute(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "run",
        path.join(directory, "bootstrap.cjs"), "--network", "hardhat", "--no-compile"], {
        cwd: path.resolve(__dirname, ".."), env, timeout: 45000,
      });
      expect(result.stdout).to.contain("REAL_RELAY_DEPLOYMENT_VERIFIED");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});

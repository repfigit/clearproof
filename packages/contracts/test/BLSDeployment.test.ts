import { expect } from "chai";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

describe("BLS benchmark deployment entrypoint", function () {
  it("verifies real valid and tampered vectors locally without claiming Sepolia confirmation", async function () {
    this.timeout(60000);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-bls-deployment-"));
    try {
      const scripts = path.join(directory, "packages/contracts/scripts");
      const deployments = path.join(directory, "packages/contracts/deployments");
      fs.mkdirSync(scripts, { recursive: true });
      fs.mkdirSync(deployments);
      fs.mkdirSync(path.join(directory, "tests/vectors"), { recursive: true });
      fs.symlinkSync(path.resolve(__dirname, "../../../node_modules"), path.join(directory, "node_modules"), "dir");
      fs.symlinkSync(path.resolve(__dirname, "../../../tests/vectors/compliance-bls"),
        path.join(directory, "tests/vectors/compliance-bls"), "dir");
      const script = path.join(scripts, "deploy-verifier-bls.ts");
      fs.copyFileSync(path.resolve(__dirname, "../scripts/deploy-verifier-bls.ts"), script);
      const result = await execute(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "run", script,
        "--network", "hardhat", "--no-compile"], { cwd: path.resolve(__dirname, ".."), timeout: 45000 });
      expect(result.stdout).to.contain("valid proof accepted: true");
      expect(result.stdout).to.contain("tampered proof rejected: true");
      expect(result.stdout).not.to.contain("Sepolia confirmation) is now complete");
      const record = JSON.parse(fs.readFileSync(path.join(deployments, "hardhat-bls-bench.json"), "utf8"));
      expect(record.network).to.equal("hardhat");
      expect(record.chainId).to.equal("31337");
      expect(record.note).to.contain("not production");
      expect(BigInt(record.deployGas)).to.be.greaterThan(0n);
      expect(BigInt(record.verifyGasEstimate)).to.be.greaterThan(0n);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});

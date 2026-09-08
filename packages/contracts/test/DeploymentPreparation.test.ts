import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { prepareLegacyVerifier } from "../scripts/legacy-verifier";
import thresholds from "../../../config/jurisdiction_thresholds.json";

describe("Legacy deployment preparation", function () {
  it("records pending activation and connects the registry to the actual router", async function () {
    const [admin] = await ethers.getSigners();
    const { router, verifier, selector, activation, timelockPeriod } = await prepareLegacyVerifier();
    expect(timelockPeriod).to.equal(86400);
    expect(activation.status).to.equal("pending-timelock");
    expect(await router.pendingRegistrations(selector)).to.equal(await verifier.getAddress());
    expect((await router.verifiers(selector)).active).to.equal(false);
    await expect(router.activateVerifier(selector, activation.name)).to.be.revertedWithCustomError(router, "Unauthorized");
    const vasp = await (await ethers.getContractFactory("VASPRegistry")).deploy(admin.address);
    const oracle = await (await ethers.getContractFactory("SanctionsOracle")).deploy(admin.address, ethers.id("synthetic"), 0);
    const registry = await (await ethers.getContractFactory("ComplianceRegistry")).deploy(
      await router.getAddress(), selector, await vasp.getAddress(), await oracle.getAddress(),
      thresholds.default.tier2, thresholds.default.tier3, thresholds.default.tier4,
    );
    expect(await registry.verifierRouter()).to.equal(await router.getAddress());
    expect(await registry.verifierSelector()).to.equal(selector);
    await time.increaseTo(BigInt(activation.activateAfter));
    await router.activateVerifier(selector, activation.name);
    expect((await router.verifiers(selector)).active).to.equal(true);
    expect((await router.verifiers(selector)).verifier).to.equal(await verifier.getAddress());
  });

  it("runs both deployment entrypoints locally and records pending router activation", async function () {
    this.timeout(120000);
    const fs = await import("node:fs");
    const path = await import("node:path");
    const os = await import("node:os");
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execute = promisify(execFile);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-deployment-test-"));
    try {
      for (const script of ["deploy.ts", "deploy-multichain.ts"]) {
        const output = path.join(directory, script);
        // The parent test run already compiled its selected artifacts. Recompiling
        // here would overwrite instrumented bytecode during coverage runs.
        await execute(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "run",
          `scripts/${script}`, "--network", "hardhat", "--no-compile"], {
          cwd: path.resolve(__dirname, ".."), timeout: 60000,
          env: { ...process.env, CLEARPROOF_DEPLOYMENTS_DIR: output },
        });
        const record = JSON.parse(fs.readFileSync(path.join(output, "hardhat.json"), "utf8"));
        expect(record.network).to.equal("hardhat");
        expect(record.chainId).to.equal("31337");
        expect(record.verifierActivation.status).to.equal("pending-timelock");
        expect(record.verifierActivation.selector).to.equal(ethers.id("groth16-bn254-v1"));
        expect(BigInt(record.verifierActivation.activateAfter)).to.be.greaterThan(0n);
        for (const name of ["VerifierRouter", "Groth16Verifier", "VASPRegistry", "SanctionsOracle", "ComplianceRegistry"]) {
          expect(ethers.isAddress(record.contracts[name])).to.equal(true);
        }
        expect(record.contracts.VerifierRouter).not.to.equal(record.contracts.Groth16Verifier);
        if (script === "deploy-multichain.ts") expect(ethers.isAddress(record.contracts.SanctionsRootRelay)).to.equal(true);
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

});

import { expect } from "chai";
import { ethers } from "hardhat";
import { setCode } from "@nomicfoundation/hardhat-network-helpers";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { artifactManifestDigest, deployPilot, PILOT_CONTRACTS, verifyPilotDeployment,
  type PilotDeployContext } from "../scripts/pilot-deployment";

// Synthetic key built from the BN254 generators. It passes the verifier's curve checks
// and proves nothing: these tests exercise deployment, never pairing soundness.
const G1 = ["1", "2", "1"];
const G2 = [
  ["10857046999023057135944570762232829481370756359578518086990519993285655852781",
    "11559732032986387107991004021392285783925812861821192530917403151452391805634"],
  ["8495653923123431417604973247489272438418190587263600148770280649306958101930",
    "4082367875863433681332203403145435568316851327593401208105741076214120093531"],
  ["1", "0"],
];
const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");

describe("Pilot deployment script (local Hardhat network)", function () {
  let directory: string;
  let bundle: string;
  let deployments: string;
  let manifestPath: string;
  let digest: string;
  let confirmations: string[];

  beforeEach(function () {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-pilot-deploy-"));
    bundle = path.join(directory, "bundle");
    deployments = path.join(directory, "deployments");
    manifestPath = path.join(deployments, "hardhat-pilot.json");
    fs.mkdirSync(bundle);
    const key = JSON.stringify({ protocol: "groth16", curve: "bn128", nPublic: 8, vk_alpha_1: G1,
      vk_beta_2: G2, vk_gamma_2: G2, vk_delta_2: G2, IC: Array(9).fill(G1) });
    fs.writeFileSync(path.join(bundle, "verification-key.json"), key);
    const file = (filename: string) => ({ filename, sha256: "11".repeat(32), size: 1 });
    const manifest = { proof_profile: "pilot-transfer-v3", policy_schema_digest: "22".repeat(32),
      source_bundle_digest: "33".repeat(32), compiler_sha256: "44".repeat(32),
      public_signals: ["projection_commitment", "authorized_issuer_root", "sanctions_root", "authorization_nullifier",
        "evaluated_at", "proof_expires_at", "domain_chain_id", "domain_registry"],
      wasm: file("pilot.wasm"), r1cs: file("pilot.r1cs"), proving_key: file("UNAPPROVED-development.zkey"),
      verification_key: { filename: "verification-key.json", sha256: sha256(key), size: key.length } };
    fs.writeFileSync(path.join(bundle, "manifest.json"), JSON.stringify(manifest));
    digest = artifactManifestDigest(manifest);
    confirmations = [];
  });
  afterEach(function () {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  async function context(overrides: Partial<PilotDeployContext> = {}, env: Record<string, string | undefined> = {}) {
    const [, registryAdmin, checkpointAdmin] = await ethers.getSigners();
    return {
      ethers, networkName: "hardhat", deploymentsDir: deployments, log: () => {},
      env: { PILOT_REGISTRY_ADMIN: registryAdmin.address, PILOT_CHECKPOINT_ADMIN: checkpointAdmin.address,
        PILOT_ARTIFACTS_DIR: bundle, PILOT_MANIFEST_DIGEST: digest, ...env },
      confirm: async (prompt: string) => { confirmations.push(prompt); return "deploy"; },
      git: (args: string[]) => (args[0] === "rev-parse" ? "0123456789abcdef0123456789abcdef01234567\n" : ""),
      ...overrides,
    } satisfies PilotDeployContext;
  }

  it("deploys all three contracts and records a manifest that matches on-chain code", async function () {
    const [deployer, registryAdmin, checkpointAdmin] = await ethers.getSigners();
    const manifest = await deployPilot(await context());
    expect(confirmations).to.have.length(1);
    expect(JSON.parse(fs.readFileSync(manifestPath, "utf8"))).to.deep.equal(JSON.parse(JSON.stringify(manifest)));
    expect(manifest).to.include({ schema: "clearproof-pilot-deployment-v1", status: "complete", network: "hardhat",
      chainId: "31337", proofProfile: "pilot-transfer-v3", assurance: "development-unapproved",
      artifactManifestDigest: "0x" + digest, deployer: deployer.address, gitDirty: false,
      gitCommit: "0123456789abcdef0123456789abcdef01234567" });
    for (const name of PILOT_CONTRACTS) {
      const record = manifest.contracts[name]!;
      const code = await ethers.provider.getCode(record.address);
      expect(code).to.not.equal("0x");
      expect(record.runtimeCodeHash).to.equal(ethers.keccak256(code));
      expect(record.runtimeSha256).to.equal(sha256(Buffer.from(code.slice(2), "hex")));
      const receipt = await ethers.provider.getTransactionReceipt(record.deployTxHash);
      expect(receipt!.contractAddress).to.equal(record.address);
      expect(receipt!.blockNumber).to.equal(record.blockNumber);
    }
    const verifierRecord = manifest.contracts.PilotGroth16Verifier!;
    const verifier = await ethers.getContractAt("PilotGroth16Verifier", verifierRecord.address);
    const registry = await ethers.getContractAt("PilotCurrentRegistry", manifest.contracts.PilotCurrentRegistry!.address);
    const checkpoint = await ethers.getContractAt("PilotRootCheckpoint", manifest.contracts.PilotRootCheckpoint!.address);
    // The registry pins exactly the deployed verifier: address, runtime code hash and manifest digest.
    expect(await registry.verifier()).to.equal(verifierRecord.address);
    expect(await registry.verifierCodeHash()).to.equal(verifierRecord.runtimeCodeHash);
    expect(await registry.artifactManifestDigest()).to.equal("0x" + digest);
    expect(await verifier.assurance()).to.equal(manifest.assurance);
    expect(await verifier.proofProfile()).to.equal(manifest.proofProfile);
    expect(await verifier.verificationKeyCommitment()).to.equal(manifest.verificationKeyCommitment);
    // Privileged roles go to the configured admins, never to the deployer.
    expect(await registry.defaultAdmin()).to.equal(registryAdmin.address);
    expect(await checkpoint.defaultAdmin()).to.equal(checkpointAdmin.address);
    const pauser = await registry.PAUSER_ROLE();
    expect(await registry.hasRole(pauser, deployer.address)).to.equal(false);
    expect(await checkpoint.hasRole(pauser, deployer.address)).to.equal(false);
    expect(manifest.contracts.PilotCurrentRegistry!.constructorArguments)
      .to.deep.equal([registryAdmin.address, verifierRecord.address]);
    expect(manifest.contracts.PilotRootCheckpoint!.constructorArguments).to.deep.equal([checkpointAdmin.address]);
    await verifyPilotDeployment(ethers, manifest);
  });

  it("refuses mainnets, unknown networks and a testnet name on the wrong chain before sending anything", async function () {
    const block = await ethers.provider.getBlockNumber();
    for (const networkName of ["ethereum", "base", "arbitrum", "polygon", "optimism", "unlisted"]) {
      await expect(deployPilot(await context({ networkName })))
        .to.be.rejectedWith(/development-unapproved.*mainnet deployment is never correct.*no override/);
    }
    await expect(deployPilot(await context({ networkName: "sepolia" })))
      .to.be.rejectedWith(/must be chain 11155111, but the RPC reports chain 31337/);
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.existsSync(deployments)).to.equal(false);
    expect(confirmations).to.deep.equal([]);
  });

  it("refuses missing or zero admins, and uses the deployer only with the local opt-in", async function () {
    const block = await ethers.provider.getBlockNumber();
    await expect(deployPilot(await context({}, { PILOT_REGISTRY_ADMIN: undefined })))
      .to.be.rejectedWith(/PILOT_REGISTRY_ADMIN .* must be an explicit nonzero address/);
    await expect(deployPilot(await context({}, { PILOT_CHECKPOINT_ADMIN: ethers.ZeroAddress })))
      .to.be.rejectedWith(/PILOT_CHECKPOINT_ADMIN .* must be an explicit nonzero address/);
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.existsSync(deployments)).to.equal(false);
    const [deployer] = await ethers.getSigners();
    const manifest = await deployPilot(await context({}, { PILOT_REGISTRY_ADMIN: undefined,
      PILOT_CHECKPOINT_ADMIN: undefined, PILOT_ALLOW_DEPLOYER_ADMIN: "1" }));
    expect(manifest.admins).to.deep.equal({ PilotCurrentRegistry: deployer.address, PilotRootCheckpoint: deployer.address });
  });

  it("does not send transactions without the typed confirmation", async function () {
    const block = await ethers.provider.getBlockNumber();
    await expect(deployPilot(await context({ confirm: async () => "yes" }))).to.be.rejectedWith(/not confirmed/);
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.existsSync(deployments)).to.equal(false);
  });

  it("verifies an existing manifest without redeploying or rewriting it", async function () {
    const first = await deployPilot(await context());
    const written = fs.readFileSync(manifestPath);
    const block = await ethers.provider.getBlockNumber();
    const again = await deployPilot(await context({ confirm: async () => { throw new Error("must not prompt"); } }));
    expect(again).to.deep.equal(JSON.parse(JSON.stringify(first)));
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.readFileSync(manifestPath).equals(written)).to.equal(true);
  });

  it("resumes an interrupted deployment and deploys only what is missing", async function () {
    const first = await deployPilot(await context());
    const partial = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    delete partial.contracts.PilotRootCheckpoint;
    partial.status = "in-progress";
    fs.writeFileSync(manifestPath, JSON.stringify(partial));
    const block = await ethers.provider.getBlockNumber();
    const resumed = await deployPilot(await context());
    expect(await ethers.provider.getBlockNumber()).to.equal(block + 1);
    expect(resumed.status).to.equal("complete");
    expect(resumed.contracts.PilotGroth16Verifier).to.deep.equal(first.contracts.PilotGroth16Verifier);
    expect(resumed.contracts.PilotCurrentRegistry).to.deep.equal(first.contracts.PilotCurrentRegistry);
    expect(resumed.contracts.PilotRootCheckpoint!.address).to.not.equal(first.contracts.PilotRootCheckpoint!.address);
    expect(resumed.createdAt).to.equal(first.createdAt);
  });

  it("resumes a recorded but unconfirmed deployment transaction instead of sending it again", async function () {
    await deployPilot(await context());
    const pending = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const { address, deployTxHash, constructorArguments } = pending.contracts.PilotRootCheckpoint;
    pending.contracts.PilotRootCheckpoint = { address, deployTxHash, constructorArguments };
    pending.status = "in-progress";
    fs.writeFileSync(manifestPath, JSON.stringify(pending));
    const block = await ethers.provider.getBlockNumber();
    const resumed = await deployPilot(await context({ confirm: async () => { throw new Error("must not prompt"); } }));
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(resumed.status).to.equal("complete");
    expect(resumed.contracts.PilotRootCheckpoint!.address).to.equal(address);
    expect(resumed.contracts.PilotRootCheckpoint!.runtimeCodeHash)
      .to.equal(ethers.keccak256(await ethers.provider.getCode(address)));
  });

  it("refuses an existing manifest that does not match on-chain code, and leaves it untouched", async function () {
    const manifest = await deployPilot(await context());
    const written = fs.readFileSync(manifestPath);
    // Different code at the recorded verifier address (here: a contract that always reverts).
    await setCode(manifest.contracts.PilotGroth16Verifier!.address, "0x60006000fd");
    const block = await ethers.provider.getBlockNumber();
    await expect(deployPilot(await context()))
      .to.be.rejectedWith(/On-chain state does not match the manifest: PilotGroth16Verifier runtime code hash/);
    await expect(verifyPilotDeployment(ethers, manifest)).to.be.rejectedWith(/PilotGroth16Verifier runtime code hash/);
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.readFileSync(manifestPath).equals(written)).to.equal(true);
  });

  it("refuses to reuse a manifest for different admins or a different chain record", async function () {
    await deployPilot(await context());
    const written = fs.readFileSync(manifestPath);
    const [, , , other] = await ethers.getSigners();
    const block = await ethers.provider.getBlockNumber();
    await expect(deployPilot(await context({}, { PILOT_REGISTRY_ADMIN: other.address })))
      .to.be.rejectedWith(/records a different deployment \(admins\). It is never overwritten/);
    expect(await ethers.provider.getBlockNumber()).to.equal(block);
    expect(fs.readFileSync(manifestPath).equals(written)).to.equal(true);
  });

  it("refuses a bundle that does not match the operator's manifest pin", async function () {
    await expect(deployPilot(await context({}, { PILOT_MANIFEST_DIGEST: "ab".repeat(32) })))
      .to.be.rejectedWith(/does not match the operator-pinned manifest digest/);
    expect(fs.existsSync(deployments)).to.equal(false);
  });
});

/**
 * Deployment logic for the current pilot (`pilot-transfer-v3`) contracts:
 * PilotGroth16Verifier, PilotCurrentRegistry and PilotRootCheckpoint.
 *
 * `scripts/deploy-pilot.ts` is the Hardhat entry point. Everything here takes its
 * network, signer, environment and file locations as arguments so it can be tested.
 *
 * Rules this module enforces:
 * - Local Hardhat networks and `testnet: true` entries of `networks.ts` only. There is
 *   no mainnet override: the verifier reports `assurance = "development-unapproved"`.
 * - Admin addresses are explicit. The deployer is used for a privileged role only with
 *   `PILOT_ALLOW_DEPLOYER_ADMIN=1`, and only on a local network.
 * - The verification key comes from an artifact bundle whose manifest digest matches an
 *   operator-supplied pin (the same pin `src/prover/pilot_artifacts.py` requires).
 * - One manifest per network, `deployments/<network>-pilot.json`. An existing manifest
 *   is resumed and checked against chain state; it is never replaced with a different
 *   deployment, and recorded contracts are never redeployed.
 *
 * Publishers are not constructor arguments. Each admin assigns them per tenant with
 * `setPublisher` after deployment; this module sends no such transaction.
 */
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { AbiCoder, ZeroAddress, getAddress, isAddress, keccak256 } from "ethers";
import { NETWORKS } from "./networks";

export const PILOT_PROFILE = "pilot-transfer-v3";
export const PILOT_ASSURANCE = "development-unapproved";
export const PILOT_MANIFEST_SCHEMA = "clearproof-pilot-deployment-v1";
export const LOCAL_NETWORKS = ["hardhat", "localhost"];
export const LOCAL_CHAIN_ID = 31337n;
export const PILOT_CONTRACTS = ["PilotGroth16Verifier", "PilotCurrentRegistry", "PilotRootCheckpoint"] as const;
export type PilotContractName = (typeof PILOT_CONTRACTS)[number];

const NO_MAINNET =
  `PilotGroth16Verifier embeds assurance = "${PILOT_ASSURANCE}" keys, so a mainnet deployment is never correct. ` +
  "There is no override.";
const KEY_TYPE = "tuple(uint256[2] alpha,uint256[2][2] beta,uint256[2][2] gamma,uint256[2][2] delta,uint256[2][9] ic)";

type HardhatEthers = (typeof import("hardhat"))["ethers"];
type G1 = [string, string];
type G2 = [G1, G1];
export interface PilotVerificationKey { alpha: G1; beta: G2; gamma: G2; delta: G2; ic: G1[] }

export interface PilotDeployConfig {
  registryAdmin: string;
  checkpointAdmin: string;
  artifactsDir: string;
  manifestDigest: string;
}

export interface PilotArtifacts {
  key: PilotVerificationKey;
  manifestDigest: string;
  verificationKeySha256: string;
  verificationKeyCommitment: string;
}

export interface PilotContractRecord {
  address: string;
  deployTxHash: string;
  constructorArguments: unknown[];
  /** Absent while the deployment transaction is recorded but not yet confirmed. */
  blockNumber?: number;
  /** keccak256 of the runtime code: the value `PilotCurrentRegistry.verifierCodeHash` pins. */
  runtimeCodeHash?: string;
  /** SHA-256 of the runtime code: the pin `scripts/publish_pilot_sanctions_head.py --runtime-sha256` takes. */
  runtimeSha256?: string;
}

export interface PilotDeploymentManifest {
  schema: string;
  status: "in-progress" | "complete";
  network: string;
  chainId: string;
  proofProfile: string;
  assurance: string;
  artifactManifestDigest: string;
  verificationKeySha256: string;
  verificationKeyCommitment: string;
  admins: { PilotCurrentRegistry: string; PilotRootCheckpoint: string };
  deployer: string;
  gitCommit: string;
  gitDirty: boolean;
  createdAt: string;
  updatedAt: string;
  contracts: Partial<Record<PilotContractName, PilotContractRecord>>;
}

export interface PilotDeployContext {
  ethers: HardhatEthers;
  /** Hardhat network name; selects the `networks.ts` entry and the manifest file name. */
  networkName: string;
  env: Record<string, string | undefined>;
  deploymentsDir: string;
  /** Asks the operator a question and returns the typed answer. */
  confirm: (prompt: string) => Promise<string>;
  log: (line: string) => void;
  /** Runs `git` with the given arguments in the repository and returns stdout. */
  git: (args: string[]) => string;
}

/**
 * Chain ID a permitted network name must report: local Hardhat networks and
 * `testnet: true` entries of `networks.ts`. Throws for every other name, without any RPC call.
 */
export function pilotChainId(networkName: string): bigint {
  const entry = Object.prototype.hasOwnProperty.call(NETWORKS, networkName) ? NETWORKS[networkName] : undefined;
  const expected = LOCAL_NETWORKS.includes(networkName) ? LOCAL_CHAIN_ID
    : entry?.testnet === true ? BigInt(entry.chainId) : undefined;
  if (expected === undefined) {
    throw new Error(`Refusing to deploy the pilot contracts to "${networkName}": only the local Hardhat networks and ` +
      `networks marked testnet: true in scripts/networks.ts are allowed. ${NO_MAINNET}`);
  }
  return expected;
}

/** A permitted network name, on the chain ID that name claims (a testnet name must not reach a mainnet RPC). */
export function assertPilotNetwork(networkName: string, chainId: bigint): void {
  const expected = pilotChainId(networkName);
  if (chainId !== expected) {
    throw new Error(`Refusing to deploy the pilot contracts: network "${networkName}" must be chain ${expected}, ` +
      `but the RPC reports chain ${chainId}. ${NO_MAINNET}`);
  }
}

/**
 * Reads the deployment inputs. Environment variables take precedence over the
 * optional JSON file named by `PILOT_DEPLOY_CONFIG`:
 *
 * | Environment              | JSON key          |
 * | ------------------------ | ----------------- |
 * | `PILOT_REGISTRY_ADMIN`   | `registryAdmin`   |
 * | `PILOT_CHECKPOINT_ADMIN` | `checkpointAdmin` |
 * | `PILOT_ARTIFACTS_DIR`    | `artifactsDir`    |
 * | `PILOT_MANIFEST_DIGEST`  | `manifestDigest`  |
 */
export function loadPilotConfig(env: Record<string, string | undefined>, networkName: string,
  deployer: string): PilotDeployConfig {
  const file: Record<string, unknown> = env.PILOT_DEPLOY_CONFIG
    ? JSON.parse(fs.readFileSync(env.PILOT_DEPLOY_CONFIG, "utf8")) : {};
  const allowDeployer = env.PILOT_ALLOW_DEPLOYER_ADMIN === "1";
  if (allowDeployer && !LOCAL_NETWORKS.includes(networkName)) {
    throw new Error("PILOT_ALLOW_DEPLOYER_ADMIN=1 is for the local Hardhat networks only; " +
      `set explicit admin addresses for "${networkName}"`);
  }
  const admin = (variable: string, key: string): string => {
    const value = env[variable] || file[key] || (allowDeployer ? deployer : undefined);
    if (typeof value !== "string" || !isAddress(value) || getAddress(value) === ZeroAddress) {
      throw new Error(`${variable} (or "${key}" in PILOT_DEPLOY_CONFIG) must be an explicit nonzero address. ` +
        "The deployer is never used for a privileged role unless PILOT_ALLOW_DEPLOYER_ADMIN=1 on a local network.");
    }
    return getAddress(value);
  };
  const registryAdmin = admin("PILOT_REGISTRY_ADMIN", "registryAdmin");
  const checkpointAdmin = admin("PILOT_CHECKPOINT_ADMIN", "checkpointAdmin");
  const artifactsDir = env.PILOT_ARTIFACTS_DIR || file.artifactsDir;
  if (typeof artifactsDir !== "string" || artifactsDir === "") {
    throw new Error('PILOT_ARTIFACTS_DIR (or "artifactsDir" in PILOT_DEPLOY_CONFIG) must name the pilot artifact bundle');
  }
  const manifestDigest = env.PILOT_MANIFEST_DIGEST || file.manifestDigest;
  if (typeof manifestDigest !== "string" || !/^[0-9a-f]{64}$/.test(manifestDigest)) {
    throw new Error('PILOT_MANIFEST_DIGEST (or "manifestDigest" in PILOT_DEPLOY_CONFIG) must be the reviewed ' +
      "artifact manifest digest: 64 lowercase hex characters, supplied by the operator and not read from the bundle");
  }
  return { registryAdmin, checkpointAdmin, artifactsDir, manifestDigest };
}

const MANIFEST_LITERALS: Record<string, string> = {
  schema_version: "clearproof-artifact-manifest-v1", protocol: "groth16", curve: "bn128",
  assurance: PILOT_ASSURANCE, transfer_schema: "clearproof-transfer-v1",
  context_schema: "clearproof-verification-context-v1",
};
const MANIFEST_KEYS = [...Object.keys(MANIFEST_LITERALS), "proof_profile", "policy_schema_digest",
  "source_bundle_digest", "compiler_sha256", "public_signals", "wasm", "r1cs", "proving_key", "verification_key",
].sort().join();

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * Digest of an artifact `manifest.json`, as `PilotArtifactManifest.digest` computes it
 * in `src/prover/pilot_artifacts.py`: SHA-256 over the domain, a zero byte and the
 * canonical record with the schema's fixed fields filled in. Rejects any profile other
 * than `pilot-transfer-v3`, any field the schema does not define and non-ASCII content.
 */
export function artifactManifestDigest(manifest: unknown): string {
  const record: Record<string, unknown> = { ...MANIFEST_LITERALS, ...(manifest as Record<string, unknown>) };
  const text = canonical(record);
  if (Object.keys(record).sort().join() !== MANIFEST_KEYS || record.proof_profile !== PILOT_PROFILE ||
      Object.entries(MANIFEST_LITERALS).some(([key, literal]) => record[key] !== literal) ||
      !/^[ -~]*$/.test(text)) {
    throw new Error(`Artifact manifest is not a ${PILOT_PROFILE} ${PILOT_ASSURANCE} manifest`);
  }
  return createHash("sha256").update("clearproof/artifact-manifest/v1\0" + text, "ascii").digest("hex");
}

const g1 = (point: string[]): G1 => [point[0], point[1]];
// snarkjs lists Fp2 coefficients as [c0, c1]; the EVM pairing precompile takes [c1, c0].
const g2 = (point: string[][]): G2 => [[point[0][1], point[0][0]], [point[1][1], point[1][0]]];

/** Loads the verification key from a bundle whose manifest matches the operator's pin. */
export function loadPilotArtifacts(directory: string, trustedDigest: string): PilotArtifacts {
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, "manifest.json"), "utf8"));
  if (artifactManifestDigest(manifest) !== trustedDigest) {
    throw new Error("Artifact manifest does not match the operator-pinned manifest digest");
  }
  const entry = manifest.verification_key;
  if (typeof entry?.filename !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(entry.filename)) {
    throw new Error("Artifact manifest names an invalid verification key file");
  }
  const raw = fs.readFileSync(path.join(directory, entry.filename));
  const verificationKeySha256 = createHash("sha256").update(raw).digest("hex");
  if (verificationKeySha256 !== entry.sha256 || raw.length !== entry.size) {
    throw new Error("Verification key file does not match the artifact manifest");
  }
  const vk = JSON.parse(raw.toString("utf8"));
  if (vk.protocol !== "groth16" || vk.curve !== "bn128" || vk.nPublic !== 8 ||
      !Array.isArray(vk.IC) || vk.IC.length !== 9) {
    throw new Error("Verification key is not an eight-signal Groth16 BN254 key");
  }
  const key: PilotVerificationKey = { alpha: g1(vk.vk_alpha_1), beta: g2(vk.vk_beta_2), gamma: g2(vk.vk_gamma_2),
    delta: g2(vk.vk_delta_2), ic: vk.IC.map(g1) };
  // Same value as PilotGroth16Verifier.verificationKeyCommitment: keccak256(abi.encode(key)).
  const verificationKeyCommitment = keccak256(AbiCoder.defaultAbiCoder().encode([KEY_TYPE], [key]));
  return { key, manifestDigest: trustedDigest, verificationKeySha256, verificationKeyCommitment };
}

const runtimeHashes = (code: string) => ({
  runtimeCodeHash: keccak256(code),
  runtimeSha256: createHash("sha256").update(Buffer.from(code.slice(2), "hex")).digest("hex"),
});

/**
 * Read-only check of a manifest against the chain: every recorded contract's runtime
 * code hash, the verifier's profile, assurance, manifest digest and key commitment,
 * the registry's verifier address and code-hash pin, and both admins.
 */
export async function verifyPilotDeployment(ethers: HardhatEthers, manifest: PilotDeploymentManifest): Promise<void> {
  const record = (name: PilotContractName): PilotContractRecord => {
    const found = manifest.contracts[name];
    if (!found?.runtimeCodeHash) throw new Error(`Manifest has no confirmed ${name} deployment`);
    return found;
  };
  const checks: [string, unknown, unknown][] = [];
  for (const name of PILOT_CONTRACTS) {
    const { address, runtimeCodeHash, runtimeSha256 } = record(name);
    const actual = runtimeHashes(await ethers.provider.getCode(address));
    checks.push([`${name} runtime code hash at ${address}`, actual.runtimeCodeHash, runtimeCodeHash],
      [`${name} runtime SHA-256 at ${address}`, actual.runtimeSha256, runtimeSha256]);
  }
  const verifierRecord = record("PilotGroth16Verifier");
  const verifier = await ethers.getContractAt("PilotGroth16Verifier", verifierRecord.address);
  const registry = await ethers.getContractAt("PilotCurrentRegistry", record("PilotCurrentRegistry").address);
  const checkpoint = await ethers.getContractAt("PilotRootCheckpoint", record("PilotRootCheckpoint").address);
  // Code hashes are compared first, so a view call is never trusted on unexpected code.
  const views: [string, () => Promise<unknown>, unknown][] = [
    ["verifier proofProfile", () => verifier.proofProfile(), manifest.proofProfile],
    ["verifier assurance", () => verifier.assurance(), manifest.assurance],
    ["verifier artifactManifestDigest", () => verifier.artifactManifestDigest(), manifest.artifactManifestDigest],
    ["verifier verificationKeyCommitment", () => verifier.verificationKeyCommitment(),
      manifest.verificationKeyCommitment],
    ["registry verifier", () => registry.verifier(), verifierRecord.address],
    ["registry verifierCodeHash", () => registry.verifierCodeHash(), verifierRecord.runtimeCodeHash],
    ["registry artifactManifestDigest", () => registry.artifactManifestDigest(), manifest.artifactManifestDigest],
    ["registry defaultAdmin", () => registry.defaultAdmin(), manifest.admins.PilotCurrentRegistry],
    ["checkpoint defaultAdmin", () => checkpoint.defaultAdmin(), manifest.admins.PilotRootCheckpoint],
  ];
  for (const [label, actual, expected] of checks) mismatch(label, actual, expected);
  for (const [label, read, expected] of views) mismatch(label, await read(), expected);
}

function mismatch(label: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) {
    throw new Error(`On-chain state does not match the manifest: ${label} is ${actual}, manifest records ${expected}. ` +
      "Nothing was deployed or overwritten; review the manifest and the chain before continuing.");
  }
}

/**
 * Deploys the three pilot contracts, or resumes and verifies an existing manifest.
 * Returns the manifest as written to `<deploymentsDir>/<network>-pilot.json`.
 */
export async function deployPilot(context: PilotDeployContext): Promise<PilotDeploymentManifest> {
  const { ethers, networkName, env, log } = context;
  pilotChainId(networkName); // Refuse a disallowed network name before contacting its RPC endpoint.
  const { chainId } = await ethers.provider.getNetwork();
  assertPilotNetwork(networkName, chainId);
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error(`No deployer account is configured for "${networkName}"`);
  const config = loadPilotConfig(env, networkName, deployer.address);
  const artifacts = loadPilotArtifacts(config.artifactsDir, config.manifestDigest);
  const manifestPath = path.join(context.deploymentsDir, `${networkName}-pilot.json`);

  const identity = {
    schema: PILOT_MANIFEST_SCHEMA, network: networkName, chainId: chainId.toString(),
    proofProfile: PILOT_PROFILE, assurance: PILOT_ASSURANCE,
    artifactManifestDigest: "0x" + artifacts.manifestDigest,
    verificationKeySha256: artifacts.verificationKeySha256,
    verificationKeyCommitment: artifacts.verificationKeyCommitment,
    admins: { PilotCurrentRegistry: config.registryAdmin, PilotRootCheckpoint: config.checkpointAdmin },
  };
  const resumed = fs.existsSync(manifestPath);
  const now = () => new Date().toISOString();
  let manifest: PilotDeploymentManifest;
  if (resumed) {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    for (const [field, expected] of Object.entries(identity)) {
      if (JSON.stringify((manifest as unknown as Record<string, unknown>)[field]) !== JSON.stringify(expected)) {
        throw new Error(`Existing manifest ${manifestPath} records a different deployment (${field}). It is never ` +
          "overwritten: review it, and move it aside deliberately before starting a new deployment.");
      }
    }
  } else {
    manifest = { ...identity, status: "in-progress", deployer: deployer.address,
      gitCommit: context.git(["rev-parse", "HEAD"]).trim(),
      gitDirty: context.git(["status", "--porcelain"]).trim() !== "",
      createdAt: now(), updatedAt: now(), contracts: {} };
  }
  const save = () => {
    manifest.updatedAt = now();
    fs.mkdirSync(context.deploymentsDir, { recursive: true });
    const temporary = `${manifestPath}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(temporary, JSON.stringify(manifest, null, 2) + "\n");
      fs.renameSync(temporary, manifestPath);
    } catch (error) {
      fs.rmSync(temporary, { force: true });
      throw error;
    }
  };
  /** Records the receipt and runtime code hashes of a deployment transaction already in the manifest. */
  const finalize = async (name: PilotContractName, entry: PilotContractRecord) => {
    const receipt = await ethers.provider.getTransactionReceipt(entry.deployTxHash);
    const code = receipt ? await ethers.provider.getCode(entry.address) : "0x";
    if (!receipt || receipt.status !== 1 || receipt.contractAddress?.toLowerCase() !== entry.address.toLowerCase() ||
        code === "0x") {
      throw new Error(`${name} deployment ${entry.deployTxHash} is recorded in ${manifestPath} but is not confirmed ` +
        `with code at ${entry.address}. Run this command again once it is mined; nothing was redeployed.`);
    }
    Object.assign(entry, { blockNumber: receipt.blockNumber, ...runtimeHashes(code) });
    save();
    log(`  ${name}: ${entry.address} (block ${entry.blockNumber}, tx ${entry.deployTxHash})`);
  };

  // Recorded contracts are checked against the chain before anything is sent.
  const missing: PilotContractName[] = [];
  for (const name of PILOT_CONTRACTS) {
    const entry = manifest.contracts[name];
    if (!entry) missing.push(name);
    else if (entry.runtimeCodeHash === undefined) await finalize(name, entry);
    else {
      mismatch(`${name} runtime code hash at ${entry.address}`,
        runtimeHashes(await ethers.provider.getCode(entry.address)).runtimeCodeHash, entry.runtimeCodeHash);
    }
  }

  if (missing.length > 0) {
    if (missing.includes("PilotGroth16Verifier") && manifest.contracts.PilotCurrentRegistry) {
      throw new Error(`Existing manifest ${manifestPath} records a registry without its verifier; ` +
        "a new verifier cannot be attached to it. Review the manifest.");
    }
    if (resumed) {
      const commit = context.git(["rev-parse", "HEAD"]).trim();
      if (manifest.deployer !== deployer.address || manifest.gitCommit !== commit) {
        throw new Error(`Existing manifest ${manifestPath} was started by ${manifest.deployer} at commit ` +
          `${manifest.gitCommit}; resume the remaining deployments with that account and commit ` +
          `(now ${deployer.address} at ${commit}).`);
      }
    }
    if (await ethers.provider.getBalance(deployer.address) === 0n) {
      throw new Error(`Deployer ${deployer.address} has no balance on "${networkName}"`);
    }
    log(`Pilot deployment (${PILOT_PROFILE}, assurance ${PILOT_ASSURANCE})`);
    log(`  network:           ${networkName} (chain ${chainId})`);
    log(`  deployer:          ${deployer.address}`);
    log(`  registry admin:    ${config.registryAdmin}`);
    log(`  checkpoint admin:  ${config.checkpointAdmin}`);
    log(`  manifest digest:   ${artifacts.manifestDigest}`);
    log(`  key commitment:    ${artifacts.verificationKeyCommitment}`);
    log(`  git commit:        ${manifest.gitCommit}${manifest.gitDirty ? " (uncommitted changes)" : ""}`);
    log(`  to deploy:         ${missing.join(", ")}`);
    log(`  manifest:          ${manifestPath}`);
    if (env.SKIP_CONFIRM !== "1" &&
        (await context.confirm('Type "deploy" to send these deployment transactions: ')).trim() !== "deploy") {
      throw new Error("Aborted: deployment was not confirmed; no transaction was sent.");
    }
    for (const name of missing) {
      const constructorArguments: unknown[] =
        name === "PilotGroth16Verifier" ? [artifacts.key, "0x" + artifacts.manifestDigest]
          : name === "PilotCurrentRegistry"
            ? [config.registryAdmin, (manifest.contracts.PilotGroth16Verifier as PilotContractRecord).address]
            : [config.checkpointAdmin];
      const factory = await ethers.getContractFactory(name, deployer);
      const contract = await factory.deploy(...constructorArguments);
      const entry: PilotContractRecord = { address: await contract.getAddress(),
        deployTxHash: contract.deploymentTransaction()!.hash, constructorArguments };
      // Persist the pending transaction first so an interrupted run resumes it instead of redeploying.
      manifest.contracts[name] = entry;
      manifest.status = "in-progress";
      save();
      await contract.waitForDeployment();
      await finalize(name, entry);
    }
  }

  await verifyPilotDeployment(ethers, manifest);
  if (manifest.status !== "complete") {
    manifest.status = "complete";
    save();
  }
  log(missing.length > 0 ? `Pilot deployment complete and verified. Saved to ${manifestPath}`
    : `Existing pilot deployment verified against ${manifestPath}; no transaction was sent.`);
  log("Publishers are not assigned: each admin must call setPublisher(tenant, publisher) per tenant.");
  return manifest;
}

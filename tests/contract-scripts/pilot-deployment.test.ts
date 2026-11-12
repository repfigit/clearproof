import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash } from 'crypto';
import { getAddress, keccak256 } from 'ethers';

vi.mock('fs', async original => {
  const actual = await original<typeof import('fs')>();
  return { ...actual, renameSync: vi.fn(actual.renameSync) };
});
import {
  artifactManifestDigest, assertPilotNetwork, deployPilot, loadPilotArtifacts, loadPilotConfig, pilotChainId,
  verifyPilotDeployment, type PilotDeployContext, type PilotDeploymentManifest,
} from '../../packages/contracts/scripts/pilot-deployment';

const address = (n: number) => getAddress('0x' + n.toString(16).padStart(40, '0'));
const DEPLOYER = address(0xd0), REGISTRY_ADMIN = address(0xa1), CHECKPOINT_ADMIN = address(0xa2);
const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest('hex');
const file = (filename: string) => ({ filename, sha256: '11'.repeat(32), size: 1 });
const G1 = ['1', '2', '1'];
const G2 = [['3', '4'], ['5', '6'], ['1', '0']];
const KEY = JSON.stringify({ protocol: 'groth16', curve: 'bn128', nPublic: 8, vk_alpha_1: G1, vk_beta_2: G2,
  vk_gamma_2: G2, vk_delta_2: G2, IC: Array(9).fill(G1) });
const baseManifest = () => ({
  proof_profile: 'pilot-transfer-v3', policy_schema_digest: '22'.repeat(32), source_bundle_digest: '33'.repeat(32),
  compiler_sha256: '44'.repeat(32),
  public_signals: ['projection_commitment', 'authorized_issuer_root', 'sanctions_root', 'authorization_nullifier',
    'evaluated_at', 'proof_expires_at', 'domain_chain_id', 'domain_registry'],
  wasm: file('pilot.wasm'), r1cs: file('pilot.r1cs'), proving_key: file('UNAPPROVED-development.zkey'),
  verification_key: { filename: 'verification-key.json', sha256: '55'.repeat(32), size: 1234 } as unknown,
});

let directory: string;
let bundle: string;
let deployments: string;
let manifestPath: string;
let digest: string;
let chain: ReturnType<typeof fakeChain>;
let logs: string[];
let prompts: string[];

function writeBundle(manifest: Record<string, unknown> = {}, key = KEY) {
  const value = { ...baseManifest(), verification_key: { filename: 'verification-key.json', sha256: sha256(key),
    size: Buffer.byteLength(key) }, ...manifest };
  fs.writeFileSync(path.join(bundle, 'verification-key.json'), key);
  fs.writeFileSync(path.join(bundle, 'manifest.json'), JSON.stringify(value));
  digest = artifactManifestDigest(value);
  return value;
}

/** In-memory stand-in for the injected Hardhat ethers object: no network, no keys. */
function fakeChain() {
  const state = {
    chainId: 31337n, balance: 1n, block: 0, count: 0, mine: true, networkReads: 0,
    signers: [{ address: DEPLOYER }] as { address: string }[],
    code: new Map<string, string>(), receipts: new Map<string, unknown>(),
    deployed: [] as string[], args: {} as Record<string, unknown[]>, addresses: {} as Record<string, string>,
    views: {} as Record<string, unknown>,
  };
  const view = (name: string, value: () => unknown) => async () => name in state.views ? state.views[name] : value();
  const contracts: Record<string, Record<string, () => Promise<unknown>>> = {
    PilotGroth16Verifier: {
      proofProfile: view('proofProfile', () => 'pilot-transfer-v3'),
      assurance: view('assurance', () => 'development-unapproved'),
      artifactManifestDigest: view('verifierDigest', () => state.args.PilotGroth16Verifier[1]),
      verificationKeyCommitment: view('commitment', () => loadPilotArtifacts(bundle, digest).verificationKeyCommitment),
    },
    PilotCurrentRegistry: {
      verifier: view('registryVerifier', () => state.args.PilotCurrentRegistry[1]),
      verifierCodeHash: view('pin', () => keccak256(state.code.get(state.addresses.PilotGroth16Verifier)!)),
      artifactManifestDigest: view('registryDigest', () => state.args.PilotGroth16Verifier[1]),
      defaultAdmin: view('registryAdmin', () => state.args.PilotCurrentRegistry[0]),
    },
    PilotRootCheckpoint: { defaultAdmin: view('checkpointAdmin', () => state.args.PilotRootCheckpoint[0]) },
  };
  const ethers = {
    provider: {
      getNetwork: async () => { state.networkReads += 1; return { chainId: state.chainId }; },
      getCode: async (target: string) => state.code.get(target) ?? '0x',
      getTransactionReceipt: async (hash: string) => state.receipts.get(hash) ?? null,
      getBalance: async () => state.balance,
    },
    getSigners: async () => state.signers,
    getContractAt: async (name: string) => contracts[name],
    getContractFactory: async (name: string, signer: unknown) => ({
      deploy: async (...args: unknown[]) => {
        expect(signer).toBe(state.signers[0]);
        const n = ++state.count, target = address(0x1000 + n), hash = '0x' + n.toString(16).padStart(64, '0');
        state.deployed.push(name); state.args[name] = args; state.addresses[name] = target;
        return {
          getAddress: async () => target,
          deploymentTransaction: () => ({ hash }),
          waitForDeployment: async () => {
            if (!state.mine) throw new Error('connection lost');
            state.code.set(target, '0x60' + n.toString(16).padStart(2, '0'));
            state.receipts.set(hash, { status: 1, contractAddress: target, blockNumber: ++state.block });
          },
        };
      },
    }),
  };
  return { state, ethers };
}

function context(env: Record<string, string | undefined> = {}, overrides: Partial<PilotDeployContext> = {}) {
  return {
    ethers: chain.ethers as unknown as PilotDeployContext['ethers'], networkName: 'hardhat', deploymentsDir: deployments,
    env: { PILOT_REGISTRY_ADMIN: REGISTRY_ADMIN, PILOT_CHECKPOINT_ADMIN: CHECKPOINT_ADMIN, PILOT_ARTIFACTS_DIR: bundle,
      PILOT_MANIFEST_DIGEST: digest, ...env },
    confirm: async (prompt: string) => { prompts.push(prompt); return ' deploy\n'; },
    log: (line: string) => { logs.push(line); },
    git: (args: string[]) => args[0] === 'rev-parse' ? COMMIT + '\n' : '',
    ...overrides,
  } satisfies PilotDeployContext;
}
const stored = (): PilotDeploymentManifest => JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const rewrite = (change: (manifest: any) => void) => {
  const manifest = stored(); change(manifest); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
};

beforeEach(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-pilot-deployment-'));
  bundle = path.join(directory, 'bundle');
  deployments = path.join(directory, 'nested', 'deployments');
  manifestPath = path.join(deployments, 'hardhat-pilot.json');
  fs.mkdirSync(bundle);
  writeBundle();
  chain = fakeChain(); logs = []; prompts = [];
});
afterEach(() => { fs.rmSync(directory, { recursive: true, force: true }); });

test('network guard allows only local networks and testnets on the chain they claim', () => {
  expect(() => assertPilotNetwork('hardhat', 31337n)).not.toThrow();
  expect(() => assertPilotNetwork('localhost', 31337n)).not.toThrow();
  for (const [name, id] of [['sepolia', 11155111n], ['base-sepolia', 84532n], ['arbitrum-sepolia', 421614n],
    ['polygon-amoy', 80002n], ['optimism-sepolia', 11155420n]] as const) {
    expect(() => assertPilotNetwork(name, id)).not.toThrow();
  }
  for (const [name, id] of [['ethereum', 1n], ['arbitrum', 42161n], ['base', 8453n], ['polygon', 137n],
    ['optimism', 10n], ['unlisted', 31337n], ['toString', 31337n], ['__proto__', 31337n]] as const) {
    expect(() => assertPilotNetwork(name, id)).toThrow(
      /only the local Hardhat networks and networks marked testnet: true.*assurance = "development-unapproved" keys, so a mainnet deployment is never correct\. There is no override\./);
  }
  expect(pilotChainId('polygon-amoy')).toBe(80002n);
  expect(() => pilotChainId('polygon')).toThrow(/no override/);
  // A testnet or local name pointed at another chain (for example a mainnet RPC URL) is refused too.
  expect(() => assertPilotNetwork('sepolia', 1n)).toThrow(/must be chain 11155111, but the RPC reports chain 1\. .*no override/);
  expect(() => assertPilotNetwork('localhost', 1n)).toThrow(/must be chain 31337, but the RPC reports chain 1\./);
});

test('configuration comes from explicit environment variables or the JSON file, environment first', () => {
  const configPath = path.join(directory, 'config.json');
  const fileConfig = { registryAdmin: REGISTRY_ADMIN.toLowerCase(), checkpointAdmin: CHECKPOINT_ADMIN,
    artifactsDir: '/from/file', manifestDigest: 'ab'.repeat(32) };
  fs.writeFileSync(configPath, JSON.stringify(fileConfig));
  expect(loadPilotConfig({ PILOT_DEPLOY_CONFIG: configPath }, 'sepolia', DEPLOYER)).toEqual(
    { ...fileConfig, registryAdmin: REGISTRY_ADMIN });
  expect(loadPilotConfig({ PILOT_DEPLOY_CONFIG: configPath, PILOT_REGISTRY_ADMIN: address(7),
    PILOT_CHECKPOINT_ADMIN: address(8), PILOT_ARTIFACTS_DIR: '/from/env', PILOT_MANIFEST_DIGEST: 'cd'.repeat(32) },
  'sepolia', DEPLOYER)).toEqual({ registryAdmin: address(7), checkpointAdmin: address(8), artifactsDir: '/from/env',
    manifestDigest: 'cd'.repeat(32) });
});

test('privileged roles are never defaulted to the deployer without the local opt-in', () => {
  const env = { PILOT_REGISTRY_ADMIN: REGISTRY_ADMIN, PILOT_CHECKPOINT_ADMIN: CHECKPOINT_ADMIN,
    PILOT_ARTIFACTS_DIR: bundle, PILOT_MANIFEST_DIGEST: digest };
  for (const network of ['hardhat', 'sepolia']) {
    expect(() => loadPilotConfig({ ...env, PILOT_REGISTRY_ADMIN: undefined }, network, DEPLOYER))
      .toThrow(/PILOT_REGISTRY_ADMIN \(or "registryAdmin" in PILOT_DEPLOY_CONFIG\) must be an explicit nonzero address/);
    expect(() => loadPilotConfig({ ...env, PILOT_CHECKPOINT_ADMIN: '' }, network, DEPLOYER))
      .toThrow(/PILOT_CHECKPOINT_ADMIN .*The deployer is never used for a privileged role/);
  }
  for (const bad of ['not-an-address', '0x' + '0'.repeat(40), REGISTRY_ADMIN.toLowerCase().replace('a', 'A') + '00']) {
    expect(() => loadPilotConfig({ ...env, PILOT_REGISTRY_ADMIN: bad }, 'sepolia', DEPLOYER)).toThrow(/PILOT_REGISTRY_ADMIN/);
  }
  const configPath = path.join(directory, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ registryAdmin: 7 }));
  expect(() => loadPilotConfig({ ...env, PILOT_REGISTRY_ADMIN: undefined, PILOT_DEPLOY_CONFIG: configPath }, 'sepolia',
    DEPLOYER)).toThrow(/PILOT_REGISTRY_ADMIN/);
  // The opt-in fills only unset admins, and only on a local network.
  expect(loadPilotConfig({ ...env, PILOT_REGISTRY_ADMIN: undefined, PILOT_ALLOW_DEPLOYER_ADMIN: '1' }, 'localhost',
    DEPLOYER)).toMatchObject({ registryAdmin: DEPLOYER, checkpointAdmin: CHECKPOINT_ADMIN });
  expect(() => loadPilotConfig({ ...env, PILOT_ALLOW_DEPLOYER_ADMIN: '1' }, 'sepolia', DEPLOYER))
    .toThrow(/PILOT_ALLOW_DEPLOYER_ADMIN=1 is for the local Hardhat networks only/);
  expect(() => loadPilotConfig({ ...env, PILOT_REGISTRY_ADMIN: undefined, PILOT_ALLOW_DEPLOYER_ADMIN: 'true' },
    'hardhat', DEPLOYER)).toThrow(/PILOT_REGISTRY_ADMIN/);
});

test('artifact bundle location and manifest pin are required operator inputs', () => {
  const env = { PILOT_REGISTRY_ADMIN: REGISTRY_ADMIN, PILOT_CHECKPOINT_ADMIN: CHECKPOINT_ADMIN,
    PILOT_ARTIFACTS_DIR: bundle, PILOT_MANIFEST_DIGEST: digest };
  const configPath = path.join(directory, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ artifactsDir: 5, manifestDigest: 5 }));
  expect(() => loadPilotConfig({ ...env, PILOT_ARTIFACTS_DIR: undefined }, 'hardhat', DEPLOYER)).toThrow(/PILOT_ARTIFACTS_DIR/);
  expect(() => loadPilotConfig({ ...env, PILOT_ARTIFACTS_DIR: undefined, PILOT_DEPLOY_CONFIG: configPath }, 'hardhat',
    DEPLOYER)).toThrow(/PILOT_ARTIFACTS_DIR/);
  expect(() => loadPilotConfig({ ...env, PILOT_MANIFEST_DIGEST: undefined, PILOT_DEPLOY_CONFIG: configPath }, 'hardhat',
    DEPLOYER)).toThrow(/PILOT_MANIFEST_DIGEST/);
  for (const bad of [undefined, '0x' + digest, digest.toUpperCase(), digest.slice(1)]) {
    expect(() => loadPilotConfig({ ...env, PILOT_MANIFEST_DIGEST: bad }, 'hardhat', DEPLOYER))
      .toThrow(/PILOT_MANIFEST_DIGEST .* 64 lowercase hex characters, supplied by the operator/);
  }
});

test('artifact manifest digest equals PilotArtifactManifest.digest and rejects other manifests', () => {
  // Known answer from src/prover/pilot_artifacts.py (PilotArtifactManifest.model_validate_json(...).digest).
  expect(artifactManifestDigest(baseManifest())).toBe('0cf6f86495b6e75a5e0de84d2944ef0220718730f20cc45397673e15eb77fc51');
  // Fields the schema fixes may be written out; they do not change the digest.
  expect(artifactManifestDigest({ ...baseManifest(), schema_version: 'clearproof-artifact-manifest-v1', curve: 'bn128' }))
    .toBe('0cf6f86495b6e75a5e0de84d2944ef0220718730f20cc45397673e15eb77fc51');
  expect(artifactManifestDigest({ ...baseManifest(), wasm: null })).toMatch(/^[0-9a-f]{64}$/);
  const { proof_profile: _profile, ...withoutProfile } = baseManifest();
  for (const bad of [null, [], withoutProfile, { ...baseManifest(), proof_profile: 'pilot-transfer-v2' },
    { ...baseManifest(), proof_profile: 'pilot-transfer-v1' }, { ...baseManifest(), assurance: 'production' },
    { ...baseManifest(), curve: 'bls12381' }, { ...baseManifest(), extra: 1 },
    { ...baseManifest(), compiler_sha256: 'café' }]) {
    expect(() => artifactManifestDigest(bad)).toThrow('Artifact manifest is not a pilot-transfer-v3 development-unapproved manifest');
  }
});

test('verification key is loaded only from a bundle matching the pin and its manifest entry', () => {
  const loaded = loadPilotArtifacts(bundle, digest);
  expect(loaded).toMatchObject({ manifestDigest: digest, verificationKeySha256: sha256(KEY) });
  expect(loaded.verificationKeyCommitment).toMatch(/^0x[0-9a-f]{64}$/);
  // snarkjs [c0, c1] becomes the precompile's [c1, c0].
  expect(loaded.key).toEqual({ alpha: ['1', '2'], beta: [['4', '3'], ['6', '5']], gamma: [['4', '3'], ['6', '5']],
    delta: [['4', '3'], ['6', '5']], ic: Array(9).fill(['1', '2']) });
  expect(() => loadPilotArtifacts(bundle, 'ab'.repeat(32))).toThrow('does not match the operator-pinned manifest digest');
  for (const entry of [null, { filename: 7 }, { filename: '../verification-key.json', sha256: sha256(KEY), size: KEY.length }]) {
    writeBundle({ verification_key: entry });
    expect(() => loadPilotArtifacts(bundle, digest)).toThrow('invalid verification key file');
  }
  writeBundle({ verification_key: { filename: 'verification-key.json', sha256: '00'.repeat(32), size: KEY.length } });
  expect(() => loadPilotArtifacts(bundle, digest)).toThrow('does not match the artifact manifest');
  writeBundle({ verification_key: { filename: 'verification-key.json', sha256: sha256(KEY), size: KEY.length + 1 } });
  expect(() => loadPilotArtifacts(bundle, digest)).toThrow('does not match the artifact manifest');
  const key = JSON.parse(KEY);
  for (const change of [{ protocol: 'plonk' }, { curve: 'bls12381' }, { nPublic: 16 }, { IC: 'none' },
    { IC: Array(17).fill(G1) }]) {
    writeBundle({}, JSON.stringify({ ...key, ...change }));
    expect(() => loadPilotArtifacts(bundle, digest)).toThrow('not an eight-signal Groth16 BN254 key');
  }
});

test('deploys in order with explicit admins, records pending transactions first and verifies', async () => {
  const manifest = await deployPilot(context());
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier', 'PilotCurrentRegistry', 'PilotRootCheckpoint']);
  const artifacts = loadPilotArtifacts(bundle, digest);
  expect(chain.state.args.PilotGroth16Verifier).toEqual([artifacts.key, '0x' + digest]);
  expect(chain.state.args.PilotCurrentRegistry).toEqual([REGISTRY_ADMIN, chain.state.addresses.PilotGroth16Verifier]);
  expect(chain.state.args.PilotRootCheckpoint).toEqual([CHECKPOINT_ADMIN]);
  expect(stored()).toEqual(JSON.parse(JSON.stringify(manifest)));
  expect(manifest).toMatchObject({
    schema: 'clearproof-pilot-deployment-v1', status: 'complete', network: 'hardhat', chainId: '31337',
    proofProfile: 'pilot-transfer-v3', assurance: 'development-unapproved', artifactManifestDigest: '0x' + digest,
    verificationKeySha256: sha256(KEY), verificationKeyCommitment: artifacts.verificationKeyCommitment,
    admins: { PilotCurrentRegistry: REGISTRY_ADMIN, PilotRootCheckpoint: CHECKPOINT_ADMIN },
    deployer: DEPLOYER, gitCommit: COMMIT, gitDirty: false,
  });
  const verifier = manifest.contracts.PilotGroth16Verifier!;
  expect(verifier).toEqual({ address: chain.state.addresses.PilotGroth16Verifier, deployTxHash: '0x' + '0'.repeat(63) + '1',
    constructorArguments: [artifacts.key, '0x' + digest], blockNumber: 1, runtimeCodeHash: keccak256('0x6001'),
    runtimeSha256: sha256(Buffer.from('6001', 'hex')) });
  expect(manifest.contracts.PilotRootCheckpoint).toMatchObject({ blockNumber: 3, constructorArguments: [CHECKPOINT_ADMIN] });
  expect(prompts).toEqual(['Type "deploy" to send these deployment transactions: ']);
  expect(logs.join('\n')).toContain(`git commit:        ${COMMIT}\n`);
  expect(logs.join('\n')).toContain('to deploy:         PilotGroth16Verifier, PilotCurrentRegistry, PilotRootCheckpoint');
  expect(logs.at(-2)).toBe(`Pilot deployment complete and verified. Saved to ${manifestPath}`);
  expect(logs.at(-1)).toContain('setPublisher');
  expect(fs.readdirSync(deployments)).toEqual(['hardhat-pilot.json']);
});

test('records a testnet deployment under its network name and flags uncommitted changes', async () => {
  chain.state.chainId = 11155111n;
  const manifest = await deployPilot(context({ SKIP_CONFIRM: '1' }, { networkName: 'sepolia',
    git: args => args[0] === 'rev-parse' ? COMMIT : ' M file\n' }));
  expect(prompts).toEqual([]);
  expect(manifest).toMatchObject({ network: 'sepolia', chainId: '11155111', gitDirty: true, status: 'complete' });
  expect(logs.join('\n')).toContain(`${COMMIT} (uncommitted changes)`);
  expect(fs.readdirSync(deployments)).toEqual(['sepolia-pilot.json']);
});

test('refuses before any transaction: network, deployer, configuration, balance and confirmation', async () => {
  const refused = async (run: Promise<unknown>, message: RegExp) => {
    await expect(run).rejects.toThrow(message);
    expect(chain.state.deployed).toEqual([]);
    expect(fs.existsSync(deployments)).toBe(false);
  };
  await refused(deployPilot(context({}, { networkName: 'ethereum' })), /mainnet deployment is never correct/);
  chain.state.chainId = 1n;
  await refused(deployPilot(context({}, { networkName: 'ethereum' })), /mainnet deployment is never correct/);
  // A mainnet name is refused before its RPC endpoint is contacted at all.
  expect(chain.state.networkReads).toBe(0);
  await refused(deployPilot(context({}, { networkName: 'sepolia' })), /must be chain 11155111/);
  expect(chain.state.networkReads).toBe(1);
  chain.state.chainId = 31337n;
  await refused(deployPilot(context({ PILOT_CHECKPOINT_ADMIN: undefined })), /PILOT_CHECKPOINT_ADMIN/);
  await refused(deployPilot(context({ PILOT_MANIFEST_DIGEST: 'ab'.repeat(32) })), /operator-pinned manifest digest/);
  await refused(deployPilot(context({}, { confirm: async () => 'y' })), /Aborted: deployment was not confirmed/);
  await refused(deployPilot(context({ SKIP_CONFIRM: 'yes' }, { confirm: async () => '' })), /Aborted/);
  chain.state.balance = 0n;
  await refused(deployPilot(context()), /has no balance on "hardhat"/);
  chain.state.signers = [];
  await refused(deployPilot(context()), /No deployer account is configured for "hardhat"/);
});

test('verifies a finished manifest again without transactions, prompts or writes', async () => {
  const first = await deployPilot(context());
  const written = fs.readFileSync(manifestPath);
  logs = []; prompts = [];
  // A different account and commit can verify: nothing is sent.
  chain.state.signers = [{ address: address(0xee) }];
  chain.state.balance = 0n;
  const again = await deployPilot(context({}, { git: () => { throw new Error('git is not needed'); } }));
  expect(again).toEqual(JSON.parse(JSON.stringify(first)));
  expect(chain.state.deployed).toHaveLength(3);
  expect(prompts).toEqual([]);
  expect(fs.readFileSync(manifestPath).equals(written)).toBe(true);
  expect(logs[0]).toBe(`Existing pilot deployment verified against ${manifestPath}; no transaction was sent.`);
});

test('an interrupted run resumes the recorded transaction instead of redeploying', async () => {
  chain.state.mine = false;
  await expect(deployPilot(context())).rejects.toThrow('connection lost');
  expect(stored()).toMatchObject({ status: 'in-progress', contracts: { PilotGroth16Verifier: {
    address: chain.state.addresses.PilotGroth16Verifier, deployTxHash: '0x' + '0'.repeat(63) + '1' } } });
  expect(stored().contracts.PilotGroth16Verifier).not.toHaveProperty('runtimeCodeHash');
  // Still unmined: refuse, and do not send it again.
  await expect(deployPilot(context())).rejects.toThrow(/is not confirmed with code at .* nothing was redeployed/);
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier']);
  const target = chain.state.addresses.PilotGroth16Verifier, hash = '0x' + '0'.repeat(63) + '1';
  for (const receipt of [{ status: 0, contractAddress: target, blockNumber: 9 },
    { status: 1, contractAddress: null, blockNumber: 9 }, { status: 1, contractAddress: address(5), blockNumber: 9 },
    { status: 1, contractAddress: target, blockNumber: 9 }]) {
    chain.state.receipts.set(hash, receipt);
    await expect(deployPilot(context())).rejects.toThrow(/is not confirmed with code/);
  }
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier']);
  // Mined later: the same transaction is finalized and the remaining two are deployed.
  chain.state.code.set(target, '0x6001');
  chain.state.mine = true;
  const manifest = await deployPilot(context());
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier', 'PilotCurrentRegistry', 'PilotRootCheckpoint']);
  expect(manifest.status).toBe('complete');
  expect(manifest.contracts.PilotGroth16Verifier).toMatchObject({ address: target, blockNumber: 9,
    runtimeCodeHash: keccak256('0x6001') });
  expect(chain.state.args.PilotCurrentRegistry).toEqual([REGISTRY_ADMIN, target]);
});

test('a pending last transaction is finalized without a prompt', async () => {
  await deployPilot(context());
  rewrite(manifest => {
    const { address: target, deployTxHash, constructorArguments } = manifest.contracts.PilotRootCheckpoint;
    manifest.contracts.PilotRootCheckpoint = { address: target, deployTxHash, constructorArguments };
    manifest.status = 'in-progress';
  });
  prompts = [];
  const manifest = await deployPilot(context({}, { git: () => { throw new Error('git is not needed'); } }));
  expect(prompts).toEqual([]);
  expect(chain.state.deployed).toHaveLength(3);
  expect(manifest).toMatchObject({ status: 'complete', contracts: { PilotRootCheckpoint: { blockNumber: 3 } } });
  expect(stored().status).toBe('complete');
});

test('resuming missing contracts needs the recorded deployer and commit', async () => {
  await deployPilot(context());
  rewrite(manifest => { delete manifest.contracts.PilotRootCheckpoint; manifest.status = 'in-progress'; });
  const written = fs.readFileSync(manifestPath);
  await expect(deployPilot(context({}, { git: () => 'f'.repeat(40) })))
    .rejects.toThrow(/resume the remaining deployments with that account and commit/);
  chain.state.signers = [{ address: address(0xee) }];
  await expect(deployPilot(context())).rejects.toThrow(/was started by .* at commit/);
  expect(chain.state.deployed).toHaveLength(3);
  expect(fs.readFileSync(manifestPath).equals(written)).toBe(true);
  chain.state.signers = [{ address: DEPLOYER }];
  const manifest = await deployPilot(context());
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier', 'PilotCurrentRegistry', 'PilotRootCheckpoint',
    'PilotRootCheckpoint']);
  expect(logs.join('\n')).toContain('to deploy:         PilotRootCheckpoint\n');
  expect(manifest.contracts.PilotRootCheckpoint!.address).toBe(chain.state.addresses.PilotRootCheckpoint);
});

test('refuses a manifest whose recorded code is not on chain, and never overwrites it', async () => {
  await deployPilot(context());
  const written = fs.readFileSync(manifestPath);
  const unchanged = () => {
    expect(chain.state.deployed).toHaveLength(3);
    expect(fs.readFileSync(manifestPath).equals(written)).toBe(true);
  };
  const registry = chain.state.addresses.PilotCurrentRegistry;
  const code = chain.state.code.get(registry)!;
  chain.state.code.set(registry, '0x00');
  await expect(deployPilot(context())).rejects.toThrow(
    /On-chain state does not match the manifest: PilotCurrentRegistry runtime code hash at .* Nothing was deployed or overwritten/);
  // A fresh local chain has no code at the recorded addresses.
  chain.state.code.clear();
  await expect(deployPilot(context())).rejects.toThrow(/PilotGroth16Verifier runtime code hash/);
  unchanged();
  chain.state.code = new Map(Object.entries({ [chain.state.addresses.PilotGroth16Verifier]: '0x6001', [registry]: code,
    [chain.state.addresses.PilotRootCheckpoint]: '0x6003' }));
  await deployPilot(context());
  // The registry must pin exactly the recorded verifier, and roles must match the manifest.
  for (const [view, value, message] of [['pin', '0x' + '00'.repeat(32), /registry verifierCodeHash/],
    ['registryVerifier', address(9), /registry verifier is/], ['assurance', 'production', /verifier assurance/],
    ['proofProfile', 'pilot-transfer-v2', /verifier proofProfile/], ['commitment', '0x00', /verificationKeyCommitment/],
    ['verifierDigest', '0x00', /verifier artifactManifestDigest/], ['registryDigest', '0x00', /registry artifactManifestDigest/],
    ['registryAdmin', DEPLOYER, /registry defaultAdmin/], ['checkpointAdmin', DEPLOYER, /checkpoint defaultAdmin/]] as const) {
    chain.state.views = { [view]: value };
    await expect(deployPilot(context())).rejects.toThrow(message);
  }
  unchanged();
});

test('refuses to reuse a manifest for a different configuration or an inconsistent record', async () => {
  await deployPilot(context());
  const written = fs.readFileSync(manifestPath);
  await expect(deployPilot(context({ PILOT_REGISTRY_ADMIN: address(9) })))
    .rejects.toThrow(/records a different deployment \(admins\)\. It is never overwritten/);
  const first = digest;
  writeBundle({ compiler_sha256: '99'.repeat(32) });
  await expect(deployPilot(context())).rejects.toThrow(/different deployment \(artifactManifestDigest\)/);
  digest = first;
  for (const [field, value] of [['schema', 'other'], ['chainId', '1'], ['network', 'localhost']] as const) {
    fs.writeFileSync(manifestPath, written);
    writeBundle();
    rewrite(manifest => { manifest[field] = value; });
    await expect(deployPilot(context())).rejects.toThrow(`records a different deployment (${field})`);
  }
  fs.writeFileSync(manifestPath, written);
  rewrite(manifest => { delete manifest.contracts.PilotGroth16Verifier; });
  await expect(deployPilot(context())).rejects.toThrow(/records a registry without its verifier/);
  expect(chain.state.deployed).toHaveLength(3);
});

test('read-only verification rejects a manifest without confirmed deployments', async () => {
  const manifest = await deployPilot(context());
  const ethers = chain.ethers as unknown as PilotDeployContext['ethers'];
  await expect(verifyPilotDeployment(ethers, manifest)).resolves.toBeUndefined();
  chain.state.code.set(chain.state.addresses.PilotRootCheckpoint, '0x6009');
  await expect(verifyPilotDeployment(ethers, manifest)).rejects.toThrow(/PilotRootCheckpoint runtime code hash/);
  const { runtimeCodeHash: _hash, ...pending } = manifest.contracts.PilotCurrentRegistry!;
  await expect(verifyPilotDeployment(ethers, { ...manifest, contracts: { ...manifest.contracts,
    PilotCurrentRegistry: pending } })).rejects.toThrow('Manifest has no confirmed PilotCurrentRegistry deployment');
  await expect(verifyPilotDeployment(ethers, { ...manifest, contracts: {} }))
    .rejects.toThrow('Manifest has no confirmed PilotGroth16Verifier deployment');
});

test('a failed manifest write leaves no temporary file and reports the failure', async () => {
  vi.mocked(fs.renameSync).mockImplementationOnce(() => { throw new Error('rename failed'); });
  await expect(deployPilot(context())).rejects.toThrow('rename failed');
  expect(fs.readdirSync(deployments)).toEqual([]);
  expect(chain.state.deployed).toEqual(['PilotGroth16Verifier']);
});

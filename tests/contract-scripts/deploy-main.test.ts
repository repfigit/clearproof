import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  readFileSync: vi.fn(), mkdirSync: vi.fn(), writeFileSync: vi.fn(), getSigners: vi.fn(),
  getContractFactory: vi.fn(), provider: { getNetwork: vi.fn(), getBalance: vi.fn() },
  keccak256: vi.fn(), toUtf8Bytes: vi.fn(), formatEther: vi.fn(), run: vi.fn(), prepare: vi.fn(),
  network: { name: 'hardhat' },
}));
vi.mock('fs', () => ({ readFileSync: mock.readFileSync, mkdirSync: mock.mkdirSync, writeFileSync: mock.writeFileSync }));
vi.mock('hardhat', () => ({ ethers: mock, run: mock.run, network: mock.network }));
vi.mock('../../packages/contracts/scripts/legacy-verifier', () => ({ prepareLegacyVerifier: mock.prepare }));
const keys = ['ETHERSCAN_API_KEY', 'BASESCAN_API_KEY', 'ARBISCAN_API_KEY', 'POLYGONSCAN_API_KEY', 'OPTIMISM_ETHERSCAN_API_KEY'];
let originalExit: typeof process.exitCode;
let config: { default: { tier2: number; tier3: number; tier4: number };
  jurisdictions: Record<string, { tier2: number; tier3: number; tier4: number }> };
let factories: Record<string, ReturnType<typeof vi.fn>>;
let seed: ReturnType<typeof vi.fn>;
let seedWait: ReturnType<typeof vi.fn>;
let grant: ReturnType<typeof vi.fn>;
let grantWait: ReturnType<typeof vi.fn>;
const activation = { status: 'pending-timelock', selector: 'selector', activateAfter: '99999999999999999999', name: 'legacy' };
class Exit extends Error {}
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks(); originalExit = process.exitCode;
  for (const key of [...keys, 'CLEARPROOF_DEPLOYMENTS_DIR']) vi.stubEnv(key, undefined);
  mock.network.name = 'hardhat';
  mock.getSigners.mockResolvedValue([{ address: 'deployer' }]);
  mock.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
  mock.provider.getBalance.mockResolvedValue(10n ** 18n);
  mock.formatEther.mockReturnValue('1.0');
  mock.toUtf8Bytes.mockImplementation(value => value);
  mock.keccak256.mockImplementation(value => `hash:${value}`);
  mock.prepare.mockResolvedValue({ router: { getAddress: vi.fn().mockResolvedValue('router') },
    verifier: { getAddress: vi.fn().mockResolvedValue('verifier') }, selector: 'selector', activation, timelockPeriod: 86400 });
  config = { default: { tier2: 10, tier3: 20, tier4: 30 },
    jurisdictions: { us: { tier2: 11, tier3: 21, tier4: 31 }, JP: { tier2: 12, tier3: 22, tier4: 32 } } };
  mock.readFileSync.mockImplementation(() => JSON.stringify(config));
  seedWait = vi.fn().mockResolvedValue(undefined);
  grantWait = vi.fn().mockResolvedValue(undefined);
  seed = vi.fn().mockResolvedValue({ wait: seedWait });
  grant = vi.fn().mockResolvedValue({ wait: grantWait });
  factories = {};
  for (const name of ['VASPRegistry', 'SanctionsOracle', 'ComplianceRegistry', 'SanctionsRootRelay']) {
    factories[name] = vi.fn().mockResolvedValue({ getAddress: vi.fn().mockResolvedValue(name),
      waitForDeployment: vi.fn().mockResolvedValue(undefined), setJurisdictionThresholds: seed, grantRole: grant });
  }
  mock.getContractFactory.mockImplementation(async name => ({ deploy: factories[name] }));
  mock.run.mockResolvedValue(undefined);
  vi.spyOn(process, 'exit').mockImplementation(() => { throw new Exit('captured exit'); });
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run(script: 'single' | 'multi') {
  if (script === 'single') await import('../../packages/contracts/scripts/deploy');
  else await import('../../packages/contracts/scripts/deploy-multichain');
  // Every external operation is an immediately settled test double. Let the
  // entrypoint's promise chain (including dynamic fs import) drain before checking.
  await vi.waitFor(() => expect(mock.writeFileSync.mock.calls.length + vi.mocked(console.error).mock.calls.length).toBeGreaterThan(0));
  await new Promise(resolve => setImmediate(resolve));
}

for (const script of ['single', 'multi'] as const) {
  test(`${script} seeds canonical thresholds before recording pending activation`, async () => {
    await run(script);
    expect(factories.VASPRegistry).toHaveBeenCalledWith('deployer');
    expect(factories.SanctionsOracle).toHaveBeenCalledWith('deployer', 'hash:initial-sanctions-root', 0);
    expect(factories.ComplianceRegistry).toHaveBeenCalledWith('router', 'selector', 'VASPRegistry', 'SanctionsOracle', 10, 20, 30);
    expect(seed.mock.calls).toEqual([[0x5553, 11, 21, 31], [0x4a50, 12, 22, 32]]);
    expect(seedWait).toHaveBeenCalledTimes(2);
    expect(seedWait.mock.invocationCallOrder[1]).toBeLessThan(mock.writeFileSync.mock.invocationCallOrder[0]);
    const [file, text] = mock.writeFileSync.mock.calls[0];
    expect(file).toContain('/deployments/hardhat.json');
    const record = JSON.parse(text);
    expect(record).toMatchObject({ network: 'hardhat', chainId: '31337', deployer: 'deployer', verifierActivation: activation });
    expect(Number.isFinite(Date.parse(record.timestamp))).toBe(true);
    expect(record.contracts).toEqual({ VerifierRouter: 'router', Groth16Verifier: 'verifier', VASPRegistry: 'VASPRegistry',
      SanctionsOracle: 'SanctionsOracle', ComplianceRegistry: 'ComplianceRegistry',
      ...(script === 'multi' ? { SanctionsRootRelay: 'SanctionsRootRelay' } : {}) });
    if (script === 'multi') {
      expect(factories.SanctionsRootRelay).toHaveBeenCalledWith('deployer', 'SanctionsOracle');
      expect(grant).toHaveBeenCalledWith('hash:ORACLE_ROLE', 'SanctionsRootRelay');
      expect(grantWait.mock.invocationCallOrder[0]).toBeLessThan(mock.writeFileSync.mock.invocationCallOrder[0]);
    }
    expect(mock.run).not.toHaveBeenCalled();
  });
  test(`${script} respects an explicit output directory and empty override table`, async () => {
    vi.stubEnv('CLEARPROOF_DEPLOYMENTS_DIR', '/synthetic/deployments');
    config.jurisdictions = {};
    await run(script);
    expect(mock.mkdirSync).toHaveBeenCalledWith('/synthetic/deployments', { recursive: true });
    expect(mock.writeFileSync).toHaveBeenCalledWith('/synthetic/deployments/hardhat.json', expect.any(String));
    expect(seed).not.toHaveBeenCalled();
  });
  test(`${script} rejects malformed jurisdiction keys without publishing a record`, async () => {
    config.jurisdictions = { USA: config.jurisdictions.us };
    await run(script);
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: 'Jurisdiction code must be alpha-2: USA' }));
    expect(mock.writeFileSync).not.toHaveBeenCalled();
  });
  test.each(['deploy', 'seed', 'confirmation', 'write'])(`${script} propagates %s failure`, async stage => {
    const error = new Error(`${stage} failed`);
    if (stage === 'deploy') factories.VASPRegistry.mockRejectedValue(error);
    else if (stage === 'seed') seed.mockRejectedValue(error);
    else if (stage === 'confirmation') seedWait.mockRejectedValue(error);
    else mock.writeFileSync.mockImplementation(() => { throw error; });
    await run(script);
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(error);
    if (stage !== 'write') expect(mock.writeFileSync).not.toHaveBeenCalled();
  });
  test.each(['hardhat', 'localhost'])(`${script} avoids explorer calls on %s even with credentials`, async network => {
    mock.network.name = network;
    vi.stubEnv('ETHERSCAN_API_KEY', 'synthetic');
    await run(script);
    expect(mock.run).not.toHaveBeenCalled();
  });
  test(`${script} skips explorer calls on an unconfigured remote network`, async () => {
    mock.network.name = 'sepolia';
    await run(script);
    expect(mock.run).not.toHaveBeenCalled();
  });
  test.each(['ETHERSCAN_API_KEY', 'BASESCAN_API_KEY'])(`${script} verifies constructor arguments using %s`, async key => {
    mock.network.name = key === 'ETHERSCAN_API_KEY' ? 'sepolia' : 'base';
    vi.stubEnv(key, 'synthetic');
    await run(script);
    expect(mock.run).toHaveBeenCalledTimes(script === 'single' ? 5 : 6);
    expect(mock.run).toHaveBeenCalledWith('verify:verify', { address: 'router', constructorArguments: [86400] });
    expect(mock.run).toHaveBeenCalledWith('verify:verify', { address: 'verifier', constructorArguments: [] });
    expect(mock.run).toHaveBeenCalledWith('verify:verify', { address: 'ComplianceRegistry',
      constructorArguments: ['router', 'selector', 'VASPRegistry', 'SanctionsOracle', 10, 20, 30] });
  });
  test.each([new Error('x'.repeat(180)), {}])(`${script} preserves deployment after explorer failure %#`, async error => {
    mock.network.name = 'sepolia';
    vi.stubEnv('ETHERSCAN_API_KEY', 'synthetic');
    mock.run.mockRejectedValue(error);
    await run(script);
    expect(mock.writeFileSync).toHaveBeenCalledOnce();
    expect(console.error).not.toHaveBeenCalled();
    expect(mock.run).toHaveBeenCalledTimes(script === 'single' ? 1 : 6);
    if (script === 'single') {
      expect(console.log).toHaveBeenCalledWith('Verification failed (can retry later):',
        error instanceof Error ? 'x'.repeat(100) : undefined);
    } else {
      expect(console.log).toHaveBeenCalledWith('  ✗ router: ' + (error instanceof Error ? 'x'.repeat(80) : 'undefined'));
    }
    expect(process.exitCode).toBe(originalExit);
  });
}

test('multi refuses to deploy with an empty balance', async () => {
  mock.provider.getBalance.mockResolvedValue(0n);
  await run('multi');
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(mock.prepare).not.toHaveBeenCalled();
  expect(mock.writeFileSync).not.toHaveBeenCalled();
});

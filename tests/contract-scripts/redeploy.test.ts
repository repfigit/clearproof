import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  existsSync: vi.fn(), readFileSync: vi.fn(), writeFileSync: vi.fn(), renameSync: vi.fn(), rmSync: vi.fn(), getSigners: vi.fn(),
  provider: { getNetwork: vi.fn(), getBalance: vi.fn(), getBlock: vi.fn() },
  getContractAt: vi.fn(), getContractFactory: vi.fn(), id: vi.fn(), ZeroAddress: 'zero',
}));
vi.mock('fs', () => ({ existsSync: mock.existsSync, readFileSync: mock.readFileSync, writeFileSync: mock.writeFileSync, renameSync: mock.renameSync, rmSync: mock.rmSync }));
vi.mock('hardhat', () => ({ ethers: mock }));
let stored: any;
let staged: any;
let time: number;
let registered: string;
let info: { active: boolean; verifier: string };
let selected: string;
let deploy: ReturnType<typeof vi.fn>;
let router: Record<string, ReturnType<typeof vi.fn>>;
let registry: Record<string, ReturnType<typeof vi.fn>>;
let finish: () => void;
let originalExit: typeof process.exitCode;
const tx = () => ({ wait: vi.fn().mockResolvedValue(undefined) });
beforeEach(() => {
  vi.resetAllMocks(); vi.resetModules();
  originalExit = process.exitCode;
  vi.stubEnv('HARDHAT_NETWORK', undefined);
  stored = { chainId: '31337', contracts: { VerifierRouter: 'router', ComplianceRegistry: 'registry',
    Groth16Verifier: 'old', VASPRegistry: 'vasp', SanctionsOracle: 'oracle' }, previous: { marker: 'preserved' } };
  time = 100; registered = 'zero'; selected = 'v1'; info = { active: false, verifier: 'zero' };
  mock.existsSync.mockReturnValue(true);
  mock.readFileSync.mockImplementation(() => JSON.stringify(stored));
  mock.writeFileSync.mockImplementation((_path, value) => { staged = JSON.parse(value); });
  mock.renameSync.mockImplementation(() => { stored = staged; });
  mock.getSigners.mockResolvedValue([{ address: 'deployer' }]);
  mock.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
  mock.provider.getBalance.mockResolvedValue(1n);
  mock.provider.getBlock.mockImplementation(async () => ({ timestamp: time }));
  mock.id.mockReturnValue('v2');
  deploy = vi.fn().mockResolvedValue({ waitForDeployment: vi.fn().mockResolvedValue(undefined),
    getAddress: vi.fn().mockResolvedValue('new') });
  mock.getContractFactory.mockResolvedValue({ deploy });
  router = {
    verifiers: vi.fn().mockImplementation(async () => info),
    pendingRegistrations: vi.fn().mockImplementation(async () => registered),
    timelocks: vi.fn().mockResolvedValue(200n),
    registerVerifier: vi.fn().mockImplementation(async (_selector, address) => { registered = address; return tx(); }),
    activateVerifier: vi.fn().mockImplementation(async () => {
      if (time < 200) throw new Error('timelock has not expired');
      info = { active: true, verifier: registered }; registered = 'zero'; return tx();
    }),
  };
  registry = { verifierRouter: vi.fn().mockResolvedValue('ROUTER'),
    verifierSelector: vi.fn().mockImplementation(async () => selected),
    setVerifierSelector: vi.fn().mockImplementation(async value => { selected = value; return tx(); }) };
  mock.getContractAt.mockImplementation(async name => name === 'VerifierRouter' ? router : registry);
  vi.spyOn(console, 'log').mockImplementation(() => finish());
  vi.spyOn(console, 'error').mockImplementation(() => finish());
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() {
  vi.resetModules();
  const done = new Promise<void>(resolve => { finish = resolve; });
  await import('../../packages/contracts/scripts/redeploy-verifier');
  await done;
}
async function prepare() {
  await run();
  expect(stored.pendingVerifierReplacement.verifier).toBe('new');
  expect(console.error).not.toHaveBeenCalled();
}

test('persists the new verifier, waits without resetting its timelock, then preserves rollback state', async () => {
  await prepare();
  expect(mock.renameSync.mock.calls[0][1]).toContain('/deployments/localhost.json');
  expect(mock.writeFileSync.mock.invocationCallOrder[0]).toBeLessThan(router.registerVerifier.mock.invocationCallOrder[0]);
  expect(stored.contracts.Groth16Verifier).toBe('old');
  expect(stored.pendingVerifierReplacement.activateAfter).toBe('200');
  expect(router.activateVerifier).not.toHaveBeenCalled();
  expect(registry.setVerifierSelector).not.toHaveBeenCalled();
  await run();
  expect(deploy).toHaveBeenCalledOnce();
  expect(router.registerVerifier).toHaveBeenCalledOnce();
  time = 200;
  await run();
  expect(router.activateVerifier).toHaveBeenCalledWith('v2', 'Groth16 BN254 v2');
  expect(registry.setVerifierSelector).toHaveBeenCalledWith('v2');
  expect(stored.contracts).toEqual({ VerifierRouter: 'router', ComplianceRegistry: 'registry', Groth16Verifier: 'new',
    VASPRegistry: 'vasp', SanctionsOracle: 'oracle' });
  expect(stored.previous).toMatchObject({ Groth16Verifier: 'old', verifierSelector: 'v1', marker: 'preserved' });
  expect(stored.pendingVerifierReplacement).toBeUndefined();
  expect(stored.verifierActivation).toMatchObject({ status: 'active', selector: 'v2', verifier: 'new' });
});

test('can activate immediately only when the actual chain timestamp permits it', async () => {
  vi.stubEnv('HARDHAT_NETWORK', 'selected-network');
  time = 200;
  await run();
  expect(stored.contracts.Groth16Verifier).toBe('new');
  expect(mock.renameSync.mock.calls[0][1]).toContain('/deployments/selected-network.json');
});

test('reuses the recorded verifier after registration fails', async () => {
  router.registerVerifier.mockRejectedValueOnce(new Error('registration failed'));
  await run();
  expect(stored.pendingVerifierReplacement.verifier).toBe('new');
  expect(process.exitCode).toBe(1);
  await run();
  expect(deploy).toHaveBeenCalledOnce();
  expect(router.registerVerifier).toHaveBeenCalledTimes(2);
});

test.each(['activation', 'selection'])('resumes after %s succeeded but the next step failed', async phase => {
  await prepare(); time = 200;
  if (phase === 'activation') registry.setVerifierSelector.mockRejectedValueOnce(new Error('selection failed'));
  else mock.writeFileSync.mockImplementationOnce((_path, value) => { staged = JSON.parse(value); })
    .mockImplementationOnce(() => { throw new Error('record failed'); });
  await run();
  expect(process.exitCode).toBe(1);
  expect(stored.pendingVerifierReplacement).toBeDefined();
  await run();
  expect(deploy).toHaveBeenCalledOnce();
  expect(router.activateVerifier).toHaveBeenCalledOnce();
  expect(registry.setVerifierSelector).toHaveBeenCalledTimes(phase === 'activation' ? 2 : 1);
  expect(stored.previous.Groth16Verifier).toBe('old');
});

test.each(['file', 'chain', 'router', 'registry', 'verifier', 'balance', 'router-binding'])(
  'rejects invalid %s before deployment', async problem => {
    if (problem === 'file') mock.existsSync.mockReturnValue(false);
    else if (problem === 'chain') stored.chainId = '1';
    else if (problem === 'router') delete stored.contracts.VerifierRouter;
    else if (problem === 'registry') delete stored.contracts.ComplianceRegistry;
    else if (problem === 'verifier') delete stored.contracts.Groth16Verifier;
    else if (problem === 'balance') mock.provider.getBalance.mockResolvedValue(0n);
    else registry.verifierRouter.mockResolvedValue('different-router');
    await run();
    expect(process.exitCode).toBe(1);
    expect(deploy).not.toHaveBeenCalled();
  },
);

test.each(['chainId', 'router', 'registry', 'selector', 'previousVerifier'])(
  'rejects mismatched pending %s before another transaction', async field => {
    await prepare();
    stored.pendingVerifierReplacement[field] = 'different';
    time = 200;
    await run();
    expect(process.exitCode).toBe(1);
    expect(router.activateVerifier).not.toHaveBeenCalled();
    expect(registry.setVerifierSelector).not.toHaveBeenCalled();
  },
);

test.each(['selector', 'pending', 'disabled', 'block'])('refuses unsafe or unavailable %s state', async state => {
  await prepare(); time = 200;
  if (state === 'selector') selected = 'unrelated';
  else if (state === 'pending') registered = 'another-verifier';
  else if (state === 'disabled') info = { active: false, verifier: 'new' };
  else mock.provider.getBlock.mockResolvedValue(null);
  await run();
  expect(process.exitCode).toBe(1);
  expect(router.activateVerifier).not.toHaveBeenCalled();
  expect(registry.setVerifierSelector).not.toHaveBeenCalled();
  expect(stored.contracts.Groth16Verifier).toBe('old');
});


test('keeps the prior record if atomic publication fails after selection, then resumes', async () => {
  await prepare(); time = 200;
  const publish = mock.renameSync.getMockImplementation()!;
  mock.renameSync.mockImplementationOnce(publish).mockImplementationOnce(() => { throw new Error('rename failed'); });
  await run();
  expect(process.exitCode).toBe(1);
  expect(stored.contracts.Groth16Verifier).toBe('old');
  expect(stored.pendingVerifierReplacement.verifier).toBe('new');
  expect(mock.rmSync).toHaveBeenCalledWith(expect.stringMatching(/\.tmp$/), { force: true });
  await run();
  expect(stored.contracts.Groth16Verifier).toBe('new');
  expect(router.activateVerifier).toHaveBeenCalledOnce();
  expect(registry.setVerifierSelector).toHaveBeenCalledOnce();
});

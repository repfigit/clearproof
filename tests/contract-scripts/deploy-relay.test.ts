import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  existsSync: vi.fn(), readFileSync: vi.fn(), writeFileSync: vi.fn(), getSigners: vi.fn(),
  provider: { getNetwork: vi.fn() }, getContractFactory: vi.fn(), getContractAt: vi.fn(),
  keccak256: vi.fn(), toUtf8Bytes: vi.fn(), run: vi.fn(),
}));
vi.mock('fs', () => ({ existsSync: mock.existsSync, readFileSync: mock.readFileSync, writeFileSync: mock.writeFileSync }));
vi.mock('hardhat', () => ({ ethers: mock, run: mock.run }));
let originalExit: typeof process.exitCode;
let done: Promise<void>;
let finish: () => void;
let deploy: ReturnType<typeof vi.fn>;
let receipt: ReturnType<typeof vi.fn>;
let oracle: { hasRole: ReturnType<typeof vi.fn>; grantRole: ReturnType<typeof vi.fn> };
class Exit extends Error { constructor(readonly code: number) { super('captured process exit'); } }

beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks();
  originalExit = process.exitCode;
  vi.stubEnv('HARDHAT_NETWORK', undefined);
  vi.stubEnv('ETHERSCAN_API_KEY', undefined);
  mock.getSigners.mockResolvedValue([{ address: 'deployer' }]);
  mock.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
  mock.existsSync.mockReturnValue(true);
  mock.readFileSync.mockReturnValue(JSON.stringify({ contracts: { SanctionsOracle: 'oracle', Existing: 'preserved' },
    network: 'local-record', timestamp: 'old-timestamp' }));
  deploy = vi.fn().mockResolvedValue({ waitForDeployment: vi.fn().mockResolvedValue(undefined),
    getAddress: vi.fn().mockResolvedValue('relay') });
  mock.getContractFactory.mockResolvedValue({ deploy });
  receipt = vi.fn().mockResolvedValue({ blockNumber: 42 });
  oracle = { hasRole: vi.fn().mockResolvedValue(false), grantRole: vi.fn().mockResolvedValue({ wait: receipt }) };
  mock.getContractAt.mockResolvedValue(oracle);
  mock.toUtf8Bytes.mockReturnValue('role-bytes');
  mock.keccak256.mockReturnValue('oracle-role');
  mock.run.mockResolvedValue(undefined);
  done = new Promise(resolve => { finish = resolve; });
  vi.spyOn(process, 'exit').mockImplementation(code => { throw new Exit(Number(code)); });
  vi.spyOn(console, 'error').mockImplementation(error => { if (typeof error !== 'string') finish(); });
  vi.spyOn(console, 'log').mockImplementation(message => {
    if (String(message).includes('✓ SanctionsRootRelay online')) finish();
  });
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() { await import('../../packages/contracts/scripts/deploy-relay'); await done; }

test('deploys, confirms the oracle role and preserves the deployment record', async () => {
  const before = Date.now();
  await run();
  expect(mock.getContractFactory).toHaveBeenCalledWith('SanctionsRootRelay');
  expect(deploy).toHaveBeenCalledWith('deployer', 'oracle');
  expect(mock.getContractAt).toHaveBeenCalledWith('SanctionsOracle', 'oracle');
  expect(mock.toUtf8Bytes).toHaveBeenCalledWith('ORACLE_ROLE');
  expect(mock.keccak256).toHaveBeenCalledWith('role-bytes');
  expect(oracle.hasRole).toHaveBeenCalledWith('oracle-role', 'relay');
  expect(oracle.grantRole).toHaveBeenCalledWith('oracle-role', 'relay');
  expect(receipt).toHaveBeenCalledOnce();
  expect(receipt.mock.invocationCallOrder[0]).toBeLessThan(mock.writeFileSync.mock.invocationCallOrder[0]);
  const [path, encoded] = mock.writeFileSync.mock.calls[0];
  expect(path).toContain('/deployments/localhost.json');
  const record = JSON.parse(encoded);
  expect(record.contracts).toEqual({ SanctionsOracle: 'oracle', Existing: 'preserved', SanctionsRootRelay: 'relay' });
  expect(record.network).toBe('local-record');
  expect(Date.parse(record.timestamp)).toBeGreaterThanOrEqual(before);
  expect(Date.parse(record.timestamp)).toBeLessThanOrEqual(Date.now());
  expect(mock.run).not.toHaveBeenCalled();
  expect(console.error).not.toHaveBeenCalled();
});

test('uses the configured network and avoids granting a role already held', async () => {
  vi.stubEnv('HARDHAT_NETWORK', 'configured-network');
  oracle.hasRole.mockResolvedValue(true);
  await run();
  expect(mock.readFileSync).toHaveBeenCalledWith(expect.stringContaining('/deployments/configured-network.json'), 'utf-8');
  expect(oracle.grantRole).not.toHaveBeenCalled();
  expect(mock.writeFileSync).toHaveBeenCalledOnce();
});

test('verifies the relay constructor on the explorer when configured', async () => {
  vi.stubEnv('ETHERSCAN_API_KEY', 'synthetic-test-value');
  await run();
  expect(mock.run).toHaveBeenCalledWith('verify:verify', { address: 'relay', constructorArguments: ['deployer', 'oracle'] });
  expect(console.log).toHaveBeenCalledWith('  verified.');
});

test.each([new Error('x'.repeat(180)), {}])('retains the deployed record if explorer verification fails %#', async error => {
  vi.stubEnv('ETHERSCAN_API_KEY', 'synthetic-test-value');
  mock.run.mockRejectedValue(error);
  await run();
  expect(mock.writeFileSync).toHaveBeenCalledOnce();
  expect(console.log).toHaveBeenCalledWith('  verification: ' + (error instanceof Error ? 'x'.repeat(120) : 'undefined'));
  expect(console.error).not.toHaveBeenCalled();
  expect(process.exitCode).toBe(originalExit);
});

test.each(['file', 'oracle'])('rejects missing deployment %s before creating a relay', async missing => {
  if (missing === 'file') mock.existsSync.mockReturnValue(false);
  else mock.readFileSync.mockReturnValue('{"contracts":{}}');
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(deploy).not.toHaveBeenCalled();
  expect(mock.writeFileSync).not.toHaveBeenCalled();
});

test.each(['deploy', 'role', 'confirmation', 'write'])('propagates %s failure without claiming the relay is online', async stage => {
  const error = new Error(`${stage} failed`);
  if (stage === 'deploy') deploy.mockRejectedValue(error);
  else if (stage === 'role') oracle.grantRole.mockRejectedValue(error);
  else if (stage === 'confirmation') receipt.mockRejectedValue(error);
  else mock.writeFileSync.mockImplementation(() => { throw error; });
  await run();
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(error);
  expect(vi.mocked(console.log).mock.calls.some(([value]) => String(value).includes('✓ SanctionsRootRelay online'))).toBe(false);
  if (stage !== 'write') expect(mock.writeFileSync).not.toHaveBeenCalled();
});

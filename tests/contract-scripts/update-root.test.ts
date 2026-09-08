import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({ existsSync: vi.fn(), readFileSync: vi.fn(), readdirSync: vi.fn(), statSync: vi.fn(),
  createInterface: vi.fn(), getSigners: vi.fn(), getContractAt: vi.fn(),
  provider: { getNetwork: vi.fn(), getBlock: vi.fn() } }));
vi.mock('fs', () => mock);
vi.mock('readline', () => ({ createInterface: mock.createInterface }));
vi.mock('hardhat', async () => {
  const { createRequire } = await import('node:module');
  const { zeroPadValue, toBeHex } = createRequire(new URL('../../packages/contracts/package.json', import.meta.url))('ethers');
  return { ethers: { ...mock, zeroPadValue, toBeHex } };
});
const root = '0x' + '00'.repeat(31) + '7b';
const old = '0x' + '00'.repeat(31) + '01';
const now = 1700000000;
let tree: any;
let oracle: Record<string, ReturnType<typeof vi.fn>>;
let receipt: ReturnType<typeof vi.fn>;
let close: ReturnType<typeof vi.fn>;
let answer: string;
let finish: () => void;
let originalExit: typeof process.exitCode;
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks(); originalExit = process.exitCode;
  vi.stubEnv('HARDHAT_NETWORK', undefined); vi.stubEnv('SKIP_CONFIRM', undefined);
  vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
  tree = { root: '123', leaf_count: 100, source_metadata: { fetch_timestamp: 'synthetic timestamp', sources: {
    sourceA: { fetched: true, addresses_found: 3 }, sourceB: { fetched: true }, sourceC: { fetched: false, error: 'unavailable' },
  } } };
  mock.existsSync.mockReturnValue(true);
  mock.readFileSync.mockImplementation((path: string) => JSON.stringify(path.includes('/deployments/')
    ? { contracts: { SanctionsOracle: 'oracle' } } : tree));
  mock.readdirSync.mockReturnValue(['local.json']);
  mock.statSync.mockReturnValue({ mtimeMs: now * 1000 });
  mock.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
  mock.provider.getBlock.mockResolvedValue({ timestamp: now });
  mock.getSigners.mockResolvedValue([{ address: 'operator' }]);
  receipt = vi.fn().mockResolvedValue({ blockNumber: 42, gasUsed: 123n });
  oracle = { currentRoot: vi.fn().mockResolvedValueOnce(old).mockResolvedValue(root),
    leafCount: vi.fn().mockResolvedValue(100n), lastUpdated: vi.fn().mockResolvedValue(BigInt(now - 7200)),
    isStale: vi.fn().mockResolvedValue(false), UPDATE_COOLDOWN: vi.fn().mockResolvedValue(3600n),
    updateRoot: vi.fn().mockResolvedValue({ hash: 'tx', wait: receipt }) };
  mock.getContractAt.mockResolvedValue(oracle);
  answer = 'yes'; close = vi.fn();
  mock.createInterface.mockReturnValue({ close, question: (_prompt: string, callback: (value: string) => void) => callback(answer) });
  vi.spyOn(process, 'exit').mockImplementation(() => { finish(); return undefined as never; });
  vi.spyOn(console, 'error').mockImplementation(value => { if (value instanceof Error) finish(); });
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(value => { if (String(value).startsWith('  Match:')) finish(); });
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() {
  const done = new Promise<void>(resolve => { finish = resolve; });
  await import('../../packages/contracts/scripts/update-sanctions-root'); await done;
}

test('confirms a synthetic update, encodes bytes32 and verifies its receipt and state', async () => {
  await run();
  expect(mock.getContractAt).toHaveBeenCalledWith('SanctionsOracle', 'oracle');
  expect(oracle.updateRoot).toHaveBeenCalledWith(root, 100);
  expect(close).toHaveBeenCalledOnce(); expect(receipt).toHaveBeenCalledOnce();
  expect(console.log).toHaveBeenCalledWith('  sourceA: ✓ 3 addresses');
  expect(console.log).toHaveBeenCalledWith('  sourceB: ✓ 0 addresses');
  expect(console.log).toHaveBeenCalledWith('  sourceC: ✗ unavailable');
  expect(console.error).not.toHaveBeenCalled();
});

test.each(['Y', 'YES', 'no', ''])('handles operator answer %j and closes the prompt', async response => {
  answer = response; await run();
  expect(close).toHaveBeenCalledOnce();
  expect(oracle.updateRoot).toHaveBeenCalledTimes(['Y', 'YES'].includes(response) ? 1 : 0);
});

test('uses explicit automation and network selection without opening a prompt', async () => {
  vi.stubEnv('SKIP_CONFIRM', '1'); vi.stubEnv('HARDHAT_NETWORK', 'synthetic-network');
  delete tree.source_metadata;
  await run();
  expect(mock.createInterface).not.toHaveBeenCalled();
  expect(mock.readFileSync).toHaveBeenCalledWith(expect.stringContaining('/deployments/synthetic-network.json'), 'utf-8');
  expect(console.log).toHaveBeenCalledWith('Tree built:       unknown');
});

test('warns about an old file without treating local file age as chain cooldown', async () => {
  mock.statSync.mockReturnValue({ mtimeMs: (now - 90000) * 1000 });
  tree.source_metadata = {};
  await run();
  expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('25.0 hours old'));
  expect(oracle.updateRoot).toHaveBeenCalledOnce();
});

test.each(['deployment', 'tree'])('rejects missing %s before submitting', async missing => {
  mock.existsSync.mockImplementation((path: string) => missing === 'deployment' ? !path.includes('/deployments/') : !path.endsWith('sanctions_tree.json'));
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(oracle.updateRoot).not.toHaveBeenCalled();
});

test('returns without prompting when root and count already match', async () => {
  oracle.currentRoot.mockReset().mockResolvedValue(root);
  await run();
  expect(process.exit).toHaveBeenCalledWith(0);
  expect(mock.createInterface).not.toHaveBeenCalled();
  expect(oracle.updateRoot).not.toHaveBeenCalled();
});

test('rejects a current cooldown before prompting', async () => {
  oracle.lastUpdated.mockResolvedValue(BigInt(now - 1));
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(mock.createInterface).not.toHaveBeenCalled();
});

test('uses the chain timestamp to recognize an expired cooldown despite host clock skew', async () => {
  oracle.lastUpdated.mockResolvedValue(BigInt(now - 1));
  mock.provider.getBlock.mockResolvedValue({ timestamp: now + 3600 });
  await run();
  expect(oracle.updateRoot).toHaveBeenCalledOnce();
});

test.each([{ count: 100n, next: 49, submits: false }, { count: 3n, next: 1, submits: true },
  { count: 0n, next: 0, submits: true }])('enforces the contract leaf floor for $count -> $next', async ({ count, next, submits }) => {
  oracle.leafCount.mockResolvedValueOnce(count).mockResolvedValue(BigInt(next));
  tree.leaf_count = next;
  await run();
  expect(oracle.updateRoot).toHaveBeenCalledTimes(submits ? 1 : 0);
});

test.each(['root', 'count'])('fails instead of reporting success when post-update %s differs', async field => {
  if (field === 'root') oracle.currentRoot.mockReset().mockResolvedValue(old);
  else oracle.leafCount.mockResolvedValueOnce(100n).mockResolvedValue(99n);
  await run();
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Post-update state') }));
});

test.each(['submit', 'receipt', 'rpc'])('propagates %s failure', async stage => {
  const error = new Error(`${stage} failed`);
  if (stage === 'submit') oracle.updateRoot.mockRejectedValue(error);
  else if (stage === 'receipt') receipt.mockRejectedValue(error);
  else oracle.currentRoot.mockReset().mockRejectedValue(error);
  await run();
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(error);
});


test.each([-1, 1.5, 2 ** 32, '100'])('rejects invalid uint32 leaf count %j before chain writes', async count => {
  tree.leaf_count = count;
  await run();
  expect(process.exitCode).toBe(1);
  expect(mock.getContractAt).not.toHaveBeenCalled();
});

test('rejects a missing chain timestamp before prompting', async () => {
  mock.provider.getBlock.mockResolvedValue(null);
  await run();
  expect(process.exitCode).toBe(1);
  expect(mock.createInterface).not.toHaveBeenCalled();
});

test('does not call equal roots synchronized when their counts differ', async () => {
  oracle.currentRoot.mockReset().mockResolvedValue(root);
  oracle.leafCount.mockResolvedValue(99n);
  await run();
  expect(process.exitCode).toBe(1);
  expect(oracle.updateRoot).not.toHaveBeenCalled();
});

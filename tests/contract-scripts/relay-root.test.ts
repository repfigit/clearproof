import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({ existsSync: vi.fn(), readFileSync: vi.fn(), readdirSync: vi.fn(), statSync: vi.fn(),
  createInterface: vi.fn(), JsonRpcProvider: vi.fn(), Contract: vi.fn(), Wallet: vi.fn(),
  zeroPadValue: vi.fn(), toBeHex: vi.fn(), formatEther: vi.fn(), getRpcUrl: vi.fn(),
  NETWORKS: { alpha: { name: 'alpha', chainId: 1 }, beta: { name: 'beta', chainId: 2 } } }));
vi.mock('fs', () => mock);
vi.mock('readline', () => ({ createInterface: mock.createInterface }));
vi.mock('ethers', () => ({ ethers: mock }));
vi.mock('../../packages/contracts/scripts/networks', () => mock);
let states: Record<string, any>;
let tree: any;
let records: Record<string, any>;
let originalExit: typeof process.exitCode;
let finish: () => void;
let answer: string;
let close: ReturnType<typeof vi.fn>;
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks(); originalExit = process.exitCode;
  vi.stubEnv('RELAY_NETWORKS', undefined); vi.stubEnv('SKIP_CONFIRM', undefined);
  vi.stubEnv('DEPLOYER_PRIVATE_KEY', 'synthetic-mocked-key');
  mock.existsSync.mockReturnValue(true);
  mock.readdirSync.mockReturnValue(['alpha.json', 'beta.json', 'README.md']);
  tree = { root: '123', leaf_count: 100 };
  records = {}; states = {};
  for (const [name, chainId] of [['alpha', 1], ['beta', 2]] as const) {
    records[name] = { chainId: String(chainId), contracts: { SanctionsOracle: `${name}-oracle`, SanctionsRootRelay: `${name}-relay` } };
    const receive = vi.fn().mockResolvedValue({ hash: `${name}-tx`, wait: vi.fn().mockResolvedValue({ blockNumber: 10, gasUsed: 99n }) });
    Object.assign(receive, { estimateGas: vi.fn().mockResolvedValue(100n) });
    states[name] = { oracle: { currentRoot: vi.fn().mockResolvedValueOnce('old-root').mockResolvedValue('new-root'),
      leafCount: vi.fn().mockResolvedValue(100n), isStale: vi.fn().mockResolvedValue(false) },
      provider: { getNetwork: vi.fn().mockResolvedValue({ chainId: BigInt(chainId) }),
        getFeeData: vi.fn().mockResolvedValue({ gasPrice: 2n }), destroy: vi.fn() }, relay: { receiveRoot: receive } };
  }
  mock.readFileSync.mockImplementation((path: string) => JSON.stringify(path.endsWith('sanctions_tree.json') ? tree
    : records[path.split('/').at(-1)!.replace('.json', '')]));
  mock.statSync.mockReturnValue({ mtimeMs: Date.now() });
  mock.getRpcUrl.mockImplementation(config => config.name);
  mock.JsonRpcProvider.mockImplementation(function (name: string) { return states[name].provider; });
  mock.Wallet.mockImplementation(function (_key: string, provider: unknown) { return { provider }; });
  mock.Contract.mockImplementation(function (address: string) {
    const [name, type] = address.split('-'); return states[name][type];
  });
  mock.toBeHex.mockReturnValue('hex'); mock.zeroPadValue.mockReturnValue('new-root'); mock.formatEther.mockReturnValue('cost');
  answer = 'yes'; close = vi.fn();
  mock.createInterface.mockReturnValue({ close, question: (_p: string, callback: (value: string) => void) => callback(answer) });
  vi.spyOn(process, 'exit').mockImplementation(() => { finish(); return undefined as never; });
  vi.spyOn(console, 'log').mockImplementation(message => {
    if (/succeeded, .*failed/.test(String(message))) finish();
  });
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(error => { if (error instanceof Error) finish(); });
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() {
  const done = new Promise<void>(resolve => { finish = resolve; });
  await import('../../packages/contracts/scripts/relay-sanctions-root'); await done;
  await new Promise(resolve => setImmediate(resolve));
}

test('relays every discovered target with confirmation and exact root/count arguments', async () => {
  await run();
  expect(vi.mocked(console.log).mock.calls.flat().join('\n')).not.toContain('✗');
  for (const name of ['alpha', 'beta']) {
    expect(states[name].relay.receiveRoot).toHaveBeenCalledWith('new-root', 100);
    expect(states[name].oracle.currentRoot).toHaveBeenCalledTimes(2);
    expect(states[name].oracle.currentRoot).toHaveBeenLastCalledWith({ blockTag: 10 });
    expect(states[name].provider.destroy).toHaveBeenCalledOnce();
  }
  expect(close).toHaveBeenCalledOnce();
  expect(console.log).toHaveBeenCalledWith('\n  2 succeeded, 0 failed');
});

test.each(['unknown', 'deployment', 'relay', 'rpc'])('reports a failed %s target instead of claiming synchronization', async failure => {
  vi.stubEnv('RELAY_NETWORKS', failure === 'unknown' ? 'unknown' : 'alpha');
  if (failure === 'deployment') mock.existsSync.mockImplementation((path: string) => !path.endsWith('alpha.json'));
  else if (failure === 'relay') delete records.alpha.contracts.SanctionsRootRelay;
  else if (failure === 'rpc') states.alpha.oracle.currentRoot.mockReset().mockRejectedValue(new Error('offline'));
  await run();
  expect(process.exitCode).toBe(1);
  expect(console.log).not.toHaveBeenCalledWith('\nAll networks are up to date. Nothing to do.');
});

test('keeps failed preflight targets in a mixed result', async () => {
  states.alpha.oracle.currentRoot.mockReset().mockRejectedValue(new Error('offline'));
  await run();
  expect(states.beta.relay.receiveRoot).toHaveBeenCalledOnce();
  expect(process.exitCode).toBe(1);
});

test.each(['root', 'count'])('fails a confirmed transaction when its resulting %s differs', async field => {
  vi.stubEnv('RELAY_NETWORKS', 'alpha');
  if (field === 'root') states.alpha.oracle.currentRoot.mockReset().mockResolvedValue('old-root');
  else states.alpha.oracle.leafCount.mockResolvedValueOnce(100n).mockResolvedValue(99n);
  await run();
  expect(process.exitCode).toBe(1);
});

test.each(['Y', 'YES', 'no', ''])('handles answer %j', async value => {
  answer = value; await run();
  expect(states.alpha.relay.receiveRoot).toHaveBeenCalledTimes(['Y', 'YES'].includes(value) ? 1 : 0);
  expect(close).toHaveBeenCalledOnce();
});

test('supports explicit target selection and automated confirmation', async () => {
  vi.stubEnv('RELAY_NETWORKS', ' beta '); vi.stubEnv('SKIP_CONFIRM', '1');
  states.beta.provider.getFeeData.mockResolvedValue({ gasPrice: null });
  mock.statSync.mockReturnValue({ mtimeMs: Date.now() - 90000000 });
  await run();
  expect(states.alpha.relay.receiveRoot).not.toHaveBeenCalled();
  expect(mock.createInterface).not.toHaveBeenCalled();
  expect(console.warn).toHaveBeenCalled();
});

test.each(['tree', 'directory', 'targets', 'key'])('rejects absent %s prerequisites', async missing => {
  if (missing === 'tree') mock.existsSync.mockImplementation((path: string) => !path.endsWith('sanctions_tree.json'));
  else if (missing === 'directory') mock.existsSync.mockImplementation((path: string) => path.endsWith('sanctions_tree.json'));
  else if (missing === 'targets') mock.readdirSync.mockReturnValue([]);
  else vi.stubEnv('DEPLOYER_PRIVATE_KEY', undefined);
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(states.alpha.relay.receiveRoot).not.toHaveBeenCalled();
});

test('skips genuinely synchronized targets without sending', async () => {
  for (const value of Object.values(states)) value.oracle.currentRoot.mockReset().mockResolvedValue('new-root');
  await run();
  expect(process.exit).toHaveBeenCalledWith(0);
  expect(states.alpha.relay.receiveRoot).not.toHaveBeenCalled();
});

test.each([{ reason: 'denied' }, new Error('x'.repeat(180)), {}])('reports transaction failures %# while continuing other targets', async error => {
  states.alpha.relay.receiveRoot.estimateGas.mockRejectedValue(error);
  await run();
  expect(process.exitCode).toBe(1);
  expect(states.beta.relay.receiveRoot).toHaveBeenCalledOnce();
});


test.each([-1, 1.5, 2 ** 32])('rejects invalid leaf count %j before constructing providers', async value => {
  tree.leaf_count = value; await run();
  expect(process.exitCode).toBe(1);
  expect(mock.JsonRpcProvider).not.toHaveBeenCalled();
});

test('deduplicates explicit targets and omits empty selections', async () => {
  vi.stubEnv('RELAY_NETWORKS', 'alpha, , alpha,'); await run();
  expect(states.alpha.relay.receiveRoot).toHaveBeenCalledOnce();
  expect(states.beta.relay.receiveRoot).not.toHaveBeenCalled();
});

test('ignores benchmark deployment records when discovering targets', async () => {
  mock.readdirSync.mockReturnValue(['alpha.json', 'alpha-bls-bench.json']); await run();
  expect(mock.JsonRpcProvider).toHaveBeenCalledTimes(1);
});

test.each(['chain', 'count', 'oracle', 'rpc-without-message'])('reports inconsistent preflight %s', async failure => {
  vi.stubEnv('RELAY_NETWORKS', 'alpha');
  if (failure === 'chain') states.alpha.provider.getNetwork.mockResolvedValue({ chainId: 999n });
  else if (failure === 'count') {
    states.alpha.oracle.currentRoot.mockReset().mockResolvedValue('new-root');
    states.alpha.oracle.leafCount.mockResolvedValue(99n);
  } else if (failure === 'oracle') delete records.alpha.contracts.SanctionsOracle;
  else states.alpha.oracle.currentRoot.mockReset().mockRejectedValue({});
  await run();
  expect(process.exitCode).toBe(1);
  expect(states.alpha.relay.receiveRoot).not.toHaveBeenCalled();
});

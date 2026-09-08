import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  existsSync: vi.fn(), readFileSync: vi.fn(), writeFileSync: vi.fn(), getSigners: vi.fn(),
  provider: { getNetwork: vi.fn(), getBalance: vi.fn() }, getContractFactory: vi.fn(), formatEther: vi.fn(),
}));
vi.mock('fs', () => ({ existsSync: mock.existsSync, readFileSync: mock.readFileSync, writeFileSync: mock.writeFileSync }));
vi.mock('hardhat', () => ({ ethers: mock }));
const proof = { pi_a: ['1', '2'], pi_b: [['3', '4'], ['5', '6']], pi_c: ['7', '8'] };
const signals = Array.from({ length: 16 }, (_, index) => String(index));
const q = BigInt('0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab');
let deploy: ReturnType<typeof vi.fn>;
let transaction: ReturnType<typeof vi.fn>;
let estimate: ReturnType<typeof vi.fn>;
let verify: ReturnType<typeof vi.fn>;
let done: Promise<void>;
let finish: () => void;
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks();
  vi.stubEnv('HARDHAT_NETWORK', undefined);
  mock.getSigners.mockResolvedValue([{ address: 'deployer' }]);
  mock.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
  mock.provider.getBalance.mockResolvedValue(1n);
  mock.formatEther.mockReturnValue('synthetic balance');
  mock.existsSync.mockReturnValue(true);
  mock.readFileSync.mockImplementation((path: string) => JSON.stringify(path.endsWith('proof_bls.json') ? proof : signals));
  estimate = vi.fn().mockResolvedValue(123456n);
  verify = vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false);
  transaction = vi.fn().mockReturnValue({ wait: vi.fn().mockResolvedValue({ gasUsed: 987654n }) });
  deploy = vi.fn().mockResolvedValue({ deploymentTransaction: transaction,
    getAddress: vi.fn().mockResolvedValue('verifier'), verifyProof: { estimateGas: estimate, staticCall: verify } });
  mock.getContractFactory.mockResolvedValue({ deploy });
  done = new Promise(resolve => { finish = resolve; });
  vi.spyOn(process, 'exit').mockImplementation(() => { finish(); return undefined as never; });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(message => {
    if (String(message).startsWith('ADR 0002 Open Task') || String(message).startsWith('Benchmark verified on this network')) finish();
  });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() { await import('../../packages/contracts/scripts/deploy-verifier-bls'); await done; }
const encode = (words: bigint[]) => '0x' + words.map(value => value.toString(16).padStart(128, '0')).join('');

test('encodes valid and negated-A proofs and records gas without claiming a Sepolia deployment', async () => {
  await run();
  expect(mock.getContractFactory).toHaveBeenCalledWith('Groth16VerifierBLS');
  expect(estimate).toHaveBeenCalledWith(encode([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]), signals);
  expect(verify.mock.calls).toEqual([
    [encode([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]), signals],
    [encode([1n, q - 2n, 3n, 4n, 5n, 6n, 7n, 8n]), signals],
  ]);
  const [path, encoded] = mock.writeFileSync.mock.calls[0];
  expect(path).toContain('/deployments/localhost-bls-bench.json');
  expect(JSON.parse(encoded)).toMatchObject({ address: 'verifier', network: 'localhost', chainId: '31337',
    deployGas: '987654', verifyGasEstimate: '123456', note: expect.stringContaining('not production') });
  expect(console.log).not.toHaveBeenCalledWith('ADR 0002 Open Task 1 (Sepolia confirmation) is now complete.');
  expect(process.exit).not.toHaveBeenCalled();
});

test('reports Sepolia confirmation only for the actual Sepolia chain ID', async () => {
  vi.stubEnv('HARDHAT_NETWORK', 'sepolia');
  mock.provider.getNetwork.mockResolvedValue({ chainId: 11155111n });
  await run();
  expect(console.log).toHaveBeenCalledWith('ADR 0002 Open Task 1 (Sepolia confirmation) is now complete.');
  expect(mock.writeFileSync.mock.calls[0][0]).toContain('/deployments/sepolia-bls-bench.json');
});

test('does not trust a Sepolia network label when the connected chain differs', async () => {
  vi.stubEnv('HARDHAT_NETWORK', 'sepolia');
  await run();
  expect(console.log).not.toHaveBeenCalledWith('ADR 0002 Open Task 1 (Sepolia confirmation) is now complete.');
});

test('handles providers without a deployment transaction receipt', async () => {
  transaction.mockReturnValue(undefined);
  await run();
  expect(JSON.parse(mock.writeFileSync.mock.calls[0][1])).not.toHaveProperty('deployGas');
  expect(process.exit).not.toHaveBeenCalled();
});

test.each(['proof_bls.json', 'public_bls.json'])('rejects missing %s before deployment', async name => {
  mock.existsSync.mockImplementation((path: string) => !path.endsWith(name));
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(deploy).not.toHaveBeenCalled();
  expect(mock.writeFileSync).not.toHaveBeenCalled();
});

test('rejects an unfunded account before deployment', async () => {
  mock.provider.getBalance.mockResolvedValue(0n);
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(deploy).not.toHaveBeenCalled();
});

test.each(['valid-rejected', 'tampered-accepted'])('does not publish a successful benchmark for %s', async result => {
  verify.mockReset();
  if (result === 'valid-rejected') verify.mockResolvedValue(false);
  else verify.mockResolvedValue(true);
  await run();
  expect(process.exit).toHaveBeenCalledWith(1);
  expect(mock.writeFileSync).not.toHaveBeenCalled();
  expect(verify).toHaveBeenCalledTimes(result === 'valid-rejected' ? 1 : 2);
});

test.each(['deploy', 'estimate', 'write'])('propagates %s errors as failure', async stage => {
  const error = new Error(`${stage} failed`);
  if (stage === 'deploy') deploy.mockRejectedValue(error);
  else if (stage === 'estimate') estimate.mockRejectedValue(error);
  else mock.writeFileSync.mockImplementation(() => { throw error; });
  await run();
  expect(console.error).toHaveBeenCalledWith(error);
  expect(process.exit).toHaveBeenCalledWith(1);
});

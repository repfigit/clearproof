import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const mock = vi.hoisted(() => ({
  existsSync: vi.fn(), readFileSync: vi.fn(), getContractAt: vi.fn(), getSigners: vi.fn(), id: vi.fn(),
}));
vi.mock('fs', () => ({ existsSync: mock.existsSync, readFileSync: mock.readFileSync }));
vi.mock('hardhat', () => ({ ethers: mock }));

const proof = { pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'] };
const signals = Array.from({ length: 16 }, (_, index) => String(index + 1));
let payload: unknown;
let exitCode: typeof process.exitCode;
let registry: { isVerified: ReturnType<typeof vi.fn>; proofs: ReturnType<typeof vi.fn>;
  verifyAndRecord: ReturnType<typeof vi.fn> };
let receiptWait: ReturnType<typeof vi.fn>;
let done: Promise<void>;

beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks();
  exitCode = process.exitCode;
  for (const name of ['COMPLIANCE_REGISTRY', 'TRANSFER_ID', 'HARDHAT_NETWORK', 'VASP_DID', 'VASP_DID_HASH', 'PROOF_PATH']) {
    vi.stubEnv(name, undefined);
  }
  payload = { proof, publicSignals: signals };
  mock.existsSync.mockReturnValue(true);
  mock.readFileSync.mockImplementation((path: string) => JSON.stringify(
    path.includes('/deployments/') ? { contracts: { ComplianceRegistry: 'registry-from-file' } } : payload,
  ));
  mock.id.mockImplementation((value: string) => `hash:${value}`);
  mock.getSigners.mockResolvedValue([{ address: 'signer' }]);
  receiptWait = vi.fn().mockResolvedValue({ blockNumber: 123, gasUsed: 456n });
  registry = {
    isVerified: vi.fn().mockResolvedValue(false),
    proofs: vi.fn().mockResolvedValue({ timestamp: 0n, proofHash: 'proof-hash' }),
    verifyAndRecord: vi.fn().mockResolvedValue({ hash: 'transaction-hash', wait: receiptWait }),
  };
  mock.getContractAt.mockResolvedValue(registry);
  let finish!: () => void;
  done = new Promise(resolve => { finish = resolve; });
  vi.spyOn(console, 'log').mockImplementation(message => {
    if (String(message).startsWith('Verified:') || String(message).startsWith('Gas used:')) finish();
  });
  vi.spyOn(console, 'error').mockImplementation(() => finish());
});
afterEach(() => { process.exitCode = exitCode; vi.restoreAllMocks(); vi.unstubAllEnvs(); });

async function run(script: 'check' | 'verify') {
  if (script === 'check') await import('../../packages/contracts/scripts/check-transfer');
  else await import('../../packages/contracts/scripts/verify-onchain');
  await done;
}

for (const script of ['check', 'verify'] as const) {
  test(`${script} resolves localhost deployment and default transfer identity`, async () => {
    await run(script);
    expect(mock.readFileSync).toHaveBeenCalledWith(expect.stringContaining('/deployments/localhost.json'), 'utf-8');
    expect(mock.getContractAt).toHaveBeenCalledWith('ComplianceRegistry', 'registry-from-file');
    expect(mock.id).toHaveBeenCalledWith('recipe-transfer-001');
    expect(console.error).not.toHaveBeenCalled();
  });
  test(`${script} uses explicit address, network and bytes32 without hashing transfer`, async () => {
    const transfer = '0x' + 'AB'.repeat(32);
    vi.stubEnv('TRANSFER_ID', transfer);
    vi.stubEnv('COMPLIANCE_REGISTRY', 'explicit-registry');
    vi.stubEnv('HARDHAT_NETWORK', 'configured-network');
    await run(script);
    expect(mock.getContractAt).toHaveBeenCalledWith('ComplianceRegistry', 'explicit-registry');
    expect(mock.id).not.toHaveBeenCalledWith(transfer);
    expect(console.log).toHaveBeenCalledWith('Network:              configured-network');
    expect(mock.readFileSync.mock.calls.some(([path]) => String(path).includes('/deployments/'))).toBe(false);
  });
  test(`${script} fails before RPC when deployment metadata is missing`, async () => {
    mock.existsSync.mockReturnValue(false);
    await run(script);
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Set COMPLIANCE_REGISTRY') }));
    expect(mock.getContractAt).not.toHaveBeenCalled();
  });
  test(`${script} reports malformed deployment metadata`, async () => {
    mock.readFileSync.mockReturnValue('{');
    await run(script);
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(expect.any(SyntaxError));
    expect(mock.getContractAt).not.toHaveBeenCalled();
  });
}

test('check prints the stored proof timestamp and hash when a record exists', async () => {
  vi.stubEnv('TRANSFER_ID', 'human-transfer');
  registry.isVerified.mockResolvedValue(true);
  registry.proofs.mockResolvedValue({ timestamp: 1711670400n, proofHash: 'stored-hash' });
  await run('check');
  expect(registry.isVerified).toHaveBeenCalledWith('hash:human-transfer');
  expect(registry.proofs).toHaveBeenCalledWith('hash:human-transfer');
  expect(console.log).toHaveBeenCalledWith('Verified:             true');
  expect(console.log).toHaveBeenCalledWith('Proof hash:           stored-hash');
  expect(console.log).toHaveBeenCalledWith('Recorded at:          2024-03-29T00:00:00.000Z');
});

test('check propagates an RPC rejection to a nonzero exit', async () => {
  registry.isVerified.mockRejectedValue(new Error('RPC unavailable'));
  await run('check');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: 'RPC unavailable' }));
  expect(registry.proofs).not.toHaveBeenCalled();
});

test.each([
  { proof, publicSignals: signals },
  { groth16_proof: proof, public_signals: signals },
  { compliance_proof: { proof, publicSignals: signals } },
  { compliance_proof: { groth16_proof: proof, public_signals: signals } },
])('verify accepts supported proof envelope %# and reorders G2 coordinates', async envelope => {
  payload = envelope;
  vi.stubEnv('PROOF_PATH', '/synthetic/proof.json');
  vi.stubEnv('VASP_DID_HASH', 'vasp-hash');
  await run('verify');
  expect(registry.verifyAndRecord).toHaveBeenCalledWith(
    'hash:recipe-transfer-001', [1n, 2n], [[4n, 3n], [6n, 5n]], [7n, 8n], signals.map(BigInt), 'vasp-hash',
  );
  expect(mock.readFileSync).toHaveBeenCalledWith('/synthetic/proof.json', 'utf-8');
  expect(receiptWait).toHaveBeenCalledOnce();
  expect(console.log).toHaveBeenCalledWith('Confirmed block:      123');
  expect(console.log).toHaveBeenCalledWith('Gas used:             456');
});

test('verify hashes an explicit VASP DID when no hash override is provided', async () => {
  vi.stubEnv('VASP_DID', 'did:web:synthetic.example');
  await run('verify');
  expect(mock.id).toHaveBeenCalledWith('did:web:synthetic.example');
});

test('verify rejects a missing default proof file before reading a signer', async () => {
  mock.existsSync.mockImplementation((path: string) => path.includes('/deployments/'));
  await run('verify');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Proof file not found:') }));
  expect(mock.getSigners).not.toHaveBeenCalled();
});

test.each([
  {}, { proof: {} }, { proof: { pi_a: [] } }, { proof: { pi_a: [], pi_b: [] } },
  { proof }, { proof, publicSignals: {} }, { compliance_proof: {} },
])('verify rejects malformed envelope %# before any transaction', async envelope => {
  payload = envelope;
  await run('verify');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Proof JSON must contain') }));
  expect(registry.verifyAndRecord).not.toHaveBeenCalled();
});

test.each([0, 15, 17])('verify rejects %i public signals', async count => {
  payload = { proof, publicSignals: Array(count).fill('1') };
  await run('verify');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: `Expected 16 public signals, got ${count}` }));
  expect(registry.verifyAndRecord).not.toHaveBeenCalled();
});

test.each(['signal', 'coordinate'])('verify rejects invalid integer %s before sending', async kind => {
  payload = kind === 'signal'
    ? { proof, publicSignals: ['invalid', ...signals.slice(1)] }
    : { proof: { ...proof, pi_a: ['invalid', '2'] }, publicSignals: signals };
  await run('verify');
  expect(process.exitCode).toBe(1);
  expect(registry.verifyAndRecord).not.toHaveBeenCalled();
});

test.each(['submit', 'receipt'])('verify exposes %s failure as a nonzero exit', async phase => {
  const error = new Error(`${phase} rejected`);
  if (phase === 'submit') registry.verifyAndRecord.mockRejectedValue(error);
  else receiptWait.mockRejectedValue(error);
  await run('verify');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(error);
});

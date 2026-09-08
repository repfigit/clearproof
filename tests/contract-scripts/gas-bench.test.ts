import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import thresholds from '../../config/jurisdiction_thresholds.json';
const mock = vi.hoisted(() => ({
  getSigners: vi.fn(), getContractFactory: vi.fn(), keccak256: vi.fn(), toUtf8Bytes: vi.fn(), id: vi.fn(),
  network: { name: 'hardhat' }, prepare: vi.fn(),
}));
vi.mock('hardhat', () => ({ ethers: mock, network: mock.network }));
vi.mock('../../packages/contracts/scripts/legacy-verifier', () => ({ prepareLegacyVerifier: mock.prepare }));
let finish: () => void;
let done: Promise<void>;
let originalExit: typeof process.exitCode;
let deploys: Record<string, ReturnType<typeof vi.fn>>;
let vasp: ReturnType<typeof contract> & { connect: ReturnType<typeof vi.fn>; grantRole: ReturnType<typeof vi.fn>;
  registerVASP: ReturnType<typeof vi.fn> };
let unauthorized: ReturnType<typeof vi.fn>;
function contract(address: string, gasUsed: bigint) {
  const result = { getAddress: vi.fn().mockResolvedValue(address), waitForDeployment: vi.fn(),
    deploymentTransaction: vi.fn().mockReturnValue({ wait: vi.fn().mockResolvedValue({ gasUsed }) }) };
  result.waitForDeployment.mockResolvedValue(result);
  return result;
}
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks();
  originalExit = process.exitCode;
  mock.network.name = 'hardhat';
  mock.getSigners.mockResolvedValue([{ address: 'deployer' }, { address: 'other' }]);
  mock.toUtf8Bytes.mockImplementation(value => `bytes:${value}`);
  mock.keccak256.mockImplementation(value => `hash:${value}`);
  mock.id.mockReturnValue('registrar-role');
  mock.prepare.mockResolvedValue({ router: { getAddress: vi.fn().mockResolvedValue('router') }, selector: 'selector' });
  unauthorized = vi.fn().mockRejectedValue(new Error('Unauthorized'));
  vasp = { ...contract('vasp', 222n), connect: vi.fn().mockReturnValue({ registerVASP: unauthorized }),
    grantRole: vi.fn().mockResolvedValue(undefined),
    registerVASP: vi.fn().mockResolvedValue({ wait: vi.fn().mockResolvedValue({ gasUsed: 444n }) }) };
  // Preserve the expanded VASP object's chainable deployment interface.
  vasp.waitForDeployment.mockResolvedValue(vasp);
  deploys = { SanctionsOracle: vi.fn().mockResolvedValue(contract('oracle', 111n)),
    VASPRegistry: vi.fn().mockResolvedValue(vasp), ComplianceRegistry: vi.fn().mockResolvedValue(contract('registry', 333n)) };
  mock.getContractFactory.mockImplementation(async name => ({ deploy: deploys[name] }));
  done = new Promise(resolve => { finish = resolve; });
  vi.spyOn(console, 'log').mockImplementation(message => {
    if (message === 'VASPRegistry.registerVASP gas:') finish();
  });
  vi.spyOn(console, 'error').mockImplementation(() => finish());
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); });
async function run() { await import('../../packages/contracts/scripts/gas-bench'); await done; }

test('reports deployment and successful registration gas after an unauthorized attempt', async () => {
  await run();
  expect(deploys.SanctionsOracle).toHaveBeenCalledWith('deployer', 'hash:bytes:root', 100);
  expect(deploys.ComplianceRegistry).toHaveBeenCalledWith('router', 'selector', 'vasp', 'oracle',
    thresholds.default.tier2, thresholds.default.tier3, thresholds.default.tier4);
  expect(unauthorized).toHaveBeenCalledWith('hash:bytes:did:test:123', 'other', 'US', 'https://example.com/.well-known/clearproof');
  expect(vasp.grantRole).toHaveBeenCalledWith('registrar-role', 'deployer');
  for (const [label, value] of [['SanctionsOracle deploy gas:', '111'], ['VASPRegistry deploy gas:', '222'],
    ['ComplianceRegistry deploy gas:', '333'], ['VASPRegistry.registerVASP gas:', '444']]) {
    expect(console.log).toHaveBeenCalledWith(label, value);
  }
  expect(console.log).toHaveBeenCalledWith('VASPRegistry.registerVASP revert (expected): custom error thrown');
  expect(console.error).not.toHaveBeenCalled();
});

test('rejects a non-ephemeral network before accessing signers or deploying', async () => {
  mock.network.name = 'sepolia';
  await run();
  expect(process.exitCode).toBe(1);
  expect(mock.getSigners).not.toHaveBeenCalled();
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: 'Gas benchmark requires the ephemeral Hardhat network' }));
});

test('propagates a deployment failure instead of reporting benchmark success', async () => {
  deploys.SanctionsOracle.mockRejectedValue(new Error('deployment failed'));
  await run();
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith(expect.objectContaining({ message: 'deployment failed' }));
  expect(deploys.VASPRegistry).not.toHaveBeenCalled();
});

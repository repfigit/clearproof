import { afterEach, beforeEach, expect, test, vi } from 'vitest';
const mock = vi.hoisted(() => ({
  ethers: { marker: 'hardhat-ethers' }, network: { name: 'hardhat' }, deployPilot: vi.fn(), execFileSync: vi.fn(),
  createInterface: vi.fn(), question: vi.fn(), close: vi.fn(),
}));
vi.mock('hardhat', () => ({ ethers: mock.ethers, network: mock.network }));
vi.mock('child_process', () => ({ execFileSync: mock.execFileSync }));
vi.mock('readline', () => ({ createInterface: mock.createInterface }));
vi.mock('../../packages/contracts/scripts/pilot-deployment', () => ({ deployPilot: mock.deployPilot }));
let originalExit: typeof process.exitCode;
beforeEach(() => {
  vi.resetModules(); vi.resetAllMocks(); originalExit = process.exitCode;
  vi.stubEnv('CLEARPROOF_DEPLOYMENTS_DIR', undefined);
  mock.network.name = 'hardhat';
  mock.createInterface.mockReturnValue({ question: mock.question, close: mock.close });
  mock.question.mockImplementation((_prompt, answer) => answer('deploy'));
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { process.exitCode = originalExit; vi.restoreAllMocks(); vi.unstubAllEnvs(); });
async function run() {
  await import('../../packages/contracts/scripts/deploy-pilot');
  await vi.waitFor(() => expect(mock.deployPilot).toHaveBeenCalled());
  await new Promise(resolve => setImmediate(resolve));
  return mock.deployPilot.mock.calls[0][0];
}

test('passes the selected Hardhat network, environment and default manifest directory', async () => {
  mock.network.name = 'sepolia';
  mock.deployPilot.mockResolvedValue({});
  mock.execFileSync.mockReturnValue('commit\n');
  const context = await run();
  expect(mock.deployPilot).toHaveBeenCalledOnce();
  expect(context.ethers).toBe(mock.ethers);
  expect(context.networkName).toBe('sepolia');
  expect(context.env).toBe(process.env);
  expect(context.deploymentsDir).toMatch(/packages\/contracts\/deployments$/);
  expect(await context.confirm('Type "deploy": ')).toBe('deploy');
  expect(mock.createInterface).toHaveBeenCalledWith({ input: process.stdin, output: process.stdout });
  expect(mock.question).toHaveBeenCalledWith('Type "deploy": ', expect.any(Function));
  expect(mock.close).toHaveBeenCalledOnce();
  context.log('line');
  expect(console.log).toHaveBeenCalledWith('line');
  expect(context.git(['rev-parse', 'HEAD'])).toBe('commit\n');
  expect(mock.execFileSync).toHaveBeenCalledWith('git', ['rev-parse', 'HEAD'],
    { cwd: expect.stringMatching(/packages\/contracts\/scripts$/), encoding: 'utf8' });
  expect(process.exitCode).toBe(originalExit);
  expect(console.error).not.toHaveBeenCalled();
});

test('honors the manifest directory override and reports a refusal as a failed run', async () => {
  vi.stubEnv('CLEARPROOF_DEPLOYMENTS_DIR', '/selected/deployments');
  const refusal = new Error('Refusing to deploy the pilot contracts to "ethereum"');
  mock.deployPilot.mockRejectedValue(refusal);
  const context = await run();
  expect(context.deploymentsDir).toBe('/selected/deployments');
  expect(console.error).toHaveBeenCalledWith(refusal);
  expect(process.exitCode).toBe(1);
});

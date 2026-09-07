import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ read: vi.fn(), request: vi.fn() }));
vi.mock('../src/api-client.js', async importOriginal => ({
  ...await importOriginal<typeof import('../src/api-client.js')>(), readPrivateInput: mocks.read, requestReport: mocks.request,
}));
const response = { schema_version: 'clearproof-policy-diff-v1', mode: 'counterfactual', cases: [] };
const bytes = Buffer.from('{"synthetic":"input"}');
let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('CLEARPROOF_API_TOKEN', 'synthetic-token');
  mocks.read.mockReset().mockResolvedValue(bytes);
  mocks.request.mockReset().mockResolvedValue(response);
  output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.exitCode = originalExitCode;
});
async function run(extra: string[] = [], origin = 'http://127.0.0.1:1234') {
  const { policyCommand } = await import('../src/commands/policy.js');
  await policyCommand.parseAsync(['diff', '--api-url', origin, ...extra], { from: 'user' });
}
describe('policy command authorization and output', () => {
  it.each([false, true])('selects the correct comparison endpoint (stored=%s)', async stored => {
    await run(stored ? ['--stored'] : []);
    expect(mocks.request).toHaveBeenCalledExactlyOnceWith('http://127.0.0.1:1234', 'synthetic-token',
      stored ? '/pilot/policy/diff/stored' : '/pilot/policy/diff', bytes);
    expect(output).toHaveBeenCalledExactlyOnceWith(JSON.stringify(response) + '\n');
    expect(errors).not.toHaveBeenCalled();
  });
  it('rejects missing tokens and unsafe destinations before reading stdin', async () => {
    vi.stubEnv('CLEARPROOF_API_TOKEN', undefined);
    await run();
    expect(mocks.read).not.toHaveBeenCalled();
    vi.stubEnv('CLEARPROOF_API_TOKEN', 'synthetic-token');
    await run([], 'http://external.example');
    expect(mocks.read).not.toHaveBeenCalled();
    expect(mocks.request).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
  it.each([
    { ...response, schema_version: 'wrong' }, { ...response, mode: 'enforcing' }, { ...response, cases: null },
  ])('rejects an unexpected report schema', async result => {
    mocks.request.mockResolvedValueOnce(result);
    await run();
    expect(output).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
  it('does not expose rejected response details', async () => {
    mocks.request.mockRejectedValueOnce(new Error('SYNTHETIC-PRIVATE-DETAIL'));
    await run();
    expect(errors).toHaveBeenCalledOnce();
    expect(errors.mock.calls.flat().join('')).not.toContain('SYNTHETIC-PRIVATE');
    expect(output).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const execute = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ execFile: execute }));
const valid = {
  status: 'development_unapproved', manifest_digest: 'a'.repeat(64), proof_profile: 'pilot-transfer-v2',
  checked_artifacts: ['wasm', 'r1cs', 'proving_key', 'verification_key'], production_eligible: false,
  policy_schema_supported: true, current_profile_supported: true,
};
let output: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  execute.mockReset().mockImplementation((_file, _args, _options, callback) => callback(null, JSON.stringify(valid)));
  output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = originalExitCode;
});
async function run(extra: string[] = [], digest = 'a'.repeat(64)) {
  const { doctorCommand } = await import('../src/commands/doctor.js');
  await doctorCommand.parseAsync(['--python', '/selected/python', '--artifacts', '/local/path;literal',
    '--trusted-manifest-digest', digest, ...extra], { from: 'user' });
}
const report = () => JSON.parse(output.mock.calls[0][0] as string);

describe('doctor CLI runtime boundary', () => {
  it('uses the explicit runtime without a shell and prints only approved fields', async () => {
    execute.mockImplementationOnce((_file, _args, _options, callback) => callback(null,
      JSON.stringify({ ...valid, extra: 'SYNTHETIC-PRIVATE' })));
    await run();
    expect(execute).toHaveBeenCalledExactlyOnceWith('/selected/python', [
      '-m', 'src.prover.pilot_artifacts', '/local/path;literal', '--trusted-manifest-digest', 'a'.repeat(64),
      '--mode', 'development',
    ], { timeout: 120000, maxBuffer: 65536, encoding: 'utf8', shell: false }, expect.any(Function));
    expect(report()).toEqual(valid);
    expect(process.exitCode).toBe(0);
  });
  it('preserves a sanitized production rejection with nonzero exit status', async () => {
    execute.mockImplementationOnce((_file, _args, _options, callback) => callback({ code: 1 },
      JSON.stringify({ status: 'rejected', reason: 'unapproved_artifacts', production_eligible: false, extra: 'private' })));
    await run(['--mode', 'production']);
    expect(report()).toEqual({ status: 'rejected', reason: 'unapproved_artifacts', production_eligible: false });
    expect(process.exitCode).toBe(1);
  });
  it.each(['ENOENT', 2])('sanitizes runtime error %s', async code => {
    execute.mockImplementationOnce((_file, _args, _options, callback) => callback({ code, message: 'private' }, 'private'));
    await run();
    expect(report()).toEqual({ status: 'rejected', reason: 'doctor_configuration_or_runtime_failed', production_eligible: false });
    expect(process.exitCode).toBe(1);
  });
  it.each([
    [['--mode', 'unsupported'], 'a'.repeat(64)],
    [[], 'bad-digest'],
    [[], 'z'.repeat(64)],
  ] as [string[], string][])('rejects invalid configuration without starting a process', async (args, digest) => {
    await run(args, digest);
    expect(execute).not.toHaveBeenCalled();
    expect(report().reason).toBe('doctor_configuration_or_runtime_failed');
    expect(process.exitCode).toBe(1);
  });
  it.each(['not-json', 'null', '{}', JSON.stringify({ ...valid, production_eligible: true })])(
    'rejects malformed or unsafe runtime output', async stdout => {
      execute.mockImplementationOnce((_file, _args, _options, callback) => callback(null, stdout));
      await run();
      expect(report().reason).toBe('doctor_configuration_or_runtime_failed');
      expect(process.exitCode).toBe(1);
    },
  );
});

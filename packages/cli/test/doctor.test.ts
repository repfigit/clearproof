import { expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { doctorReport } from '../src/commands/doctor.js';

const report = { status: 'development_unapproved', manifest_digest: 'a'.repeat(64), proof_profile: 'pilot-transfer-v2',
  checked_artifacts: ['wasm', 'r1cs', 'proving_key', 'verification_key'], production_eligible: false,
  policy_schema_supported: true, current_profile_supported: true };

it('keeps development assurance explicit and removes undeclared runtime fields', () => {
  expect(doctorReport(JSON.stringify({ ...report, path: 'PRIVATE-MARKER' }), 0)).toEqual(report);
  const denial = { status: 'rejected', reason: 'development_artifacts_forbidden', production_eligible: false };
  expect(doctorReport(JSON.stringify({ ...denial, secret: 'PRIVATE-MARKER' }), 1)).toEqual(denial);
  for (const changed of [{ ...report, production_eligible: true }, { ...report, checked_artifacts: [] },
    { ...report, manifest_digest: 'PRIVATE-MARKER' }, { ...report, proof_profile: 'unknown' }]) {
    expect(() => doctorReport(JSON.stringify(changed), 0)).toThrow();
  }
  expect(() => doctorReport(JSON.stringify(report), 1)).toThrow();
  expect(() => doctorReport('{invalid', 0)).toThrow();
  expect(() => doctorReport(JSON.stringify({ ...denial, reason: 'rejected\n' }), 1)).toThrow();
  expect(() => doctorReport(JSON.stringify({ ...report, manifest_digest: 'a'.repeat(64) + '\n' }), 0)).toThrow();
  expect(() => doctorReport(JSON.stringify({ ...denial, reason: '/private/path' }), 1)).toThrow();
});

it('built doctor reports missing runtimes without echoing paths or diagnostic text', async () => {
  const result = await promisify(execFile)(process.execPath, [resolve('dist/index.js'), 'doctor',
    '--python', '/missing/PRIVATE-MARKER', '--artifacts', '/private/artifacts',
    '--trusted-manifest-digest', 'a'.repeat(64)], { timeout: 10000 }).then(
    () => { throw new Error('Expected rejection'); },
    error => error,
  );
  expect(result.code).toBe(1);
  expect(result.stderr).toBe('');
  expect(JSON.parse(result.stdout)).toEqual({ status: 'rejected', reason: 'doctor_configuration_or_runtime_failed', production_eligible: false });
  expect(result.stdout).not.toContain('PRIVATE-MARKER');
});

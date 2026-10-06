// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const { verify } = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock('@clearproof/proof', () => ({ verifyProof: verify }));
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal();
  return { ...actual, readFile: vi.fn(actual.readFile) };
});
const originalArgv = process.argv;
let exit, log, error;
const baseline = { proofValid: true, valid: false, rejectionReasons: ['threshold_mismatch'] };
beforeEach(() => {
  vi.resetModules();
  verify.mockReset().mockResolvedValueOnce(baseline).mockResolvedValueOnce({ proofValid: false });
  process.argv = [process.execPath, 'inspect_example.mjs'];
  exit = vi.spyOn(process, 'exit').mockImplementation(() => undefined);
  log = vi.spyOn(console, 'log').mockImplementation(() => {});
  error = vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { process.argv = originalArgv; vi.restoreAllMocks(); });
const execute = () => import('../../scripts/inspect_example.mjs');

test('pairs the baseline and mutates the domain without altering the original statement', async () => {
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(0);
  expect(error).not.toHaveBeenCalled();
  const [original, altered] = verify.mock.calls;
  expect(original[0]).toEqual(altered[0]);
  expect(altered[1][12]).toBe(String(BigInt(original[1][12]) + 1n));
  expect(altered[1].filter((v, i) => v !== original[1][i])).toHaveLength(1);
  expect(original[2]).toMatch(/tests\/vectors\/compliance\/verification_key.json$/);
  const report = JSON.parse(log.mock.calls[0][0]);
  expect(report).toMatchObject({ cryptographic_valid: true, policy_accepted: false,
    tampered_pairing_rejected: true, authorization_consumed: false, production_eligible: false,
    scope: 'historical-legacy-fixture', assurance: 'development-unapproved', public_signal_count: 16 });
  expect(report).not.toHaveProperty('proof');
  expect(report).not.toHaveProperty('public_signals');
});

test.each([
  { ...baseline, proofValid: false },
  { ...baseline, valid: true },
  { ...baseline, rejectionReasons: [] },
  { ...baseline, rejectionReasons: ['other'] },
])('refuses an unexpected baseline (%#)', async result => {
  verify.mockReset().mockResolvedValueOnce(result);
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  expect(verify).toHaveBeenCalledOnce();
  expect(log).not.toHaveBeenCalled();
});

test('fails if the mutated statement is accepted by pairing', async () => {
  verify.mockReset().mockResolvedValueOnce(baseline).mockResolvedValueOnce({ proofValid: true });
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  expect(log).not.toHaveBeenCalled();
});

test('rejects arguments before reading or pairing', async () => {
  process.argv.push('unexpected-input');
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  expect(verify).not.toHaveBeenCalled();
});

test('rejects an altered verification key before pairing', async () => {
  const { readFile } = await import('node:fs/promises');
  readFile.mockResolvedValueOnce(Buffer.from('modified key'));
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  expect(verify).not.toHaveBeenCalled();
});

test('minimizes dependency and malformed-fixture errors', async () => {
  verify.mockReset().mockRejectedValue(new Error('synthetic private payload'));
  await execute();
  expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  expect(error.mock.calls.flat().join('')).not.toContain('private payload');
  expect(log).not.toHaveBeenCalled();
});

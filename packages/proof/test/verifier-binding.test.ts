import { expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as snarkjs from 'snarkjs';
import { verifyProof } from '../src/verifier.js';
import { SCALAR_FIELD_MODULUS } from '../src/field.js';

vi.mock('snarkjs', () => ({ groth16: { verify: vi.fn() } }));

it('requires both a successful pairing and matching verifier thresholds', async () => {
  const directory = resolve(__dirname, '../../../tests/vectors/compliance');
  const signals: string[] = JSON.parse(readFileSync(resolve(directory, 'public.json'), 'utf8'));
  signals.splice(8, 3, '250', '3000', '10000');
  vi.mocked(snarkjs.groth16.verify).mockResolvedValue(true);
  const accepted = await verifyProof({}, signals, resolve(directory, 'verification_key.json'), 'US');
  expect(accepted).toMatchObject({ valid: true, proofValid: true, thresholdsBound: true,
    jurisdictionMatchesVASP: true, rejectionReasons: [] });
  vi.mocked(snarkjs.groth16.verify).mockResolvedValue(false);
  const rejected = await verifyProof({}, signals, resolve(directory, 'verification_key.json'), 'US');
  expect(rejected).toMatchObject({ valid: false, thresholdsBound: true, rejectionReasons: ['groth16_invalid'] });
});

it('reports circuit outputs only for an accepted proof', async () => {
  const directory = resolve(__dirname, '../../../tests/vectors/compliance');
  const vkey = resolve(directory, 'verification_key.json');
  const signals: string[] = JSON.parse(readFileSync(resolve(directory, 'public.json'), 'utf8'));
  signals.splice(8, 3, '250', '3000', '10000');
  signals[0] = '1';
  signals[1] = '1';
  vi.mocked(snarkjs.groth16.verify).mockResolvedValue(true);
  expect(await verifyProof({}, signals, vkey)).toMatchObject({ valid: true, isCompliant: true, sarReviewFlag: true });
  vi.mocked(snarkjs.groth16.verify).mockResolvedValue(false);
  expect(await verifyProof({}, signals, vkey)).toMatchObject({ valid: false, isCompliant: false, sarReviewFlag: null });
});

it('rejects wrong-length or malformed public signals before snarkjs runs', async () => {
  vi.mocked(snarkjs.groth16.verify).mockClear();
  const good = Array(16).fill('0');
  const cases: Array<[unknown, string]> = [
    [Array(15).fill('0'), 'invalid_signal_count'],
    [Array(17).fill('0'), 'invalid_signal_count'],
    ['0'.repeat(16), 'invalid_signal_count'],
    [good.map((s, i) => (i === 8 ? 'abc' : s)), 'malformed_public_signals'],
    [good.map((s, i) => (i === 9 ? ' 250' : s)), 'malformed_public_signals'],
    [good.map((s, i) => (i === 3 ? '-1' : s)), 'malformed_public_signals'],
    [good.map((s, i) => (i === 3 ? '01' : s)), 'malformed_public_signals'],
    [good.map((s, i) => (i === 4 ? 4 : s)), 'malformed_public_signals'],
    [good.map((s, i) => (i === 5 ? SCALAR_FIELD_MODULUS.toString() : s)), 'malformed_public_signals'],
  ];
  for (const [signals, reason] of cases) {
    const result = await verifyProof({}, signals as string[], '/nonexistent/vkey.json', 'US');
    expect(result).toMatchObject({ valid: false, proofValid: false, thresholdsBound: false,
      jurisdictionMatchesVASP: false, jurisdiction: null, isCompliant: false, sarReviewFlag: null,
      rejectionReasons: [reason] });
  }
  const unverified = await verifyProof({}, [], '/nonexistent/vkey.json');
  expect(unverified.jurisdictionMatchesVASP).toBeNull();
  expect(snarkjs.groth16.verify).not.toHaveBeenCalled();
});

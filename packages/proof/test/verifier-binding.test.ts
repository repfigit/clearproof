import { expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as snarkjs from 'snarkjs';
import { verifyProof } from '../src/verifier.js';

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

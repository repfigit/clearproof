import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';
import { verifyProof } from '../src/verifier.js';

/**
 * Off-chain side of the verifier parity guarantee: the SAME committed vector
 * (tests/vectors/compliance/) must verify off-chain here via snarkjs AND
 * on-chain via packages/contracts/test/Verifier.test.ts against the deployed
 * Groth16Verifier. If either side fails, off-chain ≡ on-chain equivalence is
 * broken.
 */
const vectorDir = path.resolve(__dirname, '../../../tests/vectors/compliance');
const proofPath = path.join(vectorDir, 'proof.json');
const publicPath = path.join(vectorDir, 'public.json');
const vkeyPath = path.join(vectorDir, 'verification_key.json');
const vectorPresent = [proofPath, publicPath, vkeyPath].every((p) =>
  fs.existsSync(p),
);

describe.skipIf(!vectorPresent)('verifier parity vector (off-chain)', () => {
  const proof = JSON.parse(fs.readFileSync(proofPath, 'utf-8'));
  const publicSignals: string[] = JSON.parse(
    fs.readFileSync(publicPath, 'utf-8'),
  );

  it('verifies the committed compliance proof off-chain', async () => {
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    // The parity guarantee is cryptographic: the same proof must satisfy the
    // pairing check here and on-chain. `proofValid` is that check. `valid`
    // additionally requires policy binding, which this dev vector does not
    // satisfy — see the test below.
    expect(result.proofValid).toBe(true);
    expect(result.isCompliant).toBe(true);
    expect(result.sarReviewFlag).toBe(false);
  });

  it('documents that the committed vector does not satisfy threshold binding', async () => {
    // AIF-79. The vector claims jurisdiction "US" (signal 6 = 21843) but
    // carries thresholds 25000/300000/1000000, which match neither the US
    // table (250/3000/10000) nor any other entry — they are ~100x the real
    // values. This is precisely the defect AIF-79 fixes, preserved here in
    // the repo's own reference artifact: cryptographically valid, policy
    // meaningless.
    //
    // The vector cannot be regenerated without the proving key, which is not
    // committed (dev artifacts only; MANIFEST.json marks it devKeysOnly).
    // Regenerating it end-to-end is tracked in AIF-89; when that lands, this
    // test should flip to expecting `valid === true` and be deleted.
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    expect(result.thresholdsBound).toBe(false);
    expect(result.valid).toBe(false);
    expect(result.rejectionReasons).toContain('threshold_mismatch');
    expect(result.jurisdiction).toBe('US');
  });

  it('has the expected 16 public signals and compliant output values', () => {
    expect(publicSignals).toHaveLength(16);
    expect(publicSignals[0]).toBe('1'); // is_compliant
    expect(publicSignals[1]).toBe('0'); // sar_review_flag (tier 2 < 3)
  });

  it('rejects a tampered public signal', async () => {
    const tampered = [...publicSignals];
    tampered[4] = tampered[4] === '2' ? '3' : '2'; // flip amount_tier
    const result = await verifyProof(proof, tampered, vkeyPath);
    // Assert on the pairing check specifically: `valid` would now be false for
    // this vector regardless of tampering, so it can no longer evidence that
    // the signal flip was detected.
    expect(result.proofValid).toBe(false);
  });

  it('rejects a tampered proof element', async () => {
    const badProof = JSON.parse(JSON.stringify(proof));
    badProof.pi_a[0] = '1';
    const result = await verifyProof(badProof, publicSignals, vkeyPath);
    expect(result.valid).toBe(false);
  });
});

import * as snarkjs from 'snarkjs';
import fs from 'fs';
import type { VerifyResult } from './types.js';

/**
 * Verify a Groth16 ZK proof against the verification key.
 *
 * Reads the verification key from disk and delegates to
 * snarkjs.groth16.verify. Interprets the circuit's public outputs:
 *   - publicSignals[0] = is_compliant (1 = compliant)
 *   - publicSignals[1] = sar_review_flag (1 = needs SAR review)
 *
 * @param proof         - The Groth16 proof object
 * @param publicSignals - Array of public signal strings from the prover
 * @param vkeyPath      - Path to the verification key JSON file
 * @returns Verification result with compliance interpretation
 */
export async function verifyProof(
  proof: object,
  publicSignals: string[],
  vkeyPath: string,
): Promise<VerifyResult> {
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  return {
    valid,
    isCompliant: publicSignals[0] === '1',
    sarReviewFlag: publicSignals[1] === '1',
    publicSignals,
  };
}

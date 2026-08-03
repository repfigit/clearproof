import * as snarkjs from 'snarkjs';
import { promises as fs } from 'fs';
import type { VerifyResult } from './types.js';
import { decodeJurisdiction, thresholdsMatchJurisdiction, jurisdictionMatchesVASP as thresholdsJurisdictionMatchesVASP } from './thresholds.js';

/**
 * Verify a Groth16 ZK proof against the verification key.
 *
 * Reads the verification key from disk and delegates to
 * snarkjs.groth16.verify. Interprets the circuit's public outputs:
 *   - publicSignals[0] = is_compliant (1 = compliant)
 *   - publicSignals[1] = sar_review_flag (1 = needs SAR review)
 *
 * A cryptographically valid proof is not on its own a compliant one. The
 * circuit takes tier2/3/4_threshold (signals 8-10) as *unconstrained* public
 * inputs, so the prover chooses them: without checking them against a table
 * the verifier controls, a prover can submit an arbitrarily high
 * tier2_threshold and land any amount in tier 1, defeating both the tier
 * attestation and the SAR review flag. `valid` therefore reflects the pairing
 * check AND threshold binding, mirroring ComplianceRegistry.verifyAndRecord.
 *
 * @param proof         - The Groth16 proof object
 * @param publicSignals - Array of public signal strings from the prover
 * @param vkeyPath      - Path to the verification key JSON file
 * @param expectedJurisdiction - Expected jurisdiction code for the VASP (optional)
 * @returns Verification result with compliance interpretation
 */
export async function verifyProof(
  proof: object,
  publicSignals: string[],
  vkeyPath: string,
  expectedJurisdiction?: string
): Promise<VerifyResult> {
  const vkey = JSON.parse(await fs.readFile(vkeyPath, 'utf-8'));
  const proofValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  const thresholdsBound = thresholdsMatchJurisdiction(publicSignals);
  const jurisdictionMatchesVASP = expectedJurisdiction 
    ? thresholdsJurisdictionMatchesVASP(publicSignals, expectedJurisdiction)
    : true; // If no expected jurisdiction provided, assume it matches

  const rejectionReasons: string[] = [];
  if (!proofValid) rejectionReasons.push('groth16_invalid');
  if (!thresholdsBound) rejectionReasons.push('threshold_mismatch');

  return {
    valid: proofValid && thresholdsBound,
    proofValid,
    thresholdsBound,
    jurisdictionMatchesVASP,
    jurisdiction: publicSignals.length >= 16 ? decodeJurisdiction(publicSignals[6]) : null,
    rejectionReasons,
    isCompliant: publicSignals[0] === '1',
    sarReviewFlag: publicSignals[1] === '1',
    publicSignals,
  };
}

/**
 * Input fields for the ZK compliance circuit.
 *
 * Public inputs are supplied by the verifier; private inputs are known
 * only to the prover and never leave the proving environment.
 */
export interface ComplianceInput {
  // === Public inputs ===
  sanctionsTreeRoot: string;
  issuerTreeRoot: string;
  amountTier: number;
  transferTimestamp: number;
  jurisdictionCode: number;
  credentialCommitment: string;
  tier2Threshold: number;
  tier3Threshold: number;
  tier4Threshold: number;

  // === Public inputs: Domain binding & expiration ===
  domainChainId?: number;
  domainContractHash?: string;
  transferIdHash?: string;
  credentialNullifier: string;
  proofExpiresAt: number;

  // === Private inputs: Credential preimage ===
  issuerDid: string;
  kycTier: number;
  sanctionsClear: number;
  issuedAt: number;
  expiresAt: number;

  // === Private inputs: Issuer Merkle membership proof ===
  issuerPathElements: string[];
  issuerPathIndices: string[];

  // === Private inputs: Sanctions non-membership (gap proof) ===
  walletAddressHash: string;
  leftKey: string;
  rightKey: string;
  leftPathElements: string[];
  leftPathIndices: string[];
  rightPathElements: string[];
  rightPathIndices: string[];

  // === Private inputs: Amount tier verification ===
  actualAmount: number;
}

/**
 * Result returned after generating a Groth16 proof.
 */
export interface ProofResult {
  proof: object;
  publicSignals: string[];
  proofTime: number;
}

/**
 * Result returned after verifying a Groth16 proof.
 */
export interface VerifyResult {
  /** True only when the pairing check passes AND the thresholds are bound. */
  valid: boolean;
  /** The Groth16 pairing check alone. */
  proofValid: boolean;
  /** Whether signals 8-10 match this verifier's table for signal 6. */
  thresholdsBound: boolean;
  /** Decoded ISO 3166-1 alpha-2 code from signal 6, or null if malformed. */
  jurisdiction: string | null;
  /** Machine-readable rejection reasons; empty when `valid` is true. */
  rejectionReasons: string[];
  isCompliant: boolean;
  sarReviewFlag: boolean;
  publicSignals: string[];
}

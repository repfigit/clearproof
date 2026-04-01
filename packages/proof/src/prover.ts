import * as snarkjs from 'snarkjs';
import type { ComplianceInput, ProofResult } from './types.js';

/**
 * Generate a Groth16 ZK proof for the compliance circuit.
 *
 * Converts camelCase SDK inputs to the snake_case signal names expected
 * by the Circom circuit, then delegates to snarkjs.groth16.fullProve.
 *
 * @param input  - All public and private circuit inputs
 * @param wasmPath - Path to the compiled circuit WASM
 * @param zkeyPath - Path to the proving key (.zkey)
 * @returns Proof object, public signals array, and wall-clock proving time
 */
export async function generateProof(
  input: ComplianceInput,
  wasmPath: string,
  zkeyPath: string,
): Promise<ProofResult> {
  // --- Input validation ---------------------------------------------------
  if (input.proofExpiresAt <= input.transferTimestamp) {
    throw new Error('proofExpiresAt must be greater than transferTimestamp');
  }
  if (!input.credentialNullifier || input.credentialNullifier === '0') {
    throw new Error('credentialNullifier must not be zero or empty');
  }
  if (input.domainChainId === 0 || input.domainChainId === undefined) {
    console.warn(
      '[clearproof] WARNING: domainChainId is 0 or unset — proof has no domain binding. ' +
      'Set domainChainId to the target chain ID for replay protection.',
    );
  }

  const start = Date.now();

  // Map camelCase SDK fields to snake_case circuit signal names
  const circuitInput: Record<string, string | string[]> = {
    sanctions_tree_root: input.sanctionsTreeRoot,
    issuer_tree_root: input.issuerTreeRoot,
    amount_tier: String(input.amountTier),
    transfer_timestamp: String(input.transferTimestamp),
    jurisdiction_code: String(input.jurisdictionCode),
    credential_commitment: input.credentialCommitment,
    tier2_threshold: String(input.tier2Threshold),
    tier3_threshold: String(input.tier3Threshold),
    tier4_threshold: String(input.tier4Threshold),
    domain_chain_id: String(input.domainChainId ?? 0),
    domain_contract_hash: input.domainContractHash ?? '0',
    transfer_id_hash: input.transferIdHash ?? '0',
    credential_nullifier: input.credentialNullifier,
    proof_expires_at: String(input.proofExpiresAt),
    issuer_did: input.issuerDid,
    kyc_tier: String(input.kycTier),
    sanctions_clear: String(input.sanctionsClear),
    issued_at: String(input.issuedAt),
    expires_at: String(input.expiresAt),
    issuer_path_elements: input.issuerPathElements,
    issuer_path_indices: input.issuerPathIndices,
    wallet_address_hash: input.walletAddressHash,
    left_key: input.leftKey,
    right_key: input.rightKey,
    left_path_elements: input.leftPathElements,
    left_path_indices: input.leftPathIndices,
    right_path_elements: input.rightPathElements,
    right_path_indices: input.rightPathIndices,
    actual_amount: String(input.actualAmount),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    wasmPath,
    zkeyPath,
  );

  return {
    proof,
    publicSignals,
    proofTime: Date.now() - start,
  };
}

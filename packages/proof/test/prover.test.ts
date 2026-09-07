import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateProof } from '../src/prover.js';
import type { ComplianceInput } from '../src/types.js';

const fullProve = vi.hoisted(() => vi.fn());
vi.mock('snarkjs', () => ({ groth16: { fullProve } }));

// Distinct synthetic values expose swapped fields at the SDK/circuit boundary.
const input: ComplianceInput = {
  sanctionsTreeRoot: '101', issuerTreeRoot: '102', amountTier: 2,
  transferTimestamp: 1000, jurisdictionCode: 21843, credentialCommitment: '103',
  tier2Threshold: 25000, tier3Threshold: 300000, tier4Threshold: 1000000,
  domainChainId: 31337, domainContractHash: '104', transferIdHash: '105',
  credentialNullifier: '106', proofExpiresAt: 1300, issuerDid: '107',
  kycTier: 3, sanctionsClear: 1, issuedAt: 900, expiresAt: 2000,
  issuerPathElements: ['108'], issuerPathIndices: ['0'], walletAddressHash: '109',
  leftKey: '110', rightKey: '112', leftPathElements: ['113'], leftPathIndices: ['1'],
  rightPathElements: ['114'], rightPathIndices: ['0'], actualAmount: 12345,
};
const proof = { pi_a: ['1', '2', '1'] };
const publicSignals = ['1', '0'];

beforeEach(() => {
  fullProve.mockReset().mockResolvedValue({ proof, publicSignals });
});
afterEach(() => vi.restoreAllMocks());

describe('SDK proving boundary', () => {
  it('maps every signal, forwards caller artifacts and returns proof timing', async () => {
    vi.spyOn(Date, 'now').mockReturnValueOnce(5000).mockReturnValueOnce(5075);
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await generateProof(input, '/local/circuit.wasm', '/local/setup.zkey'))
      .toEqual({ proof, publicSignals, proofTime: 75 });
    expect(fullProve).toHaveBeenCalledExactlyOnceWith({
      sanctions_tree_root: '101', issuer_tree_root: '102', amount_tier: '2',
      transfer_timestamp: '1000', jurisdiction_code: '21843', credential_commitment: '103',
      tier2_threshold: '25000', tier3_threshold: '300000', tier4_threshold: '1000000',
      domain_chain_id: '31337', domain_contract_hash: '104', transfer_id_hash: '105',
      credential_nullifier: '106', proof_expires_at: '1300', issuer_did: '107',
      kyc_tier: '3', sanctions_clear: '1', issued_at: '900', expires_at: '2000',
      issuer_path_elements: ['108'], issuer_path_indices: ['0'], wallet_address_hash: '109',
      left_key: '110', right_key: '112', left_path_elements: ['113'], left_path_indices: ['1'],
      right_path_elements: ['114'], right_path_indices: ['0'], actual_amount: '12345',
    }, '/local/circuit.wasm', '/local/setup.zkey');
    expect(warning).not.toHaveBeenCalled();
  });

  it.each([999, 1000])('rejects expiry %s before invoking the prover', async proofExpiresAt => {
    await expect(generateProof({ ...input, proofExpiresAt }, 'c.wasm', 'c.zkey'))
      .rejects.toThrow('proofExpiresAt must be greater');
    expect(fullProve).not.toHaveBeenCalled();
  });

  it.each(['', '0'])('rejects empty or zero nullifiers (%s)', async credentialNullifier => {
    await expect(generateProof({ ...input, credentialNullifier }, 'c.wasm', 'c.zkey'))
      .rejects.toThrow('credentialNullifier must not be zero or empty');
    expect(fullProve).not.toHaveBeenCalled();
  });

  it.each([0, undefined])('warns on unbound chain %s and preserves documented defaults', async domainChainId => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await generateProof({ ...input, domainChainId, domainContractHash: undefined, transferIdHash: undefined },
      'c.wasm', 'c.zkey');
    expect(warning).toHaveBeenCalledOnce();
    expect(warning.mock.calls[0][0]).toContain('replay protection');
    expect(fullProve.mock.calls[0][0]).toMatchObject({
      domain_chain_id: '0', domain_contract_hash: '0', transfer_id_hash: '0',
    });
  });

  it('propagates proving failures instead of returning a successful result', async () => {
    const failure = new Error('witness constraint rejected');
    fullProve.mockRejectedValueOnce(failure);
    await expect(generateProof(input, 'c.wasm', 'c.zkey')).rejects.toBe(failure);
  });
});

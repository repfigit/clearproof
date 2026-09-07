import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { walletOwnershipSigningMessage, type WalletOwnershipChallenge } from '../src/wallet-ownership.js';

const vector = JSON.parse(readFileSync(new URL('../../../tests/vectors/wallet-ownership/challenge.json', import.meta.url), 'utf8'));
const challenge: WalletOwnershipChallenge = vector.challenge;
const credential = challenge.credential;
const expected = { tenantId: 'tenant-a', actorId: 'actor-a', credential, chainId: 31337,
  registryAddress: challenge.registry_address };

describe('wallet signing context', () => {
  it('matches the Python EIP-191 message byte for byte', () => {
    expect(walletOwnershipSigningMessage(challenge, expected, 1200)).toBe(vector.message);
  });
  it.each([
    { tenant_id: 'other' }, { actor_id: 'other' }, { chain_id: 1 },
    { registry_address: '0x' + '3'.repeat(40) }, { expires_at: 1401 }, { nonce: '0'.repeat(64) },
    { credential: { ...credential, credential_nonce: 'ef'.repeat(32) } },
    { credential: { ...credential, subject_wallet: '0x' + '4'.repeat(40) } },
  ])('rejects changed context', change => {
    expect(() => walletOwnershipSigningMessage({ ...challenge, ...change }, expected, 1200)).toThrow();
  });
  it.each([1099, 1400, Number.NaN])('rejects invalid time %s', now => {
    expect(() => walletOwnershipSigningMessage(challenge, expected, now)).toThrow();
  });
});

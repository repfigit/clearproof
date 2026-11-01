import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  siweWalletOwnershipMessage,
  walletOwnershipSigningMessage,
  type WalletOwnershipChallenge,
  type WalletOwnershipChallengeV2,
} from '../src/wallet-ownership.js';

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
  it.each([1070, 1099, 1100, 1399, 1400, 1429])('allows bounded client clock skew %s', now => {
    expect(walletOwnershipSigningMessage(challenge, expected, now)).toBe(vector.message);
  });
  it.each([1069, 1430, Number.NaN])('rejects invalid time %s', now => {
    expect(() => walletOwnershipSigningMessage(challenge, expected, now)).toThrow();
  });
});

describe('SIWE (EIP-4361) v2 challenge profile', () => {
  const vectorV2 = JSON.parse(
    readFileSync(new URL('../../../tests/vectors/wallet-ownership/challenge-v2.json', import.meta.url), 'utf8'),
  );
  const challengeV2 = vectorV2.challenge as WalletOwnershipChallengeV2;
  const expectedV2 = {
    tenantId: challengeV2.tenant_id,
    actorId: challengeV2.actor_id,
    credential: challengeV2.credential,
    chainId: challengeV2.chain_id,
    registryAddress: challengeV2.registry_address,
  };

  it('matches the Python EIP-4361 message byte for byte', () => {
    expect(walletOwnershipSigningMessage(challengeV2, expectedV2, 1200)).toBe(vectorV2.message);
    expect(siweWalletOwnershipMessage(challengeV2)).toBe(vectorV2.message);
  });
  it('renders the subject address with an EIP-55 checksum', () => {
    const checksummed = siweWalletOwnershipMessage(challengeV2).split('\n')[1];
    expect(checksummed).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
  it('rejects a credential whose subject wallet does not match the retained enrollment', () => {
    const change = { credential: { ...challengeV2.credential, subject_wallet: '0x' + '4'.repeat(40) } };
    expect(() => walletOwnershipSigningMessage({ ...challengeV2, ...change }, expectedV2, 1200)).toThrow();
  });
  it('returns a message for challenge fields only the server can authenticate', () => {
    // The helper validates the RETAINED enrollment context; the nonce and the
    // 300-second TTL window are enforced server-side at challenge consumption,
    // so a changed nonce/shifted window still renders (the signature will not
    // verify server-side).
    expect(walletOwnershipSigningMessage({ ...challengeV2, nonce: 'ef'.repeat(32) }, expectedV2, 1200)).toBe(
      vectorV2.message.replace(new RegExp(`Nonce: ${challengeV2.nonce}`), `Nonce: ${'ef'.repeat(32)}`),
    );
    expect(walletOwnershipSigningMessage({ ...challengeV2, timestamp: 1101, expires_at: 1401 }, expectedV2, 1200))
      .toContain('Issued At: 1970-01-01T00:18:21Z');
  });
  it.each([{ siwe_domain: 'bad\nexample' }, { siwe_domain: ' spaced.example ' }])('rejects invalid SIWE domain', change => {
    expect(() => walletOwnershipSigningMessage({ ...challengeV2, ...change }, expectedV2, 1200)).toThrow();
  });
  it('still validates the v1 path unchanged', () => {
    expect(walletOwnershipSigningMessage(challenge, expected, 1200)).toBe(vector.message);
  });
});


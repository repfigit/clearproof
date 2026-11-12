import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import * as sdk from '../src/index.js';
import type { AnyWalletOwnershipChallenge, WalletOwnershipChallengeV2 } from '../src/index.js';

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const vectorV2 = JSON.parse(
  readFileSync(new URL('../../../tests/vectors/wallet-ownership/challenge-v2.json', import.meta.url), 'utf8'),
);

describe('package entry point', () => {
  it('is the only import path the exports map allows', () => {
    // A blocked subpath means anything integrators need must be exported from the root.
    expect(Object.keys(manifest.exports)).toEqual(['.', './package.json']);
  });

  it('exports the wallet-ownership v2 (SIWE) types and renderer used by walletOwnershipSigningMessage', () => {
    const challenge: WalletOwnershipChallengeV2 = vectorV2.challenge;
    const either: AnyWalletOwnershipChallenge = challenge;
    const expected = {
      tenantId: challenge.tenant_id,
      actorId: challenge.actor_id,
      credential: challenge.credential,
      chainId: challenge.chain_id,
      registryAddress: challenge.registry_address,
    };
    expect(sdk.siweWalletOwnershipMessage(challenge)).toBe(vectorV2.message);
    expect(sdk.walletOwnershipSigningMessage(either, expected, challenge.timestamp)).toBe(vectorV2.message);
  });

  it('exports the legacy functions, the pilot API clients and the shared helpers by name', () => {
    const functions = [
      'generateProof', 'verifyProof',
      'authorizeCurrentProof', 'inspectCurrentProof', 'createObservation', 'readObservation',
      'listObservations', 'reportObservationCohort', 'requestReport', 'reportEndpoint',
      'canonicalBytes', 'recordDigest', 'walletOwnershipSigningMessage', 'siweWalletOwnershipMessage',
      'discoverVASP', 'supportsChain', 'clearDiscoveryCache', 'isFieldElementString', 'isFieldElementArray',
      'getThresholds', 'decodeJurisdiction', 'thresholdsMatchJurisdiction',
    ] as const;
    for (const name of functions) expect(typeof sdk[name], name).toBe('function');
    expect(sdk.LEGACY_PUBLIC_SIGNAL_COUNT).toBe(16);
    expect(sdk.PILOT_PUBLIC_SIGNAL_COUNT).toBe(8);
  });
});

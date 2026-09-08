import { describe, expect, it } from 'vitest';
import { recordDigest } from '../src/canonical.js';
import { listObservations, validateObservationPage } from '../src/observation-page.js';

function observation(actor: string) {
  const digest = 'a'.repeat(64);
  const record = { schema_version: 'clearproof-proof-observation-v1', mode: 'observation',
    authorization_consumed: false, execution: 'not-requested', assurance: 'development-unapproved',
    tenant_id: 'tenant-a', actor_id: actor, request_digest: digest, credential_id: digest,
    proof_digest: digest, signals_digest: digest, transfer_digest: digest, context_digest: digest,
    policy_digest: digest, manifest_digest: digest, proof_profile: 'pilot-transfer-v2', fact_ids: [],
    observed_at: 1000, cryptographic_valid: false, policy: null };
  return { observation_id: recordDigest('clearproof/proof-observation/v1', record), ...record };
}
const records = [observation('one'), observation('two')].sort((a, b) => a.observation_id.localeCompare(b.observation_id));
function page() { return { schema_version: 'clearproof-observation-page-v1', scope: 'live-retained-tenant-observations',
  order: 'observation-id-ascending', after: null, limit: 2, observations: records, next_after: records[1].observation_id }; }

describe('observation discovery pages', () => {
  it('preserves ordered records and explicit continuation or end', () => {
    expect(validateObservationPage(page(), { limit: 2 })).toEqual(page());
    expect(validateObservationPage({ ...page(), next_after: null }, { limit: 2 }).next_after).toBeNull();
    expect(validateObservationPage({ ...page(), observations: [], next_after: null }, { limit: 2 }).observations).toEqual([]);
  });
  it('rejects shifted requests, duplicate/reversed records, altered digests and invalid continuations', () => {
    for (const change of [{ after: 'b'.repeat(64) }, { limit: 3 }, { order: 'observed-at' },
      { observations: [records[0], records[0]] }, { observations: [...records].reverse() },
      { next_after: records[0].observation_id }, { observations: [], next_after: records[1].observation_id },
      { observations: [{ ...records[0], observed_at: 2000 }] }, { extra: true }]) {
      expect(() => validateObservationPage({ ...page(), ...change }, { limit: 2 })).toThrow();
    }
    expect(() => validateObservationPage({ ...page(), after: records[0].observation_id },
      { limit: 2, after: records[0].observation_id })).toThrow();
  });
  it('rejects malformed private selectors before sending them', async () => {
    for (const input of [{ limit: true }, { limit: 65 }, { after: 'PRIVATE-MARKER' }, { tenant_id: 'foreign' }]) {
      await expect(listObservations('http://127.0.0.1:1', 'token', Buffer.from(JSON.stringify(input))))
        .rejects.toThrow('Observation page unavailable or rejected');
    }
  });
});

it('rejects nonobject page requests, nonobject responses and invalid byte inputs', async () => {
  for (const value of [null, 'private', []]) {
    expect(() => validateObservationPage(value, {})).toThrow('Invalid page');
    expect(() => validateObservationPage({}, value as never)).toThrow('Invalid page request');
  }
  for (const value of [Buffer.alloc(0), Buffer.alloc(1025), null as unknown as Uint8Array]) {
    await expect(listObservations('https://operator.example', 'token', value)).rejects.toThrow('unavailable or rejected');
  }
});

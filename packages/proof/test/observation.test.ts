import { describe, expect, it } from 'vitest';
import { recordDigest } from '../src/canonical.js';
import { createObservation, readObservation, validateObservationReport } from '../src/observation.js';

function record() {
  const digest = 'a'.repeat(64);
  return {
    schema_version: 'clearproof-proof-observation-v1', mode: 'observation', authorization_consumed: false,
    execution: 'not-requested', assurance: 'development-unapproved', tenant_id: 'tenant-a', actor_id: 'observer',
    request_digest: digest, credential_id: digest, proof_digest: digest, signals_digest: digest,
    transfer_digest: digest, context_digest: digest, policy_digest: digest, manifest_digest: digest,
    proof_profile: 'pilot-transfer-v2', fact_ids: [], observed_at: 1000, cryptographic_valid: true,
    policy: { schema_version: 'clearproof-policy-evaluation-v1', policy_digest: digest, transfer_digest: digest,
      evaluated_at: 1000, outcome: 'ALLOW', matched_rule_ids: [], missing_predicates: [], unsupported_predicates: [],
      reasons: [], conflicting_effects: false, zk_coverage: 'not-established' },
  };
}
const seal = (body: object) => ({ ...body, observation_id: recordDigest('clearproof/proof-observation/v1', body) });

describe('portable observation response checks', () => {
  it('preserves all four outcomes and failed pairing without creating authorization semantics', () => {
    for (const outcome of ['ALLOW', 'DENY', 'REVIEW', 'INDETERMINATE']) {
      const body = record(); body.policy.outcome = outcome;
      expect(validateObservationReport(seal(body)).policy?.outcome).toBe(outcome);
    }
    const failed = seal({ ...record(), cryptographic_valid: false, policy: null });
    expect(validateObservationReport(failed)).toEqual(failed);
  });
  it('rejects recomputed identities containing unsupported claims or inconsistent policy', () => {
    for (const changes of [{ mode: 'enforcement' }, { authorization_consumed: true }, { execution: 'completed' },
      { assurance: 'production-approved' }, { proof_profile: 'pilot-transfer-v1' }, { private: 'PRIVATE-MARKER' },
      { fact_ids: ['a'.repeat(64), 'a'.repeat(64)] }, { policy: null }, { cryptographic_valid: false },
      { observed_at: 1001 }, { policy: { ...record().policy, zk_coverage: 'established' } },
      { policy: { ...record().policy, outcome: 'COMPLIANT' } },
      { policy: { ...record().policy, transfer_digest: 'b'.repeat(64) } },
      { policy: { ...record().policy, reasons: ['z', 'a'] } }]) {
      expect(() => validateObservationReport(seal({ ...record(), ...changes }))).toThrow();
    }
  });
  it('rejects changed report bytes under the original identifier', () => {
    expect(() => validateObservationReport({ ...seal(record()), actor_id: 'substituted' })).toThrow('identity mismatch');
  });
  it('bounds private requests before transport and returns generic errors', async () => {
    await expect(createObservation('http://127.0.0.1:1', 'token', Buffer.alloc(16385)))
      .rejects.toThrow('Observation request unavailable or rejected');
    await expect(readObservation('http://127.0.0.1:1', 'token', Buffer.alloc(1025)))
      .rejects.toThrow('Observation request unavailable or rejected');
  });
});

describe('versioned observation duration', () => {
  it('accepts bounded v2 measurements while retaining v1 identity checks', () => {
    expect(validateObservationReport(seal(record())).schema_version).toBe('clearproof-proof-observation-v1');
    const body = { ...record(), schema_version: 'clearproof-proof-observation-v2',
      latency_scope: 'current-evaluation-only', evaluation_duration_ns: 123456789 };
    const report = { ...body, observation_id: recordDigest('clearproof/proof-observation/v2', body) };
    expect(validateObservationReport(report)).toEqual(report);
    expect(() => validateObservationReport(seal(body))).toThrow('identity mismatch');
    for (const changes of [{ evaluation_duration_ns: -1 }, { evaluation_duration_ns: 60_000_000_001 },
      { evaluation_duration_ns: true }, { latency_scope: 'end-to-end' }, { mode: 'enforcement' }]) {
      const changed = { ...body, ...changes };
      expect(() => validateObservationReport({ ...changed,
        observation_id: recordDigest('clearproof/proof-observation/v2', changed) })).toThrow();
    }
  });
});

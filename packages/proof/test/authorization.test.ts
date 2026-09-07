import { describe, expect, it } from 'vitest';
import { recordDigest } from '../src/canonical.js';
import { authorizeCurrentProof, validateAuthorizationReport } from '../src/authorization.js';

const signals = ['1', '2', '3', '4', '5', '2000', '7', '8'];
function receipt() {
  return { schema_version: 'clearproof-local-authorization-v1', tenant_id: 'tenant-a', actor_id: 'operator',
    proof_id: 'a'.repeat(64), transfer_digest: 'b'.repeat(64), context_digest: 'c'.repeat(64),
    policy_digest: 'd'.repeat(64), manifest_digest: 'e'.repeat(64), proof_profile: 'pilot-transfer-v2',
    nullifier: '4'.padStart(64, '0'), authorized_at: 1000, expires_at: 2000, outcome: 'ALLOW',
    execution: 'not-requested', envelope_digest: 'f'.repeat(64), recipient_key_id: Buffer.alloc(16, 1).toString('base64'),
    information_signature_digest: 'b'.repeat(64), evidence_id: 'c'.repeat(64) };
}
function report(changes = {}) {
  const r = { ...receipt(), ...changes };
  return { schema_version: 'clearproof-authorization-response-v1', scope: 'recorded-local-authorization',
    assurance: 'development-unapproved', receipt: { receipt_id: recordDigest('clearproof/local-authorization/v1', r), ...r } };
}
describe('recorded local authorization response', () => {
  it('checks canonical receipt identity and request nullifier/expiry, without imposing a fresh clock', () => {
    expect(validateAuthorizationReport(report(), signals)).toEqual(report());
    for (const changes of [{ outcome: 'DENY' }, { execution: 'completed' }, { proof_profile: 'pilot-transfer-v1' },
      { expires_at: 2001 }, { authorized_at: 2000 }, { nullifier: '1'.repeat(64) }, { extra: 'claim' }, { recipient_key_id: 'a'.repeat(64) }, { recipient_key_id: 'A'.repeat(21) + 'B==' }]) {
      expect(() => validateAuthorizationReport(report(changes), signals)).toThrow();
    }
  });
  it('rejects unsupported claims and tampered identities', () => {
    for (const changes of [{ scope: 'current-authorization' }, { assurance: 'production-approved' },
      { authorization_consumed: true }, { receipt: { ...report().receipt, actor_id: 'changed' } }]) {
      expect(() => validateAuthorizationReport({ ...report(), ...changes }, signals)).toThrow();
    }
    for (const invalid of [[], [...signals, '0'], ['01', ...signals.slice(1)],
      [...signals.slice(0, 3), '0', ...signals.slice(4)]]) {
      expect(() => validateAuthorizationReport(report(), invalid)).toThrow();
    }
  });
  it('bounds requests and keeps uncertain failure guidance explicit', async () => {
    await expect(authorizeCurrentProof('http://127.0.0.1:1', 'private-token', Buffer.alloc(16385)))
      .rejects.toThrow('retry only the same request and idempotency key');
  });
});

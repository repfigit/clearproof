/** Explicit local authorization through an operator-selected trusted API. */
import { requestReport } from './api-client.js';
import { recordDigest } from './canonical.js';
import type { ObservationRequest } from './observation.js';

export type AuthorizationRequest = ObservationRequest;
const digests = ['receipt_id', 'proof_id', 'transfer_digest', 'context_digest', 'policy_digest', 'manifest_digest',
  'nullifier', 'envelope_digest', 'information_signature_digest', 'evidence_id'] as const;
export type AuthorizationReceipt = Record<typeof digests[number], string> & {
  schema_version: 'clearproof-local-authorization-v1';
  tenant_id: string; actor_id: string; proof_profile: 'pilot-transfer-v2';
  recipient_key_id: string;
  authorized_at: number; expires_at: number; outcome: 'ALLOW'; execution: 'not-requested';
};
export interface AuthorizationReport {
  schema_version: 'clearproof-authorization-response-v1';
  scope: 'recorded-local-authorization'; assurance: 'development-unapproved'; receipt: AuthorizationReceipt;
}
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: readonly string[]) =>
  Object.keys(v).length === keys.length && keys.every(k => k in v);
const hex = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const opaque = (v: unknown) => typeof v === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v);
const recipientKey = (v: unknown) => typeof v === 'string' && /^[A-Za-z0-9_-]{22}==$/.test(v) &&
  Buffer.from(v, 'base64url').toString('base64url') + '==' === v;
const epoch = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const scalarModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export function validateAuthorizationReport(value: unknown, signals: string[]): AuthorizationReport {
  if (!Array.isArray(signals) || signals.length !== 8 || signals.some(s => typeof s !== 'string' ||
    !/^(0|[1-9][0-9]{0,77})$/.test(s) || BigInt(s) >= scalarModulus)) throw new Error('Invalid signals');
  if (!object(value) || !exact(value, ['schema_version', 'scope', 'assurance', 'receipt']) ||
    value.schema_version !== 'clearproof-authorization-response-v1' || value.scope !== 'recorded-local-authorization' ||
    value.assurance !== 'development-unapproved' || !object(value.receipt)) throw new Error('Invalid authorization report');
  const r = value.receipt;
  if (!exact(r, [...digests, 'schema_version', 'tenant_id', 'actor_id', 'proof_profile', 'authorized_at', 'expires_at',
    'outcome', 'execution', 'recipient_key_id']) || digests.some(k => !hex(r[k])) || !recipientKey(r.recipient_key_id) || !opaque(r.tenant_id) || !opaque(r.actor_id) ||
    r.schema_version !== 'clearproof-local-authorization-v1' || r.proof_profile !== 'pilot-transfer-v2' ||
    r.outcome !== 'ALLOW' || r.execution !== 'not-requested' || !epoch(r.authorized_at) || !epoch(r.expires_at) ||
    r.authorized_at >= r.expires_at || BigInt(signals[3]) === 0n ||
    r.nullifier !== BigInt(signals[3]).toString(16).padStart(64, '0') ||
    BigInt(r.expires_at) !== BigInt(signals[5])) throw new Error('Invalid authorization receipt');
  const { receipt_id, ...receipt } = r;
  if (recordDigest('clearproof/local-authorization/v1', receipt) !== receipt_id) throw new Error('Receipt identity mismatch');
  return value as unknown as AuthorizationReport;
}
/** A success may recover a historical retry receipt. It never establishes delivery or execution. */
export async function authorizeCurrentProof(origin: string, token: string, input: Uint8Array): Promise<AuthorizationReport> {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 16384) throw new Error('Invalid input');
    const body = JSON.parse(Buffer.from(input).toString('utf8'));
    const report = await requestReport(origin, token, '/pilot/proof/authorize', Buffer.from(input));
    return validateAuthorizationReport(report, body.public_signals);
  } catch {
    // An interrupted response can follow a commit. Callers must retain and retry the SAME request/key.
    throw new Error('Authorization response unavailable or rejected; retry only the same request and idempotency key');
  }
}

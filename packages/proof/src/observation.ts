/** Remote observation transport and portable-record consistency, not authorization. */
import { requestReport } from './api-client.js';
import { recordDigest } from './canonical.js';
import type { CurrentInspectionRequest } from './current-inspection.js';

export interface ObservationRequest extends CurrentInspectionRequest {
  fact_ids: string[];
  idempotency_key: string;
}
export interface ObservedPolicy {
  schema_version: 'clearproof-policy-evaluation-v1';
  policy_digest: string; transfer_digest: string; evaluated_at: number;
  outcome: 'ALLOW' | 'DENY' | 'REVIEW' | 'INDETERMINATE';
  matched_rule_ids: string[]; missing_predicates: string[]; unsupported_predicates: string[];
  reasons: string[]; conflicting_effects: boolean; zk_coverage: 'not-established';
}
export interface ObservationReportV1 {
  observation_id: string;
  schema_version: 'clearproof-proof-observation-v1'; mode: 'observation';
  authorization_consumed: false; execution: 'not-requested'; assurance: 'development-unapproved';
  tenant_id: string; actor_id: string; request_digest: string; credential_id: string;
  proof_digest: string; signals_digest: string; transfer_digest: string; context_digest: string;
  policy_digest: string; manifest_digest: string; proof_profile: 'pilot-transfer-v2';
  fact_ids: string[]; observed_at: number; cryptographic_valid: boolean; policy: ObservedPolicy | null;
}
export type ObservationReportV2 = Omit<ObservationReportV1, 'schema_version'> & {
  schema_version: 'clearproof-proof-observation-v2';
  latency_scope: 'current-evaluation-only'; evaluation_duration_ns: number;
};
export type ObservationReport = ObservationReportV1 | ObservationReportV2;
const hex = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const opaque = (v: unknown): v is string => typeof v === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v);
const epoch = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
function fields(value: unknown, names: string[]): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(k => Object.hasOwn(value, k));
}
function ordered(value: unknown, validate: (v: unknown) => boolean): boolean {
  return Array.isArray(value) && value.length <= 64 && value.every((v, i) =>
    validate(v) && (i === 0 || value[i - 1] < v));
}
export function validateObservationReport(value: unknown): ObservationReport {
  const timed = !!value && typeof value === 'object' &&
    (value as Record<string, unknown>).schema_version === 'clearproof-proof-observation-v2';
  const digests = ['observation_id', 'request_digest', 'proof_digest', 'signals_digest', 'transfer_digest',
    'context_digest', 'policy_digest', 'manifest_digest'];
  const ids = ['tenant_id', 'actor_id', 'credential_id'];
  if (!fields(value, [...digests, ...ids, 'schema_version', 'mode', 'authorization_consumed', 'execution',
    'assurance', 'proof_profile', 'fact_ids', 'observed_at', 'cryptographic_valid', 'policy',
    ...(timed ? ['latency_scope', 'evaluation_duration_ns'] : [])]) ||
      digests.some(k => !hex(value[k])) || ids.some(k => !opaque(value[k])) ||
      value.schema_version !== (timed ? 'clearproof-proof-observation-v2' : 'clearproof-proof-observation-v1') || value.mode !== 'observation' ||
      value.authorization_consumed !== false || value.execution !== 'not-requested' ||
      value.assurance !== 'development-unapproved' || value.proof_profile !== 'pilot-transfer-v2' ||
      !ordered(value.fact_ids, hex) || !epoch(value.observed_at) || typeof value.cryptographic_valid !== 'boolean') {
    throw new Error('Invalid observation report');
  }
  if (timed && (value.latency_scope !== 'current-evaluation-only' ||
      !epoch(value.evaluation_duration_ns) || (value.evaluation_duration_ns as number) > 60_000_000_000)) {
    throw new Error('Invalid observation duration');
  }
  const policy = value.policy;
  if (value.cryptographic_valid) {
    const lists = ['matched_rule_ids', 'missing_predicates', 'unsupported_predicates', 'reasons'];
    if (!fields(policy, ['schema_version', 'policy_digest', 'transfer_digest', 'evaluated_at', 'outcome',
      ...lists, 'conflicting_effects', 'zk_coverage']) ||
        policy.schema_version !== 'clearproof-policy-evaluation-v1' ||
        policy.policy_digest !== value.policy_digest || policy.transfer_digest !== value.transfer_digest ||
        policy.evaluated_at !== value.observed_at ||
        !['ALLOW', 'DENY', 'REVIEW', 'INDETERMINATE'].includes(policy.outcome as string) ||
        lists.some(k => !ordered(policy[k], opaque)) || typeof policy.conflicting_effects !== 'boolean' ||
        policy.zk_coverage !== 'not-established') throw new Error('Invalid observation policy');
  } else if (policy !== null) throw new Error('Failed pairing cannot have an observed policy');
  const { observation_id: identifier, ...record } = value;
  if (recordDigest(timed ? 'clearproof/proof-observation/v2' : 'clearproof/proof-observation/v1', record) !== identifier) {
    throw new Error('Observation identity mismatch');
  }
  return value as unknown as ObservationReport;
}
async function observationRequest(origin: string, token: string, input: Uint8Array, read: boolean): Promise<ObservationReport> {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > (read ? 1024 : 16384)) {
      throw new Error('Invalid observation input');
    }
    const result = validateObservationReport(await requestReport(origin, token,
      read ? '/pilot/proof/observations/read' : '/pilot/proof/observe', Buffer.from(input)));
    if (read && JSON.parse(Buffer.from(input).toString('utf8')).observation_id !== result.observation_id) {
      throw new Error('Unexpected observation identity');
    }
    return result;
  } catch {
    throw new Error('Observation request unavailable or rejected');
  }
}
export const createObservation = (origin: string, token: string, input: Uint8Array) => observationRequest(origin, token, input, false);
export const readObservation = (origin: string, token: string, input: Uint8Array) => observationRequest(origin, token, input, true);

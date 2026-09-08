/** Selected-cohort response consistency; the authenticated API remains the trust boundary. */
import { requestReport } from './api-client.js';
import { compareCanonicalStrings, recordDigest } from './canonical.js';
import type { ObservedPolicy } from './observation.js';

type Outcome = ObservedPolicy['outcome'];
export interface ObservationCohortRequest {
  cohort_id: string;
  cases: { case_id: string; observation_id: string | null; baseline_outcome?: Outcome | null }[];
}
const countKeys = ['case_count', 'observed_count', 'missing_count', 'distinct_observed_transfers', 'failed_pairing_count',
  'policy_count', 'determinate_count', 'baseline_label_count', 'comparable_count', 'agreement_count', 'disagreement_count'] as const;
export type ObservationCohortReport = Record<typeof countKeys[number], number> & {
  schema_version: 'clearproof-observation-cohort-report-v2';
  mode: 'observation'; scope: 'selected-observation-cases'; assurance: 'development-unapproved';
  baseline_authority: 'caller-supplied-unverified'; cohort_id: string; cohort_digest: string;
  outcome_counts: Record<Outcome, number>; latency_status: 'complete' | 'partial' | 'not-recorded';
  latency: { scope: 'current-evaluation-only'; measured_count: number; unmeasured_observed_count: number;
    unmeasured_case_count: number; total_duration_ns: number | null; min_duration_ns: number | null; max_duration_ns: number | null };
  cases: { case_id: string; status: 'observed' | 'not-observed' | 'unavailable';
    outcome: Outcome | null; cryptographic_valid: boolean | null;
    baseline_outcome: Outcome | null; agrees_with_baseline: boolean | null }[];
};
const outcomes = ['ALLOW', 'DENY', 'REVIEW', 'INDETERMINATE'];
const outcome = (v: unknown) => typeof v === 'string' && outcomes.includes(v);
const opaque = (v: unknown) => typeof v === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v);
const hex = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
function object(v: unknown): v is Record<string, unknown> { return !!v && typeof v === 'object' && !Array.isArray(v); }
function fields(v: unknown, names: string[]): v is Record<string, unknown> {
  return object(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
}
export function normalizeCohort(v: unknown): ObservationCohortRequest {
  if (!fields(v, ['cohort_id', 'cases']) || !opaque(v.cohort_id) || !Array.isArray(v.cases) ||
      v.cases.length < 1 || v.cases.length > 64) throw new Error('Invalid cohort');
  const ids = new Set(), refs = new Set();
  const cases = v.cases.map(c => {
    if (!object(c) || !fields(c, ['case_id', 'observation_id', ...(Object.hasOwn(c, 'baseline_outcome') ? ['baseline_outcome'] : [])]) ||
        !opaque(c.case_id) || !(c.observation_id === null || hex(c.observation_id)) ||
        !(c.baseline_outcome === undefined || c.baseline_outcome === null || outcome(c.baseline_outcome)) ||
        ids.has(c.case_id) || (c.observation_id !== null && refs.has(c.observation_id))) throw new Error('Invalid cohort case');
    ids.add(c.case_id); refs.add(c.observation_id);
    return { case_id: c.case_id as string, observation_id: c.observation_id as string | null,
      baseline_outcome: (c.baseline_outcome ?? null) as Outcome | null };
  });
  cases.sort((a, b) => compareCanonicalStrings(a.case_id, b.case_id));
  return { cohort_id: v.cohort_id as string, cases };
}
export function validateCohortReport(v: unknown, input: unknown): ObservationCohortReport {
  const request = normalizeCohort(input), n = request.cases.length;
  if (!fields(v, ['schema_version', 'mode', 'scope', 'assurance', 'baseline_authority', 'cohort_id', 'cohort_digest',
    ...countKeys, 'outcome_counts', 'latency_status', 'latency', 'cases']) ||
      v.schema_version !== 'clearproof-observation-cohort-report-v2' || v.mode !== 'observation' ||
      v.scope !== 'selected-observation-cases' || v.assurance !== 'development-unapproved' ||
      v.baseline_authority !== 'caller-supplied-unverified' || v.cohort_id !== request.cohort_id ||
      v.cohort_digest !== recordDigest('clearproof/observation-cohort/v1', request) ||
      countKeys.some(k => !integer(v[k], n)) || !Array.isArray(v.cases) || v.cases.length !== n ||
      !fields(v.outcome_counts, outcomes)) throw new Error('Invalid cohort report');
  let observed = 0, failed = 0, labelled = 0, comparable = 0, agreements = 0;
  const counts: Record<string, number> = Object.fromEntries(outcomes.map(o => [o, 0]));
  v.cases.forEach((c, index) => {
    const expected = request.cases[index];
    if (!fields(c, ['case_id', 'status', 'outcome', 'cryptographic_valid', 'baseline_outcome', 'agrees_with_baseline']) ||
        c.case_id !== expected.case_id || c.baseline_outcome !== expected.baseline_outcome) throw new Error('Invalid case binding');
    if (c.status === 'observed') {
      if (expected.observation_id === null || typeof c.cryptographic_valid !== 'boolean' ||
          (c.cryptographic_valid ? !outcome(c.outcome) : c.outcome !== null)) throw new Error('Invalid observed case');
      observed++; if (!c.cryptographic_valid) failed++;
    } else if (c.status !== (expected.observation_id === null ? 'not-observed' : 'unavailable') ||
        c.cryptographic_valid !== null || c.outcome !== null) throw new Error('Invalid missing case');
    if (c.outcome !== null) counts[c.outcome as string]++;
    if (c.baseline_outcome !== null) labelled++;
    const agrees = c.outcome !== null && c.baseline_outcome !== null ? c.outcome === c.baseline_outcome : null;
    if (c.agrees_with_baseline !== agrees) throw new Error('Invalid baseline comparison');
    if (agrees !== null) comparable++; if (agrees === true) agreements++;
  });
  const policy = Object.values(counts).reduce((a, b) => a + b, 0);
  const expectedCounts = { case_count: n, observed_count: observed, missing_count: n - observed, failed_pairing_count: failed,
    policy_count: policy, determinate_count: policy - counts.INDETERMINATE, baseline_label_count: labelled,
    comparable_count: comparable, agreement_count: agreements, disagreement_count: comparable - agreements };
  if (Object.entries(expectedCounts).some(([k, count]) => v[k] !== count) ||
      outcomes.some(o => (v.outcome_counts as Record<string, unknown>)[o] !== counts[o]) ||
      (observed === 0 ? v.distinct_observed_transfers !== 0 :
        (v.distinct_observed_transfers as number) < 1 || (v.distinct_observed_transfers as number) > observed)) throw new Error('Invalid cohort counts');
  const t = v.latency;
  if (!fields(t, ['scope', 'measured_count', 'unmeasured_observed_count', 'unmeasured_case_count',
    'total_duration_ns', 'min_duration_ns', 'max_duration_ns']) || t.scope !== 'current-evaluation-only' ||
      !integer(t.measured_count, observed) || t.unmeasured_observed_count !== observed - t.measured_count ||
      t.unmeasured_case_count !== n - t.measured_count ||
      v.latency_status !== (t.measured_count === n ? 'complete' : t.measured_count ? 'partial' : 'not-recorded')) throw new Error('Invalid latency coverage');
  if (t.measured_count === 0) {
    if (t.total_duration_ns !== null || t.min_duration_ns !== null || t.max_duration_ns !== null) throw new Error('Missing latency is not zero');
  } else if (!integer(t.min_duration_ns, 60_000_000_000) || !integer(t.max_duration_ns, 60_000_000_000) ||
      !integer(t.total_duration_ns, t.measured_count * 60_000_000_000) || t.min_duration_ns > t.max_duration_ns ||
      t.total_duration_ns < t.max_duration_ns + t.min_duration_ns * (t.measured_count - 1) ||
      t.total_duration_ns > t.min_duration_ns + t.max_duration_ns * (t.measured_count - 1)) throw new Error('Invalid latency totals');
  return v as unknown as ObservationCohortReport;
}
export async function reportObservationCohort(origin: string, token: string, input: Uint8Array): Promise<ObservationCohortReport> {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 16384) throw new Error('Invalid cohort input');
    const request = JSON.parse(Buffer.from(input).toString('utf8'));
    normalizeCohort(request);
    return validateCohortReport(await requestReport(origin, token, '/pilot/proof/observations/report', Buffer.from(input)), request);
  } catch { throw new Error('Observation cohort unavailable or rejected'); }
}

import { describe, expect, it } from 'vitest';
import { recordDigest } from '../src/canonical.js';
import { normalizeCohort, validateCohortReport } from '../src/observation-cohort.js';

const input = { cohort_id: 'sample', cases: [{ case_id: 'case-a', observation_id: 'a'.repeat(64), baseline_outcome: 'ALLOW' }] };
function report() {
  return { schema_version: 'clearproof-observation-cohort-report-v2', mode: 'observation', scope: 'selected-observation-cases',
    assurance: 'development-unapproved', baseline_authority: 'caller-supplied-unverified', cohort_id: 'sample',
    cohort_digest: recordDigest('clearproof/observation-cohort/v1', normalizeCohort(input)), case_count: 1,
    observed_count: 1, missing_count: 0, distinct_observed_transfers: 1, failed_pairing_count: 0, policy_count: 1,
    determinate_count: 1, outcome_counts: { ALLOW: 0, DENY: 1, REVIEW: 0, INDETERMINATE: 0 },
    baseline_label_count: 1, comparable_count: 1, agreement_count: 0, disagreement_count: 1,
    latency_status: 'complete', latency: { scope: 'current-evaluation-only', measured_count: 1,
      unmeasured_observed_count: 0, unmeasured_case_count: 0, total_duration_ns: 5, min_duration_ns: 5, max_duration_ns: 5 },
    cases: [{ case_id: 'case-a', status: 'observed', outcome: 'DENY', cryptographic_valid: true,
      baseline_outcome: 'ALLOW', agrees_with_baseline: false }] };
}
describe('cohort client response binding', () => {
  it('preserves a disagreement and verifies its selected cohort and denominators', () => {
    expect(validateCohortReport(report(), input)).toEqual(report());
    expect(() => validateCohortReport(report(), { ...input, cohort_id: 'other' })).toThrow();
    expect(() => normalizeCohort({ ...input, cases: [...input.cases, input.cases[0]] })).toThrow();
    expect(() => normalizeCohort({ ...input, cases: [] })).toThrow();
  });
  it('rejects inconsistent counts, altered labels, unexpected claims and invalid timings', () => {
    for (const changes of [{ agreement_count: 1 }, { case_count: 2 }, { observed_count: 0 },
      { distinct_observed_transfers: 0 }, { latency_status: 'partial' }, { baseline_authority: 'verified' },
      { private: 'PRIVATE-MARKER' }, { mode: 'enforcement' }, { schema_version: 'old' },
      { outcome_counts: { ALLOW: 1, DENY: 0, REVIEW: 0, INDETERMINATE: 0 } },
      { cases: [{ ...report().cases[0], agrees_with_baseline: true }] },
      { cases: [{ ...report().cases[0], baseline_outcome: 'DENY' }] },
      { latency: { ...report().latency, total_duration_ns: 6 } },
      { latency: { ...report().latency, min_duration_ns: 4 } },
      { latency: { ...report().latency, measured_count: 0 } }]) {
      expect(() => validateCohortReport({ ...report(), ...changes }, input)).toThrow();
    }
  });
  it('does not allow a missing observation to create policy or latency evidence', () => {
    const missing = { ...report(), observed_count: 0, missing_count: 1, distinct_observed_transfers: 0,
      policy_count: 0, determinate_count: 0, comparable_count: 0, disagreement_count: 0,
      outcome_counts: { ALLOW: 0, DENY: 0, REVIEW: 0, INDETERMINATE: 0 }, latency_status: 'not-recorded',
      latency: { scope: 'current-evaluation-only', measured_count: 0, unmeasured_observed_count: 0,
        unmeasured_case_count: 1, total_duration_ns: null, min_duration_ns: null, max_duration_ns: null },
      cases: [{ ...report().cases[0], status: 'unavailable', outcome: null, cryptographic_valid: null, agrees_with_baseline: null }] };
    expect(validateCohortReport(missing, input)).toEqual(missing);
    expect(() => validateCohortReport({ ...missing, latency: { ...missing.latency, total_duration_ns: 0 } }, input)).toThrow();
  });
});

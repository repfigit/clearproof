import { expect, it } from 'vitest';
import { PILOT_AND_WALLET_ROUTES, reportEndpoint } from '../src/api-client.js';
import type { ReportPath } from '../src/api-client.js';

const EXPECTED_ROUTES = [
  '/pilot/credential/enroll',
  '/pilot/credential/list',
  '/pilot/credential/backfill',
  '/pilot/credential/revoke',
  '/pilot/policy/approve',
  '/pilot/policy/diff',
  '/pilot/policy/diff/stored',
  '/pilot/proof/inspect',
  '/pilot/proof/evaluate',
  '/pilot/proof/authorize',
  '/pilot/proof/observe',
  '/pilot/proof/observations/read',
  '/pilot/proof/observations/report',
  '/pilot/proof/observations/list',
  '/pilot/proof/jobs',
  '/pilot/proof/jobs/{job_id}',
  '/pilot/proof/jobs/{job_id}/cancel',
  '/pilot/proof/jobs/{job_id}/retry',
  '/pilot/events/ingest',
  '/pilot/events/investigate',
  '/pilot/events/queue',
  '/pilot/fireblocks/{integration_id}',
  '/pilot/usage',
  '/pilot/readiness/{capability}/{target_id}',
  '/wallet/ownership/challenge',
  '/wallet/ownership/verify',
  '/wallet/ownership/attestations/{attestation_id}',
  '/wallet/ownership/revoke',
  '/wallet/ownership/delegation-check',
  '/wallet/ownership/evidence/{attestation_id}',
  '/wallet/ownership/credential',
] as const;

type ExpectedPath = (typeof EXPECTED_ROUTES)[number];

// Compile-time exactness: neither list may omit or invent a route.
const exactUnion: [ReportPath] extends [ExpectedPath]
  ? [ExpectedPath] extends [ReportPath] ? true : false
  : false = true;

it('publishes every pilot and wallet route exactly once', () => {
  expect(exactUnion).toBe(true);
  expect(PILOT_AND_WALLET_ROUTES).toEqual(EXPECTED_ROUTES);
  expect(new Set(PILOT_AND_WALLET_ROUTES).size).toBe(PILOT_AND_WALLET_ROUTES.length);
  for (const path of EXPECTED_ROUTES) {
    expect(decodeURIComponent(reportEndpoint('https://operator.example', path).pathname)).toBe(path);
  }
});

const INPUT_LIMIT = 1024 * 1024;
const OUTPUT_LIMIT = 2 * 1024 * 1024;

/** Every authenticated pilot and wallet-ownership route, with path templates as published. */
export const PILOT_AND_WALLET_ROUTES = [
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

export type ReportPath = (typeof PILOT_AND_WALLET_ROUTES)[number];

export function reportEndpoint(base: string, path: ReportPath): URL {
  const url = new URL(base);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new Error('Invalid API origin');
  }
  url.pathname = path;
  return url;
}

export async function requestReport(base: string, token: string, path: ReportPath, input: Buffer, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (!token || /[\s\x00-\x1f\x7f]/.test(token) || input.length === 0 || input.length > INPUT_LIMIT) {
    throw new Error('Invalid comparison configuration');
  }
  const response = await fetch(reportEndpoint(base, path), {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: new Uint8Array(input),
    redirect: 'error',
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error('Comparison request rejected');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > OUTPUT_LIMIT) throw new Error('Response limit exceeded');
      chunks.push(value);
    }
  } finally {
    try { await reader.cancel(); }
    finally { reader.releaseLock(); }
  }
  const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('Invalid report');
  return report as Record<string, unknown>;
}

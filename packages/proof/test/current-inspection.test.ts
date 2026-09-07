import { afterEach, describe, expect, it } from 'vitest';
import { createServer, Server } from 'node:http';
import { inspectCurrentProof } from '../src/current-inspection.js';

let server: Server | undefined;
afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>(done => server!.close(() => done()));
    server = undefined;
  }
});
async function listen(handler: Parameters<typeof createServer>[0]) {
  server = createServer(handler);
  await new Promise<void>(done => server!.listen(0, '127.0.0.1', done));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}
const report = { schema_version: 'clearproof-current-inspection-v1', scope: 'current-statement-inspection',
  authorization_consumed: false, assurance: 'development-unapproved', cryptographic_valid: true,
  manifest_digest: 'a'.repeat(64), proof_profile: 'pilot-transfer-v2' };

describe('current inspection SDK boundary', () => {
  it('sends exact private bytes and authenticated request, preserving a false pairing result', async () => {
    let observed: unknown;
    const origin = await listen(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk);
      observed = [req.method, req.url, req.headers.authorization, Buffer.concat(chunks).toString()];
      res.end(JSON.stringify({ ...report, cryptographic_valid: false }));
    });
    const raw = '{"target_id":"x","target_id":"duplicate-for-server-rejection"}';
    expect(await inspectCurrentProof(origin, 'test-token', Buffer.from(raw)))
      .toEqual({ ...report, cryptographic_valid: false });
    expect(observed).toEqual(['POST', '/pilot/proof/inspect', 'Bearer test-token', raw]);
  });

  it('rejects mismatched profiles, assurance, authorization, extra data and malformed report fields', async () => {
    let response: unknown = report;
    const origin = await listen((_req, res) => res.end(JSON.stringify(response)));
    for (const changed of [{ proof_profile: 'legacy-compliance-16' }, { assurance: 'production-approved' },
      { authorization_consumed: true }, { cryptographic_valid: 'true' }, { private: 'PRIVATE-MARKER' },
      { schema_version: 'unknown' }, { scope: 'authorization' }, { manifest_digest: 'INVALID' }]) {
      response = { ...report, ...changed };
      await expect(inspectCurrentProof(origin, 'test-token', Buffer.from('{}')))
        .rejects.toThrow('Current proof inspection unavailable or rejected');
    }
    response = null;
    await expect(inspectCurrentProof(origin, 'test-token', Buffer.from('{}'))).rejects.toThrow();
  });

  it('rejects invalid configuration and oversized input before sending', async () => {
    let requests = 0;
    const origin = await listen((_req, res) => { requests++; res.end(JSON.stringify(report)); });
    for (const [url, token, raw] of [[origin, '', Buffer.from('{}')], [origin, 'x\nsecret', Buffer.from('{}')],
      [origin, 'test-token', Buffer.alloc(16385)], [origin, 'test-token', Buffer.alloc(0)],
      ['http://example.com', 'test-token', Buffer.from('{}')],
      ['https://private:secret@example.com', 'test-token', Buffer.from('{}')]] as const) {
      await expect(inspectCurrentProof(url, token, raw)).rejects.toThrow('Current proof inspection unavailable or rejected');
    }
    expect(requests).toBe(0);
  });

  it('does not follow redirects or surface rejected response data', async () => {
    let requests = 0;
    let status = 302;
    const origin = await listen((_req, res) => {
      requests++;
      res.writeHead(status, { location: '/private-target' });
      res.end('PRIVATE-MARKER');
    });
    for (const next of [302, 403, 422, 503]) {
      status = next;
      await expect(inspectCurrentProof(origin, 'test-token', Buffer.from('{}')))
        .rejects.toThrow('Current proof inspection unavailable or rejected');
    }
    expect(requests).toBe(4);
  });
});

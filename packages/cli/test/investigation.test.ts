import { afterEach, expect, it } from 'vitest';
import { createServer, Server } from 'node:http';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { collectQueue, renderInvestigation } from '../src/commands/investigation.js';

let server: Server | undefined;
afterEach(async () => {
  if (server) { server.closeAllConnections(); await new Promise<void>(done => server!.close(() => done())); server = undefined; }
});
const digest = (n: number) => n.toString(16).padStart(64, '0');
const item = (n: number, age: number) => ({ scope: { transfer_id: `transfer-${n}` }, scope_digest: digest(n), oldest_age_seconds: age,
  findings: [{ reason: 'settlement-failed', age_seconds: age, owner: 'operations', next_action: 'inspect-custody-failure' }] });
async function api(pages: unknown[]) {
  let calls = 0;
  server = createServer(async (req, res) => {
    expect(req.url).toBe('/pilot/events/queue');
    expect(req.headers.authorization).toBe('Bearer test-token');
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw);
    if (calls) expect(body.after).toBe(digest(calls));
    res.end(JSON.stringify(pages[calls++]));
  });
  await new Promise<void>(done => server!.listen(0, '127.0.0.1', done));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}
const page = (items: unknown[], next: string | null) => ({ schema_version: 'clearproof-investigation-queue-v1',
  ordering: 'scope-pages-age-within-page', as_of: 200, scanned_transfers: 1, items, next_cursor: next });
it('continues through empty filtered pages and sorts collected results', async () => {
  const base = await api([page([item(1, 10)], digest(1)), page([], digest(2)), page([item(3, 50)], null)]);
  const report = await collectQueue(base, 'test-token', Buffer.from('{}'), 3);
  expect(report.complete_from_start).toBe(true);
  expect(report.scanned_transfers).toBe(3);
  expect((report.items as {scope_digest: string}[]).map(i => i.scope_digest)).toEqual([digest(3), digest(1)]);
  expect(renderInvestigation(report, true)).toContain('owner operations');
});
it('marks exhausted page budgets as partial and preserves continuation', async () => {
  const base = await api([page([], digest(1))]);
  const report = await collectQueue(base, 'test-token', Buffer.from('{}'), 1);
  expect(report.complete_from_start).toBe(false);
  expect(report.next_cursor).toBe(digest(1));
  expect(renderInvestigation(report, true)).toContain('Partial queue');
});
it('rejects duplicate scopes and nonadvancing cursors', async () => {
  const base = await api([page([item(1, 10)], digest(1)), page([item(1, 10)], digest(1))]);
  await expect(collectQueue(base, 'test-token', Buffer.from('{}'), 2)).rejects.toThrow();
});
it('renders independent timeline states and rejects terminal control characters', () => {
  const report = { schema_version: 'clearproof-investigation-v1', scope_digest: digest(1), as_of: 200,
    states: { compliance: 'approved', proof: 'unknown', counterparty: 'timeout', custody: 'submitted', chain: 'unknown', evidence: 'incomplete' },
    findings: [], timeline: [{ occurred_at: 100, ingested_at: 110, source_id: 'source-a', dimension: 'custody', state: 'submitted' }] };
  expect(renderInvestigation(report, false)).toContain('chain: unknown');
  expect(() => renderInvestigation({ ...report, scope_digest: '\u001b[31msecret' }, false)).toThrow();
});

it('runs the built queue command with private stdin and JSON output', async () => {
  const provider = { source_id: 'custody', label: 'console', url: 'https://console.example/tx/opaque' };
  const base = await api([page([{ ...item(1, 10), provider_links: [provider] }], null)]);
  const child = spawn(process.execPath, [resolve('dist/index.js'), 'investigation', 'queue', '--api-url', base, '--json'], {
    env: { ...process.env, CLEARPROOF_API_TOKEN: 'test-token' }, stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.end('{}');
  const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
  const code = await new Promise<number | null>(done => child.on('close', done));
  clearTimeout(timer);
  expect(code, stderr).toBe(0);
  expect(JSON.parse(stdout).complete_from_start).toBe(true);
  expect(JSON.parse(stdout).items[0].provider_links).toEqual([provider]);
});


it('renders optional provider navigation in timelines and queues and rejects unsafe links', () => {
  const link = { source_id: 'custody', label: 'provider-console', url: 'https://console.example/tx/opaque' };
  const report = { schema_version: 'clearproof-investigation-v1', scope_digest: digest(1), as_of: 200,
    states: { compliance: 'unknown', proof: 'unknown', counterparty: 'unknown', custody: 'submitted', chain: 'unknown', evidence: 'unknown' },
    findings: [], timeline: [], provider_links: [link] };
  expect(renderInvestigation(report, false)).toContain('Provider custody | provider-console | https://console.example/tx/opaque');
  expect(renderInvestigation({ complete_from_start: true, items: [{ ...item(1, 5), provider_links: [link] }], next_cursor: null }, true)).toContain(link.url);
  for (const url of ['javascript:alert(1)', 'http://console.example/', 'https://user:secret@console.example/',
    'https://console.example/?secret=1', 'https://console.example/#secret', 'https://console.example/\u001b']) {
    expect(() => renderInvestigation({ ...report, provider_links: [{ ...link, url }] }, false)).toThrow();
  }
});

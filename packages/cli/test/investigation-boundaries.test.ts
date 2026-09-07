import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ read: vi.fn(), request: vi.fn() }));
vi.mock('../src/api-client.js', async importOriginal => ({
  ...await importOriginal<typeof import('../src/api-client.js')>(), readPrivateInput: mocks.read, requestReport: mocks.request,
}));
const digest = (n: number) => n.toString(16).padStart(64, '0');
const timeline = { schema_version: 'clearproof-investigation-v1', scope_digest: digest(1), as_of: 200,
  states: { compliance: 'approved', proof: 'unknown', counterparty: 'timeout', custody: 'submitted', chain: 'unknown', evidence: 'incomplete' },
  findings: [], timeline: [] };
const page = { schema_version: 'clearproof-investigation-queue-v1', ordering: 'scope-pages-age-within-page',
  as_of: 200, scanned_transfers: 1, items: [], next_cursor: null };
let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('CLEARPROOF_API_TOKEN', 'synthetic-token');
  mocks.read.mockReset().mockResolvedValue(Buffer.from('{}'));
  mocks.request.mockReset();
  output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.exitCode = originalExitCode;
});

describe('investigation response validation', () => {
  it.each([
    { schema_version: 'wrong' }, { states: null }, { states: 1 }, { states: [] },
    { as_of: -1 }, { as_of: 0.5 }, { scope_digest: 42 }, { scope_digest: 'x'.repeat(257) },
    { findings: {} }, { findings: Array(33).fill({}) }, { findings: [null] },
    { timeline: Array(257).fill({}) }, { provider_links: Array(9).fill({}) },
  ])('rejects malformed or unbounded report fields', async change => {
    const { renderInvestigation } = await import('../src/commands/investigation.js');
    expect(() => renderInvestigation({ ...timeline, ...change }, false)).toThrow();
  });
  it.each([42, 'https://example.com/' + 'x'.repeat(2049), 'https://example.com/a\\b',
    'https://:password@example.com/'])('rejects unsafe provider links', async url => {
    const { renderInvestigation } = await import('../src/commands/investigation.js');
    expect(() => renderInvestigation({ ...timeline, provider_links: [{ source_id: 'source', label: 'console', url }] }, false)).toThrow();
  });
  it.each([0, 33, 1.5])('rejects page budget %s before fetching', async budget => {
    const { collectQueue } = await import('../src/commands/investigation.js');
    await expect(collectQueue('https://example.com', 'token', Buffer.from('{}'), budget)).rejects.toThrow();
    expect(mocks.request).not.toHaveBeenCalled();
  });
  it.each([
    { schema_version: 'wrong' }, { ordering: 'wrong' }, { scanned_transfers: 17 },
    { next_cursor: 'short' }, { items: [{ scope_digest: null }] },
    { scanned_transfers: 0, next_cursor: digest(1) },
  ])('rejects inconsistent queue pages', async change => {
    const { collectQueue } = await import('../src/commands/investigation.js');
    mocks.request.mockResolvedValue({ ...page, ...change });
    await expect(collectQueue('https://example.com', 'token', Buffer.from('{}'), 1)).rejects.toThrow();
  });
  it('rejects a cursor that fails to advance from an explicit starting point', async () => {
    const { collectQueue } = await import('../src/commands/investigation.js');
    mocks.request.mockResolvedValue({ ...page, next_cursor: digest(1) });
    await expect(collectQueue('https://example.com', 'token', Buffer.from(JSON.stringify({ after: digest(1) })), 1))
      .rejects.toThrow('Nonadvancing cursor');
  });
  it('orders equal-aged scopes deterministically', async () => {
    const { collectQueue } = await import('../src/commands/investigation.js');
    mocks.request.mockResolvedValue({ ...page, items: [2, 1].map(n => ({ scope_digest: digest(n), oldest_age_seconds: 5 })) });
    const result = await collectQueue('https://example.com', 'token', Buffer.from('{}'), 1);
    expect((result.items as { scope_digest: string }[]).map(item => item.scope_digest)).toEqual([digest(1), digest(2)]);
  });
});

describe('investigation CLI', () => {
  it.each(['timeline', 'queue'])('renders and exports validated %s results', async name => {
    const { investigationCommand } = await import('../src/commands/investigation.js');
    mocks.request.mockResolvedValue(name === 'queue' ? page : timeline);
    for (const extra of [[], ['--json']]) {
      await investigationCommand.parseAsync([name, '--api-url', 'http://127.0.0.1:1234', ...extra], { from: 'user' });
    }
    expect(output).toHaveBeenCalledTimes(2);
    expect(output.mock.calls[0][0]).toContain(name === 'queue' ? 'Reached the end' : 'Transfer scope');
    expect(JSON.parse(output.mock.calls[1][0] as string).schema_version)
      .toBe(name === 'queue' ? 'clearproof-collected-queue-v1' : 'clearproof-investigation-v1');
    expect(errors).not.toHaveBeenCalled();
  });
  it('rejects missing tokens before reading confidential input', async () => {
    const { investigationCommand } = await import('../src/commands/investigation.js');
    vi.stubEnv('CLEARPROOF_API_TOKEN', undefined);
    await investigationCommand.parseAsync(['timeline', '--api-url', 'http://127.0.0.1:1234'], { from: 'user' });
    expect(mocks.read).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
  it('validates consumed fields even in JSON mode and emits sanitized errors', async () => {
    const { investigationCommand } = await import('../src/commands/investigation.js');
    mocks.request.mockResolvedValue({ ...timeline, states: 'SYNTHETIC-PRIVATE' });
    await investigationCommand.parseAsync(['timeline', '--api-url', 'http://127.0.0.1:1234', '--json'], { from: 'user' });
    expect(output).not.toHaveBeenCalled();
    expect(errors).toHaveBeenCalledOnce();
    expect(errors.mock.calls.flat().join('')).not.toContain('SYNTHETIC-PRIVATE');
    expect(process.exitCode).toBe(1);
  });
});


it('does not label a resumed traversal as a complete scan from the start', async () => {
  const { collectQueue, renderInvestigation } = await import('../src/commands/investigation.js');
  mocks.request.mockResolvedValue(page);
  const result = await collectQueue('https://example.com', 'token', Buffer.from(JSON.stringify({ after: digest(1) })), 1);
  expect(result.next_cursor).toBeNull();
  expect(result.started_after).toBe(digest(1));
  expect(result.complete_from_start).toBe(false);
  expect(renderInvestigation(result, true)).toContain('Partial queue traversal.');
});

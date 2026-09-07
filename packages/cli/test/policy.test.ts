import { afterEach, describe, expect, it } from 'vitest';
import { createServer, Server } from 'node:http';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { resolve } from 'node:path';
import { policyDiff, policyEndpoint, readPolicyInput } from '../src/commands/policy.js';

let server: Server | undefined;
afterEach(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((done) => server!.close(() => done()));
    server = undefined;
  }
});
async function listen(handler: Parameters<typeof createServer>[0]) {
  server = createServer(handler);
  await new Promise<void>((done) => server!.listen(0, '127.0.0.1', done));
  const address = server.address() as { port: number };
  return `http://127.0.0.1:${address.port}`;
}
const report = { schema_version: 'clearproof-policy-diff-v1', mode: 'counterfactual', cases: [], review_delta: 1 };

describe('policy API transport', () => {
  it('restricts origin syntax and bounds stdin', async () => {
    for (const origin of ['http://example.com', 'https://user:secret@example.com',
      'https://example.com/path', 'https://example.com/?token=secret', 'https://example.com/#x']) {
      expect(() => policyEndpoint(origin, false)).toThrow();
    }
    expect(policyEndpoint('https://api.example.com', true).pathname).toBe('/pilot/policy/diff/stored');
    expect(await readPolicyInput(Readable.from(['{}']))).toEqual(Buffer.from('{}'));
    await expect(readPolicyInput(Readable.from([Buffer.alloc(1024 * 1024 + 1)]))).rejects.toThrow();
    await expect(readPolicyInput(Readable.from([]))).rejects.toThrow();
  });

  it('sends exact input and bearer authorization to the selected route', async () => {
    const observed: { path?: string; auth?: string; body?: string } = {};
    const origin = await listen(async (req, res) => {
      observed.path = req.url;
      observed.auth = req.headers.authorization;
      let body = '';
      for await (const chunk of req) body += chunk;
      observed.body = body;
      res.end(JSON.stringify(report));
    });
    expect(JSON.parse(await policyDiff(origin, 'test-token', true, Buffer.from('{"case_digests":[]}')))).toEqual(report);
    expect(observed).toEqual({ path: '/pilot/policy/diff/stored', auth: 'Bearer test-token', body: '{"case_digests":[]}' });
  });

  it('does not follow redirects or expose rejected response bodies', async () => {
    let requests = 0;
    const origin = await listen((_req, res) => {
      requests++;
      res.writeHead(302, { location: '/secret-target' });
      res.end('sensitive-response');
    });
    await expect(policyDiff(origin, 'test-token', false, Buffer.from('{}'))).rejects.toThrow();
    expect(requests).toBe(1);
  });

  it('rejects oversized responses', async () => {
    const origin = await listen((_req, res) => res.end('x'.repeat(2 * 1024 * 1024 + 1)));
    await expect(policyDiff(origin, 'test-token', false, Buffer.from('{}'))).rejects.toThrow('Response limit');
  });

  it('runs the built CLI with stdin and redacts failures', async () => {
    const origin = await listen((_req, res) => res.end(JSON.stringify(report)));
    async function command(token: string) {
      const child = spawn(process.execPath, [resolve('dist/index.js'), 'policy', 'diff', '--api-url', origin, '--stored'], {
        env: { ...process.env, CLEARPROOF_API_TOKEN: token }, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '';
      child.stdout.on('data', (chunk) => { stdout += chunk; });
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.stdin.on('error', () => {});
      child.stdin.end('{"sensitive-input":"private-marker"}');
      const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
      const code = await new Promise<number | null>((done) => child.on('close', done));
      clearTimeout(timer);
      return { code, stdout, stderr };
    }
    const good = await command('test-token');
    expect(good.code, good.stderr).toBe(0);
    expect(JSON.parse(good.stdout)).toEqual(report);
    const bad = await command('');
    expect(bad.code).toBe(1);
    expect(bad.stdout).toBe('');
    expect(bad.stderr).not.toContain('private-marker');
    expect(bad.stderr).not.toContain(origin);
  });
});
